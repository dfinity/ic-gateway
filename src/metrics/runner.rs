use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::Error;
use arc_swap::ArcSwap;
use axum::{async_trait, extract::State, response::IntoResponse};
use bytes::Bytes;
use http::header::CONTENT_TYPE;
use ic_bn_lib::{tasks::Run, tls::sessions};
use prometheus::{register_int_gauge_with_registry, Encoder, IntGauge, Registry, TextEncoder};
use tikv_jemalloc_ctl::{epoch, stats};
use tokio::select;
use tokio_util::sync::CancellationToken;
use tracing::{debug, warn};

// https://prometheus.io/docs/instrumenting/exposition_formats/#basic-info
const PROMETHEUS_CONTENT_TYPE: &str = "text/plain; version=0.0.4";

pub struct MetricsCache {
    buffer: ArcSwap<Bytes>,
}

impl MetricsCache {
    pub fn new() -> Self {
        Self {
            buffer: ArcSwap::new(Arc::new(Bytes::from(vec![]))),
        }
    }
}

pub struct MetricsRunner {
    metrics_cache: Arc<MetricsCache>,
    registry: Registry,
    tls_session_cache: Arc<sessions::Storage>,
    encoder: TextEncoder,

    // Metrics
    mem_allocated: IntGauge,
    mem_resident: IntGauge,
    tls_session_cache_count: IntGauge,
    tls_session_cache_size: IntGauge,
}

// Snapshots & encodes the metrics for the handler to export
impl MetricsRunner {
    pub fn new(
        metrics_cache: Arc<MetricsCache>,
        registry: &Registry,
        tls_session_cache: Arc<sessions::Storage>,
    ) -> Self {
        let mem_allocated = register_int_gauge_with_registry!(
            format!("memory_allocated"),
            format!("Allocated memory in bytes"),
            registry
        )
        .unwrap();

        let mem_resident = register_int_gauge_with_registry!(
            format!("memory_resident"),
            format!("Resident memory in bytes"),
            registry
        )
        .unwrap();

        let tls_session_cache_count = register_int_gauge_with_registry!(
            format!("tls_session_cache_count"),
            format!("Number of TLS sessions in the cache"),
            registry
        )
        .unwrap();

        let tls_session_cache_size = register_int_gauge_with_registry!(
            format!("tls_session_cache_size"),
            format!("Size of TLS sessions in the cache"),
            registry
        )
        .unwrap();

        Self {
            metrics_cache,
            registry: registry.clone(),
            tls_session_cache,
            encoder: TextEncoder::new(),
            mem_allocated,
            mem_resident,
            tls_session_cache_count,
            tls_session_cache_size,
        }
    }
}

impl MetricsRunner {
    async fn update(&self) -> Result<(), Error> {
        // Record jemalloc memory usage
        epoch::advance().unwrap();
        self.mem_allocated
            .set(stats::allocated::read().unwrap() as i64);
        self.mem_resident
            .set(stats::resident::read().unwrap() as i64);

        // Record TLS session stats
        let stats = self.tls_session_cache.stats();
        self.tls_session_cache_count.set(stats.entries as i64);
        self.tls_session_cache_size.set(stats.size as i64);

        // Get a snapshot of metrics
        let metric_families = self.registry.gather();

        // Encode the metrics into the buffer
        let mut buffer = Vec::with_capacity(10 * 1024 * 1024);
        self.encoder.encode(&metric_families, &mut buffer)?;

        // Store the new snapshot
        self.metrics_cache
            .buffer
            .store(Arc::new(Bytes::from(buffer)));

        Ok(())
    }
}

#[async_trait]
impl Run for MetricsRunner {
    async fn run(&self, token: CancellationToken) -> Result<(), Error> {
        let mut interval = tokio::time::interval(Duration::from_secs(5));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        warn!("MetricsRunner: started");
        loop {
            select! {
                biased;

                () = token.cancelled() => {
                    warn!("MetricsRunner: exited");
                    return Ok(());
                }

                _ = interval.tick() => {
                    let start = Instant::now();
                    if let Err(e) = self.update().await {
                        warn!("Unable to update metrics: {e:#}");
                    } else {
                        debug!("Metrics updated in {}ms", start.elapsed().as_millis());
                    }
                }
            }
        }
    }
}

pub async fn handler(State(state): State<Arc<MetricsCache>>) -> impl IntoResponse {
    (
        [(CONTENT_TYPE, PROMETHEUS_CONTENT_TYPE)],
        state.buffer.load_full().as_ref().clone(),
    )
}
