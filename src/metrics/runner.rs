use std::{
    sync::{atomic::Ordering, Arc},
    time::{Duration, Instant},
};

use anyhow::Error;
use axum::{
    async_trait,
    body::Body,
    extract::{Extension, MatchedPath, Request, State},
    middleware::Next,
    response::{IntoResponse, Response},
    routing::get,
    Router,
};
use http::header::CONTENT_TYPE;
use prometheus::{
    register_histogram_vec_with_registry, register_int_counter_vec_with_registry,
    register_int_gauge_with_registry, Encoder, HistogramVec, IntCounterVec, IntGauge, Registry,
    TextEncoder,
};
use serde_json::json;
use tikv_jemalloc_ctl::{epoch, stats};
use tokio::{select, sync::RwLock};
use tokio_util::sync::CancellationToken;
use tower_http::compression::CompressionLayer;
use tracing::{debug, info, warn};
use vector_lib::{config::LogNamespace, event::Event};

use crate::{
    http::{
        calc_headers_size, http_version,
        server::{ConnInfo, TlsInfo},
    },
    routing::{
        error_cause::ErrorCause,
        ic::{BNResponseMetadata, IcResponseStatus},
        middleware::{cache::CacheStatus, request_id::RequestId},
        CanisterId, RequestCtx, RequestType, RequestTypeApi,
    },
    tasks::{Run, TaskManager},
    tls::sessions,
};

const KB: f64 = 1024.0;
const METRICS_CACHE_CAPACITY: usize = 15 * 1024 * 1024;

pub const HTTP_DURATION_BUCKETS: &[f64] = &[0.05, 0.2, 1.0, 2.0];
pub const HTTP_REQUEST_SIZE_BUCKETS: &[f64] = &[128.0, KB, 2.0 * KB, 4.0 * KB, 8.0 * KB];
pub const HTTP_RESPONSE_SIZE_BUCKETS: &[f64] = &[1.0 * KB, 8.0 * KB, 64.0 * KB, 256.0 * KB];

// https://prometheus.io/docs/instrumenting/exposition_formats/#basic-info
const PROMETHEUS_CONTENT_TYPE: &str = "text/plain; version=0.0.4";

pub struct MetricsCache {
    buffer: Vec<u8>,
}

impl MetricsCache {
    pub fn new(capacity: usize) -> Self {
        Self {
            // Preallocate a large enough vector, it'll be expanded if needed
            buffer: Vec::with_capacity(capacity),
        }
    }
}

pub struct MetricsRunner {
    metrics_cache: Arc<RwLock<MetricsCache>>,
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
        metrics_cache: Arc<RwLock<MetricsCache>>,
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

        // Take a write lock, truncate the vector and encode the metrics into it
        let mut metrics_cache = self.metrics_cache.write().await;
        metrics_cache.buffer.clear();
        self.encoder
            .encode(&metric_families, &mut metrics_cache.buffer)?;
        drop(metrics_cache); // clippy

        Ok(())
    }
}

#[async_trait]
impl Run for MetricsRunner {
    async fn run(&self, token: CancellationToken) -> Result<(), Error> {
        let mut interval = tokio::time::interval(Duration::from_secs(5));

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

pub async fn handler(State(state): State<Arc<RwLock<MetricsCache>>>) -> impl IntoResponse {
    // Get a read lock and clone the buffer contents
    (
        [(CONTENT_TYPE, PROMETHEUS_CONTENT_TYPE)],
        state.read().await.buffer.clone(),
    )
}
