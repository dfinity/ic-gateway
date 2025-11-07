use std::{sync::Arc, time::Instant};

use anyhow::Error;
use arc_swap::ArcSwap;
use async_trait::async_trait;
use axum::{extract::State, response::IntoResponse};
use bytes::{BufMut, Bytes, BytesMut};
use http::header::CONTENT_TYPE;
use ic_bn_lib::ic_agent::agent::route_provider::RouteProvider;
use ic_bn_lib_common::traits::Run;
use prometheus::{
    Encoder, IntGauge, IntGaugeVec, Registry, TextEncoder, register_int_gauge_vec_with_registry,
    register_int_gauge_with_registry,
};
use tikv_jemalloc_ctl::{epoch, stats};
use tokio_util::sync::CancellationToken;
use tracing::{debug, warn};

// https://prometheus.io/docs/instrumenting/exposition_formats/#basic-info
const PROMETHEUS_CONTENT_TYPE: &str = "text/plain; version=0.0.4";

pub struct MetricsCache {
    buffer: ArcSwap<Bytes>,
}

#[allow(clippy::new_without_default)]
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
    encoder: TextEncoder,
    route_provider: Arc<dyn RouteProvider>,
    // Metrics
    mem_allocated: IntGauge,
    mem_resident: IntGauge,
    // API boundary nodes metrics
    api_boundary_nodes: IntGaugeVec,
}

// Snapshots & encodes the metrics for the handler to export
impl MetricsRunner {
    pub fn new(
        metrics_cache: Arc<MetricsCache>,
        registry: &Registry,
        route_provider: Arc<dyn RouteProvider>,
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

        let api_boundary_nodes = register_int_gauge_vec_with_registry!(
            "api_boundary_nodes",
            "Number of API boundary nodes with status.",
            &["status"],
            registry
        )
        .unwrap();

        Self {
            metrics_cache,
            registry: registry.clone(),
            encoder: TextEncoder::new(),
            mem_allocated,
            mem_resident,
            route_provider,
            api_boundary_nodes,
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

        // Get a snapshot of metrics
        let metric_families = self.registry.gather();

        // Encode the metrics into the buffer
        let mut buffer = BytesMut::with_capacity(10 * 1024 * 1024).writer();
        self.encoder.encode(&metric_families, &mut buffer)?;

        // Store the new snapshot
        self.metrics_cache
            .buffer
            .store(Arc::new(buffer.into_inner().freeze()));

        // Update API boundary nodes stats
        let stats = self.route_provider.routes_stats();
        self.api_boundary_nodes
            .with_label_values(&["total"])
            .set(stats.total as i64);
        self.api_boundary_nodes
            .with_label_values(&["healthy"])
            .set(stats.healthy.unwrap_or(0) as i64);

        Ok(())
    }
}

#[async_trait]
impl Run for MetricsRunner {
    async fn run(&self, _: CancellationToken) -> Result<(), Error> {
        let start = Instant::now();
        if let Err(e) = self.update().await {
            warn!("Unable to update metrics: {e:#}");
        } else {
            debug!("Metrics updated in {}ms", start.elapsed().as_millis());
        }

        Ok(())
    }
}

pub async fn handler(State(state): State<Arc<MetricsCache>>) -> impl IntoResponse {
    (
        [(CONTENT_TYPE, PROMETHEUS_CONTENT_TYPE)],
        state.buffer.load().as_ref().clone(),
    )
}
