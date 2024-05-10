pub mod body;

use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::Error;
use axum::{
    async_trait,
    body::Body,
    extract::{Extension, Request, State},
    middleware::Next,
    response::{IntoResponse, Response},
    routing::get,
    Router,
};
use http::header::CONTENT_TYPE;
use jemalloc_ctl::{epoch, stats};
use prometheus::{
    register_histogram_vec_with_registry, register_int_counter_vec_with_registry,
    register_int_gauge_with_registry, Encoder, HistogramVec, IntCounterVec, IntGauge, Registry,
    TextEncoder,
};
use tokio::{select, sync::RwLock};
use tokio_util::sync::CancellationToken;
use tower_http::compression::CompressionLayer;
use tracing::{debug, info, warn};

use crate::{
    core::Run,
    http::{calc_headers_size, http_version, server::ConnInfo},
    routing::{middleware::request_id::RequestId, ErrorCause, RequestCtx},
};
use body::CountingBody;

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
    encoder: TextEncoder,
    mem_allocated: IntGauge,
    mem_resident: IntGauge,
}

// Snapshots & encodes the metrics for the handler to export
impl MetricsRunner {
    pub fn new(metrics_cache: Arc<RwLock<MetricsCache>>, registry: &Registry) -> Self {
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

        Self {
            metrics_cache,
            registry: registry.clone(),
            encoder: TextEncoder::new(),
            mem_allocated,
            mem_resident,
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
                        warn!("Unable to update metrics: {e}");
                    } else {
                        debug!("Metrics updated in {}ms", start.elapsed().as_millis());
                    }
                }
            }
        }
    }
}

async fn handler(State(state): State<Arc<RwLock<MetricsCache>>>) -> impl IntoResponse {
    // Get a read lock and clone the buffer contents
    (
        [(CONTENT_TYPE, PROMETHEUS_CONTENT_TYPE)],
        state.read().await.buffer.clone(),
    )
}

pub fn setup(registry: &Registry) -> (Router, Arc<dyn Run>) {
    let cache = Arc::new(RwLock::new(MetricsCache::new(METRICS_CACHE_CAPACITY)));
    let runner = Arc::new(MetricsRunner::new(cache.clone(), registry));

    let router = Router::new()
        .route("/metrics", get(handler))
        .layer(
            CompressionLayer::new()
                .gzip(true)
                .br(true)
                .zstd(true)
                .deflate(true),
        )
        .with_state(cache);

    (router, runner as Arc<dyn Run>)
}

#[derive(Clone)]
pub struct HttpMetrics {
    pub requests: IntCounterVec,
    pub duration: HistogramVec,
    pub duration_full: HistogramVec,
    pub request_size: HistogramVec,
    pub response_size: HistogramVec,
}

impl HttpMetrics {
    pub fn new(registry: &Registry) -> Self {
        const LABELS_HTTP: &[&str] = &["tls", "method", "http", "domain", "status", "error"];

        Self {
            requests: register_int_counter_vec_with_registry!(
                format!("http_total"),
                format!("Counts occurrences of requests"),
                LABELS_HTTP,
                registry
            )
            .unwrap(),

            duration: register_histogram_vec_with_registry!(
                format!("http_duration_sec"),
                format!("Records the duration of request processing in seconds"),
                LABELS_HTTP,
                HTTP_DURATION_BUCKETS.to_vec(),
                registry
            )
            .unwrap(),

            duration_full: register_histogram_vec_with_registry!(
                format!("http_duration_full_sec"),
                format!("Records the full duration of request processing including response streaming in seconds"),
                LABELS_HTTP,
                HTTP_DURATION_BUCKETS.to_vec(),
                registry
            )
            .unwrap(),

            request_size: register_histogram_vec_with_registry!(
                format!("http_request_size"),
                format!("Records the size of requests"),
                LABELS_HTTP,
                HTTP_REQUEST_SIZE_BUCKETS.to_vec(),
                registry
            )
            .unwrap(),

            response_size: register_histogram_vec_with_registry!(
                format!("http_response_size"),
                format!("Records the size of responses"),
                LABELS_HTTP,
                HTTP_RESPONSE_SIZE_BUCKETS.to_vec(),
                registry
            )
            .unwrap(),
        }
    }
}

pub async fn middleware(
    State(state): State<Arc<HttpMetrics>>,
    Extension(conn_info): Extension<Arc<ConnInfo>>,
    Extension(request_id): Extension<RequestId>,
    request: Request,
    next: Next,
) -> impl IntoResponse {
    // Prepare to execute the request and count its body size
    let (parts, body) = request.into_parts();
    let (tx, rx) = std::sync::mpsc::sync_channel(1);
    let request_callback = move |size: u64, _: Result<(), String>| {
        let _ = tx.send(size);
    };
    let body = Body::new(CountingBody::new(body, request_callback));
    let request = Request::from_parts(parts, body);

    // Gather needed stuff from request before it's consumed
    let method = request.method().clone();
    let http_version = http_version(request.version());
    let request_size_headers = calc_headers_size(request.headers()) as u64;
    let uri = request.uri().clone();

    // Execute the request
    let response = next.run(request).await;
    let duration = conn_info.accepted_at.elapsed();

    let ctx = response.extensions().get::<Arc<RequestCtx>>().cloned();
    let error_cause = response.extensions().get::<ErrorCause>().cloned();
    let status = response.status().as_u16().to_string();

    // By this time the channel should already have the data
    // since the response headers are already received -> request body was for sure read (or an error happened)
    let request_size = rx.recv().unwrap_or(0) + request_size_headers;

    // The callback will be executed when the streaming of the response body to the client will finish
    // or the error happens
    let response_callback = move |response_size: u64, _: Result<(), String>| {
        let duration_full = conn_info.accepted_at.elapsed();

        let (tls_version, tls_cipher) = conn_info
            .tls
            .as_ref()
            .map(|x| (x.protocol.as_str().unwrap(), x.cipher.as_str().unwrap()))
            .unwrap_or(("no", "no"));
        let domain = ctx
            .as_ref()
            .map(|x| x.canister.domain.to_string())
            .unwrap_or_else(|| "unknown".into());
        let error_cause = error_cause
            .clone()
            .map(|x| x.to_string())
            .unwrap_or_else(|| "no".into());

        let labels = &[
            tls_version,
            method.as_str(),
            http_version,
            &domain,
            &status,
            &error_cause,
        ];

        // Update metrics
        state.requests.with_label_values(labels).inc();
        state
            .duration
            .with_label_values(labels)
            .observe(duration.as_secs_f64());
        state
            .duration_full
            .with_label_values(labels)
            .observe(duration_full.as_secs_f64());
        state
            .request_size
            .with_label_values(labels)
            .observe(request_size as f64);
        state
            .response_size
            .with_label_values(labels)
            .observe(response_size as f64);

        // Log the request
        info!(
            request_id = request_id.to_string(),
            method = method.as_str(),
            http = http_version,
            status,
            tls_version,
            tls_cipher,
            domain,
            host = uri.host(),
            path = uri.path(),
            canister_id = ctx.as_ref().map(|x| x.canister.id.to_string()),
            error = error_cause,
            req_size = request_size,
            resp_size = response_size,
            dur = duration.as_millis(),
            dur_full = duration_full.as_millis(),
        );
    };

    let (parts, body) = response.into_parts();
    let body = CountingBody::new(body, response_callback);
    Response::from_parts(parts, body)
}
