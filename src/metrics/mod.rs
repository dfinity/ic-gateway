pub mod body;

use std::{
    net::SocketAddr,
    pin::Pin,
    sync::{atomic::AtomicBool, Arc},
    time::Instant,
};

use axum::{
    extract::{Extension, Request, State},
    middleware::Next,
    response::{IntoResponse, Response},
};
use prometheus::{
    proto::MetricFamily, register_histogram_vec_with_registry,
    register_int_counter_vec_with_registry, register_int_gauge_vec_with_registry,
    register_int_gauge_with_registry, Encoder, HistogramOpts, HistogramVec, IntCounterVec,
    IntGauge, IntGaugeVec, Registry, TextEncoder,
};
use tracing::warn;

use crate::routing::middleware::request_id::RequestId;
use body::CountingBody;

const KB: f64 = 1024.0;

pub const HTTP_DURATION_BUCKETS: &[f64] = &[0.05, 0.2, 1.0, 2.0];
pub const HTTP_REQUEST_SIZE_BUCKETS: &[f64] = &[128.0, KB, 2.0 * KB, 4.0 * KB, 8.0 * KB];
pub const HTTP_RESPONSE_SIZE_BUCKETS: &[f64] = &[1.0 * KB, 8.0 * KB, 64.0 * KB, 256.0 * KB];

// https://prometheus.io/docs/instrumenting/exposition_formats/#basic-info
const PROMETHEUS_CONTENT_TYPE: &str = "text/plain; version=0.0.4";

#[derive(Clone)]
pub struct HttpMetricParams {
    pub counter: IntCounterVec,
    pub durationer: HistogramVec,
    pub request_sizer: HistogramVec,
    pub response_sizer: HistogramVec,
}

impl HttpMetricParams {
    pub fn new(registry: &Registry) -> Self {
        const LABELS_HTTP: &[&str] = &["domain", "status_code", "error_cause", "cache_status"];

        Self {
            counter: register_int_counter_vec_with_registry!(
                format!("http_total"),
                format!("Counts occurrences of requests"),
                LABELS_HTTP,
                registry
            )
            .unwrap(),

            durationer: register_histogram_vec_with_registry!(
                format!("http_duration_sec"),
                format!("Records the duration of request processing in seconds"),
                LABELS_HTTP,
                HTTP_DURATION_BUCKETS.to_vec(),
                registry
            )
            .unwrap(),

            request_sizer: register_histogram_vec_with_registry!(
                format!("http_request_size"),
                format!("Records the size of requests"),
                LABELS_HTTP,
                HTTP_REQUEST_SIZE_BUCKETS.to_vec(),
                registry
            )
            .unwrap(),

            response_sizer: register_histogram_vec_with_registry!(
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
    State(state): State<HttpMetricParams>,
    Extension(request_id): Extension<RequestId>,
    request: Request,
    next: Next,
) -> impl IntoResponse {
    let response = next.run(request).await;
    let (parts, body) = response.into_parts();

    let record_metrics =
        move |response_size: u64, _body_result: Result<(), String>| warn!("{}", response_size);

    let body = CountingBody::new(body, record_metrics);
    Response::from_parts(parts, body)
}
