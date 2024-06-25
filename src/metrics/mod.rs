pub mod body;
pub mod clickhouse;
pub mod runner;
pub mod vector;

use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use axum::{
    body::Body,
    extract::{Extension, MatchedPath, Request, State},
    middleware::Next,
    response::{IntoResponse, Response},
    routing::get,
    Router,
};
use prometheus::{
    register_histogram_vec_with_registry, register_int_counter_vec_with_registry, HistogramVec,
    IntCounterVec, Registry,
};
use serde_json::json;
use tokio::sync::RwLock;
use tower_http::compression::CompressionLayer;
use tracing::info;
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
    tasks::TaskManager,
    tls::sessions,
};
use body::CountingBody;

pub use {
    clickhouse::{Clickhouse, Row},
    vector::Vector,
};

const KB: f64 = 1024.0;
const METRICS_CACHE_CAPACITY: usize = 15 * 1024 * 1024;

pub const HTTP_DURATION_BUCKETS: &[f64] = &[0.05, 0.2, 1.0, 2.0];
pub const HTTP_REQUEST_SIZE_BUCKETS: &[f64] = &[128.0, KB, 2.0 * KB, 4.0 * KB, 8.0 * KB];
pub const HTTP_RESPONSE_SIZE_BUCKETS: &[f64] = &[1.0 * KB, 8.0 * KB, 64.0 * KB, 256.0 * KB];

pub fn setup(
    registry: &Registry,
    tls_session_cache: Arc<sessions::Storage>,
    tasks: &mut TaskManager,
) -> Router {
    let cache = Arc::new(RwLock::new(runner::MetricsCache::new(
        METRICS_CACHE_CAPACITY,
    )));
    let runner = Arc::new(runner::MetricsRunner::new(
        cache.clone(),
        registry,
        tls_session_cache,
    ));
    tasks.add("metrics_runner", runner);

    Router::new()
        .route("/metrics", get(runner::handler))
        .layer(
            CompressionLayer::new()
                .gzip(true)
                .br(true)
                .zstd(true)
                .deflate(true),
        )
        .with_state(cache)
}

#[derive(Clone)]
pub struct HttpMetrics {
    pub env: String,
    pub hostname: String,

    pub requests: IntCounterVec,
    pub duration: HistogramVec,
    pub duration_full: HistogramVec,
    pub request_size: HistogramVec,
    pub response_size: HistogramVec,

    pub clickhouse: Option<Arc<Clickhouse>>,
    pub vector: Option<Arc<Vector>>,
}

impl HttpMetrics {
    pub fn new(
        registry: &Registry,
        env: String,
        hostname: String,
        clickhouse: Option<Arc<Clickhouse>>,
        vector: Option<Arc<Vector>>,
    ) -> Self {
        const LABELS_HTTP: &[&str] = &["tls", "method", "http", "domain", "status", "error"];

        Self {
            env,
            hostname,
            clickhouse,
            vector,

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
    tls_info: Option<Extension<Arc<TlsInfo>>>,
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
    let start = Instant::now();
    let timestamp = time::OffsetDateTime::now_utc();
    let mut response = next.run(request).await;
    let duration = start.elapsed();

    let ctx = response.extensions_mut().remove::<Arc<RequestCtx>>();
    let canister_id = response.extensions_mut().remove::<CanisterId>();
    let error_cause = response.extensions_mut().remove::<ErrorCause>();
    let ic_status = response.extensions_mut().remove::<IcResponseStatus>();
    let status = response.status().as_u16();

    // Gather cache info
    let cache_status = response
        .extensions_mut()
        .remove::<CacheStatus>()
        .unwrap_or_default();

    let cache_bypass_reason_str: &'static str = match &cache_status {
        CacheStatus::Bypass(v) => v.into(),
        _ => "none",
    };

    let cache_status_str: &'static str = cache_status.into();
    let request_type = response
        .extensions_mut()
        .remove::<MatchedPath>()
        .map(|x| match x.as_str() {
            "/api/v2/canister/:principal/query" => RequestType::Api(RequestTypeApi::Query),
            "/api/v2/canister/:principal/call" => RequestType::Api(RequestTypeApi::Call),
            "/api/v2/canister/:principal/read_state" => RequestType::Api(RequestTypeApi::ReadState),
            "/api/v2/subnet/:principal/read_state" => {
                RequestType::Api(RequestTypeApi::ReadStateSubnet)
            }
            "/api/v2/status" => RequestType::Api(RequestTypeApi::Status),
            "/health" => RequestType::Health,
            "/registrations" => RequestType::Registrations,
            "/registrations/:id" => RequestType::Registrations,
            _ => RequestType::Unknown,
        })
        .unwrap_or(RequestType::Http);
    let request_type: &'static str = request_type.into();

    let meta = response
        .extensions_mut()
        .remove::<BNResponseMetadata>()
        .unwrap_or_default();

    // By this time the channel should already have the data
    // since the response headers are already received -> request body was for sure read (or an error happened)
    let request_size = rx.recv().unwrap_or(0) + request_size_headers;

    // The callback will be executed when the streaming of the response body to the client will finish
    // or the error happens
    let response_callback = move |response_size: u64, _: Result<(), String>| {
        let duration_full = start.elapsed();
        let meta = meta.clone();

        let (tls_version, tls_cipher, tls_handshake) = tls_info
            .as_ref()
            .map(|x| {
                (
                    x.protocol.as_str().unwrap(),
                    x.cipher.as_str().unwrap(),
                    x.handshake_dur,
                )
            })
            .unwrap_or(("no", "no", Duration::ZERO));
        let domain = ctx
            .as_ref()
            .map(|x| x.domain.name.to_string())
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
            &status.to_string(),
            &error_cause,
            cache_status_str,
            cache_bypass_reason_str,
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

        let host = uri.host().unwrap_or("");
        let path = uri.path();
        let canister_id = canister_id
            .map(|x| x.0.to_string())
            .unwrap_or_else(|| "unknown".into());

        let conn_rcvd = conn_info.traffic.rcvd();
        let conn_sent = conn_info.traffic.sent();
        let conn_req_count = conn_info.req_count();

        let (ic_streaming, ic_upgrade) = ic_status
            .as_ref()
            .map(|x| (x.streaming, x.metadata.upgraded_to_update_call))
            .unwrap_or((false, false));

        // Log the request
        info!(
            request_id = request_id.to_string(),
            conn_id = conn_info.id.to_string(),
            method = method.as_str(),
            http = http_version,
            status,
            tls_version,
            tls_cipher,
            tls_handshake = tls_handshake.as_millis(),
            domain,
            host,
            path,
            canister_id,
            ic_streaming,
            ic_upgrade,
            ic_node_id = meta.node_id,
            ic_subnet_id = meta.subnet_id,
            ic_subnet_type = meta.subnet_type,
            ic_method_name = meta.method_name,
            ic_sender = meta.sender,
            ic_canister_id_cbor = meta.canister_id_cbor,
            ic_error_cause = meta.error_cause,
            ic_retries = meta.retries,
            ic_cache_status = meta.cache_status,
            ic_cache_bypass_reason = meta.cache_bypass_reason,
            error = error_cause,
            req_size = request_size,
            resp_size = response_size,
            dur = duration.as_millis(),
            dur_full = duration_full.as_millis(),
            dur_conn = conn_info.accepted_at.elapsed().as_millis(),
            conn_rcvd,
            conn_sent,
            conn_reqs = conn_req_count,
            cache_status = cache_status_str,
            cache_bypass_reason = cache_bypass_reason_str,
        );

        if let Some(v) = &state.clickhouse {
            let meta = meta.clone();

            let row = Row {
                env: state.env.clone(),
                hostname: state.hostname.clone(),
                date: timestamp,
                request_id: request_id.0,
                conn_id: conn_info.id,
                method: method.as_str().to_string(),
                http_version: http_version.to_string(),
                request_type: request_type.to_string(),
                status,
                domain: domain.clone(),
                host: host.into(),
                path: path.into(),
                canister_id: canister_id.clone(),
                ic_streaming,
                ic_upgrade,
                ic_node_id: meta.node_id,
                ic_subnet_id: meta.subnet_id,
                ic_subnet_type: meta.subnet_type,
                ic_method_name: meta.method_name,
                ic_sender: meta.sender,
                ic_canister_id_cbor: meta.canister_id_cbor,
                ic_error_cause: meta.error_cause,
                ic_retries: meta.retries.parse().unwrap_or(0),
                ic_cache_status: meta.cache_status,
                ic_cache_bypass_reason: meta.cache_bypass_reason,
                error_cause: error_cause.clone(),
                tls_version: tls_version.into(),
                tls_cipher: tls_cipher.into(),
                req_rcvd: request_size,
                req_sent: response_size,
                conn_rcvd,
                conn_sent,
                duration: duration.as_secs_f64(),
                duration_full: duration_full.as_secs_f64(),
                duration_conn: conn_info.accepted_at.elapsed().as_secs_f64(),
                cache_status: cache_status_str,
                cache_bypass_reason: cache_bypass_reason_str,
            };

            v.send(row);
        }

        if let Some(v) = &state.vector {
            // Convert to Vector Event
            let event = Event::from_json_value(
                json!({
                    "env": state.env.clone(),
                    "hostname": state.hostname.clone(),
                    "date": timestamp.unix_timestamp(),
                    "request_id": request_id.to_string(),
                    "conn_id": conn_info.id.to_string(),
                    "method": method.as_str().to_string(),
                    "http_version": http_version.to_string(),
                    "request_type": request_type,
                    "status": status,
                    "domain": domain,
                    "host": host,
                    "path": path,
                    "canister_id": canister_id,
                    "ic_streaming": ic_streaming,
                    "ic_upgrade": ic_upgrade,
                    "ic_node_id": meta.node_id,
                    "ic_subnet_id": meta.subnet_id,
                    "ic_subnet_type": meta.subnet_type,
                    "ic_method_name": meta.method_name,
                    "ic_sender": meta.sender,
                    "ic_canister_id_cbor": meta.canister_id_cbor,
                    "ic_error_cause": meta.error_cause,
                    "ic_retries": meta.retries,
                    "ic_cache_status": meta.cache_status,
                    "ic_cache_bypass_reason": meta.cache_bypass_reason,
                    "error_cause": error_cause,
                    "tls_version": tls_version.to_string(),
                    "tls_cipher": tls_cipher.to_string(),
                    "req_rcvd": request_size,
                    "req_sent": response_size,
                    "conn_rcvd": conn_rcvd,
                    "conn_sent": conn_sent,
                    "duration": duration.as_secs_f64(),
                    "duration_full": duration_full.as_secs_f64(),
                    "duration_conn": conn_info.accepted_at.elapsed().as_secs_f64(),
                }),
                LogNamespace::Vector,
            )
            .unwrap(); // This never fails in our case

            v.send(event);
        }
    };

    let (parts, body) = response.into_parts();
    let body = CountingBody::new(body, response_callback);
    Response::from_parts(parts, body)
}
