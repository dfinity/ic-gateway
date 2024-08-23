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
use http::header::{CONTENT_TYPE, ORIGIN, REFERER, USER_AGENT};
use ic_bn_lib::{
    http::{
        body::CountingBody,
        cache::CacheStatus,
        calc_headers_size, http_method, http_version,
        server::{ConnInfo, TlsInfo},
    },
    tasks::TaskManager,
    tls::sessions,
};
use prometheus::{
    register_histogram_vec_with_registry, register_int_counter_vec_with_registry, HistogramVec,
    IntCounterVec, Registry,
};
use serde_json::json;
use tokio::sync::RwLock;
use tower_http::compression::CompressionLayer;
use tracing::info;

use crate::{
    core::{ENV, HOSTNAME},
    routing::{
        error_cause::ErrorCause,
        ic::{BNRequestMetadata, BNResponseMetadata, IcResponseStatus},
        middleware::{geoip::CountryCode, request_id::RequestId},
        CanisterId, RequestCtx, RequestType, RequestTypeApi,
    },
};

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
    pub log_requests: bool,

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
        log_requests: bool,
        clickhouse: Option<Arc<Clickhouse>>,
        vector: Option<Arc<Vector>>,
    ) -> Self {
        const LABELS_HTTP: &[&str] = &[
            "tls",
            "method",
            "http",
            "domain",
            "status",
            "error",
            "cache_status",
            "cache_bypass_reason",
            "response_verification_version",
        ];

        Self {
            log_requests,
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

fn infer_request_type(path: &str) -> RequestType {
    match path {
        "/api/v2/canister/:principal/query" => RequestType::Api(RequestTypeApi::Query),
        "/api/v2/canister/:principal/call" => RequestType::Api(RequestTypeApi::Call),
        "/api/v2/canister/:principal/read_state" => RequestType::Api(RequestTypeApi::ReadState),
        "/api/v2/subnet/:principal/read_state" => RequestType::Api(RequestTypeApi::ReadStateSubnet),
        "/api/v2/status" => RequestType::Api(RequestTypeApi::Status),
        "/health" => RequestType::Health,
        "/registrations" | "/registrations/:id" => RequestType::Registrations,
        _ => RequestType::Unknown,
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
    let (body, rx) = CountingBody::new(body);
    let body = Body::new(body);
    let request = Request::from_parts(parts, body);

    // Gather needed stuff from request before it's consumed
    let method: &'static str = http_method(request.method());
    let http_version: &'static str = http_version(request.version());
    let request_size_headers = calc_headers_size(request.headers()) as u64;
    let uri = request.uri().clone();

    // Some headers for logging
    let header_origin = request
        .headers()
        .get(ORIGIN)
        .and_then(|x| x.to_str().ok())
        .unwrap_or_default()
        .to_string();
    let header_referer = request
        .headers()
        .get(REFERER)
        .and_then(|x| x.to_str().ok())
        .unwrap_or_default()
        .to_string();
    let header_user_agent = request
        .headers()
        .get(USER_AGENT)
        .and_then(|x| x.to_str().ok())
        .unwrap_or_default()
        .to_string();
    let header_content_type = request
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|x| x.to_str().ok())
        .unwrap_or_default()
        .to_string();

    // Execute the request
    let start = Instant::now();
    let timestamp = time::OffsetDateTime::now_utc();
    let mut response = next.run(request).await;
    let duration = start.elapsed();

    let ctx = response.extensions_mut().remove::<Arc<RequestCtx>>();
    let canister_id = response.extensions_mut().get::<CanisterId>().copied();
    let error_cause = response.extensions_mut().remove::<ErrorCause>();
    let ic_status = response.extensions_mut().remove::<IcResponseStatus>();
    let country_code = response
        .extensions_mut()
        .remove::<CountryCode>()
        .map(|x| x.0)
        .unwrap_or_default();
    let status = response.status().as_u16();

    // IC request metadata
    let req_meta = response
        .extensions_mut()
        .remove::<BNRequestMetadata>()
        .unwrap_or_default();

    // IC response metadata
    let resp_meta = response
        .extensions_mut()
        .remove::<BNResponseMetadata>()
        .unwrap_or_default();

    // Gather cache info
    let cache_status = response
        .extensions_mut()
        .remove::<CacheStatus>()
        .unwrap_or_default();

    let cache_bypass_reason_str: &'static str = match &cache_status {
        CacheStatus::Bypass(v) => v.into(),
        _ => "none",
    };

    let response_verification_version = ic_status
        .as_ref()
        .and_then(|x| x.metadata.response_verification_version)
        .map(|x| x.to_string())
        .unwrap_or_else(|| "none".into());

    let cache_status_str: &'static str = cache_status.into();
    let request_type = response
        .extensions_mut()
        .remove::<MatchedPath>()
        .map_or(RequestType::Http, |x| infer_request_type(x.as_str()));
    // Strum IntoStaticStr doesn't respect to_string macro option, so fall back to allocation for now
    let request_type = request_type.to_string();

    // By this time the channel should already have the data
    // since the response headers are already received -> request body was for sure read (or an error happened)
    let request_size = rx.await.unwrap_or(Ok(0)).unwrap_or(0) + request_size_headers;

    let (parts, body) = response.into_parts();
    let (body, rx) = CountingBody::new(body);

    // Fire up a task that will receive the size of the body when it's done streaming and will log the results
    tokio::spawn(async move {
        // Wait for the streaming to finish
        let response_size = rx.await.unwrap_or(Ok(0)).unwrap_or(0);

        let duration_full = start.elapsed();
        let req_meta = req_meta.clone();
        let resp_meta = resp_meta.clone();

        let (tls_version, tls_cipher, tls_handshake) =
            tls_info.as_ref().map_or(("", "", Duration::ZERO), |x| {
                (
                    x.protocol.as_str().unwrap(),
                    x.cipher.as_str().unwrap(),
                    x.handshake_dur,
                )
            });
        let domain = ctx
            .as_ref()
            .map_or_else(String::new, |x| x.domain.name.to_string());
        let error_cause = error_cause
            .clone()
            .map_or_else(String::new, |x| x.to_string());

        let labels = &[
            tls_version,
            method,
            http_version,
            &domain,
            &status.to_string(),
            &error_cause,
            cache_status_str,
            cache_bypass_reason_str,
            &response_verification_version,
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
        let canister_id = canister_id.map_or_else(String::new, |x| x.0.to_string());

        let conn_rcvd = conn_info.traffic.rcvd();
        let conn_sent = conn_info.traffic.sent();
        let conn_req_count = conn_info.req_count();

        let (ic_streaming, ic_upgrade) = ic_status.as_ref().map_or((false, false), |x| {
            (x.streaming, x.metadata.upgraded_to_update_call)
        });

        // Log the request
        if state.log_requests {
            info!(
                request_id = request_id.to_string(),
                conn_id = conn_info.id.to_string(),
                method,
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
                ic_node_id = resp_meta.node_id,
                ic_subnet_id = resp_meta.subnet_id,
                ic_subnet_type = resp_meta.subnet_type,
                ic_method_name = resp_meta.method_name,
                ic_sender = resp_meta.sender,
                ic_canister_id_cbor = resp_meta.canister_id_cbor,
                ic_error_cause = resp_meta.error_cause,
                ic_retries = resp_meta.retries,
                ic_cache_status = resp_meta.cache_status,
                ic_cache_bypass_reason = resp_meta.cache_bypass_reason,
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
                backend = req_meta.backend,
            );
        }

        if let Some(v) = &state.clickhouse {
            let resp_meta = resp_meta.clone();

            let row = Row {
                env: ENV.get().unwrap().as_str(),
                hostname: HOSTNAME.get().unwrap().as_str(),
                date: timestamp,
                request_id: request_id.0,
                conn_id: conn_info.id,
                method,
                http_version,
                request_type: request_type.clone(),
                status,
                domain: domain.clone(),
                host: host.into(),
                path: path.into(),
                canister_id: canister_id.clone(),
                ic_streaming,
                ic_upgrade,
                ic_node_id: resp_meta.node_id,
                ic_subnet_id: resp_meta.subnet_id,
                ic_subnet_type: resp_meta.subnet_type,
                ic_method_name: resp_meta.method_name,
                ic_sender: resp_meta.sender,
                ic_canister_id_cbor: resp_meta.canister_id_cbor,
                ic_error_cause: resp_meta.error_cause,
                ic_retries: resp_meta.retries.parse().unwrap_or(0),
                ic_cache_status: resp_meta.cache_status,
                ic_cache_bypass_reason: resp_meta.cache_bypass_reason,
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
            // TODO use proper names when the DB is updated

            // Nginx-compatible log entry
            let val = json!({
                "env": ENV.get().unwrap().as_str(),
                "hostname": HOSTNAME.get().unwrap().as_str(),
                "msec": timestamp.unix_timestamp(),
                "request_id": request_id.to_string(),
                "request_method": method,
                "server_protocol": http_version,
                "status": status,
                "status_upstream": status,
                "http_host": host,
                "http_origin": header_origin,
                "http_referer": header_referer,
                "http_user_agent": header_user_agent,
                "content_type": header_content_type,
                "geo_country_code": country_code,
                "request_uri": uri.path_and_query().map(|x| x.as_str()).unwrap_or_default(),
                "query_string": uri.query().unwrap_or_default(),
                "ic_node_id": resp_meta.node_id,
                "ic_subnet_id": resp_meta.subnet_id,
                "ic_method_name": resp_meta.method_name,
                "ic_request_type": request_type,
                "ic_sender": resp_meta.sender,
                "ic_canister_id": canister_id,
                "ic_canister_id_cbor": resp_meta.canister_id_cbor,
                "ic_error_cause": resp_meta.error_cause,
                "retries": resp_meta.retries,
                "error_cause": error_cause,
                "ssl_protocol": tls_version,
                "ssl_cipher": tls_cipher,
                "request_length": request_size,
                "body_bytes_sent": response_size,
                "bytes_sent": response_size,
                "remote_addr": conn_info.remote_addr.ip().to_string(),
                "request_time": duration_full.as_secs_f64(),
                "request_time_headers": 0,
                "cache_status": resp_meta.cache_status,
                "cache_status_nginx": cache_status_str,
                "cache_bypass_reason": resp_meta.cache_bypass_reason,
                "upstream": req_meta.backend.unwrap_or_default(),
            });

            v.send(val);
        }
    });

    Response::from_parts(parts, body)
}
