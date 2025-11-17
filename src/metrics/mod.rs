#[cfg(feature = "clickhouse")]
pub mod clickhouse;
pub mod runner;

use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use axum::{
    Router,
    body::Body,
    extract::{Extension, Request, State},
    middleware::Next,
    response::{IntoResponse, Response},
    routing::get,
};
use http::header::{CONTENT_TYPE, ORIGIN, REFERER, USER_AGENT};
use ic_bn_lib::{
    http::{
        body::CountingBody, cache::CacheStatus, calc_headers_size, extract_host, http_method,
        http_version,
    },
    ic_agent::agent::route_provider::RouteProvider,
    tasks::TaskManager,
    vector::client::Vector,
};
use ic_bn_lib_common::types::http::{ConnInfo, TlsInfo};
use prometheus::{
    HistogramVec, IntCounterVec, Registry, register_histogram_vec_with_registry,
    register_int_counter_vec_with_registry,
};
use tower_http::compression::CompressionLayer;
use tracing::info;

use crate::{
    core::{ENV, HOSTNAME},
    routing::RemoteAddr,
};

use crate::routing::{
    CanisterId, RequestCtx,
    error_cause::ErrorCause,
    ic::{BNRequestMetadata, BNResponseMetadata, IcResponseStatus},
    middleware::{geoip::CountryCode, request_id::RequestId},
};

#[cfg(feature = "clickhouse")]
pub use clickhouse::{Clickhouse, Row};

const KB: f64 = 1024.0;

pub const HTTP_DURATION_BUCKETS: &[f64] = &[0.05, 0.2, 1.0, 2.0];
pub const HTTP_REQUEST_SIZE_BUCKETS: &[f64] = &[128.0, KB, 2.0 * KB, 4.0 * KB, 8.0 * KB];
pub const HTTP_RESPONSE_SIZE_BUCKETS: &[f64] = &[1.0 * KB, 8.0 * KB, 64.0 * KB, 256.0 * KB];

pub fn setup(
    registry: &Registry,
    tasks: &mut TaskManager,
    route_provider: Arc<dyn RouteProvider>,
) -> Router {
    let cache = Arc::new(runner::MetricsCache::new());
    let runner = Arc::new(runner::MetricsRunner::new(
        cache.clone(),
        registry,
        route_provider,
    ));
    tasks.add_interval("metrics_runner", runner, Duration::from_secs(5));

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

    pub vector: Option<Arc<Vector>>,
    #[cfg(feature = "clickhouse")]
    pub clickhouse: Option<Arc<Clickhouse>>,
}

impl HttpMetrics {
    pub fn new(
        registry: &Registry,
        log_requests: bool,
        vector: Option<Arc<Vector>>,
        #[cfg(feature = "clickhouse")] clickhouse: Option<Arc<Clickhouse>>,
    ) -> Self {
        const LABELS_HTTP: &[&str] = &[
            "tls",
            "method",
            "http",
            "status",
            "error",
            "cache_status",
            "cache_bypass_reason",
            "response_verification_version",
            "upstream",
        ];

        Self {
            log_requests,
            #[cfg(feature = "clickhouse")]
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
    Extension(request_id): Extension<RequestId>,
    mut request: Request,
    next: Next,
) -> impl IntoResponse {
    let remote_addr = request.extensions_mut().remove::<RemoteAddr>();
    let tls_info = request.extensions().get::<Arc<TlsInfo>>().cloned();
    let country_code = request
        .extensions_mut()
        .remove::<CountryCode>()
        .map(|x| x.0)
        .unwrap_or_default();

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
    // Strum IntoStaticStr doesn't respect to_string macro option, so fall back to allocation for now
    let request_type = ctx
        .as_ref()
        .map(|x| x.request_type.to_string())
        .unwrap_or_else(|| "unknown".into());

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

        let (error_cause, error_cause_details) = error_cause
            .clone()
            .map_or_else(|| (String::new(), None), |x| (x.to_string(), x.details()));

        let status_upstream = resp_meta.status.map(|x| x.as_u16()).unwrap_or_default();
        let upstream = req_meta
            .upstream
            .as_ref()
            .and_then(|x| extract_host(x))
            .unwrap_or_default();

        let labels = &[
            tls_version,
            method,
            http_version,
            &status.to_string(),
            &error_cause,
            cache_status_str,
            cache_bypass_reason_str,
            &response_verification_version,
            upstream,
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

        let conn_id = conn_info.id.to_string();
        let conn_rcvd = conn_info.traffic.rcvd();
        let conn_sent = conn_info.traffic.sent();
        let conn_reqs = conn_info.req_count();
        let remote_addr = remote_addr.map(|x| x.to_string()).unwrap_or_default();
        let request_id_str = request_id.to_string();

        let (ic_http_streaming, ic_http_upgrade) = ic_status.as_ref().map_or((false, false), |x| {
            (x.streaming, x.metadata.upgraded_to_update_call)
        });

        // Log the request
        if state.log_requests {
            info!(
                request_id = request_id_str,
                conn_id,
                method,
                http = http_version,
                status,
                status_upstream,
                tls_version,
                tls_cipher,
                tls_handshake = tls_handshake.as_millis(),
                domain,
                host,
                path,
                canister_id,
                country_code,
                header_origin,
                header_referer,
                header_user_agent,
                header_content_type,
                ic_http_streaming,
                ic_http_upgrade,
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
                error_details = error_cause_details,
                remote_addr,
                req_size = request_size,
                request_type,
                resp_size = response_size,
                dur = duration.as_millis(),
                dur_full = duration_full.as_millis(),
                dur_conn = conn_info.accepted_at.elapsed().as_millis(),
                conn_rcvd,
                conn_sent,
                conn_reqs,
                cache_status = cache_status_str,
                cache_bypass_reason = cache_bypass_reason_str,
                upstream,
            );
        }

        #[cfg(feature = "clickhouse")]
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
                domain,
                host: host.into(),
                path: path.into(),
                canister_id: canister_id.clone(),
                ic_streaming: ic_http_streaming,
                ic_upgrade: ic_http_upgrade,
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
                upstream: upstream.into(),
            };

            v.send(row);
        }

        if let Some(v) = &state.vector {
            // TODO use proper names when the DB is updated

            let val = serde_json::json!({
                "bytes_sent": response_size,
                "cache_status": cache_status_str,
                "cache_bypass_reason": cache_bypass_reason_str,
                "conn_id": conn_id,
                "conn_reqs": conn_reqs,
                "conn_rcvd": conn_rcvd,
                "conn_sent": conn_sent,
                "content_type": header_content_type,
                "env": ENV.get().unwrap().as_str(),
                "error_cause": error_cause,
                "error_details": error_cause_details,
                "geo_country_code": country_code,
                "hostname": HOSTNAME.get().unwrap().as_str(),
                "http_host": host,
                "http_origin": header_origin,
                "http_referer": header_referer,
                "http_user_agent": header_user_agent,
                "ic_cache_status": resp_meta.cache_status,
                "ic_cache_bypass_reason": resp_meta.cache_bypass_reason,
                "ic_canister_id": canister_id,
                "ic_canister_id_cbor": resp_meta.canister_id_cbor,
                "ic_error_cause": resp_meta.error_cause,
                "ic_method_name": resp_meta.method_name,
                "ic_node_id": resp_meta.node_id,
                "ic_request_type": request_type,
                "ic_sender": resp_meta.sender,
                "ic_streaming": ic_http_streaming,
                "ic_subnet_id": resp_meta.subnet_id,
                "ic_upgrade": ic_http_upgrade,
                "msec": timestamp.unix_timestamp(),
                "query_string": uri.query().unwrap_or_default(),
                "request_length": request_size,
                "request_uri": uri.path_and_query().map(|x| x.as_str()).unwrap_or_default(),
                "retries": resp_meta.retries,
                "remote_addr": remote_addr,
                "request_id": request_id_str,
                "request_method": method,
                "request_time": duration_full.as_secs_f64(),
                "server_protocol": http_version,
                "ssl_protocol": tls_version,
                "ssl_cipher": tls_cipher,
                "status": status,
                "status_upstream": status_upstream,
                "tls_handshake_msec": tls_handshake.as_millis(),
                "upstream": upstream,
            });

            v.send(val);
        }
    });

    Response::from_parts(parts, body)
}
