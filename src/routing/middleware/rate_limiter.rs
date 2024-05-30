use std::{net::IpAddr, sync::Arc, time::Duration};

use ::governor::{clock::QuantaInstant, middleware::NoOpMiddleware};
use axum::{extract::Request, response::IntoResponse};
use tower::{
    layer::util::{Identity, Stack},
    ServiceBuilder,
};
use tower_governor::{
    governor::GovernorConfigBuilder, key_extractor::KeyExtractor, GovernorError, GovernorLayer,
};
use tracing::debug;

use crate::{
    http::ConnInfo,
    routing::error_cause::{ErrorCause, RateLimitCause},
};

#[derive(Clone)]
pub struct IpKeyExtractor;

impl KeyExtractor for IpKeyExtractor {
    type Key = IpAddr;

    fn extract<B>(&self, req: &Request<B>) -> Result<Self::Key, GovernorError> {
        // ConnInfo is expected to exist in request extension, otherwise 500.
        req.extensions()
            .get::<Arc<ConnInfo>>()
            .map(|x| x.remote_addr.ip())
            .ok_or(GovernorError::UnableToExtractKey)
    }
}

pub fn build_rate_limiter_middleware<T: KeyExtractor>(
    rps: u32,
    burst_size: u32,
    key_extractor: T,
) -> Option<ServiceBuilder<Stack<GovernorLayer<'static, T, NoOpMiddleware<QuantaInstant>>, Identity>>>
{
    let period = Duration::from_secs(1).checked_div(rps)?;
    let governor_conf = Box::new(
        GovernorConfigBuilder::default()
            .period(period)
            .error_handler(|err| match err {
                GovernorError::TooManyRequests { .. } => {
                    ErrorCause::RateLimited(RateLimitCause::Normal).into_response()
                }
                GovernorError::UnableToExtractKey => {
                    ErrorCause::RateLimited(RateLimitCause::UnableToExtractIpAddress)
                        .into_response()
                }
                GovernorError::Other { code, msg, headers } => {
                    let msg = format!("code={code}, msg={msg:?}, headers={headers:?}");
                    debug!("Rate limiter failed unexpectedly: {msg}");
                    ErrorCause::RateLimited(RateLimitCause::Other(msg)).into_response()
                }
            })
            .burst_size(burst_size)
            .key_extractor(key_extractor)
            .finish()?,
    );

    let gov_layer = GovernorLayer {
        config: Box::leak(governor_conf),
    };

    Some(ServiceBuilder::new().layer(gov_layer))
}

#[cfg(test)]
mod tests {
    use axum::{
        body::{to_bytes, Body},
        extract::Request,
        response::IntoResponse,
        routing::post,
        Router,
    };
    use http::StatusCode;
    use std::{
        sync::{atomic::AtomicU64, Arc},
        time::Duration,
    };

    use tokio::time::sleep;
    use tower::Service;
    use uuid::Uuid;

    use crate::{
        http::{ConnInfo, Stats},
        routing::{
            error_cause::ErrorCause,
            middleware::rate_limiter::{build_rate_limiter_middleware, IpKeyExtractor},
        },
    };

    async fn handler(_request: Request<Body>) -> Result<impl IntoResponse, ErrorCause> {
        Ok("test_call".into_response())
    }

    async fn send_request(
        router: &mut Router,
    ) -> Result<http::Response<Body>, std::convert::Infallible> {
        let conn_info = ConnInfo {
            id: Uuid::now_v7(),
            accepted_at: std::time::Instant::now(),
            local_addr: "127.0.0.1:8080".parse().unwrap(),
            remote_addr: "127.0.0.1:8080".parse().unwrap(),
            traffic: Arc::new(Stats::new()),
            req_count: AtomicU64::new(0),
        };
        let mut request = Request::post("/").body(Body::from("".to_string())).unwrap();
        request.extensions_mut().insert(Arc::new(conn_info));
        router.call(request).await
    }

    #[tokio::test]
    async fn test_rate_limiter_burst_capacity() {
        let rps = 1;
        let burst_size = 5;

        let rate_limiter_mw = build_rate_limiter_middleware(rps, burst_size, IpKeyExtractor)
            .expect("failed to build middleware");

        let mut app = Router::new()
            .route("/", post(handler))
            .layer(rate_limiter_mw);

        // All requests filling the burst capacity should succeed
        for _ in 0..burst_size {
            let result = send_request(&mut app).await.unwrap();
            assert_eq!(result.status(), StatusCode::OK);
        }

        // Once capacity is reached, request should fail with 429
        let result = send_request(&mut app).await.unwrap();
        assert_eq!(result.status(), StatusCode::TOO_MANY_REQUESTS);
        let body = to_bytes(result.into_body(), 100).await.unwrap().to_vec();
        assert_eq!(body, b"rate_limited_normal\n");

        // Wait so that requests can be accepted again.
        sleep(Duration::from_secs(1)).await;

        let result = send_request(&mut app).await.unwrap();
        assert_eq!(result.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_rate_limiter_rps_limit() {
        let rps = 10;
        let burst_size = 1;

        let rate_limiter_mw = build_rate_limiter_middleware(rps, burst_size, IpKeyExtractor)
            .expect("failed to build middleware");

        let mut app = Router::new()
            .route("/", post(handler))
            .layer(rate_limiter_mw);

        let total_requests = 20;
        let delay = Duration::from_millis((1000.0 / rps as f64) as u64);

        // All requests submitted at the max rps rate should succeed.
        for _ in 0..total_requests {
            sleep(delay).await;
            let result = send_request(&mut app).await.unwrap();
            assert_eq!(result.status(), StatusCode::OK);
        }

        // This request is submitted without delay, thus 429.
        let result = send_request(&mut app).await.unwrap();
        assert_eq!(result.status(), StatusCode::TOO_MANY_REQUESTS);
        let body = to_bytes(result.into_body(), 100).await.unwrap().to_vec();
        assert_eq!(body, b"rate_limited_normal\n");

        // Wait so that requests can be accepted again.
        sleep(delay).await;

        let result = send_request(&mut app).await.unwrap();
        assert_eq!(result.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_rate_limiter_returns_server_error() {
        let rps = 1;
        let burst_size = 1;

        let rate_limiter_mw = build_rate_limiter_middleware(rps, burst_size, IpKeyExtractor)
            .expect("failed to build middleware");

        let mut app = Router::new()
            .route("/", post(handler))
            .layer(rate_limiter_mw);

        // Send request without connection info, i.e. without ip address.
        let request = Request::post("/").body(Body::from("".to_string())).unwrap();
        let result = app.call(request).await.unwrap();

        assert_eq!(result.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let body = to_bytes(result.into_body(), 100).await.unwrap().to_vec();
        assert_eq!(body, b"rate_limited_unable_to_extract_ip_address\n");
    }
}
