use std::{net::IpAddr, sync::Arc, time::Duration};

use ::governor::{clock::QuantaInstant, middleware::NoOpMiddleware};
use anyhow::{anyhow, Error};
use axum::{extract::Request, response::IntoResponse};
use ic_bn_lib::http::ConnInfo;
use tower_governor::{
    governor::GovernorConfigBuilder, key_extractor::KeyExtractor, GovernorError, GovernorLayer,
};

use crate::routing::error_cause::{ErrorCause, RateLimitCause};

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

pub fn layer_by_ip(
    rps: u32,
    burst_size: u32,
) -> Result<GovernorLayer<IpKeyExtractor, NoOpMiddleware<QuantaInstant>>, Error> {
    layer(rps, burst_size, IpKeyExtractor, RateLimitCause::Normal)
}

pub fn layer<T: KeyExtractor>(
    rps: u32,
    burst_size: u32,
    key_extractor: T,
    rate_limit_cause: RateLimitCause,
) -> Result<GovernorLayer<T, NoOpMiddleware<QuantaInstant>>, Error> {
    let period = Duration::from_secs(1)
        .checked_div(rps)
        .ok_or_else(|| anyhow!("RPS is zero"))?;

    let config = Arc::new(
        GovernorConfigBuilder::default()
            .period(period)
            .error_handler(move |err| match err {
                GovernorError::TooManyRequests { .. } => {
                    rate_limit_cause.clone().into_response()
                }
                GovernorError::UnableToExtractKey => {
                    ErrorCause::Other("UnableToExtractIpAddress".to_string()).into_response()
                }
                GovernorError::Other { code, msg, headers } => {
                    let msg = format!("Rate limiter failed unexpectedly: code={code}, msg={msg:?}, headers={headers:?}");
                    ErrorCause::Other(msg).into_response()
                }
            })
            .burst_size(burst_size)
            .key_extractor(key_extractor)
            .finish().ok_or_else(|| anyhow!("unable to build governor config"))?);

    Ok(GovernorLayer { config })
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
    use ic_bn_lib::http::{ConnInfo, Stats};
    use std::{
        sync::{atomic::AtomicU64, Arc},
        time::Duration,
    };
    use tokio::time::sleep;
    use tokio_util::sync::CancellationToken;
    use tower::Service;
    use uuid::Uuid;

    use crate::routing::{
        error_cause::{ErrorCause, RateLimitCause},
        middleware::rate_limiter::{layer, IpKeyExtractor},
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
            remote_addr: ic_bn_lib::http::server::Addr::Tcp("127.0.0.1:8080".parse().unwrap()),
            traffic: Arc::new(Stats::new()),
            req_count: AtomicU64::new(0),
            close: CancellationToken::new(),
        };
        let mut request = Request::post("/").body(Body::from("".to_string())).unwrap();
        request.extensions_mut().insert(Arc::new(conn_info));
        router.call(request).await
    }

    #[tokio::test]
    async fn test_rate_limiter_burst_capacity() {
        let rps = 1;
        let burst_size = 5;

        let rate_limiter_mw = layer(rps, burst_size, IpKeyExtractor, RateLimitCause::Normal)
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
        assert_eq!(body, b"rate_limited_normal: normal\n");

        // Wait so that requests can be accepted again.
        sleep(Duration::from_secs(1)).await;

        let result = send_request(&mut app).await.unwrap();
        assert_eq!(result.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_rate_limiter_rps_limit() {
        let rps = 10;
        let burst_size = 1;

        let rate_limiter_mw = layer(rps, burst_size, IpKeyExtractor, RateLimitCause::Normal)
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
        assert_eq!(body, b"rate_limited_normal: normal\n");

        // Wait so that requests can be accepted again.
        sleep(delay).await;

        let result = send_request(&mut app).await.unwrap();
        assert_eq!(result.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_rate_limiter_returns_server_error() {
        let rps = 1;
        let burst_size = 1;

        let rate_limiter_mw = layer(rps, burst_size, IpKeyExtractor, RateLimitCause::Normal)
            .expect("failed to build middleware");

        let mut app = Router::new()
            .route("/", post(handler))
            .layer(rate_limiter_mw);

        // Send request without connection info, i.e. without ip address.
        let request = Request::post("/").body(Body::from("".to_string())).unwrap();
        let result = app.call(request).await.unwrap();

        assert_eq!(result.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let body = to_bytes(result.into_body(), 100).await.unwrap().to_vec();
        assert_eq!(body, b"general_error: UnableToExtractIpAddress\n");
    }
}
