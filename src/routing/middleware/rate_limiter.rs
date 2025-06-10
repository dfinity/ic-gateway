use std::{net::IpAddr, sync::Arc, time::Duration};

use ::governor::{clock::QuantaInstant, middleware::NoOpMiddleware};
use anyhow::{Error, anyhow};
use axum::{extract::Request, response::IntoResponse};
use ic_bn_lib::http::ConnInfo;
use tower_governor::{
    GovernorError, GovernorLayer,
    governor::GovernorConfigBuilder,
    key_extractor::{GlobalKeyExtractor, KeyExtractor},
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

#[allow(dead_code)]
pub fn layer_global(
    rps: u32,
    burst_size: u32,
) -> Result<GovernorLayer<GlobalKeyExtractor, NoOpMiddleware<QuantaInstant>>, Error> {
    layer(rps, burst_size, GlobalKeyExtractor, RateLimitCause::Normal)
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
        Router,
        body::{Body, to_bytes},
        extract::Request,
        response::IntoResponse,
        routing::post,
    };
    use http::StatusCode;
    use ic_bn_lib::http::ConnInfo;
    use std::{sync::Arc, time::Duration};
    use tokio::time::sleep;
    use tower::Service;

    use crate::routing::{
        RequestType,
        error_cause::{ERROR_CONTEXT, ErrorCause, RateLimitCause},
        middleware::rate_limiter::{IpKeyExtractor, layer},
    };

    async fn handler(_request: Request<Body>) -> Result<impl IntoResponse, ErrorCause> {
        Ok("test_call".into_response())
    }

    async fn send_request(
        router: &mut Router,
    ) -> Result<http::Response<Body>, std::convert::Infallible> {
        let conn_info = ConnInfo::default();
        let mut request = Request::post("/").body(Body::from("".to_string())).unwrap();
        request.extensions_mut().insert(Arc::new(conn_info));
        router.call(request).await
    }

    #[tokio::test]
    async fn test_rate_limiter_rps_limit() {
        let rps = 5;
        let burst_size = 5; // how many requests can go through at once (without delay)

        let rate_limiter_mw = layer(rps, burst_size, IpKeyExtractor, RateLimitCause::Normal)
            .expect("failed to build middleware");

        let mut app = Router::new()
            .route("/", post(handler))
            .layer(rate_limiter_mw);

        ERROR_CONTEXT
            .scope(RequestType::Unknown, async {
                // Test cases: (delay_ms, expected_status)
                let delay_for_token_ms = 230; // when a token should become available ~ 1000ms/rps=200ms (we add some delta=30 ms to avoid flakiness)
                let test_cases = vec![
                    // Initial burst of 5 requests should succeed and fills full burst capacity
                    (0, StatusCode::OK),
                    (0, StatusCode::OK),
                    (0, StatusCode::OK),
                    (0, StatusCode::OK),
                    (0, StatusCode::OK),
                    // For 6th request no tokens left => 429
                    (0, StatusCode::TOO_MANY_REQUESTS),
                    // Wait for 1 token to be available
                    (delay_for_token_ms, StatusCode::OK),
                    // Bucket is empty again, request should fail
                    (0, StatusCode::TOO_MANY_REQUESTS),
                    // Wait for 2 tokens to be available, next 2 requests succeed
                    (2 * delay_for_token_ms, StatusCode::OK),
                    (0, StatusCode::OK),
                    // Bucket is empty again, request should fail
                    (0, StatusCode::TOO_MANY_REQUESTS),
                    // Wait for 5 tokens, next 5 requests succeed
                    (5 * delay_for_token_ms, StatusCode::OK),
                    (0, StatusCode::OK),
                    (0, StatusCode::OK),
                    (0, StatusCode::OK),
                    (0, StatusCode::OK),
                    // Bucket is empty again, requests should fail
                    (0, StatusCode::TOO_MANY_REQUESTS),
                    (0, StatusCode::TOO_MANY_REQUESTS),
                ];

                // Execute all tests
                for (idx, (delay_ms, expected_status)) in test_cases.into_iter().enumerate() {
                    if delay_ms > 0 {
                        sleep(Duration::from_millis(delay_ms)).await;
                    }
                    let result = send_request(&mut app).await.unwrap();
                    assert_eq!(result.status(), expected_status, "test {idx} failed");
                }
            })
            .await;
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

        ERROR_CONTEXT
            .scope(RequestType::Unknown, async {
                // Send request without connection info, i.e. without ip address.
                let request = Request::post("/").body(Body::from("".to_string())).unwrap();
                let result = app.call(request).await.unwrap();

                assert_eq!(result.status(), StatusCode::INTERNAL_SERVER_ERROR);
                let body = to_bytes(result.into_body(), 100).await.unwrap().to_vec();
                assert!(body.starts_with(b"error: internal_server_error\n"));
            })
            .await;
    }
}
