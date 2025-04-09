use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use axum::{
    body::Body,
    extract::{MatchedPath, OriginalUri, Path, Request, State},
    response::{IntoResponse, Response},
};
use candid::Principal;
use derive_new::new;
use futures::TryFutureExt;
use http::{
    StatusCode,
    header::{CONTENT_TYPE, X_CONTENT_TYPE_OPTIONS, X_FRAME_OPTIONS},
};
use ic_agent::agent::route_provider::RouteProvider;
use ic_bn_lib::http::{
    Client, Error as IcBnError,
    body::buffer_body,
    headers::{CONTENT_TYPE_CBOR, X_CONTENT_TYPE_OPTIONS_NO_SNIFF, X_FRAME_OPTIONS_DENY},
    proxy::proxy,
};
use regex::Regex;
use tokio::time::sleep;
use url::Url;

use super::{error_cause::ErrorCause, ic::BNResponseMetadata};

lazy_static::lazy_static! {
    pub static ref REGEX_REG_ID: Regex = Regex::new(r"^[a-zA-Z0-9]+$").unwrap();
}

fn url_join(mut base: Url, mut path: &str) -> Result<Url, url::ParseError> {
    // Add trailing slash to the base URL if it's not there
    if !base.as_str().ends_with('/') {
        base.path_segments_mut()
            .map_err(|_| url::ParseError::SetHostOnCannotBeABaseUrl)?
            .push("/");
    }

    // Strip the leading slash from the path if it's there
    if path.starts_with('/') {
        let mut chars = path.chars();
        chars.next();
        path = chars.as_str();
    }

    base.join(path)
}

pub fn status_code_needs_retrying(s: http::StatusCode) -> bool {
    s == StatusCode::TOO_MANY_REQUESTS || s.is_server_error()
}

pub fn reqwest_error_needs_retrying(e: &reqwest::Error) -> bool {
    e.is_connect() || e.is_timeout()
}

// Check if we need to retry the request based on the response that we got
fn request_needs_retrying(result: &Result<Response, IcBnError>) -> bool {
    match result {
        Ok(v) => status_code_needs_retrying(v.status()),
        Err(IcBnError::RequestFailed(e)) => reqwest_error_needs_retrying(e),
        _ => false,
    }
}

#[derive(new)]
pub struct ApiProxyState {
    http_client: Arc<dyn Client>,
    route_provider: Arc<dyn RouteProvider>,
    retries: usize,
    retry_interval: Duration,
    request_max_size: usize,
    request_body_timeout: Duration,
}

// Proxies /api/v2/... and /api/v3/... endpoints to the IC
pub async fn api_proxy(
    State(state): State<Arc<ApiProxyState>>,
    OriginalUri(original_uri): OriginalUri,
    matched_path: MatchedPath,
    principal: Option<Path<String>>,
    request: Request,
) -> Result<impl IntoResponse, ErrorCause> {
    // Check principal for correctness
    if let Some(v) = principal {
        Principal::from_text(v.0).map_err(|_| ErrorCause::IncorrectPrincipal)?;
    }

    // Obtain a list of IC URLs from the provider
    let urls = state
        .route_provider
        .n_ordered_routes(state.retries)
        .map_err(|e| ErrorCause::Other(format!("Unable to obtain URLs: {e:#}")))?;

    // Buffer the request body to be able to retry it
    let (parts, body) = request.into_parts();
    let body = buffer_body(body, state.request_max_size, state.request_body_timeout)
        .map_err(|e| ErrorCause::ClientBodyError(e.to_string()))
        .await?;

    let mut retry_interval = state.retry_interval;
    let mut retries = state.retries;

    let outcome = loop {
        // Pick the next URL, wrapping around if not enough are available
        let idx = (state.retries - retries) % urls.len();
        let url = urls[idx].clone();

        // Append the query URL to the IC url
        let url = url_join(url, original_uri.path())
            .map_err(|e| ErrorCause::MalformedRequest(format!("Incorrect URL: {e:#}")))?;

        let request = Request::from_parts(parts.clone(), Body::from(body.clone()));

        // Proxy the request
        let result = proxy(url, request, &state.http_client).await;
        if !request_needs_retrying(&result) {
            break result;
        }

        sleep(retry_interval).await;
        retry_interval *= 2;
        retries -= 1;

        if retries == 0 {
            break result;
        }
    };

    match outcome {
        // If there was some response - use it
        Ok(mut v) => {
            // Set the correct content-type for all replies if it's not an error
            // The replica and the API boundary nodes should set these headers. This is just for redundancy.
            if v.status().is_success() {
                v.headers_mut().insert(CONTENT_TYPE, CONTENT_TYPE_CBOR);
                v.headers_mut()
                    .insert(X_CONTENT_TYPE_OPTIONS, X_CONTENT_TYPE_OPTIONS_NO_SNIFF);
                v.headers_mut()
                    .insert(X_FRAME_OPTIONS, X_FRAME_OPTIONS_DENY);
            }

            let bn_metadata = BNResponseMetadata::from(v.headers_mut());
            v.extensions_mut().insert(bn_metadata);
            v.extensions_mut().insert(matched_path);
            Ok(v)
        }

        Err(e) => Err(ErrorCause::from_backend_error(e)),
    }
}

#[derive(new)]
pub struct IssuerProxyState {
    http_client: Arc<dyn Client>,
    issuers: Vec<Url>,
    #[new(default)]
    next: AtomicUsize,
}

// Proxies /registrations endpoint to the certificate issuers if they're defined
pub async fn issuer_proxy(
    State(state): State<Arc<IssuerProxyState>>,
    OriginalUri(original_uri): OriginalUri,
    matched_path: MatchedPath,
    id: Option<Path<String>>,
    request: Request,
) -> Result<impl IntoResponse, ErrorCause> {
    // Validate request ID if it's provided
    if let Some(v) = id {
        if !REGEX_REG_ID.is_match(&v.0) {
            return Err(ErrorCause::MalformedRequest(
                "Incorrect request ID format".into(),
            ));
        }
    }

    // Pick next issuer using round-robin & generate request URL for it
    // TODO should we do retries here?
    let next = state.next.fetch_add(1, Ordering::SeqCst) % state.issuers.len();
    let url = state.issuers[next]
        .clone()
        .join(original_uri.path())
        .map_err(|_| ErrorCause::Other("Unable to parse path as URL part".into()))?;

    let mut response = proxy(url, request, &state.http_client)
        .await
        .map_err(ErrorCause::from_backend_error)?;

    response.extensions_mut().insert(matched_path);

    Ok(response)
}

#[cfg(test)]
mod test {
    use axum::{Router, body::to_bytes};
    use http::{Method, Uri};
    use ic_agent::agent::route_provider::RoundRobinRouteProvider;
    use ic_bn_lib::http::Client;
    use tower::ServiceExt;

    use super::*;

    #[test]
    fn test_url_join() {
        let base_url = Url::parse("http://127.0.0.1:443/foo/bar/").unwrap();
        let url = url_join(base_url, "/api/v2/status").unwrap();
        assert_eq!(url.as_str(), "http://127.0.0.1:443/foo/bar/api/v2/status");

        let base_url = Url::parse("http://127.0.0.1:443/foo/bar").unwrap();
        let url = url_join(base_url, "/api/v2/status").unwrap();
        assert_eq!(url.as_str(), "http://127.0.0.1:443/foo/bar/api/v2/status");

        let base_url = Url::parse("http://127.0.0.1:443/foo/bar").unwrap();
        let url = url_join(base_url, "api/v2/status").unwrap();
        assert_eq!(url.as_str(), "http://127.0.0.1:443/foo/bar/api/v2/status");

        let base_url = Url::parse("http://127.0.0.1:443").unwrap();
        let url = url_join(base_url, "/api/v2/status").unwrap();
        assert_eq!(url.as_str(), "http://127.0.0.1:443/api/v2/status");
    }

    #[derive(Debug)]
    struct TestClient(AtomicUsize);

    #[async_trait::async_trait]
    impl Client for TestClient {
        async fn execute(
            &self,
            req: reqwest::Request,
        ) -> Result<reqwest::Response, reqwest::Error> {
            // Make sure we get correct request body
            let req: Request<reqwest::Body> = req.try_into().unwrap();
            let (_, body) = req.into_parts();
            let body = buffer_body(body, 8192, Duration::from_secs(10))
                .await
                .unwrap();
            let body = String::from_utf8_lossy(&body).to_string();
            assert_eq!(body, "foo");

            let mut resp = http::Response::new("foo");
            *resp.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
            if self.0.fetch_add(1, Ordering::SeqCst) > 3 {
                *resp.status_mut() = StatusCode::OK;
            }

            Ok(reqwest::Response::from(resp))
        }
    }

    #[derive(Debug)]
    struct TestClientErr(AtomicUsize);

    #[async_trait::async_trait]
    impl Client for TestClientErr {
        async fn execute(&self, _: reqwest::Request) -> Result<reqwest::Response, reqwest::Error> {
            if self.0.fetch_add(1, Ordering::SeqCst) > 3 {
                return Ok(http::Response::new("foo").into());
            }

            reqwest::get("http://0.0.0.0:1").await
        }
    }

    #[derive(Debug)]
    struct TestClientFails5xx;

    #[async_trait::async_trait]
    impl Client for TestClientFails5xx {
        async fn execute(&self, _: reqwest::Request) -> Result<reqwest::Response, reqwest::Error> {
            let mut resp = http::Response::new("foo");
            *resp.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
            Ok(reqwest::Response::from(resp))
        }
    }

    #[derive(Debug)]
    struct TestClientFailsErr;

    #[async_trait::async_trait]
    impl Client for TestClientFailsErr {
        async fn execute(&self, _: reqwest::Request) -> Result<reqwest::Response, reqwest::Error> {
            reqwest::get("http://###33??").await
        }
    }

    #[tokio::test]
    async fn test_api_proxy() {
        // Test eventual success after 4 failures with 5xx
        let client = Arc::new(TestClient(AtomicUsize::new(0)));
        let rp = Arc::new(RoundRobinRouteProvider::new(vec!["http://foo"]).unwrap());
        let state = Arc::new(ApiProxyState::new(
            client,
            rp,
            5,
            Duration::ZERO,
            100000,
            Duration::from_secs(10),
        ));

        let mut req = Request::new(Body::from("foo"));
        *req.method_mut() = Method::POST;
        *req.uri_mut() = Uri::from_static("http://foo/api/v2/status");

        let router = Router::new()
            .route("/api/v2/status", axum::routing::post(api_proxy))
            .with_state(state);

        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // Test eventual success after 4 failures with err
        let client = Arc::new(TestClientErr(AtomicUsize::new(0)));
        let rp = Arc::new(RoundRobinRouteProvider::new(vec!["http://foo"]).unwrap());
        let state = Arc::new(ApiProxyState::new(
            client,
            rp,
            5,
            Duration::ZERO,
            100000,
            Duration::from_secs(10),
        ));

        let mut req = Request::new(Body::from("foo"));
        *req.method_mut() = Method::POST;
        *req.uri_mut() = Uri::from_static("http://foo/api/v2/status");

        let router = Router::new()
            .route("/api/v2/status", axum::routing::post(api_proxy))
            .with_state(state);

        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // Test failure with 5xx
        let client = Arc::new(TestClientFails5xx);
        let rp = Arc::new(RoundRobinRouteProvider::new(vec!["http://foo"]).unwrap());
        let state = Arc::new(ApiProxyState::new(
            client,
            rp,
            5,
            Duration::ZERO,
            100000,
            Duration::from_secs(10),
        ));

        let mut req = Request::new(Body::from("foo"));
        *req.method_mut() = Method::POST;
        *req.uri_mut() = Uri::from_static("http://foo/api/v2/status");

        let router = Router::new()
            .route("/api/v2/status", axum::routing::post(api_proxy))
            .with_state(state);

        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);

        // Test network failure
        let client = Arc::new(TestClientFailsErr);
        let rp = Arc::new(RoundRobinRouteProvider::new(vec!["http://foo"]).unwrap());
        let state = Arc::new(ApiProxyState::new(
            client,
            rp,
            5,
            Duration::ZERO,
            100000,
            Duration::from_secs(10),
        ));

        let mut req = Request::new(Body::from("foo"));
        *req.method_mut() = Method::POST;
        *req.uri_mut() = Uri::from_static("http://foo/api/v2/status");

        let router = Router::new()
            .route("/api/v2/status", axum::routing::post(api_proxy))
            .with_state(state);

        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);

        let body =
            String::from_utf8_lossy(&to_bytes(resp.into_body(), 8192).await.unwrap()).to_string();

        assert!(body.starts_with("error: upstream_error"));
    }
}
