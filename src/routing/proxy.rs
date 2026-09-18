use std::{sync::Arc, time::Duration};

use axum::{
    extract::{MatchedPath, OriginalUri, Path, Request, State},
    response::{IntoResponse, Response},
};
use bytes::Bytes;
use candid::Principal;
use derive_new::new;
use futures::TryFutureExt;
use http::{
    StatusCode, Version,
    header::{CONTENT_TYPE, X_CONTENT_TYPE_OPTIONS, X_FRAME_OPTIONS},
    uri::PathAndQuery,
};
use http_body_util::Full;
use ic_bn_lib::{
    http::{
        ClientHttp, Error as HttpError,
        body::buffer_body,
        headers::{
            CONTENT_TYPE_CBOR, X_CONTENT_TYPE_OPTIONS_NO_SNIFF, X_FRAME_OPTIONS_DENY,
            strip_connection_headers,
        },
        url_to_uri,
    },
    ic_agent::agent::route_provider::RouteProvider,
};
use tokio::time::sleep;
use url::Url;

use super::{
    error_cause::ErrorCause,
    ic::{BNRequestMetadata, BNResponseMetadata},
};
use crate::routing::error_cause::ClientError;

fn url_join(mut base: Url, mut path: &str) -> Result<Url, url::ParseError> {
    // Add trailing slash to the base URL if it's not there
    if !base.as_str().ends_with('/') {
        base.path_segments_mut()
            .map_err(|()| url::ParseError::SetHostOnCannotBeABaseUrl)?
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

pub fn status_code_needs_retrying(s: StatusCode) -> bool {
    s == StatusCode::TOO_MANY_REQUESTS || s.is_server_error()
}

pub fn http_error_needs_retrying(e: &HttpError) -> bool {
    match e {
        HttpError::HyperClientError(v) => v.is_connect(),
        _ => false,
    }
}

/// Check if we need to retry the request based on the response that we got
fn request_needs_retrying(result: &Result<Response, HttpError>) -> bool {
    match result {
        Ok(v) => status_code_needs_retrying(v.status()),
        Err(e) => http_error_needs_retrying(e),
    }
}

#[derive(new)]
pub struct ApiProxyState {
    http_client: Arc<dyn ClientHttp<Full<Bytes>>>,
    route_provider: Arc<dyn RouteProvider>,
    retries: usize,
    retry_interval: Duration,
    request_max_size: usize,
    request_body_timeout: Duration,
    #[new(value = "PathAndQuery::from_static(\"/\")")]
    pq_default: PathAndQuery,
}

/// Proxies /api/... endpoints to the IC
pub async fn api_proxy(
    State(state): State<Arc<ApiProxyState>>,
    OriginalUri(original_uri): OriginalUri,
    matched_path: MatchedPath,
    principal: Option<Path<String>>,
    request: Request,
) -> Result<impl IntoResponse, ErrorCause> {
    // Check principal for correctness
    if let Some(v) = principal {
        Principal::from_text(v.0)
            .map_err(|_| ErrorCause::Client(ClientError::IncorrectPrincipal))?;
    }

    // Obtain a list of IC URLs from the provider
    let urls = state
        .route_provider
        .n_ordered_routes(state.retries)
        .map_err(|e| ErrorCause::Other(format!("Unable to obtain URLs: {e:#}")))?;

    let (mut parts, body) = request.into_parts();
    // HTTP/2 requests cannot be sent over HTTP/1.1 connections, the other way around is fine.
    parts.version = Version::HTTP_11;

    // Buffer the request body to be able to retry it
    let body = Full::new(
        buffer_body(body, state.request_max_size, state.request_body_timeout)
            .map_err(|e| ErrorCause::Client(ClientError::Body(e.to_string())))
            .await?,
    );

    // Sanitize the request headers
    strip_connection_headers(&mut parts.headers);

    let mut retry_interval = state.retry_interval;
    let mut retries = state.retries;

    let (upstream, result) = loop {
        // Pick the next URL, wrapping around if not enough are available
        let idx = (state.retries - retries) % urls.len();
        let url = urls[idx].clone();
        let upstream = url.authority().to_string();

        let url = url_join(
            url,
            original_uri
                .path_and_query()
                .unwrap_or(&state.pq_default)
                .as_str(),
        )
        .map_err(|e| {
            ErrorCause::Client(ClientError::MalformedRequest(format!("invalid URL: {e:#}")))
        })?;

        let uri = url_to_uri(&url).map_err(|e| {
            ErrorCause::Client(ClientError::MalformedRequest(format!("invalid URL: {e:#}")))
        })?;

        let mut request = Request::from_parts(parts.clone(), body.clone());
        *request.uri_mut() = uri;

        // Proxy the request
        let result = state.http_client.execute(request).await;
        if !request_needs_retrying(&result) {
            break (upstream, result);
        }

        sleep(retry_interval).await;
        retry_interval *= 2;
        retries -= 1;

        if retries == 0 {
            break (upstream, result);
        }
    };

    let mut response = match result {
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

            let mut resp_meta = BNResponseMetadata::from(v.headers_mut());
            resp_meta.status = Some(v.status());

            v.extensions_mut().insert(resp_meta);
            v.extensions_mut().insert(matched_path);
            Ok(v)
        }

        Err(e) => Err(ErrorCause::from_backend_error(e)),
    }
    .into_response();

    response.extensions_mut().insert(BNRequestMetadata {
        upstream: Some(upstream),
    });

    Ok(response)
}

#[cfg(test)]
mod test {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use axum::{Router, body::Body};
    use http::{HeaderValue, Method, Request, Response, Uri};
    use http_body_util::BodyExt;
    use ic_bn_lib::{
        dns::resolvers::Resolver,
        http::{HyperClient, client::ClientOptions},
        ic_agent::agent::route_provider::RoundRobinRouteProvider,
    };
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
    impl ClientHttp<Full<Bytes>> for TestClient {
        async fn execute(&self, req: Request<Full<Bytes>>) -> Result<Response<Body>, HttpError> {
            // Make sure we get correct request body
            let (_, body) = req.into_parts();
            let body = body.collect().await.unwrap().to_bytes().to_vec();
            let body = String::from_utf8_lossy(&body).to_string();
            assert_eq!(body, "foo");

            let mut resp = Response::new(Body::empty());
            *resp.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
            if self.0.fetch_add(1, Ordering::SeqCst) > 3 {
                *resp.status_mut() = StatusCode::OK;
            }

            Ok(resp)
        }
    }

    #[derive(Debug)]
    struct TestClientErr(AtomicUsize);

    #[async_trait::async_trait]
    impl ClientHttp<Full<Bytes>> for TestClientErr {
        async fn execute(&self, _: Request<Full<Bytes>>) -> Result<Response<Body>, HttpError> {
            if self.0.fetch_add(1, Ordering::SeqCst) > 3 {
                return Ok(Response::new(Body::from("foo")));
            }

            let cli: HyperClient<Full<Bytes>> =
                HyperClient::new(ClientOptions::default(), Resolver::default());
            let mut req = Request::new(Full::new(Bytes::new()));
            *req.uri_mut() = Uri::from_static("http://0.0.0.0:1");

            cli.execute(req).await
        }
    }

    #[derive(Debug)]
    struct TestClientFails5xx;

    #[async_trait::async_trait]
    impl ClientHttp<Full<Bytes>> for TestClientFails5xx {
        async fn execute(&self, _: Request<Full<Bytes>>) -> Result<Response<Body>, HttpError> {
            let mut resp = Response::new(Body::from(""));
            *resp.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
            Ok(resp)
        }
    }

    #[derive(Debug)]
    struct TestClientFailsErr;

    #[async_trait::async_trait]
    impl ClientHttp<Full<Bytes>> for TestClientFailsErr {
        async fn execute(&self, _: Request<Full<Bytes>>) -> Result<Response<Body>, HttpError> {
            let cli: HyperClient<Full<Bytes>> =
                HyperClient::new(ClientOptions::default(), Resolver::default());
            let req = Request::new(Full::new(Bytes::new()));

            cli.execute(req).await
        }
    }

    #[tokio::test]
    async fn test_api_proxy() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

        // Test eventual success after 4 failures with 5xx
        let client = Arc::new(TestClient(AtomicUsize::new(0)));
        let rp = Arc::new(RoundRobinRouteProvider::new(vec!["http://foo"]).unwrap());
        let state = Arc::new(ApiProxyState::new(
            client,
            rp,
            5,
            Duration::ZERO,
            100_000,
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
            100_000,
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
            100_000,
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
            100_000,
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
    }

    #[test]
    fn test_url_join_with_query() {
        let base_url = Url::parse("http://127.0.0.1:443").unwrap();
        let url = url_join(base_url, "/api/v2/status?foo=bar&baz=1").unwrap();
        assert_eq!(
            url.as_str(),
            "http://127.0.0.1:443/api/v2/status?foo=bar&baz=1"
        );

        // A base path is preserved when a query is present too
        let base_url = Url::parse("http://127.0.0.1:443/prefix").unwrap();
        let url = url_join(base_url, "/api/v2/status?foo=bar").unwrap();
        assert_eq!(
            url.as_str(),
            "http://127.0.0.1:443/prefix/api/v2/status?foo=bar"
        );
    }

    #[test]
    fn test_status_code_needs_retrying() {
        // Retry on overload & any server-side failure
        assert!(status_code_needs_retrying(StatusCode::TOO_MANY_REQUESTS));
        assert!(status_code_needs_retrying(StatusCode::INTERNAL_SERVER_ERROR));
        assert!(status_code_needs_retrying(StatusCode::BAD_GATEWAY));
        assert!(status_code_needs_retrying(StatusCode::SERVICE_UNAVAILABLE));
        assert!(status_code_needs_retrying(StatusCode::GATEWAY_TIMEOUT));

        // Never retry things the client caused, or successes
        assert!(!status_code_needs_retrying(StatusCode::OK));
        assert!(!status_code_needs_retrying(StatusCode::NO_CONTENT));
        assert!(!status_code_needs_retrying(StatusCode::BAD_REQUEST));
        assert!(!status_code_needs_retrying(StatusCode::NOT_FOUND));
        assert!(!status_code_needs_retrying(StatusCode::PAYLOAD_TOO_LARGE));
        assert!(!status_code_needs_retrying(StatusCode::FORBIDDEN));
    }

    #[test]
    fn test_http_error_needs_retrying() {
        // Only a failure to connect is worth another node
        assert!(!http_error_needs_retrying(&HttpError::BodyTimedOut));
        assert!(!http_error_needs_retrying(&HttpError::BodyTooBig));
        assert!(!http_error_needs_retrying(&HttpError::BodyReadingFailed(
            "x".into()
        )));
        assert!(!http_error_needs_retrying(&HttpError::DnsError("x".into())));
    }

    /// Client that records the URLs it was asked to fetch
    #[derive(Debug, Default)]
    struct RecordingClient {
        uris: std::sync::Mutex<Vec<String>>,
        status: Option<StatusCode>,
        headers: Vec<(&'static str, &'static str)>,
    }

    #[async_trait::async_trait]
    impl ClientHttp<Full<Bytes>> for RecordingClient {
        async fn execute(
            &self,
            req: Request<Full<Bytes>>,
        ) -> Result<http::Response<Body>, HttpError> {
            self.uris.lock().unwrap().push(req.uri().to_string());

            let mut resp = http::Response::new(Body::from("cbor-payload"));
            *resp.status_mut() = self.status.unwrap_or(StatusCode::OK);
            for (k, v) in &self.headers {
                resp.headers_mut().insert(*k, HeaderValue::from_static(v));
            }
            Ok(resp)
        }
    }

    async fn proxy_once(
        client: Arc<RecordingClient>,
        routes: Vec<&str>,
        retries: usize,
        path: &str,
    ) -> axum::response::Response {
        let rp = Arc::new(RoundRobinRouteProvider::new(routes).unwrap());
        let state = Arc::new(ApiProxyState::new(
            client,
            rp,
            retries,
            Duration::ZERO,
            100_000,
            Duration::from_secs(10),
        ));

        let mut req = Request::new(Body::from("req"));
        *req.method_mut() = Method::POST;
        *req.uri_mut() = Uri::try_from(format!("http://foo{path}")).unwrap();

        Router::new()
            .route(
                "/api/v2/canister/{principal}/query",
                axum::routing::post(api_proxy),
            )
            .with_state(state)
            .oneshot(req)
            .await
            .unwrap()
    }

    /// Successful replies get the CBOR content type and the anti-sniffing /
    /// anti-framing headers forced on, whatever the upstream said.
    #[tokio::test]
    async fn test_api_proxy_sets_security_headers() {
        let client = Arc::new(RecordingClient {
            headers: vec![
                ("content-type", "text/html"),
                ("x-content-type-options", "wrong"),
                ("x-frame-options", "ALLOWALL"),
            ],
            ..Default::default()
        });

        let resp = proxy_once(
            client,
            vec!["http://bn1"],
            3,
            "/api/v2/canister/aaaaa-aa/query",
        )
        .await;

        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(resp.headers().get(CONTENT_TYPE).unwrap(), "application/cbor");
        assert_eq!(
            resp.headers().get(X_CONTENT_TYPE_OPTIONS).unwrap(),
            "nosniff"
        );
        assert_eq!(resp.headers().get(X_FRAME_OPTIONS).unwrap(), "DENY");
    }

    /// Error replies are passed through as-is - rewriting their content type
    /// would mislabel the error body.
    #[tokio::test]
    async fn test_api_proxy_leaves_error_headers_alone() {
        let client = Arc::new(RecordingClient {
            status: Some(StatusCode::BAD_REQUEST),
            headers: vec![("content-type", "text/plain")],
            ..Default::default()
        });

        let resp = proxy_once(
            client,
            vec!["http://bn1"],
            3,
            "/api/v2/canister/aaaaa-aa/query",
        )
        .await;

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert_eq!(resp.headers().get(CONTENT_TYPE).unwrap(), "text/plain");
        assert!(!resp.headers().contains_key(X_FRAME_OPTIONS));
    }

    /// The `ic-boundary` service headers are moved into the response extensions
    /// (for logging) and off the response itself.
    #[tokio::test]
    async fn test_api_proxy_extracts_bn_metadata() {
        let client = Arc::new(RecordingClient {
            headers: vec![
                ("x-ic-node-id", "node-7"),
                ("x-ic-subnet-id", "subnet-3"),
                ("x-ic-error-cause", "none"),
            ],
            ..Default::default()
        });

        let mut resp = proxy_once(
            client,
            vec!["http://bn1:8443"],
            3,
            "/api/v2/canister/aaaaa-aa/query",
        )
        .await;

        let meta = resp.extensions_mut().remove::<BNResponseMetadata>().unwrap();
        assert_eq!(meta.node_id, "node-7");
        assert_eq!(meta.subnet_id, "subnet-3");
        assert_eq!(meta.status, Some(StatusCode::OK));

        assert!(!resp.headers().contains_key("x-ic-node-id"));
        assert!(!resp.headers().contains_key("x-ic-subnet-id"));

        // The upstream we actually talked to is recorded, host only
        let req_meta = resp
            .extensions_mut()
            .remove::<BNRequestMetadata>()
            .unwrap();
        assert_eq!(req_meta.upstream.as_deref(), Some("bn1:8443"));
    }

    /// Retries walk through the provided routes rather than hammering one node.
    #[tokio::test]
    async fn test_api_proxy_rotates_routes() {
        let client = Arc::new(RecordingClient {
            status: Some(StatusCode::SERVICE_UNAVAILABLE),
            ..Default::default()
        });

        let resp = proxy_once(
            client.clone(),
            vec!["http://bn1", "http://bn2", "http://bn3"],
            3,
            "/api/v2/canister/aaaaa-aa/query",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);

        let uris = client.uris.lock().unwrap().clone();
        assert_eq!(
            uris,
            vec![
                "http://bn1/api/v2/canister/aaaaa-aa/query",
                "http://bn2/api/v2/canister/aaaaa-aa/query",
                "http://bn3/api/v2/canister/aaaaa-aa/query",
            ]
        );
    }

    /// With fewer routes than retries the rotation wraps around instead of
    /// running out of URLs.
    #[tokio::test]
    async fn test_api_proxy_wraps_routes() {
        let client = Arc::new(RecordingClient {
            status: Some(StatusCode::SERVICE_UNAVAILABLE),
            ..Default::default()
        });

        proxy_once(
            client.clone(),
            vec!["http://bn1", "http://bn2"],
            4,
            "/api/v2/canister/aaaaa-aa/query",
        )
        .await;

        let uris = client.uris.lock().unwrap().clone();
        assert_eq!(
            uris,
            vec![
                "http://bn1/api/v2/canister/aaaaa-aa/query",
                "http://bn2/api/v2/canister/aaaaa-aa/query",
                "http://bn1/api/v2/canister/aaaaa-aa/query",
                "http://bn2/api/v2/canister/aaaaa-aa/query",
            ]
        );
    }

    /// The original path & query reach the upstream untouched.
    #[tokio::test]
    async fn test_api_proxy_preserves_path_and_query() {
        let client = Arc::new(RecordingClient::default());

        proxy_once(
            client.clone(),
            vec!["http://bn1"],
            3,
            "/api/v2/canister/aaaaa-aa/query?foo=bar",
        )
        .await;

        assert_eq!(
            client.uris.lock().unwrap()[0],
            "http://bn1/api/v2/canister/aaaaa-aa/query?foo=bar"
        );
    }

    /// A malformed principal in the path is rejected before any upstream call.
    #[tokio::test]
    async fn test_api_proxy_bad_principal() {
        let client = Arc::new(RecordingClient::default());

        let mut resp = proxy_once(
            client.clone(),
            vec!["http://bn1"],
            3,
            "/api/v2/canister/not-a-principal/query",
        )
        .await;

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            resp.extensions_mut().remove::<ErrorCause>(),
            Some(ErrorCause::Client(ClientError::IncorrectPrincipal))
        );
        assert!(client.uris.lock().unwrap().is_empty());
    }

    /// A request body larger than the limit is rejected as a client error.
    #[tokio::test]
    async fn test_api_proxy_body_too_large() {
        let client = Arc::new(RecordingClient::default());
        let rp = Arc::new(RoundRobinRouteProvider::new(vec!["http://bn1"]).unwrap());
        let state = Arc::new(ApiProxyState::new(
            client.clone(),
            rp,
            3,
            Duration::ZERO,
            4, // 4 byte limit
            Duration::from_secs(10),
        ));

        let mut req = Request::new(Body::from("much longer than four bytes"));
        *req.method_mut() = Method::POST;
        *req.uri_mut() = Uri::from_static("http://foo/api/v2/canister/aaaaa-aa/query");

        let mut resp = Router::new()
            .route(
                "/api/v2/canister/{principal}/query",
                axum::routing::post(api_proxy),
            )
            .with_state(state)
            .oneshot(req)
            .await
            .unwrap();

        assert!(matches!(
            resp.extensions_mut().remove::<ErrorCause>(),
            Some(ErrorCause::Client(_))
        ));
        assert!(client.uris.lock().unwrap().is_empty());
    }
}
