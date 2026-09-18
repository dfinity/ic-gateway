use std::{cell::RefCell, sync::Arc, time::Duration};

use anyhow::anyhow;
use async_trait::async_trait;
use bytes::Bytes;
use derive_new::new;
use http::{Request, Response, StatusCode};
use http_body_util::{BodyExt, Full, Limited};
use ic_bn_lib::{
    http::{ClientHttp, Error as HttpError},
    ic_agent::{AgentError, agent::HttpService, agent_error::TransportError},
};
use reqwest::header::{HeaderMap, HeaderValue};
use tokio::task_local;

use crate::routing::proxy::{http_error_needs_retrying, status_code_needs_retrying};

/// Request context to pass information through the ic-agent boundaries
#[derive(Default)]
pub struct Context {
    pub hostname: Option<String>,
    pub headers_in: HeaderMap<HeaderValue>,
    pub headers_out: HeaderMap<HeaderValue>,
    pub status: Option<StatusCode>,
}

impl Context {
    pub fn new() -> RefCell<Self> {
        RefCell::new(Self::default())
    }
}

task_local! {
    pub static CONTEXT: RefCell<Context>;
}

/// Service that executes requests on IC-Agent's behalf
#[derive(Debug, new)]
pub struct AgentHttpService {
    client: Arc<dyn ClientHttp<Full<Bytes>>>,
    retry_interval: Duration,
}

impl AgentHttpService {
    async fn execute(
        &self,
        mut request: Request<Bytes>,
        size_limit: Option<usize>,
    ) -> Result<Response<Bytes>, HttpError> {
        let read_state = request.uri().path().ends_with("/read_state");

        // Add HTTP headers if requested
        let _ = CONTEXT.try_with(|x| {
            let mut ctx = x.borrow_mut();
            ctx.hostname = Some(
                request
                    .uri()
                    .authority()
                    .map(|x| x.to_string())
                    .unwrap_or_default(),
            );

            for (k, v) in &ctx.headers_out {
                request.headers_mut().insert(k, v.clone());
            }
        });

        let (parts, body) = request.into_parts();
        let body = Full::new(body);
        let request = Request::from_parts(parts, body);

        let response = self.client.execute(request).await?;

        // Add response headers.
        // Don't do it for the read_state calls because for a single incoming request
        // the agent can do several outgoing requests (e.g. read_state to get keys and then query)
        // and we need only one set of response headers.
        if !read_state {
            let _ = CONTEXT.try_with(|x| {
                let mut ctx = x.borrow_mut();
                ctx.status = Some(response.status());

                for (k, v) in response.headers() {
                    ctx.headers_in.insert(k, v.clone());
                }
            });
        }

        let (parts, body) = response.into_parts();
        let body = Limited::new(body, size_limit.unwrap_or(usize::MAX));
        let body = body
            .collect()
            .await
            .map_err(|e| anyhow!("unable to read response body: {e:#}"))?
            .to_bytes();

        let response = Response::from_parts(parts, body);
        Ok(response)
    }
}

#[async_trait]
impl HttpService for AgentHttpService {
    async fn call<'a>(
        &'a self,
        req: &'a (dyn Fn() -> Result<Request<Bytes>, AgentError> + Send + Sync),
        max_retries: usize,
        size_limit: Option<usize>,
    ) -> Result<Response<Bytes>, AgentError> {
        let mut retries = max_retries;
        let mut interval = self.retry_interval;

        loop {
            // TODO should we retry on Agent's request generation failure?
            let request = req()?;

            match self.execute(request, size_limit).await {
                Ok(v) => {
                    let should_retry = status_code_needs_retrying(v.status()) && retries > 0;
                    if !should_retry {
                        return Ok(v);
                    }
                }

                Err(e) => {
                    let should_retry = http_error_needs_retrying(&e) && retries > 0;
                    if !should_retry {
                        return Err(AgentError::TransportError(TransportError::Generic(
                            e.to_string(),
                        )));
                    }
                }
            }

            // Wait & backoff
            tokio::time::sleep(interval).await;
            retries -= 1;
            interval *= 2;
        }
    }
}

#[cfg(test)]
mod test {
    use std::sync::{
        Mutex,
        atomic::{AtomicUsize, Ordering},
    };

    use axum::body::Body;
    use ic_bn_lib::hval;

    use super::*;

    /// Client that replies with a canned sequence of statuses (the last one repeats
    /// forever) and records the requests it was called with.
    #[derive(Debug)]
    struct TestClient {
        statuses: Vec<StatusCode>,
        calls: AtomicUsize,
        requests: Mutex<Vec<Request<Bytes>>>,
        body: &'static str,
    }

    impl TestClient {
        fn new(statuses: &[StatusCode]) -> Self {
            Self {
                statuses: statuses.to_vec(),
                calls: AtomicUsize::new(0),
                requests: Mutex::new(vec![]),
                body: "response-body",
            }
        }

        fn calls(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }
    }

    #[async_trait]
    impl ClientHttp<Full<Bytes>> for TestClient {
        async fn execute(&self, req: Request<Full<Bytes>>) -> Result<Response<Body>, HttpError> {
            let idx = self.calls.fetch_add(1, Ordering::SeqCst);

            // Record the outgoing request (body collected to Bytes for easy asserts)
            let (parts, body) = req.into_parts();
            let body = body.collect().await.unwrap().to_bytes();
            self.requests
                .lock()
                .unwrap()
                .push(Request::from_parts(parts, body));

            let status = self.statuses[idx.min(self.statuses.len() - 1)];
            let mut resp = Response::new(Body::from(self.body));
            *resp.status_mut() = status;
            resp.headers_mut().insert("x-ic-node-id", hval!("node-1"));

            Ok(resp)
        }
    }

    /// Client that always fails with a non-retryable error
    #[derive(Debug)]
    struct FailingClient(AtomicUsize);

    #[async_trait]
    impl ClientHttp<Full<Bytes>> for FailingClient {
        async fn execute(&self, _: Request<Full<Bytes>>) -> Result<Response<Body>, HttpError> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Err(HttpError::BodyTimedOut)
        }
    }

    fn request_fn(uri: &'static str) -> impl Fn() -> Result<Request<Bytes>, AgentError> {
        move || {
            let mut req = Request::new(Bytes::from_static(b"request-body"));
            *req.uri_mut() = uri.parse().unwrap();
            Ok(req)
        }
    }

    #[tokio::test]
    async fn test_retries_until_success() {
        let client = Arc::new(TestClient::new(&[
            StatusCode::INTERNAL_SERVER_ERROR,
            StatusCode::TOO_MANY_REQUESTS,
            StatusCode::BAD_GATEWAY,
            StatusCode::OK,
        ]));
        let svc = AgentHttpService::new(client.clone(), Duration::ZERO);

        let resp = svc
            .call(&request_fn("http://foo/api/v2/status"), 5, None)
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(client.calls(), 4);
        assert_eq!(resp.into_body(), Bytes::from_static(b"response-body"));
    }

    #[tokio::test]
    async fn test_retries_exhausted_returns_last_response() {
        let client = Arc::new(TestClient::new(&[StatusCode::SERVICE_UNAVAILABLE]));
        let svc = AgentHttpService::new(client.clone(), Duration::ZERO);

        // Retries are exhausted, so the last (still failing) response is returned
        // rather than an error.
        let resp = svc
            .call(&request_fn("http://foo/api/v2/status"), 3, None)
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        // 3 retries == 4 attempts total
        assert_eq!(client.calls(), 4);
    }

    #[tokio::test]
    async fn test_no_retries() {
        let client = Arc::new(TestClient::new(&[StatusCode::SERVICE_UNAVAILABLE]));
        let svc = AgentHttpService::new(client.clone(), Duration::ZERO);

        let resp = svc
            .call(&request_fn("http://foo/api/v2/status"), 0, None)
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(client.calls(), 1);
    }

    #[tokio::test]
    async fn test_client_error_not_retried() {
        // `BodyTimedOut` is not a connect error, so `http_error_needs_retrying` is
        // false and we must fail immediately instead of burning the retry budget.
        let client = Arc::new(FailingClient(AtomicUsize::new(0)));
        let svc = AgentHttpService::new(client.clone(), Duration::ZERO);

        let err = svc
            .call(&request_fn("http://foo/api/v2/status"), 5, None)
            .await
            .unwrap_err();

        assert!(
            matches!(err, AgentError::TransportError(TransportError::Generic(_))),
            "unexpected error: {err:?}"
        );
        assert_eq!(client.0.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn test_request_generation_error_propagated() {
        let client = Arc::new(TestClient::new(&[StatusCode::OK]));
        let svc = AgentHttpService::new(client.clone(), Duration::ZERO);

        let err = svc
            .call(
                &|| Err(AgentError::MessageError("nope".into())),
                5,
                None,
            )
            .await
            .unwrap_err();

        assert!(matches!(err, AgentError::MessageError(_)));
        assert_eq!(client.calls(), 0);
    }

    #[tokio::test]
    async fn test_size_limit_exceeded() {
        let client = Arc::new(TestClient::new(&[StatusCode::OK]));
        let svc = AgentHttpService::new(client.clone(), Duration::ZERO);

        // "response-body" is 13 bytes
        let err = svc
            .call(&request_fn("http://foo/api/v2/status"), 0, Some(5))
            .await
            .unwrap_err();

        assert!(
            matches!(err, AgentError::TransportError(TransportError::Generic(_))),
            "unexpected error: {err:?}"
        );

        // The exact limit is fine
        let client = Arc::new(TestClient::new(&[StatusCode::OK]));
        let svc = AgentHttpService::new(client.clone(), Duration::ZERO);
        let resp = svc
            .call(&request_fn("http://foo/api/v2/status"), 0, Some(13))
            .await
            .unwrap();
        assert_eq!(resp.into_body().len(), 13);
    }

    #[tokio::test]
    async fn test_context_round_trip() {
        let client = Arc::new(TestClient::new(&[StatusCode::TOO_MANY_REQUESTS]));
        let svc = AgentHttpService::new(client.clone(), Duration::ZERO);

        let ctx = CONTEXT
            .scope(Context::new(), async {
                CONTEXT.with(|x| {
                    x.borrow_mut()
                        .headers_out
                        .insert("x-request-id", hval!("req-42"));
                });

                svc.call(&request_fn("http://boundary.node:8443/api/v2/query"), 0, None)
                    .await
                    .unwrap();

                CONTEXT.with(|x| {
                    let x = x.borrow();
                    (
                        x.hostname.clone(),
                        x.status,
                        x.headers_in.clone(),
                        x.headers_out.clone(),
                    )
                })
            })
            .await;

        let (hostname, status, headers_in, headers_out) = ctx;

        // Upstream authority is recorded for logging/metrics
        assert_eq!(hostname, Some("boundary.node:8443".to_string()));
        // Response status & headers are captured
        assert_eq!(status, Some(StatusCode::TOO_MANY_REQUESTS));
        assert_eq!(headers_in.get("x-ic-node-id").unwrap(), "node-1");
        // Outgoing headers were injected into the actual request
        assert_eq!(headers_out.get("x-request-id").unwrap(), "req-42");
        assert_eq!(
            client.requests.lock().unwrap()[0]
                .headers()
                .get("x-request-id")
                .unwrap(),
            "req-42"
        );
    }

    #[tokio::test]
    async fn test_context_skips_read_state_responses() {
        // A single incoming request can cause several outgoing ones (read_state for
        // the keys, then a query). Only the non-read_state response headers must be
        // captured, otherwise they'd be reported for the wrong call.
        let client = Arc::new(TestClient::new(&[StatusCode::OK]));
        let svc = AgentHttpService::new(client.clone(), Duration::ZERO);

        let (status, headers_in, hostname) = CONTEXT
            .scope(Context::new(), async {
                svc.call(
                    &request_fn("http://foo/api/v2/canister/aaaaa-aa/read_state"),
                    0,
                    None,
                )
                .await
                .unwrap();

                CONTEXT.with(|x| {
                    let x = x.borrow();
                    (x.status, x.headers_in.clone(), x.hostname.clone())
                })
            })
            .await;

        assert_eq!(status, None);
        assert!(headers_in.is_empty());
        // The hostname is still recorded - it's set before the request is made
        assert_eq!(hostname, Some("foo".to_string()));
    }

    #[tokio::test]
    async fn test_works_without_context() {
        // `create_agent` also uses this service outside of any request scope
        // (e.g. root key fetching), so a missing task-local must not panic.
        let client = Arc::new(TestClient::new(&[StatusCode::OK]));
        let svc = AgentHttpService::new(client.clone(), Duration::ZERO);

        let resp = svc
            .call(&request_fn("http://foo/api/v2/status"), 0, None)
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_backoff_grows() {
        let client = Arc::new(TestClient::new(&[
            StatusCode::SERVICE_UNAVAILABLE,
            StatusCode::SERVICE_UNAVAILABLE,
            StatusCode::SERVICE_UNAVAILABLE,
            StatusCode::OK,
        ]));
        let svc = AgentHttpService::new(client.clone(), Duration::from_millis(20));

        let start = tokio::time::Instant::now();
        let resp = svc
            .call(&request_fn("http://foo/api/v2/status"), 5, None)
            .await
            .unwrap();
        let elapsed = start.elapsed();

        assert_eq!(resp.status(), StatusCode::OK);
        // Intervals double: 20 + 40 + 80 = 140ms
        assert!(
            elapsed >= Duration::from_millis(140),
            "backoff was too short: {elapsed:?}"
        );
    }
}
