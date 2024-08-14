#![allow(clippy::declare_interior_mutable_const)]

use discower_bowndary::transport::{TransportProvider, TransportProviderError};
use futures::Future;
use futures_util::StreamExt;
use ic_agent::{
    agent::{
        agent_error::HttpErrorPayload,
        http_transport::route_provider::{RoundRobinRouteProvider, RouteProvider},
        Transport,
    },
    export::Principal,
    AgentError,
};
use ic_transport_types::{RejectResponse, TransportCallResponse};
use reqwest::{
    header::{HeaderMap, HeaderValue, CONTENT_TYPE},
    Body, Method, Request, StatusCode,
};
use std::{cell::RefCell, pin::Pin, sync::Arc, time::Duration};
use tokio::task_local;
use url::Url;

use crate::http::{headers::CONTENT_TYPE_CBOR, Client as HttpClient};

type AgentFuture<'a, V> = Pin<Box<dyn Future<Output = Result<V, AgentError>> + Send + 'a>>;

const MAX_RESPONSE_SIZE: usize = 2 * 1_048_576;

pub struct PassHeaders {
    pub headers_in: HeaderMap<HeaderValue>,
    pub headers_out: HeaderMap<HeaderValue>,
}

impl PassHeaders {
    pub fn new() -> RefCell<Self> {
        RefCell::new(Self {
            headers_in: HeaderMap::new(),
            headers_out: HeaderMap::new(),
        })
    }
}

task_local! {
    pub static PASS_HEADERS: RefCell<PassHeaders>;
}

/// A [`Transport`] using [`HttpClient`] to make HTTP calls to the Internet Computer.
#[derive(Debug)]
pub struct ReqwestTransport {
    route_provider: Arc<dyn RouteProvider>,
    client: Arc<dyn HttpClient>,
    max_response_body_size: Option<usize>,
    use_call_v3_endpoint: bool,
    max_request_retries: u32,
}

impl ReqwestTransport {
    /// Creates a transport for the agent from a [`RouteProvider`] and an [`HttpClient`].
    pub fn create_with_client_route(
        route_provider: Arc<dyn RouteProvider>,
        client: Arc<dyn HttpClient>,
        max_request_retries: u32,
    ) -> Self {
        Self {
            route_provider,
            client,
            max_response_body_size: Some(MAX_RESPONSE_SIZE),
            use_call_v3_endpoint: false,
            max_request_retries,
        }
    }

    async fn request(
        &self,
        http_request: Request,
    ) -> Result<(StatusCode, HeaderMap, Vec<u8>), AgentError> {
        let response = self
            .client
            .execute(http_request)
            .await
            .map_err(|x| AgentError::TransportError(Box::new(x)))?;

        let http_status = response.status();
        let response_headers = response.headers().clone();

        // Size Check (Content-Length)
        if matches!(self
            .max_response_body_size
            .zip(response.content_length()), Some((size_limit, content_length)) if content_length as usize > size_limit)
        {
            return Err(AgentError::ResponseSizeExceededLimit());
        }

        let mut body: Vec<u8> = response
            .content_length()
            .map_or_else(Vec::new, |n| Vec::with_capacity(n as usize));

        let mut stream = response.bytes_stream();

        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|x| AgentError::TransportError(Box::new(x)))?;

            // Size Check (Body Size)
            if matches!(self
                .max_response_body_size, Some(size_limit) if body.len() + chunk.len() > size_limit)
            {
                return Err(AgentError::ResponseSizeExceededLimit());
            }

            body.extend_from_slice(chunk.as_ref());
        }

        Ok((http_status, response_headers, body))
    }

    async fn execute(
        &self,
        method: Method,
        endpoint: &str,
        body: Option<Vec<u8>>,
    ) -> Result<(StatusCode, Vec<u8>), AgentError> {
        let create_request_with_generated_url = || -> Result<Request, AgentError> {
            let url = self.route_provider.route()?.join(endpoint)?;
            let mut http_request = Request::new(method.clone(), url);
            http_request
                .headers_mut()
                .insert(CONTENT_TYPE, CONTENT_TYPE_CBOR);

            // Add HTTP headers if requested
            let _ = PASS_HEADERS.try_with(|x| {
                let mut pass = x.borrow_mut();
                for (k, v) in &pass.headers_out {
                    http_request.headers_mut().append(k, v.clone());
                }
                pass.headers_out.clear();
            });

            *http_request.body_mut() = body.as_ref().cloned().map(Body::from);

            Ok(http_request)
        };

        let mut delay = Duration::from_millis(100);
        let mut retries = self.max_request_retries;

        let request_result = loop {
            let result = {
                // RouteProvider generates urls dynamically. Some urls can be unhealthy.
                // TCP related errors (host unreachable, connection refused, connection timed out, connection reset) can be safely retried with a newly generated url.
                loop {
                    let http_request = create_request_with_generated_url()?;

                    match self.request(http_request).await {
                        Ok(response) => break response,
                        Err(agent_error) => match agent_error {
                            AgentError::TransportError(ref err) => {
                                if err
                                    .downcast_ref::<reqwest::Error>()
                                    .is_some_and(|e| e.is_connect())
                                {
                                    if retries <= 0 {
                                        return Err(AgentError::TransportError(
                                            "retries exhausted".into(),
                                        ));
                                    }
                                    retries -= 1;
                                    // Sleep before retrying. Delay time is not changed, as is the case for http retry.
                                    tokio::time::sleep(delay).await;
                                    continue;
                                }
                                return Err(agent_error);
                            }
                            _ => return Err(agent_error),
                        },
                    }
                }
            };

            if result.0 != StatusCode::TOO_MANY_REQUESTS {
                break result;
            }

            if retries <= 0 {
                return Err(AgentError::TransportError("retries exhausted".into()));
            }

            retries -= 1;

            tokio::time::sleep(delay).await;
            delay *= 2;
        };

        let status = request_result.0;
        let headers = request_result.1;
        let body = request_result.2;

        // Add response headers.
        // Don't do it for the read_state calls because for a single incoming request
        // the agent can do several outgoing requests (e.g. read_state to get keys and then query)
        // and we need only one set of response headers.
        if !endpoint.ends_with("/read_state") {
            let _ = PASS_HEADERS.try_with(|x| {
                let mut pass = x.borrow_mut();
                pass.headers_in.clear();

                for (k, v) in &headers {
                    pass.headers_in.insert(k, v.clone());
                }
            });
        }

        // status == OK means we have an error message for call requests
        // see https://internetcomputer.org/docs/current/references/ic-interface-spec#http-call
        if status == StatusCode::OK && endpoint.ends_with("call") {
            let cbor_decoded_body: Result<RejectResponse, serde_cbor::Error> =
                serde_cbor::from_slice(&body);

            let agent_error = match cbor_decoded_body {
                Ok(replica_error) => AgentError::UncertifiedReject(replica_error),
                Err(cbor_error) => AgentError::InvalidCborData(cbor_error),
            };

            Err(agent_error)
        } else if status.is_client_error() || status.is_server_error() {
            Err(AgentError::HttpError(HttpErrorPayload {
                status: status.into(),
                content_type: headers
                    .get(CONTENT_TYPE)
                    .and_then(|value| value.to_str().ok())
                    .map(|x| x.to_string()),
                content: body,
            }))
        } else {
            Ok((status, body))
        }
    }
}

impl Transport for ReqwestTransport {
    fn call(
        &self,
        effective_canister_id: Principal,
        envelope: Vec<u8>,
    ) -> AgentFuture<ic_agent::TransportCallResponse> {
        Box::pin(async move {
            let api_version = if self.use_call_v3_endpoint {
                "v3"
            } else {
                "v2"
            };

            let endpoint = format!(
                "api/{}/canister/{}/call",
                api_version,
                effective_canister_id.to_text()
            );

            let (status_code, response_body) = self
                .execute(Method::POST, &endpoint, Some(envelope))
                .await?;

            if status_code == StatusCode::ACCEPTED {
                return Ok(TransportCallResponse::Accepted);
            }

            // status_code == OK (200)
            if self.use_call_v3_endpoint {
                serde_cbor::from_slice(&response_body).map_err(AgentError::InvalidCborData)
            } else {
                let reject_response = serde_cbor::from_slice::<RejectResponse>(&response_body)
                    .map_err(AgentError::InvalidCborData)?;

                Err(AgentError::UncertifiedReject(reject_response))
            }
        })
    }

    fn read_state(
        &self,
        effective_canister_id: Principal,
        envelope: Vec<u8>,
    ) -> AgentFuture<Vec<u8>> {
        Box::pin(async move {
            let endpoint = format!(
                "api/v2/canister/{}/read_state",
                effective_canister_id.to_text()
            );
            self.execute(Method::POST, &endpoint, Some(envelope))
                .await
                .map(|r| r.1)
        })
    }

    fn read_subnet_state(&self, subnet_id: Principal, envelope: Vec<u8>) -> AgentFuture<Vec<u8>> {
        Box::pin(async move {
            let endpoint = format!("api/v2/subnet/{}/read_state", subnet_id.to_text());
            self.execute(Method::POST, &endpoint, Some(envelope))
                .await
                .map(|r| r.1)
        })
    }

    fn query(&self, effective_canister_id: Principal, envelope: Vec<u8>) -> AgentFuture<Vec<u8>> {
        Box::pin(async move {
            let endpoint = format!("api/v2/canister/{}/query", effective_canister_id.to_text());
            self.execute(Method::POST, &endpoint, Some(envelope))
                .await
                .map(|r| r.1)
        })
    }

    fn status(&self) -> AgentFuture<Vec<u8>> {
        let endpoint = "api/v2/status";
        Box::pin(async move { self.execute(Method::GET, endpoint, None).await.map(|r| r.1) })
    }
}

#[derive(Debug)]
pub struct ReqwestTransportProvider {
    http_client: Arc<dyn HttpClient>,
}

impl ReqwestTransportProvider {
    pub fn new(http_client: Arc<dyn HttpClient>) -> Self {
        Self { http_client }
    }
}

impl TransportProvider for ReqwestTransportProvider {
    fn get_transport(&self, url: Url) -> Result<Arc<dyn Transport>, TransportProviderError> {
        // Here we need to fetch API nodes via a single static url, thus use RoundRobinRouteProvider with just one url.
        let route_provider = Arc::new(
            RoundRobinRouteProvider::new(vec![url.as_str()])
                .map_err(|err| TransportProviderError::UnableToGetTransport(err.to_string()))?,
        );

        let transport = Arc::new(ReqwestTransport::create_with_client_route(
            route_provider,
            self.http_client.clone(),
            5, // TODO: this TransportProvider aling with hard-coded value is to be removed.
        ));

        Ok(transport)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;
    use crate::http::Client as HttpClient;
    use async_trait::async_trait;
    use hyper::{Response, StatusCode};

    #[derive(Debug)]
    struct MockClient {
        http_failures_count: AtomicUsize,
        network_failures_count: AtomicUsize,
        http_failure_statuses: Vec<StatusCode>,
    }

    #[async_trait]
    impl HttpClient for MockClient {
        async fn execute(
            &self,
            _req: reqwest::Request,
        ) -> Result<reqwest::Response, reqwest::Error> {
            // throw network errors
            if self.network_failures_count.load(Ordering::Relaxed) > 0 {
                self.network_failures_count.fetch_sub(1, Ordering::Relaxed);
                let err = reqwest::get("http://0.0.0.0:1").await.unwrap_err();
                return Err(err);
            }

            // throw http errors
            if self.http_failures_count.load(Ordering::Relaxed) > 0 {
                let response = Response::new("executed erroneously");
                let (mut parts, body) = response.into_parts();
                let idx = self.http_failures_count.fetch_sub(1, Ordering::Relaxed);
                parts.status = self.http_failure_statuses[idx - 1];
                return Ok(Response::from_parts(parts, body).into());
            }

            let response = Response::new("executed successfully");

            Ok(response.into())
        }
    }

    #[tokio::test]
    async fn test_execute_with_no_retries_and_no_failures_succeeds() {
        // Arrange
        let route_provider =
            Arc::new(RoundRobinRouteProvider::new(vec!["https://ic0.app"]).unwrap());

        let client = Arc::new(MockClient {
            http_failure_statuses: vec![],
            http_failures_count: AtomicUsize::new(0),
            network_failures_count: AtomicUsize::new(0),
        });

        let transport = ReqwestTransport {
            route_provider,
            max_request_retries: 0,
            max_response_body_size: None,
            client,
            use_call_v3_endpoint: false,
        };

        // Act
        let (status, body) = transport.execute(Method::GET, "/test", None).await.unwrap();

        //Assert
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, b"executed successfully");
    }

    #[tokio::test]
    async fn test_execute_with_retries_and_network_failures_succeeds() {
        // Arrange
        let route_provider =
            Arc::new(RoundRobinRouteProvider::new(vec!["https://ic0.app"]).unwrap());

        let client = Arc::new(MockClient {
            http_failure_statuses: vec![],
            http_failures_count: AtomicUsize::new(0),
            network_failures_count: AtomicUsize::new(2),
        });

        let transport = ReqwestTransport {
            route_provider,
            max_request_retries: 2,
            max_response_body_size: None,
            client,
            use_call_v3_endpoint: false,
        };

        // Act
        let (status, body) = transport.execute(Method::GET, "/test", None).await.unwrap();

        //Assert
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, b"executed successfully");
    }

    #[tokio::test]
    async fn test_execute_with_insufficient_retries_and_network_failures_fails() {
        // Arrange
        let route_provider =
            Arc::new(RoundRobinRouteProvider::new(vec!["https://ic0.app"]).unwrap());

        let client = Arc::new(MockClient {
            http_failure_statuses: vec![],
            http_failures_count: AtomicUsize::new(0),
            network_failures_count: AtomicUsize::new(2),
        });

        let transport = ReqwestTransport {
            route_provider,
            max_request_retries: 1,
            max_response_body_size: None,
            client,
            use_call_v3_endpoint: false,
        };

        // Act
        let agent_error = transport
            .execute(Method::GET, "/test", None)
            .await
            .unwrap_err();

        //Assert
        assert!(agent_error.to_string().contains("retries exhausted"));
    }

    #[tokio::test]
    async fn test_execute_with_retries_and_http_failures_succeeds() {
        // Arrange
        let route_provider =
            Arc::new(RoundRobinRouteProvider::new(vec!["https://ic0.app"]).unwrap());

        // TOO_MANY_REQUESTS should be retried, thus success
        let client = Arc::new(MockClient {
            http_failure_statuses: vec![StatusCode::TOO_MANY_REQUESTS],
            http_failures_count: AtomicUsize::new(1),
            network_failures_count: AtomicUsize::new(0),
        });

        let transport = ReqwestTransport {
            route_provider,
            max_request_retries: 1,
            max_response_body_size: None,
            client,
            use_call_v3_endpoint: false,
        };

        // Act
        let (status, body) = transport.execute(Method::GET, "/test", None).await.unwrap();

        //Assert
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, b"executed successfully");
    }

    #[tokio::test]
    async fn test_execute_with_retries_and_http_failures_fails() {
        // Arrange
        let route_provider =
            Arc::new(RoundRobinRouteProvider::new(vec!["https://ic0.app"]).unwrap());

        // BAD_REQUEST is not retried, thus failure
        let client = Arc::new(MockClient {
            http_failure_statuses: vec![StatusCode::BAD_REQUEST],
            http_failures_count: AtomicUsize::new(1),
            network_failures_count: AtomicUsize::new(0),
        });

        let transport = ReqwestTransport {
            route_provider,
            max_request_retries: 2,
            max_response_body_size: None,
            client,
            use_call_v3_endpoint: false,
        };

        // Act
        let agent_error = transport
            .execute(Method::GET, "/test", None)
            .await
            .unwrap_err();

        //Assert
        assert!(agent_error.to_string().contains("400 Bad Request"));
    }

    #[tokio::test]
    async fn test_execute_with_insufficient_retries_and_http_failures_fails() {
        // Arrange
        let route_provider =
            Arc::new(RoundRobinRouteProvider::new(vec!["https://ic0.app"]).unwrap());

        // TOO_MANY_REQUESTS should be retried, but 2 retries is not enough, thus error.
        let client = Arc::new(MockClient {
            http_failure_statuses: vec![
                StatusCode::TOO_MANY_REQUESTS,
                StatusCode::TOO_MANY_REQUESTS,
                StatusCode::TOO_MANY_REQUESTS,
            ],
            http_failures_count: AtomicUsize::new(3),
            network_failures_count: AtomicUsize::new(0),
        });

        let transport = ReqwestTransport {
            route_provider,
            max_request_retries: 2,
            max_response_body_size: None,
            client,
            use_call_v3_endpoint: false,
        };

        // Act
        let agent_error = transport
            .execute(Method::GET, "/test", None)
            .await
            .unwrap_err();

        //Assert
        assert!(agent_error.to_string().contains("retries exhausted"));
    }

    #[tokio::test]
    async fn test_execute_with_insufficient_retries_and_network_and_http_failures_fails() {
        // Arrange
        let route_provider =
            Arc::new(RoundRobinRouteProvider::new(vec!["https://ic0.app"]).unwrap());

        // TOO_MANY_REQUESTS/network should be retried, but 5 times is not enough, thus error.
        let client = Arc::new(MockClient {
            http_failure_statuses: vec![
                StatusCode::TOO_MANY_REQUESTS,
                StatusCode::TOO_MANY_REQUESTS,
                StatusCode::TOO_MANY_REQUESTS,
            ],
            http_failures_count: AtomicUsize::new(3),
            network_failures_count: AtomicUsize::new(3),
        });

        let transport = ReqwestTransport {
            route_provider,
            max_request_retries: 5,
            max_response_body_size: None,
            client,
            use_call_v3_endpoint: false,
        };

        // Act
        let agent_error = transport
            .execute(Method::GET, "/test", None)
            .await
            .unwrap_err();

        //Assert
        assert!(agent_error.to_string().contains("retries exhausted"));
    }

    #[tokio::test]
    async fn test_execute_with_retries_and_network_and_http_failures_succeeds() {
        // Arrange
        let route_provider =
            Arc::new(RoundRobinRouteProvider::new(vec!["https://ic0.app"]).unwrap());

        // TOO_MANY_REQUESTS/network errors should be retried enough times, thus success.
        let client = Arc::new(MockClient {
            http_failure_statuses: vec![
                StatusCode::TOO_MANY_REQUESTS,
                StatusCode::TOO_MANY_REQUESTS,
                StatusCode::TOO_MANY_REQUESTS,
            ],
            http_failures_count: AtomicUsize::new(3),
            network_failures_count: AtomicUsize::new(3),
        });

        let transport = ReqwestTransport {
            route_provider,
            max_request_retries: 6,
            max_response_body_size: None,
            client,
            use_call_v3_endpoint: false,
        };

        // Act
        let (status, body) = transport.execute(Method::GET, "/test", None).await.unwrap();

        //Assert
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, b"executed successfully");
    }
}
