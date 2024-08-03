#![allow(clippy::declare_interior_mutable_const)]

use std::{cell::RefCell, pin::Pin, sync::Arc, time::Duration};

use crate::http::Client as HttpClient;
use futures::Future;
use futures_util::StreamExt;
use ic_agent::agent::RejectResponse;
use ic_agent::TransportCallResponse;
use ic_agent::{
    agent::{
        agent_error::HttpErrorPayload, http_transport::route_provider::RouteProvider, Transport,
    },
    export::Principal,
    AgentError,
};
use reqwest::{
    header::{HeaderMap, HeaderValue, CONTENT_TYPE},
    Body, Method, Request, StatusCode,
};
use tokio::task_local;

type AgentFuture<'a, V> = Pin<Box<dyn Future<Output = Result<V, AgentError>> + Send + 'a>>;

const CONTENT_TYPE_CBOR: HeaderValue = HeaderValue::from_static("application/cbor");
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
}

impl ReqwestTransport {
    /// Creates a transport for the agent from a [`RouteProvider`] and an [`HttpClient`].
    pub fn create_with_client_route(
        route_provider: Arc<dyn RouteProvider>,
        client: Arc<dyn HttpClient>,
    ) -> Self {
        Self {
            route_provider,
            client,
            max_response_body_size: Some(MAX_RESPONSE_SIZE),
            use_call_v3_endpoint: false,
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
        let url = self.route_provider.route()?.join(endpoint)?;
        let mut http_request = Request::new(method, url);
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

        *http_request.body_mut() = body.map(Body::from);

        let mut delay = Duration::from_millis(100);
        let mut retries = 5;

        let request_result = loop {
            let result = self.request(http_request.try_clone().unwrap()).await?;
            if result.0 != StatusCode::TOO_MANY_REQUESTS {
                break result;
            }

            retries -= 1;
            if retries == 0 {
                return Err(AgentError::TransportError("retries exhausted".into()));
            }

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
