use std::{cell::RefCell, sync::Arc, time::Duration};

use anyhow::anyhow;
use async_trait::async_trait;
use bytes::Bytes;
use http::{Request, Response, StatusCode};
use http_body_util::{BodyExt, Full, Limited};
use ic_bn_lib::ic_agent::{AgentError, agent::HttpService};
use ic_bn_lib_common::{traits::http::ClientHttp, types::http::Error as HttpError};
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
#[derive(Debug, derive_new::new)]
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
                        // TransportError requires reqwest::Error which cannot be instantiated outside reqwest
                        return Err(AgentError::InvalidHttpResponse(e.to_string()));
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
