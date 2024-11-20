use std::{cell::RefCell, sync::Arc, time::Duration};

use async_trait::async_trait;
use http::StatusCode;
use ic_agent::{agent::HttpService, AgentError};
use ic_bn_lib::http::Client as HttpClient;
use reqwest::{
    header::{HeaderMap, HeaderValue},
    Request, Response,
};
use tokio::task_local;

pub struct Context {
    pub hostname: Option<String>,
    pub headers_in: HeaderMap<HeaderValue>,
    pub headers_out: HeaderMap<HeaderValue>,
}

impl Context {
    pub fn new() -> RefCell<Self> {
        RefCell::new(Self {
            hostname: None,
            headers_in: HeaderMap::new(),
            headers_out: HeaderMap::new(),
        })
    }
}

task_local! {
    pub static CONTEXT: RefCell<Context>;
}

/// Service that executes requests on IC-Agent's behalf
#[derive(Debug, derive_new::new)]
pub struct AgentHttpService {
    client: Arc<dyn HttpClient>,
    retry_interval: Duration,
}

impl AgentHttpService {
    async fn execute(&self, mut request: Request) -> Result<Response, reqwest::Error> {
        let read_state = request.url().path().ends_with("/read_state");

        // Add HTTP headers if requested
        let _ = CONTEXT.try_with(|x| {
            let mut ctx = x.borrow_mut();
            ctx.hostname = Some(request.url().authority().to_string());

            for (k, v) in &ctx.headers_out {
                request.headers_mut().insert(k, v.clone());
            }
        });

        let response = self.client.execute(request).await?;

        // Add response headers.
        // Don't do it for the read_state calls because for a single incoming request
        // the agent can do several outgoing requests (e.g. read_state to get keys and then query)
        // and we need only one set of response headers.
        if !read_state {
            let _ = CONTEXT.try_with(|x| {
                let mut ctx = x.borrow_mut();

                for (k, v) in response.headers() {
                    ctx.headers_in.insert(k, v.clone());
                }
            });
        }

        Ok(response)
    }
}

#[async_trait]
impl HttpService for AgentHttpService {
    async fn call<'a>(
        &'a self,
        req: &'a (dyn Fn() -> Result<Request, AgentError> + Send + Sync),
        max_retries: usize,
    ) -> Result<Response, AgentError> {
        let mut retry = 0;
        let mut interval = self.retry_interval;

        loop {
            // TODO should we retry on Agent's request generation failure?
            let request = req()?;

            match self.execute(request).await {
                Ok(v) => {
                    // Retry only on 429 for now
                    if v.status() != StatusCode::TOO_MANY_REQUESTS || retry >= max_retries {
                        return Ok(v);
                    }
                }

                Err(e) => {
                    // Don't retry on any errors except connect for now
                    if !e.is_connect() || retry >= max_retries {
                        return Err(AgentError::TransportError(e));
                    }
                }
            }

            // Wait & backoff
            tokio::time::sleep(interval).await;
            retry += 1;
            interval *= 2;
        }
    }
}
