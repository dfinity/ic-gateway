use async_trait::async_trait;
use http::{Method, StatusCode};
use ic_agent::agent::http_transport::dynamic_routing::{
    dynamic_route_provider::DynamicRouteProviderError,
    health_check::{HealthCheck, HealthCheckStatus},
    node::Node,
};
use reqwest::{Client, Request};
use std::time::{Duration, Instant};
use tracing::error;
use url::Url;

pub const CHECK_TIMEOUT: Duration = Duration::from_secs(1);
const HEALTH_CHECKER: &str = "HealthChecker";

/// A struct implementing the `HealthCheck` for the nodes.
#[derive(Debug)]
pub struct HealthChecker {
    http_client: Client,
    timeout: Duration,
}

impl HealthChecker {
    /// Creates a new `HealthChecker` instance.
    pub const fn new(http_client: Client, timeout: Duration) -> Self {
        Self {
            http_client,
            timeout,
        }
    }
}

#[async_trait]
impl HealthCheck for HealthChecker {
    async fn check(&self, node: &Node) -> Result<HealthCheckStatus, DynamicRouteProviderError> {
        // API boundary node exposes /health endpoint and should respond with 204 (No Content) if it's healthy.
        let url = Url::parse(&format!("https://{}/health", node.domain())).unwrap();

        let mut request = Request::new(Method::GET, url.clone());
        *request.timeout_mut() = Some(self.timeout);

        let start = Instant::now();
        let response = self.http_client.execute(request).await.map_err(|err| {
            DynamicRouteProviderError::HealthCheckError(format!(
                "Failed to execute GET request to {url}: {err}"
            ))
        })?;
        let latency = start.elapsed();

        if response.status() != StatusCode::NO_CONTENT {
            let err_msg = format!(
                "{HEALTH_CHECKER}: Unexpected http status code {} for url={url} received",
                response.status()
            );
            error!(err_msg);
            return Err(DynamicRouteProviderError::HealthCheckError(err_msg));
        }

        Ok(HealthCheckStatus::new(Some(latency)))
    }
}
