use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use async_trait::async_trait;
use discower_bowndary::{
    check::{HealthCheck, HealthCheckError, HealthCheckResult},
    node::Node,
};
use http::{Method, StatusCode};
use reqwest::Request;
use tracing::{error, warn};
use url::Url;

use crate::http::Client;

const SERVICE_NAME: &str = "HealthChecker";

#[derive(Debug)]
pub struct HealthChecker {
    http_client: Arc<dyn Client>,
    timeout: Duration,
}

impl HealthChecker {
    pub fn new(http_client: Arc<dyn Client>, timeout: Duration) -> Self {
        Self {
            http_client,
            timeout,
        }
    }
}

// NOTE: We can't use the implementation provided in the Discovery Library. It needs an http_client of concrete type.
#[async_trait]
impl HealthCheck for HealthChecker {
    async fn check(&self, node: &Node) -> Result<HealthCheckResult, HealthCheckError> {
        let url = Url::parse(&format!("https://{}/health", node.domain))?;

        let mut request = Request::new(Method::GET, url.clone());
        *request.timeout_mut() = Some(self.timeout);

        let start = Instant::now();
        let response = self.http_client.execute(request).await;
        let elapsed = start.elapsed();

        // Set latency to Some() only for successful health check.
        let latency = match response {
            Ok(res) if res.status() == StatusCode::NO_CONTENT => Some(elapsed),
            Ok(res) => {
                error!(
                    "{SERVICE_NAME}: check() for url={url} received unexpected http status {}",
                    res.status()
                );
                None
            }
            Err(err) => {
                warn!("{SERVICE_NAME}: check() failed for url={url}: {err:?}");
                None
            }
        };

        Ok(HealthCheckResult { latency })
    }
}
