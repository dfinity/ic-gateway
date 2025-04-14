use crate::helpers::retry_async;
use crate::helpers::{TestEnv, verify_status_call_headers};
use anyhow::anyhow;
use reqwest::Client;
use std::time::Duration;
use tokio::runtime::Runtime;

const STATUS_CALL_RETRY_TIMEOUT: Duration = Duration::from_secs(50);
const STATUS_CALL_RETRY_INTERVAL: Duration = Duration::from_secs(10);

// Test scenario:
// - make an HTTP GET request to http://ic0.app/api/v2/status
// - verify necessary headers are present in response: [content-type, x-content-type-options, x-frame-options]

pub fn content_type_headers_test(env: &TestEnv) -> anyhow::Result<()> {
    let http_client = Client::builder()
        .resolve(&env.ic_gateway_domain, env.ic_gateway_addr)
        .build()
        .map_err(|e| anyhow!("failed to build http client: {e}"))?;

    let rt = Runtime::new().map_err(|e| anyhow!("failed to start tokio runtime: {e}"))?;

    rt.block_on(retry_async(
        "verifying correct headers in /api/v2/status response",
        STATUS_CALL_RETRY_TIMEOUT,
        STATUS_CALL_RETRY_INTERVAL,
        || verify_status_call_headers(&http_client, "http://ic0.app/api/v2/status"),
    ))
    .map_err(|e| anyhow!("failed to verify correct headers: {e}"))?;

    Ok(())
}
