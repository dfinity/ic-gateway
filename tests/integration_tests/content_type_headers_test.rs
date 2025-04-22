use crate::helpers::TestEnv;
use crate::helpers::{ExpectedResponse, check_response, retry_async};
use anyhow::{Context, anyhow};
use http::{Method, StatusCode};
use reqwest::{Client, Request};
use std::collections::HashMap;
use std::time::Duration;
use tokio::runtime::Runtime;
use url::Url;

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

    let expected_headers: HashMap<String, String> = vec![
        ("content-type", "application/cbor"),
        ("x-content-type-options", "nosniff"),
        ("x-frame-options", "DENY"),
    ]
    .iter()
    .map(|(k, v)| (k.to_string(), v.to_string()))
    .collect();

    let rt = Runtime::new().map_err(|e| anyhow!("failed to start tokio runtime: {e}"))?;

    let request = Request::new(
        Method::GET,
        Url::parse("http://ic0.app/api/v2/status").unwrap(),
    );
    let expected_response =
        ExpectedResponse::new(Some(StatusCode::OK), None, Some(expected_headers));

    rt.block_on(retry_async(
        "verifying HTTP response to /api/v2/status",
        STATUS_CALL_RETRY_TIMEOUT,
        STATUS_CALL_RETRY_INTERVAL,
        || async {
            let response = http_client
                .execute(request.try_clone().unwrap())
                .await
                .context("failed to execute request")?;

            check_response(response, &expected_response).await
        },
    ))
    .context(anyhow!("failed to verify HTTP response"))?;

    Ok(())
}
