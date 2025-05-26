use std::collections::HashMap;

use anyhow::{Context, anyhow};
use http::{Method, StatusCode};
use reqwest::{Client, Request};
use url::Url;

use crate::helpers::{
    ExpectedResponse, RETRY_INTERVAL, RETRY_TIMEOUT, TestEnv, check_response, retry_async,
};

// Test scenario:
// - make an HTTP GET request to http://ic0.app/api/v2/status
// - verify necessary headers are present in response: [content-type, x-content-type-options, x-frame-options]

pub async fn content_type_headers_test(env: &TestEnv) -> anyhow::Result<()> {
    let http_client = Client::builder()
        .resolve(&env.ic_gateway_domain, env.ic_gateway_addr)
        .build()
        .map_err(|e| anyhow!("failed to build http client: {e}"))?;

    let expected_headers = HashMap::from([
        ("content-type".to_string(), "application/cbor".to_string()),
        ("x-content-type-options".to_string(), "nosniff".to_string()),
        ("x-frame-options".to_string(), "DENY".to_string()),
    ]);

    let request = Request::new(
        Method::GET,
        Url::parse("http://ic0.app/api/v2/status").unwrap(),
    );
    let expected_response =
        ExpectedResponse::new(Some(StatusCode::OK), None, Some(expected_headers));

    retry_async(
        "verifying HTTP response to /api/v2/status",
        RETRY_TIMEOUT,
        RETRY_INTERVAL,
        || async {
            let response = http_client
                .execute(request.try_clone().unwrap())
                .await
                .context("failed to execute request")?;

            check_response(response, &expected_response).await
        },
    )
    .await
    .context(anyhow!("failed to verify HTTP response"))?;

    Ok(())
}
