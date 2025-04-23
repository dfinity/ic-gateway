use std::{collections::HashMap, time::Duration};

use crate::helpers::{ExpectedResponse, TestEnv, check_response, retry_async};
use anyhow::{Context, anyhow};
use candid::Principal;
use http::{Method, StatusCode};
use reqwest::{Client, Request};
use tokio::runtime::Runtime;
use tracing::info;
use url::Url;

const REQUEST_RETRY_TIMEOUT: Duration = Duration::from_secs(20);
const REQUEST_RETRY_INTERVAL: Duration = Duration::from_secs(2);

// Test scenario:
// - install counter canister
// - make various HTTP requests OPTIONS/GET/POST and verify the CORS headers of the responses

pub fn cors_headers_test(env: &TestEnv) -> anyhow::Result<()> {
    // some canister ID and subnet ID for testing -- they need to be valid principals, but don't need to exist
    // as OPTIONS requests are directly replied to by the IC gateway and all other requests will just return a 400
    // but the IC gateway still sets the CORS headers.
    let canister_id =
        Principal::from_text("rwlgt-iiaaa-aaaaa-aaaaa-cai").expect("failed to parse canister id");
    let subnet_id =
        Principal::from_text("tdb26-jop6k-aogll-7ltgs-eruif-6kk7m-qpktf-gdiqx-mxtrf-vb5e6-eqe")
            .expect("failed to parse subnet id");

    info!("making various HTTP requests and checking the CORS headers ...");

    // Create a URL and HTTP client to make requests to the IC gateway
    let url = Url::parse(&format!(
        "http://{}:{}",
        env.ic_gateway_domain,
        env.ic_gateway_addr.port(),
    ))
    .context(anyhow!("failed to parse url"))?;

    let http_client = Client::builder()
        .resolve(&env.ic_gateway_domain, env.ic_gateway_addr)
        .build()
        .context("failed to build http client")?;

    // Execute all HTTP requests and verify responses
    let rt = Runtime::new().context("failed to start tokio runtime")?;
    for (test_case_name, request, expected_response) in
        test_cases(url, canister_id, subnet_id).iter()
    {
        let msg = format!("verifying HTTP response for '{test_case_name}'");

        rt.block_on(retry_async(
            msg,
            REQUEST_RETRY_TIMEOUT,
            REQUEST_RETRY_INTERVAL,
            || async {
                let response = http_client
                    .execute(request.try_clone().unwrap())
                    .await
                    .context("failed to execute request")?;

                check_response(response, &expected_response).await
            },
        ))
        .context(anyhow!("failed to verify HTTP response"))?;
    }

    Ok(())
}

fn test_cases(
    url: Url,
    canister_id: Principal,
    subnet_id: Principal,
) -> Vec<(String, Request, ExpectedResponse)> {
    // Expected CORS headers for OPTIONS requests
    let headers_common_opts = HashMap::from([
        ("Access-Control-Allow-Origin".to_string(), "*".to_string()),
        (
            "Access-Control-Allow-Headers".to_string(),
            "DNT,User-Agent,X-Requested-With,If-None-Match,If-Modified-Since,Cache-Control,Content-Type,Range,Cookie,X-Ic-Canister-Id".to_string(),
        ),
        ("Access-Control-Max-Age".to_string(), "7200".to_string()),
    ]);

    // Expected CORS headers for GET/POST requests
    let headers_common = HashMap::from([
        ("Access-Control-Allow-Origin".to_string(), "*".to_string()),
        (
            "Access-Control-Expose-Headers".to_string(),
            "Accept-Ranges,Content-Length,Content-Range,X-Request-Id,X-Ic-Canister-Id".to_string(),
        ),
    ]);

    let test_cases = [
        (
            "status OPTIONS request".to_string(),
            Request::new(Method::OPTIONS, url.join("/api/v2/status").unwrap()),
            ExpectedResponse::new(
                Some(StatusCode::OK),
                None,
                Some(headers_common_opts.clone()),
            )
            .with_header("Access-Control-Allow-Methods", "HEAD, GET"),
        ),
        (
            "status GET request".to_string(),
            Request::new(Method::GET, url.join("/api/v2/status").unwrap()),
            ExpectedResponse::new(Some(StatusCode::OK), None, Some(headers_common.clone())),
        ),
        (
            "query OPTIONS request".to_string(),
            Request::new(
                Method::OPTIONS,
                url.join(&format!("/api/v2/canister/{canister_id}/query"))
                    .unwrap(),
            ),
            ExpectedResponse::new(
                Some(StatusCode::OK),
                None,
                Some(headers_common_opts.clone()),
            )
            .with_header("Access-Control-Allow-Methods", "POST"),
        ),
        (
            "query POST request".to_string(),
            Request::new(
                Method::POST,
                url.join(&format!("/api/v2/canister/{canister_id}/query"))
                    .unwrap(),
            ),
            ExpectedResponse::new(None, None, Some(headers_common.clone())),
        ),
        (
            "call OPTIONS request".to_string(),
            Request::new(
                Method::OPTIONS,
                url.join(&format!("/api/v2/canister/{canister_id}/call"))
                    .unwrap(),
            ),
            ExpectedResponse::new(
                Some(StatusCode::OK),
                None,
                Some(headers_common_opts.clone()),
            )
            .with_header("Access-Control-Allow-Methods", "POST"),
        ),
        (
            "call POST request".to_string(),
            Request::new(
                Method::POST,
                url.join(&format!("/api/v2/canister/{canister_id}/call"))
                    .unwrap(),
            ),
            ExpectedResponse::new(None, None, Some(headers_common.clone())),
        ),
        (
            "sync_call OPTIONS request".to_string(),
            Request::new(
                Method::OPTIONS,
                url.join(&format!("/api/v3/canister/{canister_id}/call"))
                    .unwrap(),
            ),
            ExpectedResponse::new(
                Some(StatusCode::OK),
                None,
                Some(headers_common_opts.clone()),
            )
            .with_header("Access-Control-Allow-Methods", "POST"),
        ),
        (
            "sync_call POST request".to_string(),
            Request::new(
                Method::POST,
                url.join(&format!("/api/v3/canister/{canister_id}/call"))
                    .unwrap(),
            ),
            ExpectedResponse::new(None, None, Some(headers_common.clone())),
        ),
        (
            "canister read_state OPTIONS request".to_string(),
            Request::new(
                Method::OPTIONS,
                url.join(&format!("/api/v2/canister/{canister_id}/read_state"))
                    .unwrap(),
            ),
            ExpectedResponse::new(
                Some(StatusCode::OK),
                None,
                Some(headers_common_opts.clone()),
            )
            .with_header("Access-Control-Allow-Methods", "POST"),
        ),
        (
            "canister read_state POST request".to_string(),
            Request::new(
                Method::POST,
                url.join(&format!("/api/v2/canister/{canister_id}/read_state"))
                    .unwrap(),
            ),
            ExpectedResponse::new(None, None, Some(headers_common.clone())),
        ),
        (
            "subnet read_state OPTIONS request".to_string(),
            Request::new(
                Method::OPTIONS,
                url.join(&format!("/api/v2/subnet/{subnet_id}/read_state"))
                    .unwrap(),
            ),
            ExpectedResponse::new(
                Some(StatusCode::OK),
                None,
                Some(headers_common_opts.clone()),
            )
            .with_header("Access-Control-Allow-Methods", "POST"),
        ),
        (
            "subnet read_state POST request".to_string(),
            Request::new(
                Method::POST,
                url.join(&format!("/api/v2/subnet/{subnet_id}/read_state"))
                    .unwrap(),
            ),
            ExpectedResponse::new(None, None, Some(headers_common.clone())),
        ),
    ];

    test_cases.into()
}
