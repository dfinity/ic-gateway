use std::{collections::HashMap, time::Duration};

use crate::helpers::{ExpectedResponse, TestEnv, check_response, retry_async};
use anyhow::{Context, anyhow};
use candid::Principal;
use http::{Method, StatusCode};
use reqwest::{Client, Request};
use tokio::runtime::Runtime;
use tracing::info;
use url::Url;

const REQUEST_RETRY_TIMEOUT: Duration = Duration::from_secs(50);
const REQUEST_RETRY_INTERVAL: Duration = Duration::from_secs(10);

// Test scenario:
// - install counter canister
// - make various HTTP requests GET/POST/OPTIONS and verify correct status codes and headers of the responses

pub fn cors_headers_test(env: &TestEnv) -> anyhow::Result<()> {
    info!("counter canister installation start ...");
    let canister_id =
        Principal::from_text("rwlgt-iiaaa-aaaaa-aaaaa-cai").expect("failed to parse canister id");
    let subnet_id =
        Principal::from_text("tdb26-jop6k-aogll-7ltgs-eruif-6kk7m-qpktf-gdiqx-mxtrf-vb5e6-eqe")
            .expect("failed to parse subnet id");

    info!("testing various HTTP requests ...");
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

    let rt = Runtime::new().context("failed to start tokio runtime")?;

    // Execute all HTTP requests and verify responses
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
    let headers_common_opts = HashMap::from([
        ("Access-Control-Allow-Origin".to_string(), "*".to_string()),
        (
            "Access-Control-Allow-Headers".to_string(),
            "DNT,User-Agent,X-Requested-With,If-None-Match,If-Modified-Since,Cache-Control,Content-Type,Range,Cookie,X-Ic-Canister-Id".to_string(),
        ),
        ("Access-Control-Max-Age".to_string(), "7200".to_string()),
    ]);

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
            ExpectedResponse::new(
                Some(StatusCode::BAD_REQUEST),
                None,
                Some(headers_common.clone()),
            ),
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
            ExpectedResponse::new(
                Some(StatusCode::BAD_REQUEST),
                None,
                Some(headers_common.clone()),
            ),
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
            ExpectedResponse::new(
                Some(StatusCode::BAD_REQUEST),
                None,
                Some(headers_common.clone()),
            ),
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
            ExpectedResponse::new(
                Some(StatusCode::BAD_REQUEST),
                None,
                Some(headers_common.clone()),
            ),
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
            ExpectedResponse::new(
                Some(StatusCode::BAD_REQUEST),
                None,
                Some(headers_common.clone()),
            ),
        ),
    ];

    test_cases.into()
}
