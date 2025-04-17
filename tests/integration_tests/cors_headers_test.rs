use std::{collections::HashMap, time::Duration};

use crate::{
    counter_canister::COUNTER_WAT,
    helpers::{
        ExpectedResponse, TestEnv, check_response, create_canister_with_cycles, retry_async,
    },
};
use anyhow::{Context, anyhow};
use candid::{Encode, Principal};
use hex::encode;
use http::{Method, StatusCode};
use reqwest::{Client, Request};
use tokio::runtime::Runtime;
use tracing::info;
use url::Url;

const CANISTER_INITIAL_CYCLES: u128 = 100_000_000_000_000;
const REQUEST_RETRY_TIMEOUT: Duration = Duration::from_secs(50);
const REQUEST_RETRY_INTERVAL: Duration = Duration::from_secs(10);

// Test scenario:
// - install counter canister
// - make various HTTP requests GET/POST/OPTIONS and verify correct status codes and headers of the responses

pub fn cors_headers_test(env: &TestEnv) -> anyhow::Result<()> {
    info!("counter canister installation start ...");
    let canister_id =
        create_canister_with_cycles(&env.pic, Principal::anonymous(), CANISTER_INITIAL_CYCLES);
    env.pic.install_canister(
        canister_id,
        wat::parse_str(COUNTER_WAT).unwrap(),
        Encode!(&()).unwrap(),
        None,
    );
    let module_hash = env
        .pic
        .canister_status(canister_id, None)
        .unwrap()
        .module_hash
        .unwrap();
    let hash_str = encode(module_hash);
    info!("counter canister with id={canister_id} installed, hash={hash_str}");

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
    for (idx, (request, expected_response)) in test_cases(url, canister_id).iter().enumerate() {
        let msg = format!("verifying HTTP response for test case {idx}");

        rt.block_on(retry_async(
            msg,
            REQUEST_RETRY_TIMEOUT,
            REQUEST_RETRY_INTERVAL,
            || {
                check_response(
                    &http_client,
                    request.try_clone().unwrap(),
                    &expected_response,
                )
            },
        ))
        .context(anyhow!("failed to verify HTTP response"))?;
    }

    Ok(())
}

fn test_cases(url: Url, canister_id: Principal) -> Vec<(Request, ExpectedResponse)> {
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
            Request::new(Method::OPTIONS, url.join("/api/v2/status").unwrap()),
            ExpectedResponse::new(
                Some(StatusCode::OK),
                None,
                Some(headers_common_opts.clone()),
            )
            .with_header("Access-Control-Allow-Methods", "HEAD, GET"),
        ),
        (
            Request::new(Method::GET, url.join("/api/v2/status").unwrap()),
            ExpectedResponse::new(Some(StatusCode::OK), None, Some(headers_common.clone())),
        ),
        //
        (
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
        //
        (
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
        //
        (
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
    ];

    test_cases.into()
}
