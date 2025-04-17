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

    info!("testing HTTP request ...");
    let url = Url::parse(&format!(
        "http://{}:{}",
        env.ic_gateway_domain,
        env.ic_gateway_addr.port(),
    ))
    .context(anyhow!("failed to parse url"))?;

    let http_client = Client::builder()
        .resolve(&env.ic_gateway_domain, env.ic_gateway_addr)
        .build()
        .map_err(|e| anyhow!("failed to build http client: {e}"))?;

    let rt = Runtime::new().map_err(|e| anyhow!("failed to start tokio runtime: {e}"))?;

    // Execute all test HTTP calls
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
    let headers_common_opts: HashMap<String, String> = vec![
        ("Access-Control-Allow-Origin", "*"),
        (
            "Access-Control-Allow-Headers",
            "DNT,User-Agent,X-Requested-With,If-None-Match,If-Modified-Since,Cache-Control,Content-Type,Range,Cookie,X-Ic-Canister-Id",
        ),
        ("Access-Control-Max-Age", "7200"),
    ]
    .iter()
    .map(|(k, v)| (k.to_string(), v.to_string()))
    .collect();

    let headers_common: HashMap<String, String> = vec![
        ("Access-Control-Allow-Origin", "*"),
        (
            "Access-Control-Expose-Headers",
            "Accept-Ranges,Content-Length,Content-Range,X-Request-Id,X-Ic-Canister-Id",
        ),
    ]
    .iter()
    .map(|(k, v)| (k.to_string(), v.to_string()))
    .collect();

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
