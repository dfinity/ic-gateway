use crate::helpers::{
    DENYLISTED_CANISTER_ID, ExpectedResponse, RETRY_INTERVAL, RETRY_TIMEOUT, TestEnv,
    check_response, get_asset_canister_wasm, install_canister, retry_async,
};
use anyhow::{Context, anyhow};
use candid::{Encode, Principal};
use http::{Method, StatusCode};
use ic_agent::Agent;
use ic_gateway::principal;
use reqwest::{Client, Request};
use tracing::info;
use url::Url;

// Test scenario:
// - install a counter canister
// - create an agent to interact with the canister
// - make API calls (status, query, call, read_state) to the canister

pub async fn denylist_test(env: &TestEnv) -> anyhow::Result<()> {
    info!("install denylisted asset canister ...");
    let denylisted_canister_id = install_canister(
        &env.pic,
        Principal::anonymous(),
        Some(principal!(DENYLISTED_CANISTER_ID)),
        get_asset_canister_wasm(),
    )
    .await;

    info!("setup HTTP client ...");
    let certified_domain = format!("{}.{}", denylisted_canister_id, env.ic_gateway_domain);
    let api_domain = format!("{}", env.ic_gateway_domain);

    let http_client = Client::builder()
        .resolve(certified_domain.as_str(), env.ic_gateway_addr)
        .resolve(api_domain.as_str(), env.ic_gateway_addr)
        .build()
        .context(anyhow!("failed to build http client"))?;

    let request = {
        let asset_url = Url::parse(&format!(
            "http://{}:{}/",
            certified_domain,
            env.ic_gateway_addr.port(),
        ))
        .expect("failed to parse url");
        Request::new(Method::GET, asset_url)
    };

    retry_async(
        format!("verifying that canister is blocked at the HTTP gateway level"),
        RETRY_TIMEOUT,
        RETRY_INTERVAL,
        || async {
            let response = http_client
                .execute(request.try_clone().unwrap())
                .await
                .context("failed to execute request")?;

            check_response(
                response,
                &ExpectedResponse {
                    status: Some(StatusCode::UNAVAILABLE_FOR_LEGAL_REASONS),
                    body: None,
                    headers: None,
                },
            )
            .await
        },
    )
    .await
    .context(anyhow!(
        "managed to fetch asset from canister, while it should be blocked"
    ))?;

    info!("create an agent to interact with the canister ...");
    let url = Url::parse(&format!(
        "http://{}:{}",
        api_domain,
        env.ic_gateway_addr.port(),
    ))
    .context(anyhow!("failed to parse URL"))?;

    let agent = Agent::builder()
        .with_url(url)
        .with_http_client(http_client)
        .build()?;
    agent.fetch_root_key().await?;

    info!("verify that API calls to the denylisted canister are NOT blocked");
    agent
        .query(&denylisted_canister_id, "api_version")
        .with_arg(Encode!(&()).unwrap())
        .call()
        .await?;

    Ok(())
}
