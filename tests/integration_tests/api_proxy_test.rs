use crate::helpers::{COUNTER_WAT, TestEnv, install_canister};
use anyhow::{Context, anyhow, bail};
use candid::Principal;
use ic_bn_lib::ic_agent::Agent;
use reqwest::Client;
use tracing::info;
use url::Url;

// Test scenario:
// - install a counter canister
// - create an agent to interact with the canister
// - make API calls (status, query, call, read_state) to the canister

pub async fn proxy_api_calls_test(env: &TestEnv) -> anyhow::Result<()> {
    info!("install counter canister ...");
    let canister_id = install_canister(
        &env.pic,
        Principal::anonymous(),
        None,
        wat::parse_str(COUNTER_WAT).unwrap(),
    )
    .await;

    info!("create agent to interact with the canister ...");
    let url = Url::parse(&format!(
        "http://{}:{}",
        env.ic_gateway_domain,
        env.ic_gateway_addr.port(),
    ))
    .context(anyhow!("failed to parse URL"))?;

    let http_client = Client::builder()
        .resolve(&env.ic_gateway_domain, env.ic_gateway_addr)
        .build()
        .context("failed to build http client")?;

    let agent = Agent::builder()
        .with_url(url)
        .with_http_client(http_client)
        .build()?;

    info!("test proxying of various API calls ...");
    info!("api/v2/status - status call");
    let status = agent.status().await?;
    assert_eq!(status.replica_health_status, Some("healthy".into()));

    // Set the actual root key
    agent.set_root_key(env.root_key.clone());

    info!("api/v2/query - query counter");
    let out = agent.query(&canister_id, "read").call().await?;
    if !out.eq(&[0, 0, 0, 0]) {
        bail!("failed: got {:?}, expected {:?}", out, &[0, 0, 0, 0],)
    }

    info!("api/v3/call - increase counter");
    agent.update(&canister_id, "write").call_and_wait().await?;
    let out = agent.query(&canister_id, "read").call().await?;
    if !out.eq(&[1, 0, 0, 0]) {
        bail!("failed: got {:?}, expected {:?}", out, &[1, 0, 0, 0],)
    }

    info!("api/v2/read_state - fetch canister module hash");
    let _ = agent
        .read_state_canister_info(canister_id, "module_hash")
        .await?;

    Ok(())
}
