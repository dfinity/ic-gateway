use crate::helpers::{COUNTER_WAT, TestEnv, create_canister_with_cycles};
use anyhow::{Context, anyhow, bail};
use candid::{Encode, Principal};
use hex::encode;
use ic_agent::Agent;
use reqwest::Client;
use tokio::runtime::Runtime;
use tracing::info;
use url::Url;

const CANISTER_INITIAL_CYCLES: u128 = 100_000_000_000_000;

// Test scenario:
// - install a counter canister
// - create an agent to interact with the canister
// - make API calls (status, query, call, read_state) to the canister

pub fn proxy_api_calls_test(env: &TestEnv) -> anyhow::Result<()> {
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

    let rt = Runtime::new().context("failed to start tokio runtime")?;
    rt.block_on(async {
        info!("api/v2/status - implicit status to fetch the root key");
        agent.fetch_root_key().await?;

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
    })
    .context(anyhow!("failed to proxy API calls"))?;

    Ok(())
}
