use crate::helpers::{
    ExpectedResponse, TestEnv, check_response, create_canister_with_cycles,
    get_asset_canister_wasm, retry_async, upload_asset_to_asset_canister,
};
use anyhow::{Context, anyhow};
use candid::{Encode, Principal};
use hex::encode;
use http::{Method, StatusCode};
use reqwest::{Client, Request};
use std::time::Duration;
use tokio::runtime::Runtime;
use tracing::info;
use url::Url;

const CANISTER_INITIAL_CYCLES: u128 = 100_000_000_000_000;
const FETCH_ASSET_RETRY_TIMEOUT: Duration = Duration::from_secs(50);
const FETCH_ASSET_RETRY_INTERVAL: Duration = Duration::from_secs(10);

// Test scenario:
// - deploy asset canister via pocket-ic interface
// - upload some sample asset to the canister
// - retrieve asset via HTTP client through ic-gateway endpoint
// - verify asset integrity

pub fn asset_canister_test(env: &TestEnv) -> anyhow::Result<()> {
    info!("asset canister installation start ...");
    let asset_canister_id =
        create_canister_with_cycles(&env.pic, Principal::anonymous(), CANISTER_INITIAL_CYCLES);
    env.pic.install_canister(
        asset_canister_id,
        get_asset_canister_wasm(),
        Encode!(&()).unwrap(),
        None,
    );
    let module_hash = env
        .pic
        .canister_status(asset_canister_id, None)
        .unwrap()
        .module_hash
        .unwrap();
    let hash_str = encode(module_hash);
    info!("asset canister with id={asset_canister_id} installed, hash={hash_str}");

    info!("uploading an asset to the canister in chunks ...");
    let asset_name = "/funky_asset".to_string();
    let asset_bytes = b"the quick brown fox jumps over the lazy dog".repeat(20);
    upload_asset_to_asset_canister(
        asset_canister_id,
        asset_name.clone(),
        &env.pic,
        asset_bytes.to_vec(),
        10,
    );
    info!("asset with name={asset_name} is uploaded to asset canister");

    info!("downloading asset from canister via ic-gateway service");

    let asset_domain = format!("{asset_canister_id}.raw.{}", env.ic_gateway_domain);

    let http_client = Client::builder()
        .resolve(asset_domain.as_str(), env.ic_gateway_addr)
        .build()
        .context(anyhow!("failed to build http client"))?;

    let rt = Runtime::new().context(anyhow!("failed to start tokio runtime"))?;

    let request = {
        let asset_url = Url::parse(&format!(
            "http://{asset_domain}:{}{asset_name}",
            env.ic_gateway_addr.port()
        ))
        .expect("failed to parse url");
        Request::new(Method::GET, asset_url)
    };
    let expected_response = ExpectedResponse::new(Some(StatusCode::OK), Some(asset_bytes), None);

    rt.block_on(retry_async(
        "downloading and verifying stored asset",
        FETCH_ASSET_RETRY_TIMEOUT,
        FETCH_ASSET_RETRY_INTERVAL,
        || {
            check_response(
                &http_client,
                request.try_clone().unwrap(),
                &expected_response,
            )
        },
    ))
    .context(anyhow!("failed to verify stored asset"))?;

    Ok(())
}
