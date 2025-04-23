use crate::helpers::{
    ExpectedResponse, TestEnv, check_response, get_asset_canister_wasm, install_canister,
    retry_async, upload_asset_to_asset_canister,
};
use anyhow::{Context, anyhow};
use candid::Principal;
use http::{Method, StatusCode};
use reqwest::{Client, Request};
use std::time::Duration;
use tokio::runtime::Runtime;
use tracing::info;
use url::Url;

const FETCH_ASSET_RETRY_TIMEOUT: Duration = Duration::from_secs(20);
const FETCH_ASSET_RETRY_INTERVAL: Duration = Duration::from_secs(2);

// Test scenario:
// - deploy asset canister via pocket-ic interface
// - upload some sample asset to the canister
// - retrieve asset via HTTP client through ic-gateway endpoint
// - verify asset integrity

pub fn asset_canister_test(env: &TestEnv) -> anyhow::Result<()> {
    info!("install asset canister ...");
    let asset_canister_id =
        install_canister(&env.pic, Principal::anonymous(), get_asset_canister_wasm());

    info!("upload an asset ...");
    let asset_name = "/funky_asset".to_string();
    let asset_bytes = b"the quick brown fox jumps over the lazy dog".repeat(20);
    upload_asset_to_asset_canister(
        &env.pic,
        asset_canister_id,
        asset_name.clone(),
        asset_bytes.to_vec(),
        "text/plain".to_string(),
        "identity".to_string(),
        None,
    );

    info!("download the asset via ic-gateway ...");
    let asset_domain = format!("{asset_canister_id}.{}", env.ic_gateway_domain);

    let http_client = Client::builder()
        .resolve(asset_domain.as_str(), env.ic_gateway_addr)
        .build()
        .context(anyhow!("failed to build http client"))?;

    let request = {
        let asset_url = Url::parse(&format!(
            "http://{asset_domain}:{}{asset_name}",
            env.ic_gateway_addr.port()
        ))
        .expect("failed to parse url");
        Request::new(Method::GET, asset_url)
    };
    let expected_response = ExpectedResponse::new(Some(StatusCode::OK), Some(asset_bytes), None);

    let rt = Runtime::new().context(anyhow!("failed to start tokio runtime"))?;
    rt.block_on(retry_async(
        "downloading and verifying stored asset",
        FETCH_ASSET_RETRY_TIMEOUT,
        FETCH_ASSET_RETRY_INTERVAL,
        || async {
            let response = http_client
                .execute(request.try_clone().unwrap())
                .await
                .context("failed to execute request")?;

            check_response(response, &expected_response).await
        },
    ))
    .context(anyhow!("failed to verify stored asset"))?;

    Ok(())
}
