use candid::{Encode, Principal};
use helpers::{
    create_canister_with_cycles, get_asset_canister_wasm, init_logging, retry_async,
    start_ic_gateway, stop_ic_gateway, upload_asset_to_asset_canister, verify_canister_asset,
};
use hex::encode;
use pocket_ic::PocketIcBuilder;
use reqwest::Client;
use std::{net::SocketAddr, str::FromStr, time::Duration};
use tokio::runtime::Runtime;
use tracing::info;
mod helpers;

const IC_GATEWAY_DOMAIN: &str = "gateway.icp";
const IC_GATEWAY_ADDR: &str = "127.0.0.1:8080";
const CANISTER_INITIAL_CYCLES: u128 = 100_000_000_000_000;
const FETCH_ASSET_RETRY_TIMEOUT: Duration = Duration::from_secs(50);
const FETCH_ASSET_RETRY_INTERVAL: Duration = Duration::from_secs(10);

// Test scenario:
// - start pocket-ic server with one nns subnet
// - start ic-gateway service connected to the pocket-ic endpoint
// - deploy asset canister via pocket-ic interface
// - upload some sample asset to the canister
// - retrieve asset via HTTP client through ic-gateway endpoint
// - verify asset integrity

#[test]
fn asset_canister_test() {
    init_logging();

    info!("pocket-ic server starting ...");
    let pic = PocketIcBuilder::new().with_nns_subnet().build();
    info!("pocket-ic server started");

    let ic_gateway_addr = SocketAddr::from_str(IC_GATEWAY_ADDR).expect("failed to parse address");
    let ic_url = format!("{}instances/{}/", pic.get_server_url(), pic.instance_id());
    let process = start_ic_gateway(IC_GATEWAY_ADDR, IC_GATEWAY_DOMAIN, &ic_url);

    info!("asset canister installation start ...");
    let asset_canister_id =
        create_canister_with_cycles(&pic, Principal::anonymous(), CANISTER_INITIAL_CYCLES);
    pic.install_canister(
        asset_canister_id,
        get_asset_canister_wasm(),
        Encode!(&()).unwrap(),
        None,
    );
    let module_hash = pic
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
        &pic,
        asset_bytes.to_vec(),
        10,
    );
    info!("asset with name={asset_name} is uploaded to asset canister");

    info!("downloading asset from canister via ic-gateway service");
    let asset_domain = format!("{asset_canister_id}.raw.{IC_GATEWAY_DOMAIN}");
    let asset_url = format!(
        "http://{asset_domain}:{}{asset_name}",
        ic_gateway_addr.port()
    );
    let http_client = Client::builder()
        .resolve(asset_domain.as_str(), ic_gateway_addr)
        .build()
        .expect("failed to build http client");
    let rt = Runtime::new().expect("failed to start tokio runtime");
    rt.block_on(retry_async(
        "downloading and verifying stored asset",
        FETCH_ASSET_RETRY_TIMEOUT,
        FETCH_ASSET_RETRY_INTERVAL,
        || verify_canister_asset(&http_client, &asset_url, &asset_bytes),
    ))
    .expect("failed to verify stored asset");

    stop_ic_gateway(process);
}
