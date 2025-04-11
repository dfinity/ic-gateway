use candid::{Encode, Principal};
use helpers::{
    create_canister_with_cycles, get_asset_canister_wasm, get_binary_path, retry_async,
    upload_asset_to_asset_canister, verify_canister_asset,
};
use hex::encode;
use pocket_ic::PocketIcBuilder;
use reqwest::Client;
use std::{net::SocketAddr, process::Command, str::FromStr, time::Duration};
use tokio::runtime::Runtime;
use tracing::info;
mod helpers;

const IC_GATEWAY_BIN: &str = "ic-gateway";
const IC_GATEWAY_DOMAIN: &str = "gateway.icp";
const IC_GATEWAY_ADDR: &str = "127.0.0.1:8080";
const CANISTER_INITIAL_CYCLES: u128 = 100_000_000_000_000;
const FETCH_ASSET_RETRY_TIMEOUT: Duration = Duration::from_secs(50);
const FETCH_ASSET_RETRY_INTERVAL: Duration = Duration::from_secs(10);

fn init_logging() {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_test_writer()
        .try_init()
        .expect("failed to init logger")
}

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

    info!("ic-gateway service starting ...");
    let ic_gateway_addr = SocketAddr::from_str(IC_GATEWAY_ADDR).expect("failed to parse address");
    let ic_url = format!("{}instances/{}/", pic.get_server_url(), pic.instance_id());
    let mut child = Command::new(get_binary_path(IC_GATEWAY_BIN))
        .arg("--listen-plain")
        .arg(IC_GATEWAY_ADDR)
        .arg("--ic-url")
        .arg(ic_url)
        .arg("--domain")
        .arg(IC_GATEWAY_DOMAIN)
        .arg("--listen-insecure-serve-http-only")
        .spawn()
        .expect("failed to start ic-gateway service");
    info!("ic-gateway service started");

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

    info!("gracefulyy terminating ic-gateway process");
    child.kill().expect("failed to kill process");
    let exit_status = child.wait().expect("failed to wait on child process");
    info!("ic-gateway process exited with: {:?}", exit_status);
}
