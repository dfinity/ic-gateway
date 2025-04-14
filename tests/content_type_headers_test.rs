use crate::helpers::verify_status_call_headers;
use helpers::{init_logging, retry_async, start_ic_gateway, stop_ic_gateway};
use pocket_ic::PocketIcBuilder;
use reqwest::Client;
use std::{net::SocketAddr, str::FromStr, time::Duration};
use tokio::runtime::Runtime;
use tracing::info;
mod helpers;

const IC_GATEWAY_DOMAIN: &str = "ic0.app";
const IC_GATEWAY_ADDR: &str = "127.0.0.1:8080";
const STATUS_CALL_RETRY_TIMEOUT: Duration = Duration::from_secs(50);
const STATUS_CALL_RETRY_INTERVAL: Duration = Duration::from_secs(10);

// Test scenario:
// - start pocket-ic server with one nns subnet
// - start ic-gateway service connected to the pocket-ic endpoint
// - make an HTTP GET request to http://ic0.app/api/v2/status
// - verify necessary headers are present in response: [content-type, x-content-type-options, x-frame-options]

#[test]
fn content_type_headers_test() {
    init_logging();

    info!("pocket-ic server starting ...");
    let pic = PocketIcBuilder::new().with_nns_subnet().build();
    info!("pocket-ic server started");

    let ic_gateway_addr = SocketAddr::from_str(IC_GATEWAY_ADDR).expect("failed to parse address");
    let ic_url = format!("{}instances/{}/", pic.get_server_url(), pic.instance_id());
    let process = start_ic_gateway(IC_GATEWAY_ADDR, IC_GATEWAY_DOMAIN, &ic_url);

    let http_client = Client::builder()
        .resolve(IC_GATEWAY_DOMAIN, ic_gateway_addr)
        .build()
        .expect("failed to build http client");

    let rt = Runtime::new().expect("failed to start tokio runtime");

    rt.block_on(retry_async(
        "verifying correct headers in /api/v2/status response",
        STATUS_CALL_RETRY_TIMEOUT,
        STATUS_CALL_RETRY_INTERVAL,
        || verify_status_call_headers(&http_client, "http://ic0.app/api/v2/status"),
    ))
    .expect("failed to verify correct headers");

    stop_ic_gateway(process);
}
