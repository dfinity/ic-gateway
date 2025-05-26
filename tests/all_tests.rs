mod helpers;
mod integration_tests;

use helpers::TestEnv;
use integration_tests::{
    api_proxy_test::proxy_api_calls_test,
    content_type_headers_test::content_type_headers_test,
    cors_headers_test::cors_headers_test,
    denylist_test::denylist_test,
    http_gateway_test::{basic_http_gateway_test, large_assets_http_gateway_test},
};

const IC_GATEWAY_DOMAIN: &str = "ic0.app";
const IC_GATEWAY_ADDR: &str = "127.0.0.1:18080";
const IC_BOUNDARY_PORT: &str = "18081";

#[tokio::test]
async fn all_intergration_tests() -> anyhow::Result<()> {
    let env = TestEnv::new(IC_GATEWAY_ADDR, IC_GATEWAY_DOMAIN, IC_BOUNDARY_PORT).await;

    // run all integration tests sequentially
    basic_http_gateway_test(&env).await?;
    content_type_headers_test(&env).await?;
    cors_headers_test(&env).await?;
    proxy_api_calls_test(&env).await?;
    large_assets_http_gateway_test(&env).await?;
    denylist_test(&env).await?;

    Ok(())
}
