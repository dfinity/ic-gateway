use helpers::TestEnv;
use integration_tests::{
    api_proxy_test::proxy_api_calls_test,
    content_type_headers_test::content_type_headers_test,
    cors_headers_test::cors_headers_test,
    denylist_test::denylist_test,
    http_gateway_test::{basic_http_gateway_test, large_assets_http_gateway_test},
};

mod helpers;
mod integration_tests;

const IC_GATEWAY_DOMAIN: &str = "ic0.app";
const IC_GATEWAY_ADDR: &str = "127.0.0.1:8080";

#[tokio::test]
async fn all_intergration_tests() {
    let env = TestEnv::new(IC_GATEWAY_ADDR, IC_GATEWAY_DOMAIN).await;
    // run all integration tests sequentially
    basic_http_gateway_test(&env).await.unwrap();
    content_type_headers_test(&env).await.unwrap();
    cors_headers_test(&env).await.unwrap();
    proxy_api_calls_test(&env).await.unwrap();
    large_assets_http_gateway_test(&env).await.unwrap();
    denylist_test(&env).await.unwrap();
}
