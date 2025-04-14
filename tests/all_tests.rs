use helpers::TestEnv;
use integration_tests::{
    asset_canister_test::asset_canister_test, content_type_headers_test::content_type_headers_test,
};

const IC_GATEWAY_DOMAIN: &str = "ic0.app";
const IC_GATEWAY_ADDR: &str = "127.0.0.1:8080";

mod helpers;
mod integration_tests;

#[test]
fn all_intergration_tests() {
    let env = TestEnv::new(IC_GATEWAY_ADDR, IC_GATEWAY_DOMAIN);
    // run all tests
    asset_canister_test(&env).unwrap();
    content_type_headers_test(&env).unwrap();
}
