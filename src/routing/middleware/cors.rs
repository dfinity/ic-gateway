#![allow(clippy::declare_interior_mutable_const)]

use std::time::Duration;

use http::{
    header::{
        ACCEPT_RANGES, CACHE_CONTROL, CONTENT_LENGTH, CONTENT_RANGE, CONTENT_TYPE, COOKIE, DNT,
        IF_MODIFIED_SINCE, IF_NONE_MATCH, RANGE, USER_AGENT,
    },
    Method,
};
use ic_bn_lib::http::headers::{X_IC_CANISTER_ID, X_REQUESTED_WITH, X_REQUEST_ID};
use tower_http::cors::{Any, CorsLayer};

const MINUTE: Duration = Duration::from_secs(60);

/*
add_header "Access-Control-Allow-Origin" "*" always;
add_header "Access-Control-Allow-Methods" "$cors_allow_methods" always;
add_header "Access-Control-Allow-Headers" "DNT,User-Agent,X-Requested-With,If-None-Match,If-Modified-Since,Cache-Control,Content-Type,Range,Cookie,X-Ic-Canister-Id" always;
add_header "Access-Control-Expose-Headers" "Accept-Ranges,Content-Length,Content-Range,X-Request-Id,X-Ic-Canister-Id" always;
add_header "Access-Control-Max-Age" "600" always;
*/

pub fn layer(methods: &[Method]) -> CorsLayer {
    CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(methods.to_vec())
        .expose_headers([
            ACCEPT_RANGES,
            CONTENT_LENGTH,
            CONTENT_RANGE,
            X_REQUEST_ID,
            X_IC_CANISTER_ID,
        ])
        .allow_headers([
            USER_AGENT,
            DNT,
            IF_NONE_MATCH,
            IF_MODIFIED_SINCE,
            CACHE_CONTROL,
            CONTENT_TYPE,
            RANGE,
            COOKIE,
            X_REQUESTED_WITH,
            X_IC_CANISTER_ID,
        ])
        .max_age(10 * MINUTE)
}
