use axum::{extract::Request, middleware::Next, response::Response};
use bytes::Bytes;
use http::header::{HeaderName, HeaderValue, STRICT_TRANSPORT_SECURITY};
use ic_bn_lib::http::headers::{
    HSTS_1YEAR, X_IC_CACHE_BYPASS_REASON, X_IC_CACHE_STATUS, X_IC_CANISTER_ID,
    X_IC_CANISTER_ID_CBOR, X_IC_COUNTRY_CODE, X_IC_ERROR_CAUSE, X_IC_METHOD_NAME, X_IC_NODE_ID,
    X_IC_REQUEST_TYPE, X_IC_RETRIES, X_IC_SENDER, X_IC_SUBNET_ID, X_IC_SUBNET_TYPE,
};

use crate::routing::CanisterId;

/// Service headers to remove from the `ic-boundary` response
const HEADERS_REMOVE: [HeaderName; 12] = [
    X_IC_CACHE_BYPASS_REASON,
    X_IC_CACHE_STATUS,
    X_IC_CANISTER_ID_CBOR,
    X_IC_ERROR_CAUSE,
    X_IC_METHOD_NAME,
    X_IC_NODE_ID,
    X_IC_REQUEST_TYPE,
    X_IC_RETRIES,
    X_IC_SENDER,
    X_IC_SUBNET_ID,
    X_IC_SUBNET_TYPE,
    X_IC_COUNTRY_CODE,
];

/// Add various headers to the response
pub async fn middleware(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;

    // Remove headers that were added by ic-boundary
    for h in HEADERS_REMOVE {
        response.headers_mut().remove(h);
    }

    // Insert canister id into response if it was resolved
    if let Some(v) = response.extensions().get::<CanisterId>().copied() {
        response.headers_mut().insert(
            X_IC_CANISTER_ID,
            HeaderValue::from_maybe_shared(Bytes::from(v.to_string())).unwrap(),
        );
    }

    // HSTS
    // TODO make age configurable?
    response
        .headers_mut()
        .insert(STRICT_TRANSPORT_SECURITY, HSTS_1YEAR);

    response
}
