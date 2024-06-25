#![allow(clippy::declare_interior_mutable_const)]
#![allow(clippy::borrow_interior_mutable_const)]

use axum::{extract::Request, middleware::Next, response::Response};
use bytes::Bytes;
use http::header::{HeaderName, HeaderValue, STRICT_TRANSPORT_SECURITY};

use super::X_IC_CANISTER_ID;
use crate::routing::{ic::*, CanisterId};

const HEADER_HSTS: HeaderValue = HeaderValue::from_static("max-age=31536000; includeSubDomains");

const HEADERS_REMOVE: [HeaderName; 13] = [
    HEADER_IC_CACHE_BYPASS_REASON,
    HEADER_IC_CACHE_STATUS,
    HEADER_IC_CANISTER_ID,
    HEADER_IC_CANISTER_ID_CBOR,
    HEADER_IC_ERROR_CAUSE,
    HEADER_IC_METHOD_NAME,
    HEADER_IC_NODE_ID,
    HEADER_IC_REQUEST_TYPE,
    HEADER_IC_RETRIES,
    HEADER_IC_SENDER,
    HEADER_IC_SUBNET_ID,
    HEADER_IC_SUBNET_TYPE,
    HEADER_IC_COUNTRY_CODE,
];

// Add various headers
pub async fn middleware(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;

    // Remove headers that were proxied from ic-boundary
    for h in HEADERS_REMOVE {
        response.headers_mut().remove(h);
    }

    // Insert canister id into response if it was resolved
    if let Some(v) = response.extensions().get::<CanisterId>().cloned() {
        response.headers_mut().insert(
            X_IC_CANISTER_ID,
            HeaderValue::from_maybe_shared(Bytes::from(v.0.to_string())).unwrap(),
        );
    }

    // HSTS
    // TODO make age configurable?
    response
        .headers_mut()
        .insert(STRICT_TRANSPORT_SECURITY, HEADER_HSTS);

    response
}
