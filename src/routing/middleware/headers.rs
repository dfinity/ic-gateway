#![allow(clippy::declare_interior_mutable_const)]

use axum::{extract::Request, middleware::Next, response::Response};
use bytes::Bytes;
use http::header::{HeaderName, HeaderValue, STRICT_TRANSPORT_SECURITY};

use crate::routing::CanisterId;

pub const X_IC_CANISTER_ID: HeaderName = HeaderName::from_static("x-ic-canister-id");
const HEADER_HSTS: HeaderValue = HeaderValue::from_static("max-age=31536000; includeSubDomains");

// Add various headers
pub async fn middleware(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;

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
