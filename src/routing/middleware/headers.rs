use std::sync::Arc;

use axum::{extract::Request, middleware::Next, response::Response};
use bytes::Bytes;
use http::header::{HeaderName, HeaderValue};

use crate::routing::RequestCtx;

#[allow(clippy::declare_interior_mutable_const)]
const HEADER_CANISTER_ID: HeaderName = HeaderName::from_static("x-ic-canister-id");

// Add various headers
pub async fn middleware(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;

    // Insert canister id into response if it was inferred
    if let Some(v) = response.extensions().get::<Arc<RequestCtx>>().cloned() {
        response.headers_mut().insert(
            HEADER_CANISTER_ID,
            HeaderValue::from_maybe_shared(Bytes::from(v.canister.id.to_string())).unwrap(),
        );
    }

    response
}
