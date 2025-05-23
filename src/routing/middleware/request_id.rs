use std::ops::Deref;

use axum::{extract::Request, middleware::Next, response::Response};
use bytes::Bytes;
use http::header::HeaderValue;
use ic_bn_lib::http::headers::X_REQUEST_ID;
use uuid::Uuid;

#[derive(Clone, Copy)]
pub struct RequestId(pub Uuid);

impl Deref for RequestId {
    type Target = Uuid;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

// Generate & insert request UUID into extensions and headers
pub async fn middleware(mut request: Request, next: Next) -> Response {
    let request_id = RequestId(Uuid::now_v7());
    let hdr = request_id.to_string();
    let hdr = HeaderValue::from_maybe_shared(Bytes::from(hdr)).unwrap();

    request.extensions_mut().insert(request_id);
    request.headers_mut().insert(X_REQUEST_ID, hdr.clone());

    let mut response = next.run(request).await;
    response.extensions_mut().insert(request_id);
    response.headers_mut().insert(X_REQUEST_ID, hdr);
    response
}
