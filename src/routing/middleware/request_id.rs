use std::{ops::Deref, str::FromStr};

use axum::{
    extract::{Request, State},
    middleware::Next,
    response::Response,
};
use bytes::Bytes;
use derive_new::new;
use http::header::HeaderValue;
use ic_bn_lib::http::{headers::X_REQUEST_ID, middleware::extract_ip_from_request};
use uuid::Uuid;

use crate::routing::RemoteAddr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RequestId(pub Uuid);

impl Deref for RequestId {
    type Target = Uuid;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(Clone, new)]
pub struct RequestIdState {
    trust_incoming: bool,
}

fn extract_request_id(request: &Request) -> Option<RequestId> {
    request
        .headers()
        .get(X_REQUEST_ID)
        .and_then(|x| x.to_str().ok())
        .and_then(|x| Uuid::from_str(x).ok())
        .map(RequestId)
}

/// Generate & insert request UUID into extensions and headers
pub async fn middleware(
    State(state): State<RequestIdState>,
    mut request: Request,
    next: Next,
) -> Response {
    // Try to get & parse incoming request UUID if it's there
    let request_id = if let Some(v) = extract_request_id(&request)
        && state.trust_incoming
    {
        v
    } else {
        RequestId(Uuid::now_v7())
    };

    // Extract client's IP
    let remote_addr = extract_ip_from_request(&request).map(RemoteAddr);
    if let Some(v) = remote_addr {
        request.extensions_mut().insert(v);
    }

    let hdr = HeaderValue::from_maybe_shared(Bytes::from(request_id.to_string())).unwrap();

    request.extensions_mut().insert(request_id);
    request.headers_mut().insert(X_REQUEST_ID, hdr.clone());

    let mut response = next.run(request).await;
    response.headers_mut().insert(X_REQUEST_ID, hdr);

    #[cfg(test)]
    {
        response.extensions_mut().insert(request_id);
        if let Some(v) = remote_addr {
            response.extensions_mut().insert(v);
        }
    }

    response
}

#[cfg(test)]
mod test {
    use axum::body::Body;
    use uuid::uuid;

    use super::*;

    #[test]
    fn test_extract_request_id() {
        // No ID
        let req = Request::builder().body(Body::empty()).unwrap();
        assert!(extract_request_id(&req).is_none());

        // Bad ID
        let req = Request::builder()
            .header(X_REQUEST_ID, "foo")
            .body(Body::empty())
            .unwrap();
        assert!(extract_request_id(&req).is_none());

        // Good ID
        let req = Request::builder()
            .header(X_REQUEST_ID, "01980a3a-4e95-78f2-a86c-fc84d0e749c8")
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            extract_request_id(&req).unwrap(),
            RequestId(uuid!("01980a3a-4e95-78f2-a86c-fc84d0e749c8"))
        );
    }
}
