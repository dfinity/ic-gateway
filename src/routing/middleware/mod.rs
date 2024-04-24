pub mod geoip;

use std::{str::FromStr, sync::Arc};

use axum::{
    extract::{Request, State},
    middleware::Next,
    response::IntoResponse,
};
use fqdn::FQDN;

use crate::{
    http::ConnInfo,
    routing::{ErrorCause, RequestCtx},
};

use super::canister::ResolvesCanister;

// Attempts to extract host from HTTP2 "authority" pseudo-header or from HTTP/1.1 "Host" header
fn extract_authority(request: &Request) -> Option<FQDN> {
    // Try HTTP2 first, then Host header
    request
        .uri()
        .authority()
        .map(|x| x.host())
        .or_else(|| {
            request.headers().get(http::header::HOST).and_then(|x| {
                x.to_str()
                    .ok()
                    // Split the header if it has a port
                    .and_then(|x| x.split_once(':').map(|v| v.0).or(Some(x)))
            })
        })
        .and_then(|x| FQDN::from_str(x).ok())
}

pub async fn validate_request(
    State(resolver): State<Arc<dyn ResolvesCanister>>,
    mut request: Request,
    next: Next,
) -> Result<impl IntoResponse, impl IntoResponse> {
    // It should always be there, if not - then it's a bug and it's better to die
    let conn_info = request.extensions().get::<Arc<ConnInfo>>().unwrap();

    let authority = match extract_authority(&request) {
        Some(v) => v,
        None => return Err(ErrorCause::NoAuthority),
    };

    // If it's a TLS request - check that authority matches SNI
    if let Some(v) = &conn_info.tls {
        if v.sni != authority {
            return Err(ErrorCause::SNIMismatch);
        }
    }

    // Resolve the canister
    let canister = resolver
        .resolve_canister(&authority)
        .ok_or(ErrorCause::CanisterIdNotFound)?;

    println!("{:?}", canister.id.to_string());

    let ctx = Arc::new(RequestCtx {
        authority,
        canister,
    });
    request.extensions_mut().insert(ctx);

    let resp = next.run(request).await;
    Ok(resp)
}

#[cfg(test)]
mod test {
    use super::*;
    use anyhow::Error;
    use fqdn::fqdn;
    use http::{HeaderValue, Uri};

    #[test]
    fn test_extract_authority() -> Result<(), Error> {
        // Try with port
        let req = axum::extract::Request::builder()
            .method("GET")
            .version(axum::http::version::Version::HTTP_11)
            .uri("http://foo.bar:12345")
            .body(axum::body::Body::empty())
            .unwrap();

        let auth = extract_authority(&req);
        assert_eq!(auth, Some(fqdn!("foo.bar")));

        // Without port
        let req = axum::extract::Request::builder()
            .method("GET")
            .version(axum::http::version::Version::HTTP_11)
            .uri("http://foo.bar")
            .body(axum::body::Body::empty())
            .unwrap();

        let auth = extract_authority(&req);
        assert_eq!(auth, Some(fqdn!("foo.bar")));

        // HTTP2
        let req = axum::extract::Request::builder()
            .method("GET")
            .version(axum::http::version::Version::HTTP_2)
            .uri("http://foo.bar")
            .body(axum::body::Body::empty())
            .unwrap();

        let auth = extract_authority(&req);
        assert_eq!(auth, Some(fqdn!("foo.bar")));

        // Missing authority
        let mut req = axum::extract::Request::builder()
            .method("GET")
            .version(axum::http::version::Version::HTTP_2)
            .uri("http://foo.bar")
            .body(axum::body::Body::empty())
            .unwrap();
        *req.uri_mut() = Uri::default();

        let auth = extract_authority(&req);
        assert_eq!(auth, None);

        // Missing authority / present header
        let mut req = axum::extract::Request::builder()
            .method("GET")
            .version(axum::http::version::Version::HTTP_11)
            .uri("http://foo.bar")
            .body(axum::body::Body::empty())
            .unwrap();
        *req.uri_mut() = Uri::default();
        (*req.headers_mut()).insert(http::header::HOST, HeaderValue::from_static("foo.bar"));

        let auth = extract_authority(&req);
        assert_eq!(auth, Some(fqdn!("foo.bar")));

        Ok(())
    }
}
