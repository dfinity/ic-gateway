use std::sync::Arc;

use axum::{extract::Request, middleware::Next, response::IntoResponse};

use crate::{
    http::ConnInfo,
    routing::{ErrorCause, RequestCtx},
};

// Attempts to extract host from HTTP2 "authority" pseudo-header or from HTTP/1.1 "Host" header
fn extract_authority(request: &Request) -> Option<&str> {
    // Try HTTP2 first, then Host header
    request.uri().authority().map(|x| x.host()).or_else(|| {
        request.headers().get(http::header::HOST).and_then(|x| {
            x.to_str()
                .ok()
                // Split the header if it has a port
                .and_then(|x| x.split_once(':').map(|v| v.0).or(Some(x)))
        })
    })
}

pub async fn validate_request(
    mut request: Request,
    next: Next,
) -> Result<impl IntoResponse, impl IntoResponse> {
    // It should always be there, if not - then it's a bug and it's better to die
    let conn_info = request.extensions().get::<Arc<ConnInfo>>().unwrap();

    let authority = match extract_authority(&request) {
        Some(v) => v,
        None => {
            return Err(ErrorCause::MalformedRequest(
                "No valid authority found".to_string(),
            ))
        }
    };

    // If it's a TLS request - check the authority
    if let Some(v) = &conn_info.tls {
        if v.sni != authority {
            return Err(ErrorCause::MalformedRequest(
                "TLS SNI should match HTTP authority".to_string(),
            ));
        }
    }

    let ctx = Arc::new(RequestCtx {
        authority: authority.into(),
    });

    request.extensions_mut().insert(ctx);

    let resp = next.run(request).await;
    Ok(resp)
}

#[cfg(test)]
mod test {
    use super::*;
    use anyhow::Error;
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
        assert_eq!(auth, Some("foo.bar"));

        // Without port
        let req = axum::extract::Request::builder()
            .method("GET")
            .version(axum::http::version::Version::HTTP_11)
            .uri("http://foo.bar")
            .body(axum::body::Body::empty())
            .unwrap();

        let auth = extract_authority(&req);
        assert_eq!(auth, Some("foo.bar"));

        // HTTP2
        let req = axum::extract::Request::builder()
            .method("GET")
            .version(axum::http::version::Version::HTTP_2)
            .uri("http://foo.bar")
            .body(axum::body::Body::empty())
            .unwrap();

        let auth = extract_authority(&req);
        assert_eq!(auth, Some("foo.bar"));

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
        assert_eq!(auth, Some("foo.bar"));

        Ok(())
    }
}
