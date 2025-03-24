#![allow(clippy::declare_interior_mutable_const)]

use std::{sync::Arc, time::Duration};

use axum::{
    extract::{Request, State},
    middleware::Next,
    response::{IntoResponse, Response},
};
use http::{
    Method,
    header::{
        ACCEPT_RANGES, ACCESS_CONTROL_ALLOW_HEADERS, ACCESS_CONTROL_ALLOW_METHODS,
        ACCESS_CONTROL_ALLOW_ORIGIN, ACCESS_CONTROL_EXPOSE_HEADERS, ACCESS_CONTROL_MAX_AGE,
        CACHE_CONTROL, CONTENT_LENGTH, CONTENT_RANGE, CONTENT_TYPE, COOKIE, DNT, HeaderName,
        HeaderValue, IF_MODIFIED_SINCE, IF_NONE_MATCH, RANGE, USER_AGENT,
    },
};
use ic_bn_lib::http::headers::{X_IC_CANISTER_ID, X_REQUEST_ID, X_REQUESTED_WITH};
use itertools::Itertools;
use tower_http::cors::{Any, CorsLayer};

const MINUTE: Duration = Duration::from_secs(60);

const X_OC_JWT: HeaderName = HeaderName::from_static("x-oc-jwt");
const X_OC_API_KEY: HeaderName = HeaderName::from_static("x-oc-api-key");

// Methods allowed for HTTP calls
const ALLOW_METHODS_HTTP: [Method; 6] = [
    Method::HEAD,
    Method::GET,
    Method::POST,
    Method::PUT,
    Method::DELETE,
    Method::PATCH,
];

// Base headers
const EXPOSE_HEADERS: [HeaderName; 5] = [
    ACCEPT_RANGES,
    CONTENT_LENGTH,
    CONTENT_RANGE,
    X_REQUEST_ID,
    X_IC_CANISTER_ID,
];

const ALLOW_HEADERS: [HeaderName; 10] = [
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
];

// Additional headers to allow for HTTP calls
const ALLOW_HEADERS_HTTP: [HeaderName; 2] = [X_OC_JWT, X_OC_API_KEY];

const HEADER_WILDCARD: HeaderValue = HeaderValue::from_static("*");
const HEADER_MAX_AGE: HeaderValue = HeaderValue::from_static("7200");

pub struct CorsStateHttp {
    allow_methods: HeaderValue,
    allow_headers: HeaderValue,
    expose_headers: HeaderValue,
}

impl CorsStateHttp {
    pub fn new() -> Self {
        let allow_methods = HeaderValue::from_str(&ALLOW_METHODS_HTTP.iter().join(", ")).unwrap();

        let allow_headers = HeaderValue::from_str(
            &ALLOW_HEADERS
                .into_iter()
                .chain(ALLOW_HEADERS_HTTP)
                .join(", "),
        )
        .unwrap();

        let expose_headers = HeaderValue::from_str(&EXPOSE_HEADERS.into_iter().join(", ")).unwrap();

        Self {
            allow_headers,
            allow_methods,
            expose_headers,
        }
    }

    pub fn apply_cors(&self, response: &mut Response) {
        let hdr = response.headers_mut();

        // Insert our CORS headers if they're missing in the response
        if !hdr.contains_key(ACCESS_CONTROL_ALLOW_METHODS) {
            hdr.insert(ACCESS_CONTROL_ALLOW_METHODS, self.allow_methods.clone());
        }

        if !hdr.contains_key(ACCESS_CONTROL_ALLOW_HEADERS) {
            hdr.insert(ACCESS_CONTROL_ALLOW_HEADERS, self.allow_headers.clone());
        }

        if !hdr.contains_key(ACCESS_CONTROL_EXPOSE_HEADERS) {
            hdr.insert(ACCESS_CONTROL_EXPOSE_HEADERS, self.expose_headers.clone());
        }

        if !hdr.contains_key(ACCESS_CONTROL_ALLOW_ORIGIN) {
            hdr.insert(ACCESS_CONTROL_ALLOW_ORIGIN, HEADER_WILDCARD);
        }

        if !hdr.contains_key(ACCESS_CONTROL_MAX_AGE) {
            hdr.insert(ACCESS_CONTROL_MAX_AGE, HEADER_MAX_AGE);
        }
    }
}

pub async fn middleware(
    State(state): State<Arc<CorsStateHttp>>,
    request: Request,
    next: Next,
) -> impl IntoResponse {
    let mut response = next.run(request).await;
    state.apply_cors(&mut response);
    response
}

pub fn layer(methods: &[Method]) -> CorsLayer {
    CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(methods.to_vec())
        .expose_headers(EXPOSE_HEADERS)
        .allow_headers(ALLOW_HEADERS)
        .max_age(10 * MINUTE)
}

#[cfg(test)]
mod test {
    use super::*;
    use axum::body::Body;

    #[test]
    fn test_cors_http() {
        let s = CorsStateHttp::new();
        assert_eq!(s.allow_methods, "HEAD, GET, POST, PUT, DELETE, PATCH");
        assert_eq!(
            s.allow_headers,
            "user-agent, dnt, if-none-match, if-modified-since, cache-control, content-type, range, cookie, x-requested-with, x-ic-canister-id, x-oc-jwt, x-oc-api-key"
        );
        assert_eq!(
            s.expose_headers,
            "accept-ranges, content-length, content-range, x-request-id, x-ic-canister-id"
        );

        // Check that the existing response headers are not overriden
        let mut resp = Response::new(Body::empty());
        resp.headers_mut().insert(
            ACCESS_CONTROL_ALLOW_HEADERS,
            HeaderValue::from_static("foo"),
        );
        resp.headers_mut().insert(
            ACCESS_CONTROL_EXPOSE_HEADERS,
            HeaderValue::from_static("bar"),
        );
        resp.headers_mut().insert(
            ACCESS_CONTROL_ALLOW_METHODS,
            HeaderValue::from_static("baz"),
        );
        resp.headers_mut()
            .insert(ACCESS_CONTROL_MAX_AGE, HeaderValue::from_static("1234"));
        resp.headers_mut().insert(
            ACCESS_CONTROL_ALLOW_ORIGIN,
            HeaderValue::from_static("foobar.com"),
        );

        s.apply_cors(&mut resp);

        assert_eq!(
            resp.headers()
                .get(ACCESS_CONTROL_ALLOW_HEADERS)
                .unwrap()
                .to_str()
                .unwrap(),
            "foo"
        );
        assert_eq!(
            resp.headers()
                .get(ACCESS_CONTROL_EXPOSE_HEADERS)
                .unwrap()
                .to_str()
                .unwrap(),
            "bar"
        );
        assert_eq!(
            resp.headers()
                .get(ACCESS_CONTROL_ALLOW_METHODS)
                .unwrap()
                .to_str()
                .unwrap(),
            "baz"
        );
        assert_eq!(
            resp.headers()
                .get(ACCESS_CONTROL_MAX_AGE)
                .unwrap()
                .to_str()
                .unwrap(),
            "1234"
        );
        assert_eq!(
            resp.headers()
                .get(ACCESS_CONTROL_ALLOW_ORIGIN)
                .unwrap()
                .to_str()
                .unwrap(),
            "foobar.com"
        );

        // Check that default headers are added
        let mut resp = Response::new(Body::empty());
        s.apply_cors(&mut resp);

        assert_eq!(
            resp.headers()
                .get(ACCESS_CONTROL_ALLOW_HEADERS)
                .unwrap()
                .to_str()
                .unwrap(),
            s.allow_headers.to_str().unwrap()
        );
        assert_eq!(
            resp.headers()
                .get(ACCESS_CONTROL_EXPOSE_HEADERS)
                .unwrap()
                .to_str()
                .unwrap(),
            s.expose_headers.to_str().unwrap()
        );
        assert_eq!(
            resp.headers()
                .get(ACCESS_CONTROL_ALLOW_METHODS)
                .unwrap()
                .to_str()
                .unwrap(),
            s.allow_methods.to_str().unwrap(),
        );
        assert_eq!(
            resp.headers()
                .get(ACCESS_CONTROL_MAX_AGE)
                .unwrap()
                .to_str()
                .unwrap(),
            HEADER_MAX_AGE.to_str().unwrap()
        );
        assert_eq!(
            resp.headers()
                .get(ACCESS_CONTROL_ALLOW_ORIGIN)
                .unwrap()
                .to_str()
                .unwrap(),
            HEADER_WILDCARD.to_str().unwrap(),
        );
    }
}
