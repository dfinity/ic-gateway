#![allow(clippy::declare_interior_mutable_const)]

use std::{sync::Arc, time::Duration};

use anyhow::Error;
use axum::{
    body::Body,
    extract::{Request, State},
    middleware::Next,
    response::{IntoResponse, Response},
};
use http::{
    Method,
    header::{
        ACCEPT_RANGES, ACCESS_CONTROL_ALLOW_CREDENTIALS, ACCESS_CONTROL_ALLOW_HEADERS,
        ACCESS_CONTROL_ALLOW_METHODS, ACCESS_CONTROL_ALLOW_ORIGIN, ACCESS_CONTROL_EXPOSE_HEADERS,
        ACCESS_CONTROL_MAX_AGE, CACHE_CONTROL, CONTENT_LENGTH, CONTENT_RANGE, CONTENT_TYPE, COOKIE,
        DNT, HeaderName, HeaderValue, IF_MODIFIED_SINCE, IF_NONE_MATCH, RANGE, USER_AGENT, VARY,
    },
};
use http_body::Body as _;
use ic_bn_lib::{
    hname,
    http::headers::{X_IC_CANISTER_ID, X_REQUEST_ID, X_REQUESTED_WITH},
};
use itertools::Itertools;
use moka::sync::{Cache, CacheBuilder};
use tower_http::cors::{Any, CorsLayer, preflight_request_headers};

use crate::routing::CanisterId;

const X_OC_JWT: HeaderName = hname!("x-oc-jwt");
const X_OC_API_KEY: HeaderName = hname!("x-oc-api-key");

// Possible CORS headers in OPTIONS response
const OPTIONS_CORS_HEADERS: [HeaderName; 5] = [
    ACCESS_CONTROL_ALLOW_HEADERS,
    ACCESS_CONTROL_ALLOW_METHODS,
    ACCESS_CONTROL_ALLOW_ORIGIN,
    ACCESS_CONTROL_ALLOW_CREDENTIALS,
    ACCESS_CONTROL_MAX_AGE,
];

// Methods allowed for HTTP calls
pub const ALLOW_METHODS_HTTP: [Method; 6] = [
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

pub const ALLOW_HEADERS: [HeaderName; 10] = [
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
pub const ALLOW_HEADERS_HTTP: [HeaderName; 2] = [X_OC_JWT, X_OC_API_KEY];

pub struct CorsStateHttp {
    allow_methods: HeaderValue,
    allow_headers: HeaderValue,
    allow_origin: HeaderValue,
    expose_headers: HeaderValue,
    max_age: HeaderValue,
    vary: HeaderValue,

    invalid_canisters: Cache<CanisterId, ()>,
}

impl CorsStateHttp {
    pub fn new(
        invalid_canisters_max: u64,
        invalid_canisters_ttl: Duration,
        allow_origin: Vec<HeaderValue>,
        max_age: Duration,
    ) -> Result<Self, Error> {
        let allow_methods = HeaderValue::from_str(&ALLOW_METHODS_HTTP.iter().join(", "))?;
        let allow_headers = HeaderValue::from_str(
            &ALLOW_HEADERS
                .into_iter()
                .chain(ALLOW_HEADERS_HTTP)
                .join(", "),
        )?;

        // Concatenate provided headers with a separator
        let allow_origin = HeaderValue::from_bytes(
            allow_origin
                .iter()
                .map(|x| x.as_bytes().to_vec())
                .interleave(std::iter::repeat_n(b", ".to_vec(), allow_origin.len() - 1))
                .flatten()
                .collect::<Vec<_>>()
                .as_slice(),
        )?;

        let max_age = HeaderValue::from_str(&max_age.as_secs().to_string())?;
        let expose_headers = HeaderValue::from_str(&EXPOSE_HEADERS.into_iter().join(", "))?;
        let vary = HeaderValue::from_str(&preflight_request_headers().join(", "))?;

        let invalid_canisters = CacheBuilder::new(invalid_canisters_max)
            .time_to_live(invalid_canisters_ttl)
            .build();

        Ok(Self {
            allow_headers,
            allow_methods,
            allow_origin,
            expose_headers,
            max_age,
            vary,
            invalid_canisters,
        })
    }

    /// Applies missing CORS headers to the response
    fn apply_cors(&self, method: Method, response: &mut Response) {
        let hdr = response.headers_mut();

        // These go only to preflight response
        if method == Method::OPTIONS {
            if !hdr.contains_key(ACCESS_CONTROL_ALLOW_METHODS) {
                hdr.insert(ACCESS_CONTROL_ALLOW_METHODS, self.allow_methods.clone());
            }

            if !hdr.contains_key(ACCESS_CONTROL_ALLOW_HEADERS) {
                hdr.insert(ACCESS_CONTROL_ALLOW_HEADERS, self.allow_headers.clone());
            }

            if !hdr.contains_key(ACCESS_CONTROL_MAX_AGE) {
                hdr.insert(ACCESS_CONTROL_MAX_AGE, self.max_age.clone());
            }
        } else {
            // This only to the actual response
            if !hdr.contains_key(ACCESS_CONTROL_EXPOSE_HEADERS) {
                hdr.insert(ACCESS_CONTROL_EXPOSE_HEADERS, self.expose_headers.clone());
            }
        }

        // These are sent out always
        if !hdr.contains_key(ACCESS_CONTROL_ALLOW_ORIGIN) {
            hdr.insert(ACCESS_CONTROL_ALLOW_ORIGIN, self.allow_origin.clone());
        }

        if !hdr.contains_key(VARY) {
            hdr.insert(VARY, self.vary.clone());
        }
    }

    /// Default response for OPTIONS request
    fn default_preflight_response(&self) -> Response {
        let mut response = Response::new(Body::empty());
        let hdr = response.headers_mut();
        hdr.insert(ACCESS_CONTROL_ALLOW_METHODS, self.allow_methods.clone());
        hdr.insert(ACCESS_CONTROL_ALLOW_HEADERS, self.allow_headers.clone());
        hdr.insert(ACCESS_CONTROL_MAX_AGE, self.max_age.clone());
        hdr.insert(ACCESS_CONTROL_ALLOW_ORIGIN, self.allow_origin.clone());
        hdr.insert(VARY, self.vary.clone());
        response
    }
}

fn is_valid_preflight_response(response: &Response) -> bool {
    // Must be a success
    if !response.status().is_success() {
        return false;
    }

    // OPTIONS response should have no body
    if response.body().size_hint().exact() != Some(0) {
        return false;
    }

    // There should be at least one CORS header
    if !response
        .headers()
        .keys()
        .any(|x| OPTIONS_CORS_HEADERS.contains(x))
    {
        return false;
    }

    true
}

pub async fn middleware(
    State(state): State<Arc<CorsStateHttp>>,
    request: Request,
    next: Next,
) -> impl IntoResponse {
    let canister_id = request.extensions().get::<CanisterId>().copied();
    let method = request.method().clone();

    // If there's no canister id - just return default response or pass it forward
    let Some(canister_id) = canister_id else {
        if method == Method::OPTIONS {
            // Return our standard preflight response
            return state.default_preflight_response();
        } else {
            let mut response = next.run(request).await;
            // Apply relevant CORS headers to non-preflight response
            state.apply_cors(method, &mut response);
            return response;
        }
    };

    // If the response is known to be invalid - respond with ours
    if method == Method::OPTIONS && state.invalid_canisters.contains_key(&canister_id) {
        return state.default_preflight_response();
    }

    // Pass the request further
    let mut response = next.run(request).await;

    // If the request was OPTIONS but we didn't get a valid response,
    // return our own response with default headers set and mark canister as invalid.
    if method == Method::OPTIONS && !is_valid_preflight_response(&response) {
        state.invalid_canisters.insert(canister_id, ());
        return state.default_preflight_response();
    }

    state.apply_cors(method, &mut response);
    response
}

pub fn layer(max_age: Duration, allow_origin: Vec<HeaderValue>) -> CorsLayer {
    let mut layer = CorsLayer::new()
        .expose_headers(EXPOSE_HEADERS)
        .allow_headers(ALLOW_HEADERS)
        .max_age(max_age);

    if allow_origin.len() == 1 && allow_origin[0] == "*" {
        layer = layer.allow_origin(Any);
    } else {
        layer = layer.allow_origin(allow_origin);
    }

    layer
}

#[cfg(test)]
mod test {
    use super::*;
    use axum::{Router, body::Body, middleware::from_fn_with_state};
    use bytes::Bytes;
    use http::StatusCode;
    use ic_bn_lib::hval;
    use ic_bn_lib_common::principal;
    use tower::ServiceExt;

    #[tokio::test]
    async fn test_cors_http() {
        let s = Arc::new(
            CorsStateHttp::new(
                10,
                Duration::from_secs(600),
                vec![hval!("foo"), hval!("bar")],
                Duration::from_secs(7200),
            )
            .unwrap(),
        );

        assert_eq!(s.allow_methods, "HEAD, GET, POST, PUT, DELETE, PATCH");
        assert_eq!(
            s.allow_headers,
            "user-agent, dnt, if-none-match, if-modified-since, cache-control, content-type, range, cookie, x-requested-with, x-ic-canister-id, x-oc-jwt, x-oc-api-key"
        );
        assert_eq!(s.allow_origin, "foo, bar");
        assert_eq!(
            s.expose_headers,
            "accept-ranges, content-length, content-range, x-request-id, x-ic-canister-id"
        );
        assert_eq!(s.max_age, "7200");
        assert_eq!(
            s.vary,
            "origin, access-control-request-method, access-control-request-headers"
        );

        let canister_id = CanisterId(principal!("aaaaa-aa"));

        // Check that the existing response headers are not overridden
        let router = Router::new()
            .fallback(|req: Request| async move {
                let mut resp = Response::new(Body::empty());

                if req.method() == Method::OPTIONS {
                    resp.headers_mut()
                        .insert(ACCESS_CONTROL_ALLOW_HEADERS, hval!("foo"));
                    resp.headers_mut()
                        .insert(ACCESS_CONTROL_ALLOW_METHODS, hval!("baz"));
                    resp.headers_mut()
                        .insert(ACCESS_CONTROL_MAX_AGE, hval!("1234"));
                } else {
                    resp.headers_mut()
                        .insert(ACCESS_CONTROL_EXPOSE_HEADERS, hval!("bar"));
                }

                resp.headers_mut()
                    .insert(ACCESS_CONTROL_ALLOW_ORIGIN, hval!("foobar.com"));
                resp.headers_mut().insert(VARY, hval!("vary"));

                resp
            })
            .layer(from_fn_with_state(s.clone(), middleware));

        // For preflight
        let mut req = Request::new(Body::empty());
        *req.method_mut() = Method::OPTIONS;
        req.extensions_mut().insert(canister_id);
        let resp = router.clone().oneshot(req).await.unwrap();

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
        assert_eq!(resp.headers().get(VARY).unwrap().to_str().unwrap(), "vary");

        // For normal request
        let req = Request::new(Body::empty());
        let resp = router.oneshot(req).await.unwrap();

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
                .get(ACCESS_CONTROL_ALLOW_ORIGIN)
                .unwrap()
                .to_str()
                .unwrap(),
            "foobar.com"
        );
        assert_eq!(resp.headers().get(VARY).unwrap().to_str().unwrap(), "vary");

        // Check that default headers are added
        let router = Router::new()
            .fallback(|| async { "foo" })
            .layer(from_fn_with_state(s.clone(), middleware));

        // For preflight w/o canister
        let mut req = Request::new(Body::empty());
        *req.method_mut() = Method::OPTIONS;
        let resp = router.clone().oneshot(req).await.unwrap();

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
            s.max_age,
        );
        assert_eq!(
            resp.headers()
                .get(ACCESS_CONTROL_ALLOW_ORIGIN)
                .unwrap()
                .to_str()
                .unwrap(),
            s.allow_origin,
        );
        assert_eq!(resp.headers().get(VARY).unwrap().to_str().unwrap(), s.vary);
        assert!(resp.headers().get(ACCESS_CONTROL_EXPOSE_HEADERS).is_none());

        // For preflight with canister
        let mut req = Request::new(Body::empty());
        *req.method_mut() = Method::OPTIONS;
        req.extensions_mut().insert(canister_id);
        let resp = router.oneshot(req).await.unwrap();

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
            s.max_age,
        );
        assert_eq!(
            resp.headers()
                .get(ACCESS_CONTROL_ALLOW_ORIGIN)
                .unwrap()
                .to_str()
                .unwrap(),
            s.allow_origin,
        );
        assert_eq!(resp.headers().get(VARY).unwrap().to_str().unwrap(), s.vary);
        assert!(resp.headers().get(ACCESS_CONTROL_EXPOSE_HEADERS).is_none());

        // For normal request w/o canister
        let router = Router::new()
            .fallback(|| async { "foo" })
            .layer(from_fn_with_state(s.clone(), middleware));

        let req = Request::new(Body::empty());
        let resp = router.clone().oneshot(req).await.unwrap();

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
                .get(ACCESS_CONTROL_ALLOW_ORIGIN)
                .unwrap()
                .to_str()
                .unwrap(),
            s.allow_origin,
        );
        assert_eq!(resp.headers().get(VARY).unwrap().to_str().unwrap(), s.vary);
        assert!(resp.headers().get(ACCESS_CONTROL_ALLOW_METHODS).is_none());
        assert!(resp.headers().get(ACCESS_CONTROL_ALLOW_HEADERS).is_none());
        assert!(resp.headers().get(ACCESS_CONTROL_MAX_AGE).is_none());

        // For normal request with canister
        let router = Router::new()
            .fallback(|| async { "foo" })
            .layer(from_fn_with_state(s.clone(), middleware));

        let mut req = Request::new(Body::empty());
        req.extensions_mut().insert(canister_id);
        let resp = router.oneshot(req).await.unwrap();

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
                .get(ACCESS_CONTROL_ALLOW_ORIGIN)
                .unwrap()
                .to_str()
                .unwrap(),
            s.allow_origin,
        );
        assert_eq!(resp.headers().get(VARY).unwrap().to_str().unwrap(), s.vary);
        assert!(resp.headers().get(ACCESS_CONTROL_ALLOW_METHODS).is_none());
        assert!(resp.headers().get(ACCESS_CONTROL_ALLOW_HEADERS).is_none());
        assert!(resp.headers().get(ACCESS_CONTROL_MAX_AGE).is_none());

        // Check that default response is sent for OPTIONS request if the backend returns incorrect response
        let router = Router::new()
            .fallback(|| async { StatusCode::METHOD_NOT_ALLOWED })
            .layer(from_fn_with_state(s.clone(), middleware));

        let mut req = Request::new(Body::empty());
        *req.method_mut() = Method::OPTIONS;
        req.extensions_mut().insert(canister_id);
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // Make sure the canister is marked as invalid
        assert!(s.invalid_canisters.contains_key(&canister_id));

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
            s.max_age,
        );
        assert_eq!(
            resp.headers()
                .get(ACCESS_CONTROL_ALLOW_ORIGIN)
                .unwrap()
                .to_str()
                .unwrap(),
            s.allow_origin,
        );
        assert_eq!(resp.headers().get(VARY).unwrap().to_str().unwrap(), s.vary);
        assert!(resp.headers().get(ACCESS_CONTROL_EXPOSE_HEADERS).is_none());
    }

    #[test]
    fn test_is_valid_preflight_response() {
        // Check ok
        let mut r = Response::new(Body::empty());
        r.headers_mut()
            .insert(ACCESS_CONTROL_ALLOW_HEADERS, hval!("foo"));
        assert!(
            is_valid_preflight_response(&r),
            "Expected valid preflight response, but it was invalid"
        );

        // Check no headers
        let r = Response::new(Body::empty());
        assert!(
            !is_valid_preflight_response(&r),
            "Expected invalid preflight response due to missing headers, but it was valid"
        );

        // Check non-empty body
        let mut r = Response::new(Body::new(http_body_util::Full::new(Bytes::from_static(
            b"foo",
        ))));
        r.headers_mut()
            .insert(ACCESS_CONTROL_ALLOW_HEADERS, hval!("foo"));
        assert!(
            !is_valid_preflight_response(&r),
            "Expected invalid preflight response due to non-empty body, but it was valid"
        );

        // Check bad status
        let mut r = Response::new(Body::empty());
        *r.status_mut() = StatusCode::METHOD_NOT_ALLOWED;
        assert!(
            !is_valid_preflight_response(&r),
            "Expected invalid preflight response due to non-success status code, but it was valid"
        );
    }
}
