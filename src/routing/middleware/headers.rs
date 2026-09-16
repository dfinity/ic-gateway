use axum::{extract::Request, middleware::Next, response::Response};
use bytes::Bytes;
use http::header::{HeaderName, HeaderValue, STRICT_TRANSPORT_SECURITY};
use ic_bn_lib::http::headers::{
    HSTS_1YEAR, X_IC_CACHE_BYPASS_REASON, X_IC_CACHE_STATUS, X_IC_CANISTER_ID,
    X_IC_CANISTER_ID_CBOR, X_IC_COUNTRY_CODE, X_IC_METHOD_NAME, X_IC_NODE_ID, X_IC_REQUEST_TYPE,
    X_IC_RETRIES, X_IC_SENDER, X_IC_SUBNET_ID, X_IC_SUBNET_TYPE,
};

use crate::routing::CanisterId;

/// Service headers to remove from the `ic-boundary` response
const HEADERS_REMOVE: [HeaderName; 11] = [
    X_IC_CACHE_BYPASS_REASON,
    X_IC_CACHE_STATUS,
    X_IC_CANISTER_ID_CBOR,
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

#[cfg(test)]
mod test {
    use axum::{Router, body::Body, middleware::from_fn};
    use candid::Principal;
    use http::{Request, Response, header::CONTENT_TYPE};
    use ic_bn_lib::{hval, principal};
    use tower::ServiceExt;

    use super::*;

    /// Runs a request through the middleware against an upstream that sets all the
    /// `HEADERS_REMOVE` headers plus a couple that must survive.
    ///
    /// `canister_id` is what the gateway resolved (reported via response extensions),
    /// `spoofed` is an `x-ic-canister-id` the upstream put on the response itself.
    async fn call(canister_id: Option<Principal>, spoofed: bool) -> Response<Body> {
        let router = Router::new()
            .fallback(move || async move {
                let mut resp = Response::new(Body::empty());

                for h in HEADERS_REMOVE {
                    resp.headers_mut().insert(h, hval!("boundary-node-secret"));
                }

                // Header that must pass through untouched
                resp.headers_mut().insert(CONTENT_TYPE, hval!("text/plain"));

                if spoofed {
                    resp.headers_mut()
                        .insert(X_IC_CANISTER_ID, hval!("upstream-provided"));
                }

                if let Some(v) = canister_id {
                    resp.extensions_mut().insert(CanisterId(v));
                }

                resp
            })
            .layer(from_fn(middleware));

        router.oneshot(Request::new(Body::empty())).await.unwrap()
    }

    #[test]
    fn test_headers_remove_has_no_dupes() {
        // A duplicate in the list would silently mask a header that someone
        // intended to add, so keep it a set.
        let mut sorted = HEADERS_REMOVE
            .into_iter()
            .map(|x| x.to_string())
            .collect::<Vec<_>>();
        sorted.sort_unstable();
        let len = sorted.len();
        sorted.dedup();
        assert_eq!(sorted.len(), len, "HEADERS_REMOVE contains duplicates");
    }

    #[tokio::test]
    async fn test_middleware_strips_service_headers() {
        let resp = call(None, false).await;

        // Every ic-boundary service header must be gone
        for h in HEADERS_REMOVE {
            assert!(
                !resp.headers().contains_key(&h),
                "header {h} leaked to the client"
            );
        }

        // Unrelated headers are untouched
        assert_eq!(resp.headers().get(CONTENT_TYPE).unwrap(), "text/plain");

        // HSTS is always added
        assert_eq!(
            resp.headers().get(STRICT_TRANSPORT_SECURITY).unwrap(),
            HSTS_1YEAR
        );
    }

    #[tokio::test]
    async fn test_middleware_canister_id_not_resolved() {
        // Nothing to report -> no canister id header is invented
        let resp = call(None, false).await;
        assert!(!resp.headers().contains_key(X_IC_CANISTER_ID));
    }

    #[tokio::test]
    async fn test_middleware_canister_id_resolved() {
        let canister_id = principal!("s6hwe-laaaa-aaaab-qaeba-cai");

        for spoofed in [false, true] {
            let resp = call(Some(canister_id), spoofed).await;

            // The resolved id wins over whatever the upstream claimed, and there's
            // exactly one value (insert, not append).
            assert_eq!(
                resp.headers()
                    .get_all(X_IC_CANISTER_ID)
                    .into_iter()
                    .collect::<Vec<_>>(),
                vec![canister_id.to_string().as_str()],
                "spoofed = {spoofed}",
            );
        }
    }
}
