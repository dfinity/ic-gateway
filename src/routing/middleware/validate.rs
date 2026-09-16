use std::{str::FromStr, sync::Arc};

use anyhow::Error;
use axum::{
    extract::{Request, State},
    middleware::Next,
    response::IntoResponse,
};
use candid::Principal;
use derive_new::new;
use fqdn::FQDN;
use http::header::REFERER;
use ic_bn_lib::http::extract_authority;
use url::{Url, form_urlencoded};

use crate::routing::{
    CanisterId, ErrorCause, RequestCtx, RequestType,
    domain::ResolvesDomain,
    error_cause::{CanisterError, ClientError, ERROR_CONTEXT},
};

#[derive(Clone, new)]
pub struct ValidateState {
    pub resolver: Arc<dyn ResolvesDomain>,
    pub canister_id_from_query_params: bool,
    pub canister_id_from_referer: bool,
}

pub async fn middleware(
    State(state): State<ValidateState>,
    mut request: Request,
    next: Next,
) -> Result<impl IntoResponse, ErrorCause> {
    // Try to extract the authority
    let Some(authority) = extract_authority(&request).and_then(|x| FQDN::from_str(x).ok()) else {
        return Err(ErrorCause::Client(ClientError::NoAuthority));
    };

    // Inject authority into error context
    let _ = ERROR_CONTEXT.try_with(|x| {
        let mut ctx = x.borrow_mut();
        ctx.authority = Some(authority.clone());
    });

    // Resolve the domain
    let mut lookup = state
        .resolver
        .resolve(&authority)
        .ok_or_else(|| ErrorCause::Client(ClientError::UnknownDomain(authority.clone())))?;

    if let Some(v) = lookup.flags {
        request.extensions_mut().insert(v);
    }

    // If configured - try to resolve canister id from query params
    if state.canister_id_from_query_params && lookup.canister_id.is_none() {
        lookup.canister_id = canister_id_from_query_params(&request)
            .map_err(|e| ErrorCause::Canister(CanisterError::IdIncorrect(e.to_string())))?;
    }

    if state.canister_id_from_referer && lookup.canister_id.is_none() {
        lookup.canister_id = request
            .headers()
            .get(REFERER)
            .and_then(|x| x.to_str().ok())
            .and_then(|referer| Url::parse(referer).ok())
            .and_then(|url| {
                canister_id_from_referer_host(&url)
                    .or_else(|| canister_id_from_referer_query_params(&url))
            });
    }

    // Inject the canister id separately if it was resolved
    if let Some(v) = lookup.canister_id {
        // Inject the canister id into error context
        let _ = ERROR_CONTEXT.try_with(|x| {
            let mut ctx = x.borrow_mut();
            ctx.canister_id = Some(v);
        });

        request.extensions_mut().insert(CanisterId(v));
    }

    let request_type = request
        .extensions()
        .get::<RequestType>()
        .copied()
        .unwrap_or_default();

    // Inject request context
    let ctx = Arc::new(RequestCtx {
        authority,
        domain: lookup.domain,
        verify: lookup.verify,
        request_type,
    });

    request.extensions_mut().insert(ctx.clone());

    // Execute the request
    let mut response = next.run(request).await;

    // Inject the same into the response
    response.extensions_mut().insert(ctx);
    if let Some(v) = lookup.canister_id {
        response.extensions_mut().insert(CanisterId(v));
    }

    Ok(response)
}

/// Tries to extract canister id from query params
fn canister_id_from_query_params(request: &Request) -> Result<Option<Principal>, Error> {
    let Some(query) = request.uri().query() else {
        return Ok(None);
    };

    let Some(id) = form_urlencoded::parse(query.as_bytes()).find(|(k, _)| k == "canisterId") else {
        return Ok(None);
    };

    let id = Principal::from_text(id.1)?;
    Ok(Some(id))
}

/// Tries to extract canister id from referer host
fn canister_id_from_referer_host(url: &Url) -> Option<Principal> {
    let domain = url.host_str().and_then(|host| FQDN::from_str(host).ok())?;

    let subdomain = domain.labels().next()?;
    Principal::from_text(subdomain).ok()
}

/// Tries to extract canister id from referer query parameters
fn canister_id_from_referer_query_params(url: &Url) -> Option<Principal> {
    let id = url
        .query_pairs()
        .find(|(key, _)| key == "canisterId")
        .map(|(_, value)| value.into_owned())?;

    Principal::from_text(id).ok()
}

#[cfg(test)]
mod test {
    use axum::{Router, body::Body, middleware::from_fn_with_state, response::Response};
    use fqdn::{Fqdn, fqdn};
    use http::{HeaderValue, StatusCode, header::HOST};
    use ic_bn_lib::{
        custom_domains::flags::{DomainFlags, FLAG_PRERENDER},
        principal,
    };
    use tower::ServiceExt;

    use crate::routing::domain::{Domain, DomainLookup};

    use super::*;

    #[test]
    fn test_canister_id_from_query_params() {
        // good
        let req = Request::builder()
            .uri("http://foo.bar/?canisterId=aaaaa-aa")
            .body(Body::empty())
            .unwrap();

        assert_eq!(
            canister_id_from_query_params(&req).unwrap(),
            Some(principal!("aaaaa-aa"))
        );

        // with other params
        let req = Request::builder()
            .uri("http://foo.bar/?foo=bar&canisterId=aaaaa-aa")
            .body(Body::empty())
            .unwrap();

        assert_eq!(
            canister_id_from_query_params(&req).unwrap(),
            Some(principal!("aaaaa-aa"))
        );

        // bad
        let req = Request::builder()
            .uri("http://foo.bar/?foo=bar&canisterId=aa")
            .body(Body::empty())
            .unwrap();

        assert!(canister_id_from_query_params(&req).is_err());

        // no param
        let req = Request::builder()
            .uri("http://foo.bar/?foo=bar")
            .body(Body::empty())
            .unwrap();

        assert_eq!(canister_id_from_query_params(&req).unwrap(), None);
    }

    #[test]
    fn test_canister_id_from_referer_header_host() {
        // good
        let uri = Url::parse("http://aaaaa-aa.foo.bar/?xyz=abc").unwrap();
        assert_eq!(
            canister_id_from_referer_host(&uri),
            Some(principal!("aaaaa-aa"))
        );

        // good
        let uri = Url::parse("http://aaaaa-aa.foo.bar.baz/?xyz=abc").unwrap();
        assert_eq!(
            canister_id_from_referer_host(&uri),
            Some(principal!("aaaaa-aa"))
        );

        // bad canister id
        let uri = Url::parse("http://aa.foo.bar/").unwrap();
        assert_eq!(canister_id_from_referer_host(&uri), None);

        // no canister id
        let uri = Url::parse("http://foo.bar/").unwrap();
        assert_eq!(canister_id_from_referer_host(&uri), None);

        // canister id is not first subdomain
        let uri = Url::parse("http://foo.aaaaa-aa.bar/").unwrap();
        assert_eq!(canister_id_from_referer_host(&uri), None);
    }

    #[test]
    fn test_canister_id_from_referer_header_query_params() {
        // good
        let uri = Url::parse("http://foo.bar/?canisterId=aaaaa-aa").unwrap();
        assert_eq!(
            canister_id_from_referer_query_params(&uri),
            Some(principal!("aaaaa-aa"))
        );

        // good
        let uri = Url::parse("http://foo.bar/?foo=bar&canisterId=aaaaa-aa").unwrap();
        assert_eq!(
            canister_id_from_referer_query_params(&uri),
            Some(principal!("aaaaa-aa"))
        );

        // no canister id
        let uri = Url::parse("http://foo.bar/?foo=bar").unwrap();
        assert_eq!(canister_id_from_referer_query_params(&uri), None);
    }

    /// Resolver that returns a canned lookup for one host and nothing for others
    #[derive(Debug, Clone)]
    struct TestResolver(Option<DomainLookup>);

    impl ResolvesDomain for TestResolver {
        fn resolve(&self, host: &Fqdn) -> Option<DomainLookup> {
            self.0
                .clone()
                .filter(|_| host == &fqdn!("known.example.com"))
        }
    }

    fn lookup(canister_id: Option<Principal>, flags: Option<DomainFlags>) -> DomainLookup {
        DomainLookup {
            domain: Domain {
                name: fqdn!("known.example.com"),
                custom: false,
                http: true,
                api: true,
            },
            canister_id,
            timestamp: 0,
            verify: true,
            priority: 0,
            flags,
        }
    }

    /// What the inner handler saw, plus the response the chain produced
    #[derive(Debug)]
    struct Seen {
        canister_id: Option<CanisterId>,
        ctx: Option<Arc<RequestCtx>>,
        flags: Option<DomainFlags>,
        response: Response,
    }

    async fn run(state: ValidateState, request: Request<Body>) -> Result<Seen, ErrorCause> {
        // The middleware's error is converted into a response by axum, so capture
        // the `ErrorCause` from the response extensions to assert on it directly.
        let router = Router::new()
            .fallback(|request: Request| async move {
                let mut resp = Response::new(Body::empty());
                // Echo what the middleware injected back out via extensions
                if let Some(v) = request.extensions().get::<CanisterId>().copied() {
                    resp.extensions_mut().insert(("seen_canister_id", v));
                }
                if let Some(v) = request.extensions().get::<Arc<RequestCtx>>().cloned() {
                    resp.extensions_mut().insert(("seen_ctx", v));
                }
                if let Some(v) = request.extensions().get::<DomainFlags>().copied() {
                    resp.extensions_mut().insert(("seen_flags", v));
                }
                resp
            })
            .layer(from_fn_with_state(state, middleware));

        let mut response = router.oneshot(request).await.unwrap();

        if let Some(e) = response.extensions_mut().remove::<ErrorCause>() {
            return Err(e);
        }

        Ok(Seen {
            canister_id: response
                .extensions_mut()
                .remove::<(&str, CanisterId)>()
                .map(|x| x.1),
            ctx: response
                .extensions_mut()
                .remove::<(&str, Arc<RequestCtx>)>()
                .map(|x| x.1),
            flags: response
                .extensions_mut()
                .remove::<(&str, DomainFlags)>()
                .map(|x| x.1),
            response,
        })
    }

    fn request(host: &str, path_and_query: &str) -> Request<Body> {
        Request::builder()
            .uri(format!("http://{host}{path_and_query}"))
            .header(HOST, host)
            .body(Body::empty())
            .unwrap()
    }

    fn state(canister_id: Option<Principal>) -> ValidateState {
        ValidateState::new(
            Arc::new(TestResolver(Some(lookup(canister_id, None)))),
            false,
            false,
        )
    }

    #[tokio::test]
    async fn test_middleware_no_authority() {
        // No Host header and no authority in the URI
        let req = Request::builder().uri("/foo").body(Body::empty()).unwrap();

        let err = run(state(None), req).await.unwrap_err();
        assert_eq!(err, ErrorCause::Client(ClientError::NoAuthority));
    }

    #[tokio::test]
    async fn test_middleware_bad_authority() {
        // An authority that isn't a valid FQDN is the same as none
        let req = Request::builder()
            .uri("/foo")
            .header(HOST, HeaderValue::from_static("...."))
            .body(Body::empty())
            .unwrap();

        let err = run(state(None), req).await.unwrap_err();
        assert_eq!(err, ErrorCause::Client(ClientError::NoAuthority));
    }

    #[tokio::test]
    async fn test_middleware_unknown_domain() {
        let err = run(state(None), request("unknown.example.com", "/"))
            .await
            .unwrap_err();

        assert_eq!(
            err,
            ErrorCause::Client(ClientError::UnknownDomain(fqdn!("unknown.example.com")))
        );
    }

    #[tokio::test]
    async fn test_middleware_injects_context() {
        let canister_id = principal!("s6hwe-laaaa-aaaab-qaeba-cai");
        let seen = run(
            state(Some(canister_id)),
            request("known.example.com", "/index.html"),
        )
        .await
        .unwrap();

        // Canister id & context reach the inner handler...
        assert_eq!(seen.canister_id, Some(CanisterId(canister_id)));
        let ctx = seen.ctx.unwrap();
        assert_eq!(ctx.authority, fqdn!("known.example.com"));
        assert_eq!(ctx.domain.name, fqdn!("known.example.com"));
        assert!(ctx.verify);
        assert_eq!(ctx.request_type, RequestType::Unknown);

        // ...and are also re-attached to the response for the outer middleware
        // (metrics/headers) to pick up.
        let mut response = seen.response;
        assert_eq!(
            response.extensions_mut().remove::<CanisterId>(),
            Some(CanisterId(canister_id))
        );
        assert!(response.extensions_mut().remove::<Arc<RequestCtx>>().is_some());
    }

    #[tokio::test]
    async fn test_middleware_no_canister_id() {
        let seen = run(state(None), request("known.example.com", "/"))
            .await
            .unwrap();

        assert_eq!(seen.canister_id, None);
        // Context is still injected even without a canister id
        let mut response = seen.response;
        assert!(response.extensions_mut().remove::<Arc<RequestCtx>>().is_some());
        assert_eq!(response.extensions_mut().remove::<CanisterId>(), None);
    }

    #[tokio::test]
    async fn test_middleware_request_type_preserved() {
        // `preprocess` runs before us and puts the request type in the extensions
        let mut req = request("known.example.com", "/");
        req.extensions_mut().insert(RequestType::Health);

        let seen = run(state(None), req).await.unwrap();
        assert_eq!(seen.ctx.unwrap().request_type, RequestType::Health);
    }

    #[tokio::test]
    async fn test_middleware_flags_injected() {
        let flags = DomainFlags::new([FLAG_PRERENDER]);
        let st = ValidateState::new(Arc::new(TestResolver(Some(lookup(None, Some(flags))))), false, false);

        let seen = run(st, request("known.example.com", "/")).await.unwrap();
        assert_eq!(seen.flags, Some(flags));
    }

    #[tokio::test]
    async fn test_middleware_canister_id_from_query_params() {
        let canister_id = principal!("s6hwe-laaaa-aaaab-qaeba-cai");

        // Disabled -> query param is ignored
        let seen = run(
            state(None),
            request("known.example.com", &format!("/?canisterId={canister_id}")),
        )
        .await
        .unwrap();
        assert_eq!(seen.canister_id, None);

        // Enabled -> picked up
        let st = ValidateState::new(Arc::new(TestResolver(Some(lookup(None, None)))), true, false);
        let seen = run(
            st.clone(),
            request("known.example.com", &format!("/?canisterId={canister_id}")),
        )
        .await
        .unwrap();
        assert_eq!(seen.canister_id, Some(CanisterId(canister_id)));

        // A malformed one is a hard error rather than a silent fallthrough
        let err = run(st, request("known.example.com", "/?canisterId=nope"))
            .await
            .unwrap_err();
        assert!(
            matches!(err, ErrorCause::Canister(CanisterError::IdIncorrect(_))),
            "unexpected error: {err:?}"
        );
    }

    #[tokio::test]
    async fn test_middleware_domain_canister_id_wins_over_query_params() {
        // The domain already resolved a canister id, so the client-supplied
        // query param must not be able to override it.
        let from_domain = principal!("s6hwe-laaaa-aaaab-qaeba-cai");
        let st = ValidateState::new(
            Arc::new(TestResolver(Some(lookup(Some(from_domain), None)))),
            true,
            true,
        );

        let mut req = request("known.example.com", "/?canisterId=aaaaa-aa");
        req.headers_mut()
            .insert(REFERER, HeaderValue::from_static("http://aaaaa-aa.foo.bar/"));

        let seen = run(st, req).await.unwrap();
        assert_eq!(seen.canister_id, Some(CanisterId(from_domain)));
    }

    #[tokio::test]
    async fn test_middleware_canister_id_from_referer() {
        let canister_id = principal!("s6hwe-laaaa-aaaab-qaeba-cai");
        let st = ValidateState::new(Arc::new(TestResolver(Some(lookup(None, None)))), false, true);

        // From the referer host
        let mut req = request("known.example.com", "/");
        req.headers_mut().insert(
            REFERER,
            HeaderValue::from_str(&format!("http://{canister_id}.example.com/app")).unwrap(),
        );
        let seen = run(st.clone(), req).await.unwrap();
        assert_eq!(seen.canister_id, Some(CanisterId(canister_id)));

        // Falling back to the referer query params
        let mut req = request("known.example.com", "/");
        req.headers_mut().insert(
            REFERER,
            HeaderValue::from_str(&format!("http://example.com/app?canisterId={canister_id}"))
                .unwrap(),
        );
        let seen = run(st.clone(), req).await.unwrap();
        assert_eq!(seen.canister_id, Some(CanisterId(canister_id)));

        // A garbage referer resolves to nothing, and (unlike the query param path)
        // is not an error
        for referer in ["not-a-url", "http://example.com/app?canisterId=nope"] {
            let mut req = request("known.example.com", "/");
            req.headers_mut()
                .insert(REFERER, HeaderValue::from_str(referer).unwrap());
            let seen = run(st.clone(), req).await.unwrap();
            assert_eq!(seen.canister_id, None, "referer {referer}");
        }

        // Disabled -> ignored
        let mut req = request("known.example.com", "/");
        req.headers_mut().insert(
            REFERER,
            HeaderValue::from_str(&format!("http://{canister_id}.example.com/app")).unwrap(),
        );
        let seen = run(state(None), req).await.unwrap();
        assert_eq!(seen.canister_id, None);
    }

    #[tokio::test]
    async fn test_middleware_error_context_populated() {
        // The error pages need the authority & canister id to render, and they're
        // read from the task-local set up by `preprocess`.
        let canister_id = principal!("s6hwe-laaaa-aaaab-qaeba-cai");

        let ctx = ERROR_CONTEXT
            .scope(std::cell::RefCell::default(), async {
                let _ = run(
                    state(Some(canister_id)),
                    request("known.example.com", "/"),
                )
                .await;

                ERROR_CONTEXT.with(|x| x.borrow().clone())
            })
            .await;

        assert_eq!(ctx.authority, Some(fqdn!("known.example.com")));
        assert_eq!(ctx.canister_id, Some(canister_id));
    }

    #[tokio::test]
    async fn test_middleware_error_context_authority_on_unknown_domain() {
        // The authority must be recorded even when the domain lookup fails, since
        // the alternate-error-domain check depends on it.
        let ctx = ERROR_CONTEXT
            .scope(std::cell::RefCell::default(), async {
                let _ = run(state(None), request("unknown.example.com", "/")).await;
                ERROR_CONTEXT.with(|x| x.borrow().clone())
            })
            .await;

        assert_eq!(ctx.authority, Some(fqdn!("unknown.example.com")));
        assert_eq!(ctx.canister_id, None);
    }

    #[tokio::test]
    async fn test_middleware_verify_flag_propagated() {
        // `verify: false` (a "raw" domain) must reach the handler so that response
        // verification is skipped there.
        let mut lookup = lookup(None, None);
        lookup.verify = false;
        let st = ValidateState::new(Arc::new(TestResolver(Some(lookup))), false, false);

        let seen = run(st, request("known.example.com", "/")).await.unwrap();
        assert!(!seen.ctx.unwrap().verify);
    }

    #[tokio::test]
    async fn test_middleware_error_status_codes() {
        // Sanity-check what the client actually gets
        let router = Router::new()
            .fallback(|| async { StatusCode::OK })
            .layer(from_fn_with_state(state(None), middleware));

        let resp = router
            .oneshot(request("unknown.example.com", "/"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }
}
