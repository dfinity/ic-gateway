use std::sync::Arc;

use ahash::AHashSet;
use anyhow::{Context, Error};
use axum::{
    extract::{Extension, Request, State},
    middleware::Next,
    response::Response,
};

use crate::{
    cli::Cli,
    policy::{domain_canister::DomainCanisterMatcher, load_principal_list},
    routing::{
        CanisterId, ErrorCause, RequestCtx, error_cause::ClientError,
        ic::routing_table_manager::LooksUpSubnetType,
    },
};

#[derive(Clone)]
pub struct CanisterMatcherState {
    matcher: Arc<DomainCanisterMatcher>,
}

impl CanisterMatcherState {
    pub fn new(cli: &Cli, subnet_type_lookup: Arc<dyn LooksUpSubnetType>) -> Result<Self, Error> {
        let pre_isolation_canisters =
            if let Some(v) = cli.policy.policy_pre_isolation_canisters.as_ref() {
                load_principal_list(v).context("unable to load pre-isolation canisters")?
            } else {
                AHashSet::new()
            };

        let matcher = DomainCanisterMatcher::new(
            pre_isolation_canisters,
            cli.domain.domain_app.clone(),
            cli.domain.domain_system.clone(),
            cli.domain.domain_engine.clone(),
            subnet_type_lookup,
        );

        Ok(Self {
            matcher: Arc::new(matcher),
        })
    }
}

pub async fn middleware(
    State(state): State<CanisterMatcherState>,
    Extension(ctx): Extension<Arc<RequestCtx>>,
    request: Request,
    next: Next,
) -> Result<Response, ErrorCause> {
    let canister_id = request.extensions().get::<CanisterId>().copied();

    if let Some(v) = canister_id {
        // Do not run for custom domains
        if !ctx.domain.custom && !state.matcher.check(v.0, &ctx.authority) {
            return Err(ErrorCause::Client(ClientError::DomainCanisterMismatch(v.0)));
        }
    }

    Ok(next.run(request).await)
}

#[cfg(test)]
mod test {
    use ahash::AHashSet;
    use axum::{Router, body::Body, middleware::from_fn_with_state, response::IntoResponse};
    use candid::Principal;
    use fqdn::{FQDN, fqdn};
    use http::{Request, StatusCode};
    use ic_bn_lib::{ic_agent::agent::SubnetType, principal};
    use tower::ServiceExt;

    use crate::routing::{
        RequestType,
        domain::Domain,
        error_cause::{ClientError, ErrorCause},
    };

    use super::*;

    const CANISTER_SYSTEM: &str = "qoctq-giaaa-aaaaa-aaaea-cai";
    const CANISTER_APP: &str = "oydqf-haaaa-aaaao-afpsa-cai";

    struct TestLookup;
    impl LooksUpSubnetType for TestLookup {
        fn lookup_subnet_type(&self, canister_id: &Principal) -> Option<SubnetType> {
            (canister_id == &principal!(CANISTER_SYSTEM)).then_some(SubnetType::System)
        }
    }

    fn state() -> CanisterMatcherState {
        CanisterMatcherState {
            matcher: Arc::new(DomainCanisterMatcher::new(
                AHashSet::new(),
                vec![fqdn!("icp0.io")], // app
                vec![fqdn!("ic0.app")], // system
                vec![],                 // engine
                Arc::new(TestLookup),
            )),
        }
    }

    fn ctx(authority: FQDN, custom: bool) -> Arc<RequestCtx> {
        Arc::new(RequestCtx {
            domain: Domain {
                name: authority.clone(),
                custom,
                http: true,
                api: true,
            },
            authority,
            verify: true,
            request_type: RequestType::Http,
        })
    }

    async fn run(ctx: Arc<RequestCtx>, canister_id: Option<Principal>) -> Response {
        let mut req = Request::new(Body::empty());
        req.extensions_mut().insert(ctx);
        if let Some(v) = canister_id {
            req.extensions_mut().insert(CanisterId(v));
        }

        Router::new()
            .fallback(|| async { StatusCode::OK.into_response() })
            .layer(from_fn_with_state(state(), middleware))
            .oneshot(req)
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn test_middleware_allows_match() {
        let resp = run(
            ctx(fqdn!("ic0.app"), false),
            Some(principal!(CANISTER_SYSTEM)),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);

        let resp = run(
            ctx(fqdn!("icp0.io"), false),
            Some(principal!(CANISTER_APP)),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_middleware_rejects_mismatch() {
        let canister_id = principal!(CANISTER_SYSTEM);
        let mut resp = run(ctx(fqdn!("icp0.io"), false), Some(canister_id)).await;

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            resp.extensions_mut().remove::<ErrorCause>(),
            Some(ErrorCause::Client(ClientError::DomainCanisterMismatch(
                canister_id
            )))
        );
    }

    /// Custom domains point at a single canister by definition, so the
    /// base-domain policy must not be applied to them.
    #[tokio::test]
    async fn test_middleware_skips_custom_domains() {
        let resp = run(
            ctx(fqdn!("foo.example.com"), true),
            Some(principal!(CANISTER_SYSTEM)),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
    }

    /// Nothing to check if the canister wasn't resolved - the handler will
    /// produce its own error later.
    #[tokio::test]
    async fn test_middleware_no_canister_id() {
        let resp = run(ctx(fqdn!("icp0.io"), false), None).await;
        assert_eq!(resp.status(), StatusCode::OK);
    }

    /// A subdomain of a configured domain is matched too (e.g. <id>.icp0.io)
    #[tokio::test]
    async fn test_middleware_subdomains() {
        let canister_id = principal!(CANISTER_APP);
        let authority = fqdn!(&format!("{canister_id}.icp0.io"));

        let resp = run(ctx(authority.clone(), false), Some(canister_id)).await;
        assert_eq!(resp.status(), StatusCode::OK);

        // ...but not of the wrong one
        let authority = fqdn!(&format!("{canister_id}.ic0.app"));
        let resp = run(ctx(authority, false), Some(canister_id)).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }
}
