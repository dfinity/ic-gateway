use std::sync::Arc;

use ahash::AHashSet;
use anyhow::{Context, Error};
use arc_swap::ArcSwap;
use axum::{
    extract::{Extension, Request, State},
    middleware::Next,
    response::Response,
};

use crate::{
    cli::Cli,
    policy::{domain_canister::DomainCanisterMatcher, load_principal_list},
    routing::ic::subnets_info::SubnetsInfo,
    routing::{CanisterId, ErrorCause, RequestCtx, error_cause::ClientError},
};

#[derive(Clone)]
pub struct CanisterMatcherState {
    matcher: Arc<DomainCanisterMatcher>,
    subnets_info: Arc<ArcSwap<SubnetsInfo>>,
}

impl CanisterMatcherState {
    pub fn new(
        cli: &Cli,
        subnets_info: Arc<ArcSwap<SubnetsInfo>>,
    ) -> Result<Self, Error> {
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
        );

        Ok(Self {
            matcher: Arc::new(matcher),
            subnets_info,
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
        if !ctx.domain.custom
            && !state
                .matcher
                .check(v.0, &ctx.authority, &state.subnets_info.load())
        {
            return Err(ErrorCause::Client(ClientError::DomainCanisterMismatch(v.0)));
        }
    }

    Ok(next.run(request).await)
}
