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
    routing::{CanisterId, ErrorCause, RequestCtx},
};

#[derive(Clone)]
pub struct CanisterMatcherState(Arc<DomainCanisterMatcher>);

impl CanisterMatcherState {
    pub fn new(cli: &Cli) -> Result<Self, Error> {
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
        );

        Ok(Self(Arc::new(matcher)))
    }
}

pub async fn middleware(
    State(state): State<CanisterMatcherState>,
    Extension(ctx): Extension<Arc<RequestCtx>>,
    canister_id: Option<Extension<CanisterId>>,
    request: Request,
    next: Next,
) -> Result<Response, ErrorCause> {
    if let Some(v) = canister_id {
        // Do not run for custom domains
        if !ctx.domain.custom && !state.0.check(v.0.into(), &ctx.authority) {
            return Err(ErrorCause::DomainCanisterMismatch);
        }
    }

    Ok(next.run(request).await)
}
