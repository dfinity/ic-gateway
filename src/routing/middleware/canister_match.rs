use std::{collections::HashSet, sync::Arc};

use anyhow::{Context, Error};
use axum::{
    extract::{Extension, Request, State},
    middleware::Next,
    response::Response,
};

use crate::{
    cli::Cli,
    policy::{domain_canister::DomainCanisterMatcher, load_canister_list},
    routing::{ErrorCause, RequestCtx},
};

#[derive(Clone)]
pub struct CanisterMatcherState(Arc<DomainCanisterMatcher>);

impl CanisterMatcherState {
    pub fn new(cli: &Cli) -> Result<Self, Error> {
        let pre_isolation_canisters = if let Some(v) = cli.policy.pre_isolation_canisters.as_ref() {
            load_canister_list(v).context("unable to load pre-isolation canisters")?
        } else {
            HashSet::new()
        };

        let matcher = DomainCanisterMatcher::new(
            pre_isolation_canisters,
            cli.domain.domains_app.clone(),
            cli.domain.domains_system.clone(),
        );

        Ok(Self(Arc::new(matcher)))
    }
}

pub async fn middleware(
    State(state): State<CanisterMatcherState>,
    Extension(ctx): Extension<Arc<RequestCtx>>,
    request: Request,
    next: Next,
) -> Result<Response, ErrorCause> {
    if !state.0.check(ctx.canister.id, &ctx.authority) {
        return Err(ErrorCause::DomainCanisterMismatch);
    }

    Ok(next.run(request).await)
}
