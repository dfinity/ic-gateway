use std::{collections::HashSet, sync::Arc};

use anyhow::{Context, Error};
use axum::{
    extract::{Extension, Request, State},
    middleware::Next,
    response::Response,
};
use prometheus::Registry;

use crate::{
    cli::Cli,
    core::Run,
    http::Client,
    policy::{denylist::Denylist, domain_canister::DomainCanisterMatcher, load_canister_list},
    routing::{middleware::geoip::CountryCode, ErrorCause, RequestCtx},
};

pub struct PolicyState {
    domain_canister_matcher: DomainCanisterMatcher,
    denylist: Option<Arc<Denylist>>,
}

impl PolicyState {
    pub fn new(
        cli: &Cli,
        http_client: Arc<dyn Client>,
        registry: &Registry,
    ) -> Result<(Self, Option<Arc<dyn Run>>), Error> {
        let pre_isolation_canisters = if let Some(v) = cli.policy.pre_isolation_canisters.as_ref() {
            load_canister_list(v).context("unable to load pre-isolation canisters")?
        } else {
            HashSet::new()
        };

        let domain_canister_matcher = DomainCanisterMatcher::new(
            pre_isolation_canisters,
            cli.domain.domains_app.clone(),
            cli.domain.domains_system.clone(),
        );

        let denylist = if cli.policy.denylist_seed.is_some() || cli.policy.denylist_url.is_some() {
            Some(Arc::new(
                Denylist::init(
                    cli.policy.denylist_url.clone(),
                    cli.policy.denylist_allowlist.clone(),
                    cli.policy.denylist_seed.clone(),
                    http_client,
                    cli.policy.denylist_poll_interval,
                    registry,
                )
                .context("unable to init denylist")?,
            ))
        } else {
            None
        };

        Ok((
            Self {
                domain_canister_matcher,
                denylist: denylist.clone(),
            },
            denylist.map(|x| x as Arc<dyn Run>),
        ))
    }
}

pub async fn middleware(
    State(state): State<Arc<PolicyState>>,
    country_code: Option<Extension<CountryCode>>,
    Extension(ctx): Extension<Arc<RequestCtx>>,
    request: Request,
    next: Next,
) -> Result<Response, ErrorCause> {
    // Check denylisting
    if let Some(v) = state.denylist.as_ref() {
        if v.is_blocked(ctx.canister.id, country_code.map(|x| x.0)) {
            return Err(ErrorCause::Denylisted);
        }
    }

    // Check domain-canister matching
    if !state
        .domain_canister_matcher
        .check(ctx.canister.id, &ctx.authority)
    {
        return Err(ErrorCause::DomainCanisterMismatch);
    }

    Ok(next.run(request).await)
}
