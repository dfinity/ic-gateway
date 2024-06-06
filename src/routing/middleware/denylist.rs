use std::sync::Arc;

use anyhow::{Context, Error};
use axum::{
    extract::{Extension, Request, State},
    middleware::Next,
    response::Response,
};
use prometheus::Registry;

use crate::{
    cli::Cli,
    http::Client,
    policy::denylist::Denylist,
    routing::{middleware::geoip::CountryCode, CanisterId, ErrorCause},
    tasks::TaskManager,
};

#[derive(Clone)]
pub struct DenylistState(Arc<Denylist>);

#[allow(clippy::type_complexity)]
impl DenylistState {
    pub fn new(
        cli: &Cli,
        tasks: &mut TaskManager,
        http_client: Arc<dyn Client>,
        registry: &Registry,
    ) -> Result<Self, Error> {
        let denylist = Arc::new(
            Denylist::init(
                cli.policy.denylist_url.clone(),
                cli.policy.denylist_allowlist.clone(),
                cli.policy.denylist_seed.clone(),
                http_client,
                cli.policy.denylist_poll_interval,
                registry,
            )
            .context("unable to init denylist")?,
        );

        tasks.add("denylist_updater", denylist.clone());
        Ok(Self(denylist))
    }
}

pub async fn middleware(
    State(state): State<DenylistState>,
    country_code: Option<Extension<CountryCode>>,
    canister_id: Option<Extension<CanisterId>>,
    request: Request,
    next: Next,
) -> Result<Response, ErrorCause> {
    // Check denylisting if configured
    if let Some(v) = canister_id {
        if state.0.is_blocked(v.0.into(), country_code.map(|x| x.0)) {
            return Err(ErrorCause::Denylisted);
        }
    }

    Ok(next.run(request).await)
}
