use std::{path::PathBuf, sync::Arc, time::Duration};

use anyhow::{Context, Error};
use axum::{
    extract::{Extension, Request, State},
    middleware::Next,
    response::Response,
};
use ic_bn_lib::{http::Client, tasks::TaskManager};
use prometheus::Registry;
use reqwest::Url;

use crate::{
    policy::denylist::Denylist,
    routing::{middleware::geoip::CountryCode, CanisterId, ErrorCause},
};

#[derive(Clone)]
pub struct DenylistState(Arc<Denylist>);

#[allow(clippy::type_complexity)]
impl DenylistState {
    pub fn new(
        denylist_url: Option<Url>,
        denylist_seed: Option<PathBuf>,
        allowlist: Option<PathBuf>,
        poll_interval: Duration,
        tasks: &mut TaskManager,
        http_client: Arc<dyn Client>,
        registry: &Registry,
    ) -> Result<Self, Error> {
        let denylist = Arc::new(
            Denylist::init(
                denylist_url.clone(),
                allowlist,
                denylist_seed,
                http_client,
                poll_interval,
                registry,
            )
            .context("unable to init denylist")?,
        );

        // Only run if a URL was given
        if denylist_url.is_some() {
            tasks.add("denylist_updater", denylist.clone());
        }
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
