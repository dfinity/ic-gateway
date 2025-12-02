use std::{path::PathBuf, sync::Arc};

use anyhow::{Context, Error};
use async_trait::async_trait;
use axum::{
    extract::{Request, State},
    middleware::Next,
    response::Response,
};
use ic_bn_lib_common::traits::{Run, http::Client};
use prometheus::{IntCounterVec, Registry, register_int_counter_vec_with_registry};
use reqwest::Url;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use crate::{
    policy::denylist::Denylist,
    routing::{CanisterId, ErrorCause, middleware::geoip::CountryCode},
};

#[derive(Clone)]
pub struct MetricParams {
    pub updates: IntCounterVec,
}

impl MetricParams {
    pub fn new(registry: &Registry) -> Self {
        Self {
            updates: register_int_counter_vec_with_registry!(
                format!("denylist_updates"),
                format!("Counts denylist updates and results"),
                &["result"],
                registry
            )
            .unwrap(),
        }
    }
}

#[derive(Clone)]
pub struct DenylistState(Arc<Denylist>, MetricParams);

impl DenylistState {
    pub fn new(
        denylist_url: Option<Url>,
        denylist_seed: Option<PathBuf>,
        allowlist: Option<PathBuf>,
        http_client: Arc<dyn Client>,
        registry: &Registry,
    ) -> Result<Self, Error> {
        let denylist = Arc::new(
            Denylist::init(denylist_url, allowlist, denylist_seed, http_client)
                .context("unable to init denylist")?,
        );

        Ok(Self(denylist, MetricParams::new(registry)))
    }
}

#[async_trait]
impl Run for DenylistState {
    async fn run(&self, _: CancellationToken) -> Result<(), Error> {
        let res = self.0.update().await;

        let lbl = match &res {
            Err(e) => {
                warn!("Denylist update failed: {e:#}");
                "fail"
            }

            Ok(v) => {
                info!("Denylist updated: {} canisters", v);
                "ok"
            }
        };

        self.1.updates.with_label_values(&[lbl]).inc();
        res.map(|_| ())
    }
}

pub async fn middleware(
    State(state): State<DenylistState>,
    request: Request,
    next: Next,
) -> Result<Response, ErrorCause> {
    let country_code = request.extensions().get::<CountryCode>().cloned();
    let canister_id = request.extensions().get::<CanisterId>().copied();

    // Check denylisting if configured
    if let Some(v) = canister_id
        && state.0.is_blocked(v.0, country_code)
    {
        return Err(ErrorCause::Denylisted);
    }

    Ok(next.run(request).await)
}
