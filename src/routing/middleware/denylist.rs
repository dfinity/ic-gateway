use std::{path::PathBuf, sync::Arc};

use anyhow::{Context, Error};
use async_trait::async_trait;
use axum::{
    extract::{Request, State},
    middleware::Next,
    response::Response,
};
use ic_bn_lib::{geoip::CountryCode, http::Client, tasks::Run};
use prometheus::{IntCounterVec, Registry, register_int_counter_vec_with_registry};
use reqwest::Url;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use crate::{
    policy::denylist::Denylist,
    routing::{CanisterId, ErrorCause},
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
    let country_code = request.extensions().get::<CountryCode>().copied();
    let canister_id = request.extensions().get::<CanisterId>().copied();

    // Check denylisting if configured
    if let Some(v) = canister_id
        && state.0.is_blocked(v.0, country_code)
    {
        return Err(ErrorCause::Denylisted);
    }

    Ok(next.run(request).await)
}

#[cfg(test)]
mod test {
    use ahash::AHashSet;
    use axum::{Router, body::Body, middleware::from_fn_with_state, response::IntoResponse};
    use candid::Principal;
    use http::{Request, StatusCode};
    use ic_bn_lib::principal;
    use tower::ServiceExt;

    use super::*;

    const CANISTER_BLOCKED: &str = "s6hwe-laaaa-aaaab-qaeba-cai";
    const CANISTER_BLOCKED_CH: &str = "qoctq-giaaa-aaaaa-aaaea-cai";
    const CANISTER_ALLOWED: &str = "oydqf-haaaa-aaaao-afpsa-cai";

    /// Client that's never called - the denylist is seeded from JSON directly
    #[derive(Debug)]
    struct UnusedClient;

    #[async_trait]
    impl Client for UnusedClient {
        async fn execute(
            &self,
            _req: reqwest::Request,
        ) -> Result<reqwest::Response, reqwest::Error> {
            unimplemented!()
        }
    }

    fn state(registry: &Registry) -> DenylistState {
        let denylist = Denylist::new(None, AHashSet::new(), Arc::new(UnusedClient));
        denylist
            .load_json(
                serde_json::json!({
                    "canisters": {
                        CANISTER_BLOCKED: {"localities": []},
                        CANISTER_BLOCKED_CH: {"localities": ["CH"]},
                    }
                })
                .to_string()
                .as_bytes(),
            )
            .unwrap();

        DenylistState(Arc::new(denylist), MetricParams::new(registry))
    }

    async fn run(
        state: DenylistState,
        canister_id: Option<Principal>,
        country_code: Option<&str>,
    ) -> Response {
        let mut req = Request::new(Body::empty());
        if let Some(v) = canister_id {
            req.extensions_mut().insert(CanisterId(v));
        }
        if let Some(v) = country_code {
            req.extensions_mut()
                .insert(CountryCode(v.try_into().unwrap()));
        }

        Router::new()
            .fallback(|| async { StatusCode::OK.into_response() })
            .layer(from_fn_with_state(state, middleware))
            .oneshot(req)
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn test_middleware_blocks_globally() {
        let st = state(&Registry::new());

        // Blocked with an empty locality list means blocked everywhere
        for country_code in [None, Some("CH"), Some("US")] {
            let mut resp = run(st.clone(), Some(principal!(CANISTER_BLOCKED)), country_code).await;

            assert_eq!(
                resp.status(),
                StatusCode::UNAVAILABLE_FOR_LEGAL_REASONS,
                "country {country_code:?}"
            );
            assert_eq!(
                resp.extensions_mut().remove::<ErrorCause>(),
                Some(ErrorCause::Denylisted),
                "country {country_code:?}"
            );
        }
    }

    #[tokio::test]
    async fn test_middleware_blocks_per_country() {
        let st = state(&Registry::new());
        let canister_id = principal!(CANISTER_BLOCKED_CH);

        let resp = run(st.clone(), Some(canister_id), Some("CH")).await;
        assert_eq!(resp.status(), StatusCode::UNAVAILABLE_FOR_LEGAL_REASONS);

        // Other countries pass...
        let resp = run(st.clone(), Some(canister_id), Some("US")).await;
        assert_eq!(resp.status(), StatusCode::OK);

        // ...and so does an unknown location
        let resp = run(st, Some(canister_id), None).await;
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_middleware_passes_through() {
        let st = state(&Registry::new());

        // Canister that isn't on the list
        let resp = run(st.clone(), Some(principal!(CANISTER_ALLOWED)), Some("CH")).await;
        assert_eq!(resp.status(), StatusCode::OK);

        // Nothing to check without a canister id
        let resp = run(st, None, Some("CH")).await;
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_middleware_respects_allowlist() {
        let registry = Registry::new();
        let denylist = Denylist::new(
            None,
            AHashSet::from([principal!(CANISTER_BLOCKED)]),
            Arc::new(UnusedClient),
        );
        denylist
            .load_json(
                serde_json::json!({ "canisters": { CANISTER_BLOCKED: {"localities": []} } })
                    .to_string()
                    .as_bytes(),
            )
            .unwrap();

        let st = DenylistState(Arc::new(denylist), MetricParams::new(&registry));
        let resp = run(st, Some(principal!(CANISTER_BLOCKED)), None).await;
        assert_eq!(resp.status(), StatusCode::OK);
    }

    /// The updater task must record its outcome either way, and not swallow errors
    #[tokio::test]
    async fn test_run_records_metrics() {
        let registry = Registry::new();
        // No URL configured -> `update()` fails
        let st = DenylistState(
            Arc::new(Denylist::new(None, AHashSet::new(), Arc::new(UnusedClient))),
            MetricParams::new(&registry),
        );

        assert!(st.run(CancellationToken::new()).await.is_err());
        assert_eq!(st.1.updates.with_label_values(&["fail"]).get(), 1);
        assert_eq!(st.1.updates.with_label_values(&["ok"]).get(), 0);
    }
}
