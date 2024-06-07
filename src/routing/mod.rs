pub mod body;
pub mod domain;
pub mod error_cause;
pub mod handler;
pub mod ic;
pub mod middleware;
pub mod proxy;

use std::sync::Arc;

use anyhow::Error;
use axum::{
    extract::{Host, OriginalUri, Request},
    middleware::{from_fn, from_fn_with_state, FromFnLayer},
    response::{IntoResponse, Redirect},
    routing::{get, post},
    Extension, Router,
};
use axum_extra::middleware::option_layer;
use candid::Principal;
use domain::{CustomDomainStorage, DomainResolver, ProvidesCustomDomains};
use fqdn::FQDN;
use http::{uri::PathAndQuery, Uri};
use ic_agent::agent::http_transport::route_provider::RoundRobinRouteProvider;
use prometheus::Registry;
use tower::{ServiceBuilder, ServiceExt};

use crate::{
    cli::Cli,
    http::Client,
    log::clickhouse::Clickhouse,
    metrics,
    routing::middleware::{canister_match, geoip, headers, rate_limiter, request_id, validate},
    tasks::TaskManager,
};

use self::middleware::denylist;

use {
    domain::{Domain, ResolvesDomain},
    error_cause::ErrorCause,
};

#[derive(Clone, Copy, Eq, PartialEq, PartialOrd, Ord)]
pub struct CanisterId(pub Principal);

impl From<CanisterId> for Principal {
    fn from(value: CanisterId) -> Self {
        value.0
    }
}

#[derive(Clone)]
pub struct RequestCtx {
    // HTTP2 authority or HTTP1 Host header
    pub authority: FQDN,
    pub domain: Domain,
}

impl RequestCtx {
    fn is_base_domain(&self) -> bool {
        !self.domain.custom && self.authority == self.domain.name
    }
}

// Redirects any request to an HTTPS scheme
pub async fn redirect_to_https(
    Host(host): Host,
    OriginalUri(uri): OriginalUri,
) -> impl IntoResponse {
    let fallback_path = PathAndQuery::from_static("/");
    let pq = uri.path_and_query().unwrap_or(&fallback_path).as_str();

    Redirect::permanent(
        &Uri::builder()
            .scheme("https")
            .authority(host)
            .path_and_query(pq)
            .build()
            .unwrap()
            .to_string(),
    )
}

pub fn setup_router(
    cli: &Cli,
    domains: Vec<FQDN>,
    custom_domain_providers: Vec<Arc<dyn ProvidesCustomDomains>>,
    tasks: &mut TaskManager,
    http_client: Arc<dyn Client>,
    registry: &Registry,
    clickhouse: Option<Arc<Clickhouse>>,
) -> Result<Router, Error> {
    let custom_domain_storage = Arc::new(CustomDomainStorage::new(
        custom_domain_providers,
        cli.cert.poll_interval,
    ));
    tasks.add("custom_domain_storage", custom_domain_storage.clone());

    // Prepare domain resolver to resolve domains & infer canister_id from requests
    let domain_resolver = Arc::new(DomainResolver::new(
        domains,
        cli.domain.canister_aliases.clone(),
        custom_domain_storage,
    )?) as Arc<dyn ResolvesDomain>;

    // GeoIP
    let geoip_mw = cli
        .misc
        .geoip_db
        .as_ref()
        .map(|x| -> Result<FromFnLayer<_, _, _>, Error> {
            let geoip_db = geoip::GeoIp::new(x)?;
            Ok(from_fn_with_state(Arc::new(geoip_db), geoip::middleware))
        })
        .transpose()?;

    // Denylist
    let denylist_mw = if cli.policy.denylist_seed.is_some() || cli.policy.denylist_url.is_some() {
        Some(from_fn_with_state(
            denylist::DenylistState::new(cli, tasks, http_client.clone(), registry)?,
            denylist::middleware,
        ))
    } else {
        None
    };

    // Domain-Canister Matching
    // CLI makes sure that domains_system is also set
    let canister_match_mw = if !cli.domain.domains_app.is_empty() {
        Some(from_fn_with_state(
            canister_match::CanisterMatcherState::new(cli)?,
            canister_match::middleware,
        ))
    } else {
        None
    };

    // Metrics
    let metrics_mw = from_fn_with_state(
        Arc::new(metrics::HttpMetrics::new(
            registry,
            cli.misc.env.clone(),
            cli.misc.hostname.clone(),
            clickhouse,
        )),
        metrics::middleware,
    );

    // Prepare the HTTP->IC library
    let route_provider = Arc::new(RoundRobinRouteProvider::new(cli.ic.url.clone())?);
    let client = ic::setup(cli, http_client.clone(), route_provider.clone())?;

    // Prepare the states
    let state_handler = Arc::new(handler::HandlerState::new(client));
    let state_api = Arc::new(proxy::ApiProxyState::new(
        http_client.clone(),
        route_provider,
    ));

    // IC API proxy router
    let router_api = Router::new()
        .route("/canister/:principal/query", post(proxy::api_proxy))
        .route("/canister/:principal/call", post(proxy::api_proxy))
        .route("/canister/:principal/read_state", post(proxy::api_proxy))
        .route("/subnet/:principal/read_state", post(proxy::api_proxy))
        .route("/status", get(proxy::api_proxy))
        .with_state(state_api.clone());

    let router_health = Router::new().route("/health", get(proxy::api_proxy).with_state(state_api));

    // Layers for the main HTTP->IC route
    let http_layers = ServiceBuilder::new()
        .layer(option_layer(denylist_mw))
        .layer(option_layer(canister_match_mw));

    let router_http = Router::new().fallback(
        post(handler::handler)
            .get(handler::handler)
            .layer(http_layers)
            .with_state(state_handler),
    );

    // Setup issuer proxy endpoint if we have them configured
    let router_issuer = if !cli.cert.issuer_urls.is_empty() {
        // Init it early to avoid threading races
        lazy_static::initialize(&proxy::REGEX_REG_ID);

        let state = Arc::new(proxy::IssuerProxyState::new(
            http_client,
            cli.cert.issuer_urls.clone(),
        ));
        let router = Router::new()
            .route(
                "/registrations/:id",
                get(proxy::issuer_proxy)
                    .put(proxy::issuer_proxy)
                    .delete(proxy::issuer_proxy),
            )
            .route("/registrations", post(proxy::issuer_proxy))
            .layer(rate_limiter::layer_by_ip(1, 2)?)
            .with_state(state);

        Some(router)
    } else {
        None
    };

    // Common layers for all routes
    let common_layers = ServiceBuilder::new()
        .layer(from_fn(request_id::middleware))
        .layer(from_fn(headers::middleware))
        .layer(metrics_mw)
        .layer(option_layer(geoip_mw))
        .layer(from_fn_with_state(domain_resolver, validate::middleware));

    // Top-level router
    let router = Router::new()
        .nest("/api/v2", router_api)
        .fallback(
            |ctx: Extension<Arc<RequestCtx>>, request: Request| async move {
                let path = request.uri().path();
                // If there are issuers defined and the request came to the base domain -> proxy to them
                if let Some(v) = router_issuer {
                    if path.starts_with("/registrations") && ctx.is_base_domain() {
                        return v.oneshot(request).await;
                    }
                }

                // Proxy /health only from base domain and not custom ones
                if path.starts_with("/health") && ctx.is_base_domain() {
                    return router_health.oneshot(request).await;
                }

                // Otherwise request goes to the canister
                router_http.oneshot(request).await
            },
        )
        .layer(common_layers);

    // The layer that's added last is executed first
    Ok(router)
}
