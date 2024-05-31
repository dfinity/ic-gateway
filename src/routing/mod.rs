pub mod body;
pub mod canister;
pub mod error_cause;
pub mod handler;
pub mod ic;
pub mod middleware;
pub mod proxy;

use std::sync::Arc;

use anyhow::Error;
use axum::{
    extract::{Host, OriginalUri},
    middleware::{from_fn, from_fn_with_state, FromFnLayer},
    response::{IntoResponse, Redirect},
    routing::{get, post},
    Router,
};
use axum_extra::middleware::option_layer;
use fqdn::FQDN;
use http::{uri::PathAndQuery, Uri};
use ic_agent::agent::http_transport::route_provider::RoundRobinRouteProvider;
use prometheus::Registry;
use tower::ServiceBuilder;

use crate::{
    cli::Cli,
    http::Client,
    log::clickhouse::Clickhouse,
    metrics,
    routing::middleware::{canister_match, geoip, headers, request_id, validate},
    tasks::TaskManager,
};

use self::middleware::denylist;

use {
    canister::{Canister, ResolvesCanister},
    error_cause::ErrorCause,
};

pub struct RequestCtx {
    // HTTP2 authority or HTTP1 Host header
    pub authority: FQDN,
    pub canister: Canister,
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
    tasks: &mut TaskManager,
    http_client: Arc<dyn Client>,
    registry: &Registry,
    canister_resolver: Arc<dyn ResolvesCanister>,
    clickhouse: Option<Arc<Clickhouse>>,
) -> Result<Router, Error> {
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

    // Compose common layers
    let common_layers = ServiceBuilder::new()
        .layer(from_fn(request_id::middleware))
        .layer(from_fn(headers::middleware))
        .layer(metrics_mw)
        .layer(option_layer(geoip_mw))
        .layer(from_fn_with_state(canister_resolver, validate::middleware))
        .layer(option_layer(denylist_mw))
        .layer(option_layer(canister_match_mw));

    // Prepare the HTTP-IC library
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
        .with_state(state_api);

    let router = Router::new()
        .nest("/api/v2", router_api)
        .fallback(
            get(handler::handler)
                .post(handler::handler)
                .with_state(state_handler),
        )
        .layer(common_layers);

    // Setup issuer proxy endpoint if we have them configured
    let router = if !cli.cert.issuer_urls.is_empty() {
        // Init it early to avoid threading races
        lazy_static::initialize(&proxy::REGEX_REG_ID);

        // Strip possible path from URLs
        let mut urls = cli.cert.issuer_urls.clone();
        urls.iter_mut().for_each(|x| x.set_path(""));

        let state = Arc::new(proxy::IssuerProxyState::new(http_client, urls));
        let router_issuer = Router::new()
            .route(
                "/:id",
                get(proxy::issuer_proxy)
                    .put(proxy::issuer_proxy)
                    .delete(proxy::issuer_proxy),
            )
            .route("/", post(proxy::issuer_proxy))
            .with_state(state);

        router.nest("/registrations", router_issuer)
    } else {
        router
    };

    Ok(router)
}
