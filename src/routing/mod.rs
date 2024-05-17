pub mod body;
pub mod canister;
pub mod error_cause;
pub mod middleware;

use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

use anyhow::Error;
use axum::{
    body::Body,
    extract::{Path, Request, State},
    middleware::{from_fn, from_fn_with_state, FromFnLayer},
    response::{IntoResponse, Response},
    routing::{get, post},
    Router,
};
use axum_extra::middleware::option_layer;
use derive_new::new;
use fqdn::FQDN;
use prometheus::Registry;
use regex::Regex;
use tower::ServiceBuilder;
use tracing::warn;
use url::Url;

use crate::{
    cli::Cli,
    http::{Client, ConnInfo},
    log::clickhouse::Clickhouse,
    metrics,
    routing::middleware::{geoip, headers, policy, request_id, validate},
    tasks::TaskManager,
};

use {
    canister::{Canister, ResolvesCanister},
    error_cause::ErrorCause,
};

lazy_static::lazy_static! {
    static ref REGEX_REG_ID: Regex = Regex::new(r"^[a-zA-Z0-9]+$").unwrap();
}

pub struct RequestCtx {
    // HTTP2 authority or HTTP1 Host header
    pub authority: FQDN,
    pub canister: Canister,
}

// Proxies provided Axum request to a given URL using Reqwest Client trait object and returns Axum response
async fn proxy(
    url: Url,
    request: Request,
    http_client: &Arc<dyn Client>,
) -> Result<Response, Error> {
    // Convert Axum request into Reqwest one
    let (parts, body) = request.into_parts();
    let mut request = reqwest::Request::new(parts.method.clone(), url);
    *request.headers_mut() = parts.headers;
    // Use SyncBodyDataStream wrapper that is Sync (Axum body is !Sync)
    *request.body_mut() = Some(reqwest::Body::wrap_stream(body::SyncBodyDataStream::new(
        body,
    )));

    // Execute the request
    let response = http_client.execute(request).await?;
    let headers = response.headers().clone();

    // Convert the Reqwest response back to the Axum one
    let mut response = Response::builder()
        .status(response.status())
        .body(Body::from_stream(response.bytes_stream()))?;
    *response.headers_mut() = headers;

    Ok(response)
}

#[derive(new)]
struct IssuerProxyState {
    http_client: Arc<dyn Client>,
    issuers: Vec<Url>,
    #[new(default)]
    next: AtomicUsize,
}

// Proxies /registrations endpoint to the certificate issuers if they're defined
async fn issuer_proxy(
    State(state): State<Arc<IssuerProxyState>>,
    id: Option<Path<String>>,
    request: Request,
) -> Result<impl IntoResponse, ErrorCause> {
    // Validate request ID if it's provided
    if let Some(v) = id {
        if !REGEX_REG_ID.is_match(&v.0) {
            return Err(ErrorCause::MalformedRequest(
                "Incorrect request ID format".into(),
            ));
        }
    }

    // Extract path part from the request
    let path = request.uri().path();

    // Pick next issuer using round-robin & generate request URL for it
    // TODO should we do retries here?
    let next = state.next.fetch_add(1, Ordering::SeqCst) % state.issuers.len();
    let url = state.issuers[next]
        .clone()
        .join(path)
        .map_err(|_| ErrorCause::MalformedRequest("unable to parse path as URL part".into()))?;

    let response = proxy(url, request, &state.http_client)
        .await
        .map_err(ErrorCause::from)?;

    Ok(response)
}

async fn handler(request: Request) -> impl IntoResponse {
    warn!("{:?}", request.extensions().get::<Arc<ConnInfo>>());
    warn!("{:?}", request.extensions().get::<geoip::CountryCode>());
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

    // Policy
    let (policy_state, denylist_runner) =
        policy::PolicyState::new(cli, http_client.clone(), registry)?;
    let policy_mw = policy_state.map(|x| from_fn_with_state(Arc::new(x), policy::middleware));
    if let Some(v) = denylist_runner {
        tasks.add("denylist_runner", v);
    }

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

    // Common layers
    let common_layers = ServiceBuilder::new()
        .layer(from_fn(request_id::middleware))
        .layer(from_fn(headers::middleware))
        .layer(metrics_mw)
        .layer(option_layer(geoip_mw))
        .layer(from_fn_with_state(canister_resolver, validate::middleware))
        .layer(option_layer(policy_mw));

    let router = axum::Router::new()
        .route("/", get(handler))
        .layer(common_layers);

    // Setup issuer proxy endpoint if we have them configured
    let router = if !cli.cert.issuer_urls.is_empty() {
        // Init it early to avoid threading races
        lazy_static::initialize(&REGEX_REG_ID);

        // Strip possible path from URLs
        let mut urls = cli.cert.issuer_urls.clone();
        urls.iter_mut().for_each(|x| x.set_path(""));

        let state = Arc::new(IssuerProxyState::new(http_client, urls));

        router
            .route(
                "/registrations/:id",
                get(issuer_proxy)
                    .put(issuer_proxy)
                    .delete(issuer_proxy)
                    .with_state(state.clone()),
            )
            .route("/registrations", post(issuer_proxy).with_state(state))
    } else {
        router
    };

    Ok(router)
}
