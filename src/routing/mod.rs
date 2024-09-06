pub mod domain;
pub mod error_cause;
pub mod ic;
pub mod middleware;
pub mod proxy;

use std::sync::{Arc, Mutex};

use anyhow::{Context, Error};
use axum::{
    body::{Body, Bytes},
    extract::{Host, OriginalUri, Request},
    handler::Handler,
    middleware::{from_fn, from_fn_with_state, FromFnLayer},
    response::{IntoResponse, Redirect, Response},
    routing::{get, post},
    Extension, Router,
};
use axum_extra::middleware::option_layer;
use candid::Principal;
use domain::{CustomDomainStorage, DomainResolver, ProvidesCustomDomains};
use fqdn::FQDN;
use http::{method::Method, uri::PathAndQuery, StatusCode, Uri};
use ic::route_provider::setup_route_provider;
use ic_bn_lib::{
    http::{
        cache::{Cache, KeyExtractorUriRange, Opts},
        Client,
    },
    tasks::TaskManager,
};
use little_loadshedder::{LoadShedLayer, LoadShedResponse};
use middleware::cache;
use prometheus::Registry;
use sev::firmware::guest::Firmware;
use strum::{Display, IntoStaticStr};
use tower::{limit::ConcurrencyLimitLayer, util::MapResponseLayer, ServiceBuilder, ServiceExt};
use tracing::warn;

use crate::{
    cli::Cli,
    metrics::{self, clickhouse::Clickhouse, Vector},
    routing::middleware::{
        canister_match, cors, geoip, headers, rate_limiter, request_id, validate,
    },
};

use self::middleware::denylist;

use {
    domain::{Domain, ResolvesDomain},
    error_cause::ErrorCause,
    ic::handler,
};

#[derive(Clone, Copy, Eq, PartialEq, PartialOrd, Ord)]
pub struct CanisterId(pub Principal);

impl From<CanisterId> for Principal {
    fn from(value: CanisterId) -> Self {
        value.0
    }
}

// Type of IC API request
#[derive(Debug, Clone, Copy, Display, PartialEq, Eq, Hash, IntoStaticStr)]
#[strum(serialize_all = "snake_case")]
pub enum RequestTypeApi {
    Status,
    Query,
    Call,
    ReadState,
    ReadStateSubnet,
}

#[derive(Debug, Clone, Copy, Display, PartialEq, Eq, Hash, IntoStaticStr)]
#[strum(serialize_all = "snake_case")]
pub enum RequestType {
    Http,
    Health,
    Registrations,
    #[strum(to_string = "{0}")]
    Api(RequestTypeApi),
    Unknown,
}

#[derive(Clone)]
pub struct RequestCtx {
    // HTTP2 authority or HTTP1 Host header
    pub authority: FQDN,
    pub domain: Domain,
    pub verify: bool,
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
) -> Result<impl IntoResponse, ErrorCause> {
    let fallback_path = PathAndQuery::from_static("/");
    let pq = uri.path_and_query().unwrap_or(&fallback_path).as_str();

    Ok(Redirect::permanent(
        &Uri::builder()
            .scheme("https")
            .authority(host)
            .path_and_query(pq)
            .build()
            .map_err(|_| ErrorCause::MalformedRequest("incorrect url".into()))?
            .to_string(),
    ))
}

#[allow(clippy::too_many_arguments)]
pub async fn setup_router(
    cli: &Cli,
    custom_domain_providers: Vec<Arc<dyn ProvidesCustomDomains>>,
    tasks: &mut TaskManager,
    http_client: Arc<dyn Client>,
    reqwest_client: reqwest::Client,
    registry: &Registry,
    clickhouse: Option<Arc<Clickhouse>>,
    vector: Option<Arc<Vector>>,
) -> Result<Router, Error> {
    let custom_domain_storage = Arc::new(CustomDomainStorage::new(
        custom_domain_providers,
        cli.cert.cert_provider_poll_interval,
    ));
    tasks.add("custom_domain_storage", custom_domain_storage.clone());

    // Prepare domain resolver to resolve domains & infer canister_id from requests
    let mut domains_base = cli.domain.domain.clone();
    domains_base.extend_from_slice(&cli.domain.domain_app);
    domains_base.extend_from_slice(&cli.domain.domain_system);

    let domain_resolver = Arc::new(DomainResolver::new(
        domains_base,
        cli.domain.domain_api.clone(),
        cli.domain.domain_canister_alias.clone(),
        custom_domain_storage,
    )) as Arc<dyn ResolvesDomain>;

    // GeoIP
    let geoip_mw = option_layer(
        cli.misc
            .geoip_db
            .as_ref()
            .map(|x| -> Result<FromFnLayer<_, _, _>, Error> {
                let geoip_db = geoip::GeoIp::new(x)?;
                Ok(from_fn_with_state(Arc::new(geoip_db), geoip::middleware))
            })
            .transpose()?,
    );

    // Denylist
    let denylist_mw =
        if cli.policy.policy_denylist_seed.is_some() || cli.policy.policy_denylist_url.is_some() {
            Some(from_fn_with_state(
                denylist::DenylistState::new(
                    cli.policy.policy_denylist_url.clone(),
                    cli.policy.policy_denylist_seed.clone(),
                    cli.policy.policy_denylist_allowlist.clone(),
                    cli.policy.policy_denylist_poll_interval,
                    tasks,
                    http_client.clone(),
                    registry,
                )?,
                denylist::middleware,
            ))
        } else {
            warn!("Running without denylist: neither a seed nor a URL has been specified.");
            None
        };

    // Domain-Canister Matching
    // CLI makes sure that domains_system is also set
    let canister_match_mw = if !cli.domain.domain_app.is_empty() {
        Some(from_fn_with_state(
            canister_match::CanisterMatcherState::new(cli)?,
            canister_match::middleware,
        ))
    } else {
        warn!("Running without domain-canister matching.");
        None
    };

    // Metrics
    let metrics_mw = from_fn_with_state(
        Arc::new(metrics::HttpMetrics::new(
            registry,
            cli.log.log_requests,
            clickhouse,
            vector,
        )),
        metrics::middleware,
    );

    // Concurrency
    let concurrency_limit_mw = option_layer(
        cli.load
            .load_max_concurrency
            .map(ConcurrencyLimitLayer::new),
    );

    // Load shedder
    let load_shedder_mw = option_layer(cli.load.load_shed_ewma_param.map(|x| {
        ServiceBuilder::new()
            .layer(MapResponseLayer::new(|resp| match resp {
                LoadShedResponse::Inner(inner) => inner,
                LoadShedResponse::Overload => ErrorCause::LoadShed.into_response(),
            }))
            .layer(LoadShedLayer::new(x, cli.load.load_shed_target_latency))
    }));

    // Prepare the HTTP->IC library
    let route_provider =
        setup_route_provider(&cli.ic.ic_url, cli.ic.ic_use_discovery, reqwest_client).await?;
    let client = ic::setup(cli, http_client.clone(), route_provider.clone())?;

    // Prepare the states
    let state_handler = Arc::new(handler::HandlerState::new(
        client,
        !cli.ic.ic_unsafe_disable_response_verification,
        cli.http_server.http_server_body_read_timeout,
    ));
    let state_api = Arc::new(proxy::ApiProxyState::new(
        http_client.clone(),
        route_provider,
    ));

    // Common CORS layers
    let cors_post = cors::layer(&[Method::POST]);
    let cors_get = cors::layer(&[Method::HEAD, Method::GET]);

    // IC API proxy routers
    let router_api_v2 = Router::new()
        .route(
            "/canister/:principal/query",
            post(proxy::api_proxy).layer(cors_post.clone()),
        )
        .route(
            "/canister/:principal/call",
            post(proxy::api_proxy).layer(cors_post.clone()),
        )
        .route(
            "/canister/:principal/read_state",
            post(proxy::api_proxy).layer(cors_post.clone()),
        )
        .route(
            "/subnet/:principal/read_state",
            post(proxy::api_proxy).layer(cors_post.clone()),
        )
        .route("/status", get(proxy::api_proxy).layer(cors_get.clone()))
        .fallback(|| async { (StatusCode::NOT_FOUND, "") })
        .with_state(state_api.clone());

    let router_api_v3 = Router::new()
        .route(
            "/canister/:principal/call",
            post(proxy::api_proxy).layer(cors_post.clone()),
        )
        .fallback(|| async { (StatusCode::NOT_FOUND, "") })
        .with_state(state_api.clone());

    let router_health = Router::new().route(
        "/health",
        get(proxy::api_proxy).layer(cors_get).with_state(state_api),
    );

    // Caching middleware
    let cache_middleware = option_layer(if let Some(v) = cli.cache.cache_size {
        let opts = Opts {
            cache_size: v,
            max_item_size: cli.cache.cache_max_item_size,
            ttl: cli.cache.cache_ttl,
            lock_timeout: cli.cache.cache_lock_timeout,
            body_timeout: cli.cache.cache_body_timeout,
            xfetch_beta: cli.cache.cache_xfetch_beta,
            methods: vec![Method::GET],
        };

        let cache = Arc::new(Cache::new(opts, KeyExtractorUriRange, registry)?);
        tasks.add("cache", cache.clone());
        Some(from_fn_with_state(cache, cache::middleware))
    } else {
        warn!("Running without HTTP cache.");
        None
    });

    // Layers for the main HTTP->IC route
    let http_layers = ServiceBuilder::new()
        .layer(option_layer(denylist_mw))
        .layer(option_layer(canister_match_mw))
        .layer(cache_middleware);

    let router_http = Router::new().fallback(
        post(handler::handler)
            .get(handler::handler)
            .put(handler::handler)
            .delete(handler::handler)
            .layer(cors::layer(&[
                Method::HEAD,
                Method::GET,
                Method::POST,
                Method::PUT,
                Method::DELETE,
            ]))
            .layer(http_layers)
            .with_state(state_handler),
    );

    // Setup certificate issuer proxy endpoint if we have them configured
    let router_issuer = if !cli.cert.cert_provider_issuer_url.is_empty() {
        // Init it early to avoid threading races
        lazy_static::initialize(&proxy::REGEX_REG_ID);

        let state = Arc::new(proxy::IssuerProxyState::new(
            http_client,
            cli.cert.cert_provider_issuer_url.clone(),
        ));

        let router = Router::new()
            .route(
                "/registrations/:id",
                get(proxy::issuer_proxy)
                    .put(proxy::issuer_proxy)
                    .delete(proxy::issuer_proxy)
                    .layer(cors::layer(&[
                        Method::HEAD,
                        Method::GET,
                        Method::PUT,
                        Method::DELETE,
                    ])),
            )
            .route("/registrations", post(proxy::issuer_proxy).layer(cors_post))
            .layer(rate_limiter::layer_by_ip(1, 2)?)
            .with_state(state);

        Some(router)
    } else {
        warn!("Running without certificate issuer.");
        None
    };

    // Common layers for all routes
    let common_layers = ServiceBuilder::new()
        .layer(from_fn(request_id::middleware))
        .layer(from_fn(headers::middleware))
        .layer(metrics_mw)
        .layer(concurrency_limit_mw)
        .layer(geoip_mw)
        .layer(load_shedder_mw)
        .layer(from_fn_with_state(domain_resolver, validate::middleware));

    // SEV-SNP (Firmware and handler)
    let fw = Firmware::open()
        .inspect_err(|e| warn!(?e, msg = "unable to open sev-snp firmware"))
        .ok();

    let fw = Mutex::new(fw);
    let fw = Arc::new(fw);

    let report_handler = report_handler.layer(Extension(fw));

    // Top-level router
    let router = Router::new()
        .nest("/api/v2", router_api_v2)
        .nest("/api/v3", router_api_v3)
        .route("/report", post(report_handler))
        .fallback(
            |Extension(ctx): Extension<Arc<RequestCtx>>, request: Request| async move {
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

                // Redirect to the dashboard if the request is to the root of the base domain
                // or to a bare "raw" subdomain w/o canister id.
                if path == "/"
                    && (ctx.is_base_domain() || ctx.authority.labels().next() == Some("raw"))
                {
                    return Ok(
                        Redirect::temporary("https://dashboard.internetcomputer.org/")
                            .into_response(),
                    );
                }

                // Otherwise request goes to the HTTP->IC handler
                router_http.oneshot(request).await
            },
        )
        .layer(common_layers);

    // The layer that's added last is executed first
    Ok(router)
}

#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error("status {0}: {1}")]
    Custom(StatusCode, String),

    #[error(transparent)]
    Unspecified(#[from] anyhow::Error),
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (match self {
            Self::Custom(c, b) => (c, b),
            Self::Unspecified(_) => (StatusCode::INTERNAL_SERVER_ERROR, self.to_string()),
        })
        .into_response()
    }
}

async fn report_handler(
    Extension(fw): Extension<Arc<Mutex<Option<Firmware>>>>,
    body: Bytes,
) -> Result<impl IntoResponse, ApiError> {
    if body.len() != 128 {
        return Err(ApiError::Custom(
            StatusCode::BAD_REQUEST,
            "payload must be exactly 128 bytes".to_string(),
        ));
    }

    let body: [u8; 128] = body
        .as_ref()
        .try_into()
        .context("failed to read request body")?;

    // Expect hex payload
    let mut data = [0u8; 64];

    hex::decode_to_slice(
        body,      // data
        &mut data, // out
    )
    .context("failed to decode hex string")?;

    let mut fw = fw.lock().unwrap();
    let fw = match fw.as_mut() {
        Some(fw) => fw,
        None => {
            return Err(ApiError::Custom(
                StatusCode::SERVICE_UNAVAILABLE,
                "the server you have reached does not support sev-snp".to_string(),
            ))
        }
    };

    let r = fw
        .get_report(
            None,       // message_version
            Some(data), // data
            Some(1),    // vmpl
        )
        .context("failed to get report")?;

    let bs = bincode::serialize(&r).context("failed to serialize attestation report")?;

    Ok(Response::builder()
        .status(StatusCode::OK)
        .body(Body::from(bs))
        .unwrap())
}
