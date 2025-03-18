pub mod custom_domains;
pub mod domain;
pub mod error_cause;
pub mod ic;
pub mod middleware;
pub mod proxy;

use std::{fmt, str::FromStr, sync::Arc, time::Duration};

use anyhow::{Context, Error};
use axum::{
    extract::{MatchedPath, OriginalUri, Request},
    middleware::{from_fn, from_fn_with_state, FromFnLayer},
    response::{IntoResponse, Redirect},
    routing::{get, post},
    Extension, Router,
};
use axum_extra::{extract::Host, middleware::option_layer};
use candid::Principal;
use domain::{CustomDomainStorage, DomainResolver, ProvidesCustomDomains};
use fqdn::FQDN;
use http::{method::Method, uri::PathAndQuery, StatusCode, Uri};
use ic_agent::agent::route_provider::RouteProvider;
use ic::route_provider::ApiBoundaryNodesStats;
use ic_bn_lib::{
    http::{
        cache::{Cache, KeyExtractorUriRange, Opts},
        shed::{
            sharded::{ShardedLittleLoadShedderLayer, ShardedOptions, TypeExtractor},
            system::{SystemInfo, SystemLoadShedderLayer},
            ShedResponse,
        },
        Client,
    },
    tasks::TaskManager,
    types::RequestType as RequestTypeApi,
};
use middleware::{cache, validate::ValidateState};
use prometheus::Registry;
use strum::{Display, IntoStaticStr};
use tower::{limit::ConcurrencyLimitLayer, util::MapResponseLayer, ServiceBuilder, ServiceExt};
use tracing::{debug, warn};

use crate::{
    cli::Cli,
    metrics::{self, clickhouse::Clickhouse, Vector},
    routing::middleware::{
        canister_match, cors, geoip, headers, rate_limiter, request_id, request_type, validate,
    },
};

use self::middleware::denylist;

use {
    domain::{Domain, ResolvesDomain},
    error_cause::ErrorCause,
    ic::handler,
};

#[derive(Debug, Clone, Copy, Eq, PartialEq, PartialOrd, Ord)]
pub struct CanisterId(pub Principal);

impl From<CanisterId> for Principal {
    fn from(value: CanisterId) -> Self {
        value.0
    }
}

impl fmt::Display for CanisterId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(
    Debug, Default, Clone, Copy, Display, PartialEq, Eq, PartialOrd, Ord, Hash, IntoStaticStr,
)]
#[strum(serialize_all = "snake_case")]
pub enum RequestType {
    Http,
    Health,
    Registrations,
    #[strum(to_string = "{0}")]
    Api(RequestTypeApi),
    #[default]
    Unknown,
}

// Strum can't handle FromStr for nested types (Api) the way we want
impl FromStr for RequestType {
    type Err = ic_bn_lib::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "http" => Self::Http,
            "health" => Self::Health,
            "registrations" => Self::Registrations,
            "unknown" => Self::Unknown,
            _ => Self::Api(RequestTypeApi::from_str(s).context("unable to parse API type")?),
        })
    }
}

// Derive request type from the matched path if there's one
impl From<Option<&MatchedPath>> for RequestType {
    fn from(path: Option<&MatchedPath>) -> Self {
        let Some(path) = path else {
            return Self::Http;
        };

        match path.as_str() {
            "/api/v2/canister/{principal}/query" => Self::Api(RequestTypeApi::Query),
            "/api/v2/canister/{principal}/call" => Self::Api(RequestTypeApi::Call),
            "/api/v3/canister/{principal}/call" => Self::Api(RequestTypeApi::SyncCall),
            "/api/v2/canister/{principal}/read_state" => Self::Api(RequestTypeApi::ReadState),
            "/api/v2/subnet/{principal}/read_state" => Self::Api(RequestTypeApi::ReadStateSubnet),
            "/api/v2/status" => Self::Api(RequestTypeApi::Status),
            "/health" => Self::Health,
            "/registrations" | "/registrations/{id}" => Self::Registrations,
            _ => Self::Unknown,
        }
    }
}

#[derive(Debug, Clone)]
pub struct RequestCtx {
    // HTTP2 authority or HTTP1 Host header
    pub authority: FQDN,
    pub domain: Domain,
    pub verify: bool,
    pub request_type: RequestType,
}

impl RequestCtx {
    fn is_base_domain(&self) -> bool {
        !self.domain.custom && self.authority == self.domain.name
    }
}

#[derive(Clone, Debug)]
struct RequestTypeExtractor;
impl TypeExtractor for RequestTypeExtractor {
    type Type = RequestType;
    type Request = Request;

    fn extract(&self, req: &Self::Request) -> Option<Self::Type> {
        req.extensions()
            .get::<Arc<RequestCtx>>()
            .map(|x| x.request_type)
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
            .map_err(|_| ErrorCause::MalformedRequest("Incorrect URL".into()))?
            .to_string(),
    ))
}

#[allow(clippy::too_many_arguments)]
#[allow(clippy::cognitive_complexity)]
pub fn setup_router(
    cli: &Cli,
    custom_domain_providers: Vec<Arc<dyn ProvidesCustomDomains>>,
    tasks: &mut TaskManager,
    http_client: Arc<dyn Client>,
    route_provider: Arc<dyn RouteProvider>,
    registry: &Registry,
    clickhouse: Option<Arc<Clickhouse>>,
    vector: Option<Arc<Vector>>,
) -> Result<Router, Error> {
    let custom_domain_storage = Arc::new(CustomDomainStorage::new(custom_domain_providers));
    tasks.add_interval(
        "custom_domain_storage",
        custom_domain_storage.clone(),
        cli.domain.domain_custom_provider_poll_interval,
    );

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
            let state = denylist::DenylistState::new(
                cli.policy.policy_denylist_url.clone(),
                cli.policy.policy_denylist_seed.clone(),
                cli.policy.policy_denylist_allowlist.clone(),
                http_client.clone(),
                registry,
            )?;

            // Only run periodic job if an URL was given
            if cli.policy.policy_denylist_url.is_some() {
                tasks.add_interval(
                    "denylist_updater",
                    Arc::new(state.clone()),
                    cli.policy.policy_denylist_poll_interval,
                );
            }

            Some(from_fn_with_state(state, denylist::middleware))
        } else {
            debug!("Running without denylist: neither a seed nor a URL has been specified.");
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
        debug!("Running without domain-canister matching.");
        None
    };

    // Metrics
    let metrics_state = Arc::new(metrics::HttpMetrics::new(
        registry,
        cli.log.log_requests,
        clickhouse,
        vector,
    ));
    let metrics_mw = from_fn_with_state(metrics_state, metrics::middleware);

    // Concurrency
    let concurrency_limit_mw = option_layer(
        cli.load
            .load_max_concurrency
            .map(ConcurrencyLimitLayer::new),
    );

    // Load shedders

    // We need to map the generic response of a shedder to an Axum's Response
    let shed_map_response = MapResponseLayer::new(|resp| match resp {
        ShedResponse::Inner(inner) => inner,
        ShedResponse::Overload(_) => ErrorCause::LoadShed.into_response(),
    });

    let load_shedder_system_mw = option_layer({
        let opts = &[
            cli.shed_system.shed_system_cpu,
            cli.shed_system.shed_system_memory,
            cli.shed_system.shed_system_load_avg_1,
            cli.shed_system.shed_system_load_avg_5,
            cli.shed_system.shed_system_load_avg_15,
        ];

        if opts.iter().any(|x| x.is_some()) {
            warn!("System load shedder enabled ({:?})", cli.shed_system);

            Some(
                ServiceBuilder::new()
                    .layer(shed_map_response.clone())
                    .layer(SystemLoadShedderLayer::new(
                        cli.shed_system.shed_system_ewma,
                        cli.shed_system.clone().into(),
                        SystemInfo::new(),
                    )),
            )
        } else {
            None
        }
    });

    let load_shedder_latency_mw =
        option_layer(if !cli.shed_latency.shed_sharded_latency.is_empty() {
            warn!("Latency load shedder enabled ({:?})", cli.shed_latency);

            Some(ServiceBuilder::new().layer(shed_map_response).layer(
                ShardedLittleLoadShedderLayer::new(ShardedOptions {
                    extractor: RequestTypeExtractor,
                    ewma_alpha: cli.shed_latency.shed_sharded_ewma,
                    passthrough_count: cli.shed_latency.shed_sharded_passthrough,
                    latencies: cli.shed_latency.shed_sharded_latency.clone(),
                }),
            ))
        } else {
            None
        });

    // Prepare the HTTP->IC library
    let client = ic::setup(cli, http_client.clone(), route_provider.clone())?;

    tasks.add_interval(
        "api_boundary_nodes_stats",
        Arc::new(ApiBoundaryNodesStats::new(route_provider.clone(), registry)),
        cli.misc.api_boundary_nodes_stats_refresh_interval,
    );

    // Prepare the states
    let state_handler = Arc::new(handler::HandlerState::new(
        client,
        !cli.ic.ic_unsafe_disable_response_verification,
        cli.http_server.http_server_body_read_timeout,
        cli.ic.ic_request_max_size,
    ));
    let state_api = Arc::new(proxy::ApiProxyState::new(
        http_client.clone(),
        route_provider,
        cli.ic.ic_request_retries,
        cli.ic.ic_request_retry_interval,
        cli.ic.ic_request_max_size,
        cli.ic.ic_request_body_timeout,
    ));

    // Common CORS layers
    let cors_post = cors::layer(&[Method::POST]);
    let cors_get = cors::layer(&[Method::HEAD, Method::GET]);

    // IC API proxy routers
    let router_api_v2 = Router::new()
        .route(
            "/canister/{principal}/query",
            post(proxy::api_proxy).layer(cors_post.clone()),
        )
        .route(
            "/canister/{principal}/call",
            post(proxy::api_proxy).layer(cors_post.clone()),
        )
        .route(
            "/canister/{principal}/read_state",
            post(proxy::api_proxy).layer(cors_post.clone()),
        )
        .route(
            "/subnet/{principal}/read_state",
            post(proxy::api_proxy).layer(cors_post.clone()),
        )
        .route("/status", get(proxy::api_proxy).layer(cors_get.clone()))
        .fallback(|| async { (StatusCode::NOT_FOUND, "") })
        .with_state(state_api.clone());

    let router_api_v3 = Router::new()
        .route(
            "/canister/{principal}/call",
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
        tasks.add_interval("cache", cache.clone(), Duration::from_secs(5));
        Some(from_fn_with_state(cache, cache::middleware))
    } else {
        warn!("Running without HTTP cache");
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
            .patch(handler::handler)
            .layer(cors::http_gw_layer(&[
                Method::HEAD,
                Method::GET,
                Method::POST,
                Method::PUT,
                Method::DELETE,
                Method::PATCH,
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
                "/registrations/{id}",
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

    let validate_state = ValidateState {
        resolver: domain_resolver,
        canister_id_from_query_params: cli.domain.domain_canister_id_from_query_params,
    };

    // Common layers for all routes
    let common_layers = ServiceBuilder::new()
        .layer(from_fn(request_id::middleware))
        .layer(from_fn(headers::middleware))
        .layer(from_fn(request_type::middleware))
        .layer(metrics_mw)
        .layer(load_shedder_system_mw)
        .layer(from_fn_with_state(validate_state, validate::middleware))
        .layer(concurrency_limit_mw)
        .layer(geoip_mw)
        .layer(load_shedder_latency_mw);

    // Top-level router
    let router = Router::new()
        .nest("/api/v2", router_api_v2)
        .nest("/api/v3", router_api_v3)
        .fallback(
            |Extension(ctx): Extension<Arc<RequestCtx>>, request: Request| async move {
                let path = request.uri().path();
                let canister_id = request.extensions().get::<CanisterId>();

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
                // Do so only if canister id wasn't resolved.
                if path == "/"
                    && (ctx.is_base_domain() || ctx.authority.labels().next() == Some("raw"))
                    && canister_id.is_none()
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

#[cfg(test)]
mod test {
    use super::*;
    use clap::Parser;
    use ic_agent::agent::route_provider::RoundRobinRouteProvider;
    use ic_bn_lib::tls::prepare_client_config;
    use std::str::FromStr;

    #[test]
    fn test_request_type() {
        assert_eq!(RequestType::Http, RequestType::from_str("http").unwrap());
        assert_eq!(
            RequestType::Health,
            RequestType::from_str("health").unwrap()
        );
        assert_eq!(
            RequestType::Registrations,
            RequestType::from_str("registrations").unwrap()
        );
        assert_eq!(
            RequestType::Unknown,
            RequestType::from_str("unknown").unwrap()
        );

        assert_eq!(
            RequestType::Api(RequestTypeApi::Query),
            RequestType::from_str("query").unwrap()
        );
        assert_eq!(
            RequestType::Api(RequestTypeApi::Call),
            RequestType::from_str("call").unwrap()
        );
        assert_eq!(
            RequestType::Api(RequestTypeApi::SyncCall),
            RequestType::from_str("sync_call").unwrap()
        );
        assert_eq!(
            RequestType::Api(RequestTypeApi::Status),
            RequestType::from_str("status").unwrap()
        );
        assert_eq!(
            RequestType::Api(RequestTypeApi::ReadState),
            RequestType::from_str("read_state").unwrap()
        );
        assert_eq!(
            RequestType::Api(RequestTypeApi::ReadStateSubnet),
            RequestType::from_str("read_state_subnet").unwrap()
        );
    }

    #[test]
    fn test_setup_router() {
        let args = vec!["", "--domain", "ic0.app"];
        let cli = Cli::parse_from(args);

        rustls::crypto::ring::default_provider()
            .install_default()
            .unwrap();

        let mut http_client_opts: ic_bn_lib::http::client::Options<ic_bn_lib::http::dns::Resolver> =
            (&cli.http_client).into();
        http_client_opts.tls_config = Some(prepare_client_config(&[
            &rustls::version::TLS13,
            &rustls::version::TLS12,
        ]));
        let http_client =
            Arc::new(ic_bn_lib::http::ReqwestClient::new(http_client_opts.clone()).unwrap());

        let route_provider = RoundRobinRouteProvider::new(vec!["https://icp-api.io"]).unwrap();

        let mut tasks = TaskManager::new();

        let _ = setup_router(
            &cli,
            vec![],
            &mut tasks,
            http_client,
            Arc::new(route_provider),
            &Registry::new(),
            None,
            None,
        )
        .unwrap();
    }
}
