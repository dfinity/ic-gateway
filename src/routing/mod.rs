pub mod domain;
pub mod error_cause;
pub mod ic;
pub mod middleware;
pub mod proxy;

use std::{net::IpAddr, ops::Deref, str::FromStr, sync::Arc, time::Duration};

use anyhow::{Context, Error};
use axum::{
    Extension, Router,
    extract::Request,
    middleware::{FromFnLayer, from_fn, from_fn_with_state},
    response::{IntoResponse, Redirect},
    routing::{get, post},
};
use axum_extra::{either::Either, extract::Host, middleware::option_layer};
use bytes::Bytes;
use candid::Principal;
use fqdn::FQDN;
use http::{HeaderValue, StatusCode, method::Method};
use http_body_util::Full;
use ic_bn_lib::{
    http::{
        cache::{CacheBuilder, KeyExtractorUriRange},
        extract_host,
        middleware::waf::WafLayer,
        shed::{
            sharded::ShardedLittleLoadShedderLayer,
            system::{SystemInfo, SystemLoadShedderLayer},
        },
    },
    hval,
    ic_agent::agent::route_provider::RouteProvider,
    tasks::TaskManager,
    utils::health_manager::HealthManager,
    vector::client::Vector,
};
use ic_bn_lib_common::{
    traits::{
        custom_domains::ProvidesCustomDomains,
        http::{Client, ClientHttp},
        shed::TypeExtractor,
    },
    types::{
        RequestType as RequestTypeApi,
        shed::{ShardedOptions, ShedResponse},
    },
};
use prometheus::Registry;
use strum::Display;
use tokio_util::sync::CancellationToken;
use tower::{ServiceBuilder, ServiceExt, limit::ConcurrencyLimitLayer, util::MapResponseLayer};
use tracing::warn;
use tracing_core::LevelFilter;
use tracing_subscriber::reload::Handle;

use crate::{
    api::setup_api_router,
    cli::Cli,
    metrics::{self},
    routing::middleware::{canister_match, cors, geoip, headers, preprocess, request_id, validate},
};
use domain::{CustomDomainStorage, DomainResolver};
use middleware::{
    cache,
    cors::{ALLOW_HEADERS, ALLOW_HEADERS_HTTP, ALLOW_METHODS_HTTP},
    preprocess::PreprocessState,
    validate::ValidateState,
};

#[cfg(feature = "clickhouse")]
use crate::metrics::Clickhouse;

use self::middleware::denylist;

use {
    domain::{Domain, ResolvesDomain},
    error_cause::ErrorCause,
    ic::handler,
};

pub const CONTENT_TYPE_JSON: HeaderValue = hval!("application/json");

#[derive(Debug, Clone, Copy, Eq, PartialEq, PartialOrd, Ord, Hash)]
pub struct CanisterId(pub Principal);

impl From<CanisterId> for Principal {
    fn from(value: CanisterId) -> Self {
        value.0
    }
}

impl Deref for CanisterId {
    type Target = Principal;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(Debug, Default, Clone, Copy, Display, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[strum(serialize_all = "snake_case")]
pub enum RequestType {
    Http,
    Health,
    Registrations,
    CustomDomains,
    #[strum(transparent)]
    Api(RequestTypeApi),
    #[default]
    Unknown,
}

// Strum can't handle FromStr for nested types (Api) the way we want.
// See https://github.com/Peternator7/strum/pull/331
impl FromStr for RequestType {
    type Err = ic_bn_lib_common::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "http" => Self::Http,
            "health" => Self::Health,
            "registrations" => Self::Registrations,
            "custom_domains" => Self::CustomDomains,
            "unknown" => Self::Unknown,
            _ => Self::Api(RequestTypeApi::from_str(s).context("unable to parse API type")?),
        })
    }
}

// Derive request type from the matched path if there's one
impl From<Option<&str>> for RequestType {
    fn from(path: Option<&str>) -> Self {
        let Some(path) = path else {
            return Self::Http;
        };

        if path.starts_with("/custom-domains/v1/") {
            return Self::CustomDomains;
        }

        match path {
            "/api/v2/canister/{principal}/query" => Self::Api(RequestTypeApi::QueryV2),
            "/api/v3/canister/{principal}/query" => Self::Api(RequestTypeApi::QueryV3),
            "/api/v2/canister/{principal}/call" => Self::Api(RequestTypeApi::CallV2),
            "/api/v3/canister/{principal}/call" => Self::Api(RequestTypeApi::CallV3),
            "/api/v4/canister/{principal}/call" => Self::Api(RequestTypeApi::CallV4),
            "/api/v2/canister/{principal}/read_state" => Self::Api(RequestTypeApi::ReadStateV2),
            "/api/v3/canister/{principal}/read_state" => Self::Api(RequestTypeApi::ReadStateV3),
            "/api/v2/subnet/{principal}/read_state" => Self::Api(RequestTypeApi::ReadStateSubnetV2),
            "/api/v3/subnet/{principal}/read_state" => Self::Api(RequestTypeApi::ReadStateSubnetV3),
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

/// Client address
#[derive(Debug, Clone, Copy)]
pub struct RemoteAddr(pub IpAddr);

impl Deref for RemoteAddr {
    type Target = IpAddr;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

// TODO: make it less horrible by using maybe builder pattern or just a struct
#[allow(clippy::too_many_arguments)]
#[allow(clippy::cognitive_complexity)]
pub async fn setup_router(
    cli: &Cli,
    custom_domain_providers: Vec<Arc<dyn ProvidesCustomDomains>>,
    log_handle: Handle<LevelFilter, tracing_subscriber::registry::Registry>,
    tasks: &mut TaskManager,
    health_manager: Arc<HealthManager>,
    http_client: Arc<dyn Client>,
    http_client_hyper: Arc<dyn ClientHttp<Full<Bytes>>>,
    route_provider: Arc<dyn RouteProvider>,
    registry: &Registry,
    shutdown_token: CancellationToken,
    vector: Option<Arc<Vector>>,
    waf_layer: Option<WafLayer>,
    custom_domains_router: Option<Router>,
    #[cfg(feature = "clickhouse")] clickhouse: Option<Arc<Clickhouse>>,
) -> Result<Router, Error> {
    // Setup API router
    let router_api = setup_api_router(
        cli,
        log_handle,
        health_manager.clone(),
        shutdown_token,
        waf_layer.clone(),
    )
    .context("unable to setup API Router")?;

    let custom_domain_storage =
        Arc::new(CustomDomainStorage::new(custom_domain_providers, registry));
    tasks.add_interval(
        "custom_domain_storage",
        custom_domain_storage.clone(),
        cli.domain.domain_custom_provider_poll_interval,
    );

    // Check custom domains health if requested
    if cli.misc.custom_domain_provider_critical {
        health_manager.add(custom_domain_storage.clone());
    }

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
            .transpose()
            .context("unable to init GeoIP")?,
    );

    // Denylist
    let denylist_mw = option_layer(
        (cli.policy.policy_denylist_seed.is_some() || cli.policy.policy_denylist_url.is_some())
            .then(|| -> Result<_, Error> {
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

                Ok(from_fn_with_state(state, denylist::middleware))
            })
            .transpose()
            .context("unable to init Denylisting")?,
    );

    // Domain-Canister Matching
    // CLI makes sure that domains_system is also set
    let canister_match_mw = option_layer(
        (!cli.domain.domain_app.is_empty())
            .then(|| -> Result<_, Error> {
                Ok(from_fn_with_state(
                    canister_match::CanisterMatcherState::new(cli)?,
                    canister_match::middleware,
                ))
            })
            .transpose()
            .context("unable to init Domain-Canister matcher")?,
    );

    // Metrics
    let metrics_state = Arc::new(metrics::HttpMetrics::new(
        registry,
        cli.log.log_requests,
        vector,
        #[cfg(feature = "clickhouse")]
        clickhouse,
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

        opts.iter().any(|x| x.is_some()).then(|| {
            warn!("System load shedder enabled ({:?})", cli.shed_system);

            ServiceBuilder::new()
                .layer(shed_map_response.clone())
                .layer(SystemLoadShedderLayer::new(
                    cli.shed_system.shed_system_ewma,
                    cli.shed_system.clone().into(),
                    SystemInfo::new(),
                ))
        })
    });

    let load_shedder_latency_mw = option_layer(
        (!cli.shed_latency.shed_sharded_latency.is_empty()).then(|| {
            warn!("Latency load shedder enabled ({:?})", cli.shed_latency);

            ServiceBuilder::new().layer(shed_map_response).layer(
                ShardedLittleLoadShedderLayer::new(ShardedOptions {
                    extractor: RequestTypeExtractor,
                    ewma_alpha: cli.shed_latency.shed_sharded_ewma,
                    passthrough_count: cli.shed_latency.shed_sharded_passthrough,
                    latencies: cli.shed_latency.shed_sharded_latency.clone(),
                }),
            )
        }),
    );

    // Prepare the HTTP->IC library
    let ic_client = ic::setup(cli, http_client_hyper.clone(), route_provider.clone())
        .await
        .context("unable to init IC client")?;

    // Prepare the states
    let state_handler = Arc::new(handler::HandlerState::new(
        ic_client,
        !cli.ic.ic_unsafe_disable_response_verification,
        cli.http_server.http_server_body_read_timeout,
        cli.ic.ic_request_max_size,
    ));
    let state_api = Arc::new(proxy::ApiProxyState::new(
        http_client_hyper,
        route_provider,
        cli.ic.ic_request_retries,
        cli.ic.ic_request_retry_interval,
        cli.ic.ic_request_max_size,
        cli.ic.ic_request_body_timeout,
    ));

    let cors_base = cors::layer(cli.cors.cors_max_age, cli.cors.cors_allow_origin.clone());

    // Common CORS layers
    let cors_post = cors_base.clone().allow_methods([Method::POST]);
    let cors_get = cors_base.clone().allow_methods([Method::HEAD, Method::GET]);

    let api_proxy_handler = post(proxy::api_proxy).layer(cors_post);

    // IC API proxy routers
    let router_api_v2 = Router::new()
        .route("/canister/{principal}/query", api_proxy_handler.clone())
        .route("/canister/{principal}/call", api_proxy_handler.clone())
        .route(
            "/canister/{principal}/read_state",
            api_proxy_handler.clone(),
        )
        .route("/subnet/{principal}/read_state", api_proxy_handler.clone())
        .route("/status", get(proxy::api_proxy).layer(cors_get))
        .fallback(|| async { StatusCode::NOT_FOUND })
        .with_state(state_api.clone());

    let router_api_v3 = Router::new()
        .route("/canister/{principal}/query", api_proxy_handler.clone())
        .route("/canister/{principal}/call", api_proxy_handler.clone())
        .route(
            "/canister/{principal}/read_state",
            api_proxy_handler.clone(),
        )
        .route("/subnet/{principal}/read_state", api_proxy_handler.clone())
        .fallback(|| async { StatusCode::NOT_FOUND })
        .with_state(state_api.clone());

    let router_api_v4 = Router::new()
        .route("/canister/{principal}/call", api_proxy_handler)
        .fallback(|| async { StatusCode::NOT_FOUND })
        .with_state(state_api);

    // Caching middleware
    let cache_middleware = option_layer(
        cli.cache
            .cache_size
            .map(|v| -> Result<_, Error> {
                let builder = CacheBuilder::new(KeyExtractorUriRange)
                    .cache_size(v)
                    .max_item_size(cli.cache.cache_max_item_size)
                    .obey_cache_control(!cli.cache.cache_disregard_cache_control)
                    .ttl(cli.cache.cache_ttl)
                    .max_ttl(cli.cache.cache_max_ttl)
                    .lock_timeout(cli.cache.cache_lock_timeout)
                    .body_timeout(cli.cache.cache_body_timeout)
                    .xfetch_beta(cli.cache.cache_xfetch_beta)
                    .registry(registry);

                let cache = Arc::new(builder.build().context("unable to build cache")?);
                tasks.add_interval("cache", cache.clone(), Duration::from_secs(5));
                Ok(from_fn_with_state(cache, cache::middleware))
            })
            .transpose()
            .context("unable to init cache")?,
    );

    // Use either static CORS layer or a dynamic one
    let cors_http = if cli.cors.cors_canister_passthrough {
        Either::E1(from_fn_with_state(
            Arc::new(
                cors::CorsStateHttp::new(
                    cli.cors.cors_invalid_canisters_max,
                    cli.cors.cors_invalid_canisters_ttl,
                    cli.cors.cors_allow_origin.clone(),
                    cli.cors.cors_max_age,
                )
                .context("unable to init CORS")?,
            ),
            cors::middleware,
        ))
    } else {
        Either::E2(
            cors_base
                .clone()
                .allow_methods(ALLOW_METHODS_HTTP)
                .allow_headers([ALLOW_HEADERS.as_slice(), ALLOW_HEADERS_HTTP.as_slice()].concat()),
        )
    };

    // Layers for the main HTTP->IC route
    let http_layers = ServiceBuilder::new()
        .layer(cors_http)
        .layer(denylist_mw)
        .layer(canister_match_mw)
        .layer(cache_middleware);

    let router_http = Router::new().fallback(
        post(handler::handler)
            .get(handler::handler)
            .put(handler::handler)
            .delete(handler::handler)
            .patch(handler::handler)
            .options(handler::handler)
            .layer(http_layers)
            .with_state(state_handler),
    );

    let validate_state = ValidateState::new(
        domain_resolver,
        cli.domain.domain_canister_id_from_query_params,
        cli.domain.domain_canister_id_from_referer,
    );

    // Request type state for alternate error domain configuration
    let request_type_state = Arc::new(PreprocessState::new(
        cli.misc.alternate_error_domain.clone(),
        cli.misc.disable_html_error_messages,
    ));

    // Common layers for all routes
    let common_layers = ServiceBuilder::new()
        .layer(from_fn_with_state(
            request_id::RequestIdState::new(cli.network.network_trust_x_request_id),
            request_id::middleware,
        ))
        .layer(from_fn(headers::middleware))
        .layer(from_fn_with_state(
            request_type_state,
            preprocess::middleware,
        ))
        .layer(geoip_mw)
        .layer(metrics_mw)
        .layer(option_layer(waf_layer))
        .layer(load_shedder_system_mw)
        .layer(from_fn_with_state(validate_state, validate::middleware))
        .layer(concurrency_limit_mw)
        .layer(load_shedder_latency_mw);

    let api_hostname = cli.api.api_hostname.clone().map(|x| x.to_string());

    let custom_domains_router = custom_domains_router.map(|x| {
        Router::new()
            .nest("/custom-domains", x)
            .layer(cors_base.allow_methods([
                Method::HEAD,
                Method::GET,
                Method::POST,
                Method::DELETE,
                Method::PATCH,
            ]))
    });

    // Top-level router
    #[allow(unused_mut)]
    let mut router = Router::new()
        .nest("/api/v2", router_api_v2)
        .nest("/api/v3", router_api_v3)
        .nest("/api/v4", router_api_v4)
        .fallback(
            |Host(host): Host, Extension(ctx): Extension<Arc<RequestCtx>>, request: Request| async move {
                // Check if the request's host matches API hostname
                if api_hostname.zip(extract_host(&host)).map(|(a, b)| a == b) == Some(true) {
                    return router_api.oneshot(request).await;
                }

                let path = request.uri().path();
                let canister_id = request.extensions().get::<CanisterId>();

                // If the custom domains are enabled and the request came to the base domain
                if let Some(v) = custom_domains_router && ctx.is_base_domain() && path.starts_with("/custom-domains") {
                    return v.oneshot(request).await;
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

    #[cfg(all(target_os = "linux", feature = "sev-snp"))]
    if cli.sev_snp.sev_snp_enable {
        let router_sev_snp = Router::new().route(
            "/sev-snp/report",
            post(ic_bn_lib::utils::sev_snp::handler)
                .with_state(
                    ic_bn_lib::utils::sev_snp::SevSnpState::new(
                        cli.sev_snp.sev_snp_cache_ttl,
                        cli.sev_snp.sev_snp_cache_size,
                    )
                    .context("unable to init SEV-SNP")?,
                )
                .layer(ic_bn_lib::http::middleware::rate_limiter::layer_global(
                    50,
                    100,
                    crate::routing::error_cause::RateLimitCause::Normal,
                    cli.rate_limit.rate_limit_bypass_token.clone(),
                )?),
        );

        router = router.merge(router_sev_snp)
    }

    Ok(router)
}

#[cfg(test)]
mod test {
    use crate::{
        routing::middleware::{geoip::CountryCode, request_id::RequestId},
        test::setup_test_router,
    };

    use super::*;
    use axum::body::{Body, to_bytes};
    use http::{HeaderValue, Uri};
    use ic_bn_lib::http::headers::{X_REAL_IP, X_REQUEST_ID};
    use ic_bn_lib_common::types::http::ConnInfo;
    use rand::{seq::SliceRandom, thread_rng};
    use std::str::FromStr;
    use tower::Service;
    use uuid::Uuid;

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
            RequestType::Api(RequestTypeApi::QueryV2),
            RequestType::from_str("query_v2").unwrap()
        );
        assert_eq!(
            RequestType::Api(RequestTypeApi::CallV2),
            RequestType::from_str("call_v2").unwrap()
        );
        assert_eq!(
            RequestType::Api(RequestTypeApi::CallV3),
            RequestType::from_str("call_v3").unwrap()
        );
        assert_eq!(
            RequestType::Api(RequestTypeApi::Status),
            RequestType::from_str("status").unwrap()
        );
        assert_eq!(
            RequestType::Api(RequestTypeApi::ReadStateV2),
            RequestType::from_str("read_state_v2").unwrap()
        );
        assert_eq!(
            RequestType::Api(RequestTypeApi::ReadStateSubnetV2),
            RequestType::from_str("read_state_subnet_v2").unwrap()
        );
    }

    #[test]
    fn test_request_type_derive() {
        let cases = [
            (
                "/api/v2/canister/{principal}/query",
                RequestType::Api(RequestTypeApi::QueryV2),
            ),
            (
                "/api/v3/canister/{principal}/query",
                RequestType::Api(RequestTypeApi::QueryV3),
            ),
            (
                "/api/v2/canister/{principal}/call",
                RequestType::Api(RequestTypeApi::CallV2),
            ),
            (
                "/api/v3/canister/{principal}/call",
                RequestType::Api(RequestTypeApi::CallV3),
            ),
            (
                "/api/v4/canister/{principal}/call",
                RequestType::Api(RequestTypeApi::CallV4),
            ),
            (
                "/api/v2/canister/{principal}/read_state",
                RequestType::Api(RequestTypeApi::ReadStateV2),
            ),
            (
                "/api/v3/canister/{principal}/read_state",
                RequestType::Api(RequestTypeApi::ReadStateV3),
            ),
            (
                "/api/v2/subnet/{principal}/read_state",
                RequestType::Api(RequestTypeApi::ReadStateSubnetV2),
            ),
            (
                "/api/v3/subnet/{principal}/read_state",
                RequestType::Api(RequestTypeApi::ReadStateSubnetV3),
            ),
            ("/api/v2/status", RequestType::Api(RequestTypeApi::Status)),
            ("/health", RequestType::Health),
            ("/registrations", RequestType::Registrations),
            ("/custom-domains/v1/foo.bar", RequestType::CustomDomains),
            (
                "/custom-domains/v1/foo.bar/validate",
                RequestType::CustomDomains,
            ),
            ("", RequestType::Unknown),
        ];

        for (path, rt) in cases {
            assert_eq!(RequestType::from(Some(path)), rt);
        }

        assert_eq!(RequestType::from(None), RequestType::Http);
    }

    #[tokio::test]
    async fn test_setup_router() {
        let _ = rustls::crypto::ring::default_provider().install_default();

        let mut rng = thread_rng();

        // Create the test router
        let mut tasks = TaskManager::new();
        let (mut router, domains) = setup_test_router(&mut tasks).await;
        // Start the tasks and give them some time to finish
        tasks.start();
        tokio::time::sleep(Duration::from_secs(1)).await;

        // Pick some random domain & create request
        let domain = domains.choose(&mut rng).unwrap();
        let mut req = axum::extract::Request::new(Body::from(""));
        *req.uri_mut() = Uri::try_from(format!("http://{domain}")).unwrap();
        let conn_info = Arc::new(ConnInfo::default());
        req.extensions_mut().insert(conn_info);
        // Some Swiss IP
        let remote_addr = IpAddr::from_str("77.109.180.4").unwrap();
        req.headers_mut().insert(
            X_REAL_IP,
            HeaderValue::from_str(&remote_addr.to_string()).unwrap(),
        );

        // Send request id
        let request_id = Uuid::from_str("7373F02E-9560-4E16-AC6D-4974300C827B").unwrap();
        req.headers_mut().insert(
            X_REQUEST_ID,
            HeaderValue::from_str(&request_id.to_string()).unwrap(),
        );

        // Make sure that we get right answer
        let resp = router.call(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.extensions().get::<RemoteAddr>().unwrap().0,
            remote_addr,
        );
        assert_eq!(resp.extensions().get::<CountryCode>().unwrap().0, "CH");
        assert_eq!(resp.extensions().get::<RequestId>().unwrap().0, request_id);

        let body = resp.into_body();
        let body = to_bytes(body, 1024).await.unwrap();
        assert_eq!(body, b"X".repeat(512));
    }
}
