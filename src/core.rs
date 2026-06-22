use std::{
    sync::{Arc, OnceLock},
    time::Duration,
};

use anyhow::{Context, Error, anyhow};
use axum::Router;
use ic_bn_lib::{
    custom_domains::{self},
    http::{self as bnhttp, dns::ApiBnResolver, middleware::waf::WafLayer, redirect_to_https},
    tasks::TaskManager,
    tls::{prepare_client_config, verify::NoopServerCertVerifier},
    utils::health_manager::HealthManager,
    vector::{self, VectorOptions, client::Vector},
};
use ic_bn_lib_common::{
    traits::{custom_domains::ProvidesCustomDomains, tls::ProvidesCertificates},
    types::{
        dns::Options as DnsOptions,
        http::{ClientOptions, Metrics, ServerOptions},
    },
};
use itertools::Itertools;
use prometheus::Registry;
use tokio_util::sync::CancellationToken;
use tracing::warn;
use tracing_subscriber::{EnvFilter, reload::Handle};

use crate::{
    cli::Cli,
    metrics,
    routing::{
        self,
        domain::CustomDomainStorage,
        ic::{
            MAINNET_ROOT_SUBNET_ID, create_agent,
            http_service::AgentHttpService,
            route_provider::{RouteProviderWrapper, setup_route_provider},
            routing_table_manager::RoutingTableManager,
        },
    },
    tls::{self},
};

pub const SERVICE_NAME: &str = "ic_gateway";
pub const AUTHOR_NAME: &str = "Boundary Node Team <boundary-nodes@dfinity.org>";

// Store env/hostname in statics so that we don't have to clone them
pub static ENV: OnceLock<String> = OnceLock::new();
pub static HOSTNAME: OnceLock<String> = OnceLock::new();

#[allow(clippy::cognitive_complexity)]
pub async fn main(
    cli: &Cli,
    log_handle: Handle<EnvFilter, tracing_subscriber::Registry>,
) -> Result<(), Error> {
    ENV.set(cli.misc.env.clone()).unwrap();
    HOSTNAME.set(cli.misc.hostname.clone()).unwrap();

    if cli.ic.ic_enable_replica_signed_queries {
        warn!("Replica-signed queries are enabled");
    }

    if cli.ic.ic_unsafe_disable_response_verification {
        warn!("Response verification is disabled");
    }

    // Make a list of all supported domains
    let mut domains = cli.domain.domain.clone();
    domains.extend_from_slice(&cli.domain.domain_system);
    domains.extend_from_slice(&cli.domain.domain_app);
    domains.extend_from_slice(&cli.domain.domain_api);

    if domains.is_empty() {
        return Err(anyhow!(
            "No domains to serve specified (use --domain* args)"
        ));
    }

    // Leave only unique domains
    domains = domains.into_iter().unique().collect();

    warn!(
        "Running with domains: {:?}",
        domains.iter().map(|x| x.to_string()).collect::<Vec<_>>()
    );

    // Install crypto-provider
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .map_err(|_| anyhow!("unable to install Rustls crypto provider"))?;

    // Prepare some general stuff
    let shutdown_token = CancellationToken::new();

    let health_manager = Arc::new(HealthManager::default());
    let mut custom_domain_providers: Vec<Arc<dyn ProvidesCustomDomains>> = vec![];
    let mut certificate_providers: Vec<Arc<dyn ProvidesCertificates>> = vec![];

    let registry = Registry::new_custom(Some(SERVICE_NAME.into()), None)
        .context("unable to create Prometheus registry")?;

    // DNS resolver
    let dns_options: DnsOptions = (&cli.dns).into();
    let dns_resolver =
        bnhttp::dns::Resolver::new(dns_options.clone()).context("unable to create DNS Resolver")?;

    // HTTP client
    let mut http_client_opts: ClientOptions = (&cli.http_client).into();

    // Prepare TLS client config
    let mut tls_config = prepare_client_config(&[&rustls::version::TLS13, &rustls::version::TLS12]);

    // Disable TLS certificate verification if instructed
    if cli
        .network
        .network_http_client_insecure_bypass_tls_verification
    {
        tls_config
            .dangerous()
            .set_certificate_verifier(Arc::new(NoopServerCertVerifier::default()));
    }

    http_client_opts.tls_config = Some(tls_config);

    // Reqwest-based HTTP client
    let http_client = Arc::new(bnhttp::ReqwestClient::new(
        http_client_opts.clone(),
        Some(dns_resolver.clone()),
    )?);

    // Simple Hyper-based HTTP client & an HTTP-service for the Agents backed by it.
    // Used by lower-load tasks like RouteProvider
    let http_client_hyper = Arc::new(bnhttp::HyperClient::new(
        http_client_opts.clone(),
        dns_resolver.clone(),
    ));

    let http_service = Arc::new(AgentHttpService::new(
        http_client_hyper.clone(),
        cli.ic.ic_request_retry_interval,
    ));

    // Create route provider
    let (route_provider, dynamic_route_provider) =
        setup_route_provider(cli, http_client_hyper, http_service.clone(), &registry).await?;
    health_manager.add(Arc::new(RouteProviderWrapper::new(route_provider.clone())));

    // Create a separate Agent to use solely with Resolver.
    // This way we avoid a chicken-and-egg problem:
    // - Hyper client needs resolver
    // - Resolver needs Agent
    // - Agent needs Hyper client
    let ic_agent_resolver = create_agent(cli, http_service, route_provider.clone()).await?;
    let api_bn_resolver = ApiBnResolver::new(dns_resolver.clone(), ic_agent_resolver);

    // Least-load Hyper-based HTTP Client
    let http_client_hyper_ll = Arc::new(bnhttp::HyperClientLeastLoaded::new(
        http_client_opts,
        api_bn_resolver.clone(),
        cli.network.network_http_client_count as usize,
        Some(&registry),
    ));

    // HTTP service for the agents
    let http_service_ll = Arc::new(AgentHttpService::new(
        http_client_hyper_ll.clone(),
        cli.ic.ic_request_retry_interval,
    ));

    // Event sinks
    let vector_metrics = vector::client::Metrics::new(&registry);
    let vector_http = if cli.log.vector.log_vector_url.is_some() {
        let vector_opts =
            VectorOptions::try_from(&cli.log.vector).context("unable to parse Vector options")?;

        Some(Arc::new(Vector::new_with_metrics(
            vector_opts,
            http_client.clone(),
            "http",
            vector_metrics.clone(),
        )))
    } else {
        None
    };

    // List of cancellable tasks to execute & track
    let mut tasks = TaskManager::new();
    tasks.add_interval(
        "api_bn_resolver",
        Arc::new(api_bn_resolver),
        Duration::from_mins(1),
    );

    // Handle SIGTERM/SIGHUP and Ctrl+C
    // Cancelling a token cancels all of its clones too
    let handler_token = shutdown_token.clone();
    ctrlc::set_handler(move || handler_token.cancel())?;

    // HTTP server metrics
    let http_metrics = Metrics::new(&registry);

    // Setup custom domains
    let custom_domains_router = if let Some(v) = &cli.custom_domains {
        let router = setup_custom_domains(
            v,
            dns_options,
            &registry,
            &mut tasks,
            &mut certificate_providers,
            &mut custom_domain_providers,
            cli.rate_limit.rate_limit_bypass_token.clone(),
        )
        .await
        .context("unable to setup Custom Domains")?;

        warn!("Custom Domains: initialized");
        Some(router)
    } else {
        None
    };

    // Load generic custom domain providers
    custom_domain_providers.extend(cli.domain.domain_custom_provider.iter().map(|x| {
        warn!("Adding custom domain provider: {x}");

        Arc::new(custom_domains::GenericProvider::new(
            http_client.clone(),
            x.clone(),
            cli.domain.domain_custom_provider_timeout,
        )) as Arc<dyn ProvidesCustomDomains>
    }));

    custom_domain_providers.extend(
        cli.domain
            .domain_custom_provider_timestamped
            .iter()
            .map(|x| {
                warn!("Adding timestamped custom domain provider: {x}");

                Arc::new(custom_domains::GenericProviderTimestamped::new(
                    http_client.clone(),
                    x.clone(),
                    cli.domain.domain_custom_provider_timeout,
                )) as Arc<dyn ProvidesCustomDomains>
            }),
    );

    custom_domain_providers.extend(cli.domain.domain_custom_provider_diff.iter().map(|x| {
        warn!("Adding diff custom domain provider: {x}");

        Arc::new(custom_domains::GenericProviderDiff::new(
            http_client.clone(),
            x.clone(),
            cli.domain.domain_custom_provider_timeout,
        )) as Arc<dyn ProvidesCustomDomains>
    }));

    // Load local file custom domain provider
    if let Some(path) = &cli.domain.domain_custom_provider_local_file {
        warn!("Adding local file custom domain provider: {path}");

        custom_domain_providers.push(
            Arc::new(custom_domains::LocalFileProvider::new(path.into()))
                as Arc<dyn ProvidesCustomDomains>,
        );
    }

    // Create IC Agent for use by RoutingTableManager / SMTP
    let ic_agent = create_agent(cli, http_service_ll, route_provider.clone())
        .await
        .context("unable to create agent for subnets info fetcher")?;

    // Create a routing table manager that handles per-subnet information fetching
    let routing_table_manager = Arc::new(RoutingTableManager::new(
        ic_agent.clone(),
        MAINNET_ROOT_SUBNET_ID,
        cli.ic.ic_routing_table_poll_interval,
        &registry,
    ));
    health_manager.add(routing_table_manager.clone());
    tasks.add("subnets_info_fetcher", routing_table_manager.clone());

    // Setup WAF
    let waf_layer = if cli.waf.waf_enable {
        let v = WafLayer::new_from_cli(&cli.waf, Some(http_client.clone()))
            .context("unable to create WAF layer")?;

        // Run background poller
        tasks.add("waf", Arc::new(v.clone()));
        Some(v)
    } else {
        None
    };

    let custom_domain_storage =
        Arc::new(CustomDomainStorage::new(custom_domain_providers, &registry));
    tasks.add_interval(
        "custom_domain_storage",
        custom_domain_storage.clone(),
        cli.domain.domain_custom_provider_poll_interval,
    );

    // Create gateway router to serve all endpoints
    let gateway_router = routing::setup_router(
        cli,
        custom_domain_storage.clone(),
        log_handle,
        &mut tasks,
        health_manager.clone(),
        http_client.clone(),
        http_client_hyper_ll,
        route_provider.clone(),
        &registry,
        shutdown_token.clone(),
        vector_http.clone(),
        waf_layer,
        custom_domains_router,
        routing_table_manager,
    )
    .await
    .context("unable to setup Axum router")?;

    // Set up HTTP router (redirecting to HTTPS or serving all endpoints)
    let http_router = if cli.listen.listen_insecure_serve_http_only {
        gateway_router.clone()
    } else {
        Router::new().fallback(redirect_to_https)
    };

    // Create HTTP server
    let http_server = Arc::new(
        bnhttp::ServerBuilder::new(http_router)
            .listen_tcp(cli.listen.listen_plain)
            .with_options((&cli.http_server).into())
            .with_metrics(http_metrics.clone())
            .build()
            .unwrap(),
    );
    tasks.add("http_server", http_server);

    // Prepare TLS config
    let rustls_cfg = if cli.listen.listen_insecure_serve_http_only {
        None
    } else {
        Some(
            tls::setup(
                cli,
                &mut tasks,
                health_manager,
                #[cfg(feature = "acme")]
                domains.clone(),
                #[cfg(feature = "acme")]
                Arc::new(dns_resolver),
                certificate_providers,
                &registry,
            )
            .await
            .context("unable to setup TLS")?,
        )
    };

    // Create HTTPS server
    if let Some(v) = rustls_cfg.clone() {
        let https_server = Arc::new(
            bnhttp::ServerBuilder::new(gateway_router)
                .listen_tcp(cli.listen.listen_tls)
                .with_options((&cli.http_server).into())
                .with_metrics(http_metrics.clone())
                .with_rustls_config(v)
                .build()
                .unwrap(),
        );

        tasks.add("https_server", https_server);
    }

    // Setup SMTP server
    #[cfg(feature = "smtp")]
    let vector_smtp = if cli.smtp_server.smtp_server_listen.is_some() {
        crate::smtp::setup_smtp_server(
            cli,
            rustls_cfg.map(Arc::new),
            ic_agent,
            http_client,
            custom_domain_storage,
            &mut tasks,
            &registry,
            vector_metrics,
        )
        .context("unable to setup SMTP server")?
    } else {
        None
    };

    // Setup metrics
    if let Some(addr) = cli.metrics.metrics_listen {
        let router = metrics::setup(&registry, &mut tasks, route_provider);
        let mut opts = ServerOptions::from(&cli.http_server);
        opts.proxy_protocol_mode = cli.metrics.metrics_proxy_protocol_mode;

        let srv = Arc::new(
            bnhttp::ServerBuilder::new(router)
                .listen_tcp(addr)
                .with_options(opts)
                .with_metrics(http_metrics.clone())
                .build()
                .unwrap(),
        );

        tasks.add("metrics_server", srv);
    }

    // Spawn & track tasks
    tasks.start();

    warn!("Service is running, waiting for the shutdown signal");
    shutdown_token.cancelled().await;

    warn!("Shutdown signal received, cleaning up");
    tasks.stop().await;

    if let Some(v) = &dynamic_route_provider {
        v.stop().await;
    }

    // Vector should stop last to ensure that all requests are finished & flushed
    if let Some(v) = vector_http {
        v.stop().await;
    }

    #[cfg(feature = "smtp")]
    if let Some(v) = vector_smtp {
        v.stop().await;
    }

    Ok(())
}

async fn setup_custom_domains(
    cli: &ic_custom_domains_base::cli::CustomDomainsCli,
    dns_options: DnsOptions,
    metrics_registry: &Registry,
    tasks: &mut TaskManager,
    certificate_providers: &mut Vec<Arc<dyn ProvidesCertificates>>,
    custom_domain_providers: &mut Vec<Arc<dyn ProvidesCustomDomains>>,
    rate_limiter_bypass_token: Option<String>,
) -> Result<Router, Error> {
    let token = tasks.token();
    let (workers, router, client) = ic_custom_domains_backend::setup(
        cli,
        dns_options,
        token,
        HOSTNAME.get().unwrap(),
        metrics_registry.clone(),
        rate_limiter_bypass_token,
    )
    .await?;

    for (i, worker) in workers.into_iter().enumerate() {
        tasks.add(&format!("custom_domains_worker_{i}"), Arc::new(worker));
    }
    tasks.add("custom_domains_canister_client", client.clone());

    certificate_providers.push(client.clone());
    custom_domain_providers.push(client);

    Ok(router)
}
