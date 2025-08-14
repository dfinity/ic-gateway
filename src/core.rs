use std::sync::{Arc, OnceLock};

use anyhow::{Context, Error, anyhow};
use axum::Router;
use ic_bn_lib::{
    custom_domains::{self, ProvidesCustomDomains},
    http::{self as bnhttp, dns::ApiBnResolver, redirect_to_https},
    tasks::TaskManager,
    tls::{prepare_client_config, verify::NoopServerCertVerifier},
    vector::client::Vector,
};
use itertools::Itertools;
use prometheus::Registry;
use tokio_util::sync::CancellationToken;
use tracing::warn;

use crate::{
    cli::Cli,
    metrics,
    routing::{
        self,
        ic::{create_agent, route_provider::setup_route_provider},
    },
    tls::{self, setup_issuer_providers},
};

pub const SERVICE_NAME: &str = "ic_gateway";
pub const AUTHOR_NAME: &str = "Boundary Node Team <boundary-nodes@dfinity.org>";

// Store env/hostname in statics so that we don't have to clone them
pub static ENV: OnceLock<String> = OnceLock::new();
pub static HOSTNAME: OnceLock<String> = OnceLock::new();

#[allow(clippy::cognitive_complexity)]
pub async fn main(cli: &Cli) -> Result<(), Error> {
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
    rustls::crypto::ring::default_provider()
        .install_default()
        .map_err(|_| anyhow!("unable to install Rustls crypto provider"))?;

    // Prepare some general stuff
    let token = CancellationToken::new();
    let registry = Registry::new_custom(Some(SERVICE_NAME.into()), None)
        .context("unable to create Prometheus registry")?;

    // DNS resolver
    let dns_resolver = bnhttp::dns::Resolver::new((&cli.dns).into());

    // HTTP client
    let mut http_client_opts: bnhttp::client::Options = (&cli.http_client).into();

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

    // Bare reqwest client is for now needed for the Route Provider.
    // TODO improve
    let reqwest_client =
        bnhttp::client::clients_reqwest::new(http_client_opts.clone(), Some(dns_resolver.clone()))?;
    let route_provider = setup_route_provider(cli, reqwest_client.clone()).await?;

    // Create a separate agent that will be used for resolver.
    let agent = create_agent(cli, Arc::new(reqwest_client), route_provider.clone()).await?;
    let api_bn_resolver = ApiBnResolver::new(agent)?;

    let http_client = Arc::new(bnhttp::ReqwestClient::new(
        http_client_opts.clone(),
        Some(dns_resolver.clone()),
    )?);

    let http_client_hyper = Arc::new(bnhttp::HyperClientLeastLoaded::new(
        http_client_opts,
        api_bn_resolver.clone(),
        cli.network.network_http_client_count as usize,
        Some(&registry),
    ));

    // Event sinks
    #[cfg(feature = "clickhouse")]
    let clickhouse = if cli.log.clickhouse.log_clickhouse_url.is_some() {
        Some(Arc::new(
            metrics::Clickhouse::new(&cli.log.clickhouse).context("unable to init Clickhouse")?,
        ))
    } else {
        None
    };
    let vector = cli
        .log
        .vector
        .log_vector_url
        .as_ref()
        .map(|_| Arc::new(Vector::new(&cli.log.vector, http_client.clone(), &registry)));

    // List of cancellable tasks to execute & track
    let mut tasks = TaskManager::new();
    tasks.add("api_bn_resolver", Arc::new(api_bn_resolver));

    // Handle SIGTERM/SIGHUP and Ctrl+C
    // Cancelling a token cancels all of its clones too
    let handler_token = token.clone();
    ctrlc::set_handler(move || handler_token.cancel())?;

    // HTTP server metrics
    let http_metrics = bnhttp::server::Metrics::new(&registry);

    // Custom domains from issuers
    let (issuer_certificate_providers, mut custom_domain_providers) =
        setup_issuer_providers(cli, &mut tasks, http_client.clone(), &registry);

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

    // Create gateway router to serve all endpoints
    let gateway_router = routing::setup_router(
        cli,
        custom_domain_providers,
        &mut tasks,
        http_client.clone(),
        http_client_hyper,
        Arc::clone(&route_provider),
        &registry,
        vector.clone(),
        #[cfg(feature = "clickhouse")]
        clickhouse.clone(),
    )
    .await
    .context("unable to setup Axum router")?;

    // Set up HTTP router (redirecting to HTTPS or serving all endpoints)
    let http_router = if !cli.listen.listen_insecure_serve_http_only {
        Router::new().fallback(redirect_to_https)
    } else {
        gateway_router.clone()
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

    // Create HTTPS server
    if !cli.listen.listen_insecure_serve_http_only {
        // Prepare TLS related stuff
        let rustls_cfg = tls::setup(
            cli,
            &mut tasks,
            #[cfg(feature = "acme")]
            domains.clone(),
            #[cfg(feature = "acme")]
            Arc::new(dns_resolver),
            issuer_certificate_providers,
            &registry,
        )
        .await
        .context("unable to setup TLS")?;

        let https_server = Arc::new(
            bnhttp::ServerBuilder::new(gateway_router)
                .listen_tcp(cli.listen.listen_tls)
                .with_options((&cli.http_server).into())
                .with_metrics(http_metrics.clone())
                .with_rustls_config(rustls_cfg)
                .build()
                .unwrap(),
        );

        tasks.add("https_server", https_server);
    }

    // Setup metrics
    if let Some(addr) = cli.metrics.metrics_listen {
        let router = metrics::setup(&registry, &mut tasks, route_provider);
        let mut opts = bnhttp::server::Options::from(&cli.http_server);
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
    token.cancelled().await;

    warn!("Shutdown signal received, cleaning up");
    tasks.stop().await;

    // Clickhouse/Vector should stop last to ensure that all requests are finished & flushed
    if let Some(v) = vector {
        v.stop().await;
    }

    #[cfg(feature = "clickhouse")]
    if let Some(v) = clickhouse {
        v.stop().await;
    }

    Ok(())
}
