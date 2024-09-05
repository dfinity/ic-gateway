use std::sync::{Arc, OnceLock};

use anyhow::{anyhow, Context, Error};
use axum::Router;
use ic_bn_lib::{http, tasks::TaskManager, tls::sessions};
use itertools::Itertools;
use prometheus::Registry;
use tokio_util::sync::CancellationToken;
use tracing::warn;

use crate::{
    cli::Cli,
    metrics,
    routing::{self},
    tls,
};

pub const SERVICE_NAME: &str = "ic_gateway";
pub const AUTHOR_NAME: &str = "Boundary Node Team <boundary-nodes@dfinity.org>";

// Store env/hostname in statics so that we don't have to clone them
pub static ENV: OnceLock<String> = OnceLock::new();
pub static HOSTNAME: OnceLock<String> = OnceLock::new();

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
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .map_err(|_| anyhow!("unable to install Rustls crypto provider"))?;

    // Prepare some general stuff
    let token = CancellationToken::new();
    let registry = Registry::new_custom(Some(SERVICE_NAME.into()), None)
        .context("unable to create Prometheus registry")?;

    // DNS resolver
    let dns_resolver = http::dns::Resolver::new((&cli.dns).into());

    // HTTP client
    let mut http_client_opts: http::client::Options<_> = (&cli.http_client).into();
    http_client_opts.dns_resolver = Some(dns_resolver.clone());
    let reqwest_client = http::client::new(http_client_opts)?;
    let http_client = Arc::new(http::ReqwestClient::new(reqwest_client.clone()));

    // TLS session cache
    let tls_session_cache = Arc::new(sessions::Storage::new(
        cli.http_server.http_server_tls_session_cache_size,
        cli.http_server.http_server_tls_session_cache_tti,
    ));

    // Event sinks
    let clickhouse = if cli.log.clickhouse.log_clickhouse_url.is_some() {
        Some(Arc::new(
            metrics::Clickhouse::new(&cli.log.clickhouse).context("unable to init Clickhouse")?,
        ))
    } else {
        None
    };
    let vector = cli.log.vector.log_vector_url.as_ref().map(|_| {
        Arc::new(metrics::Vector::new(
            &cli.log.vector,
            http_client.clone(),
            &registry,
        ))
    });

    // List of cancellable tasks to execute & track
    let mut tasks = TaskManager::new();

    // Handle SIGTERM/SIGHUP and Ctrl+C
    // Cancelling a token cancels all of its clones too
    let handler_token = token.clone();
    ctrlc::set_handler(move || handler_token.cancel())?;

    // Prepare TLS related stuff
    let (rustls_cfg, custom_domain_providers) = tls::setup(
        cli,
        &mut tasks,
        domains.clone(),
        http_client.clone(),
        Arc::new(dns_resolver),
        tls_session_cache.clone(),
        &registry,
    )
    .await
    .context("unable to setup TLS")?;

    // Create routers
    let https_router = routing::setup_router(
        cli,
        custom_domain_providers,
        &mut tasks,
        http_client.clone(),
        reqwest_client,
        &registry,
        clickhouse.clone(),
        vector.clone(),
    )
    .await?;
    let http_router = Router::new().fallback(routing::redirect_to_https);

    // HTTP server metrics
    let http_metrics = http::server::Metrics::new(&registry);

    // Set up HTTP
    let http_server = Arc::new(http::Server::new(
        http::server::Addr::Tcp(cli.http_server.http_server_listen_plain),
        http_router,
        (&cli.http_server).into(),
        http_metrics.clone(),
        None,
    ));
    tasks.add("http_server", http_server);

    let https_server = Arc::new(http::Server::new(
        http::server::Addr::Tcp(cli.http_server.http_server_listen_tls),
        https_router,
        (&cli.http_server).into(),
        http_metrics.clone(),
        Some(rustls_cfg),
    ));
    tasks.add("https_server", https_server);

    // Setup metrics
    if let Some(addr) = cli.metrics.metrics_listen {
        let router = metrics::setup(&registry, tls_session_cache, &mut tasks);

        let srv = Arc::new(http::Server::new(
            http::server::Addr::Tcp(addr),
            router,
            (&cli.http_server).into(),
            http_metrics,
            None,
        ));
        tasks.add("metrics_server", srv);
    }

    // Spawn & track tasks
    tasks.start();

    warn!("Service is running, waiting for the shutdown signal");
    token.cancelled().await;

    warn!("Shutdown signal received, cleaning up");
    tasks.stop().await;

    // Clickhouse/Vector should stop last to ensure that all requests are finished & flushed
    if let Some(v) = clickhouse {
        v.stop().await;
    }
    if let Some(v) = vector {
        v.stop().await;
    }

    Ok(())
}
