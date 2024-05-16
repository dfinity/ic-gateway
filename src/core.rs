use std::sync::Arc;

use anyhow::{anyhow, Context, Error};
use prometheus::Registry;

use tokio_util::sync::CancellationToken;
use tracing::warn;

use crate::{
    cli::Cli,
    http, metrics,
    routing::{
        self,
        canister::{CanisterResolver, ResolvesCanister},
    },
    tasks::TaskManager,
    tls::{
        self,
        cert::{LooksupCustomDomain, Storage},
    },
};

pub const SERVICE_NAME: &str = "ic_gateway";
pub const AUTHOR_NAME: &str = "Boundary Node Team <boundary-nodes@dfinity.org>";

pub async fn main(cli: &Cli) -> Result<(), Error> {
    // Make a list of all supported domains
    let mut domains = cli.domain.domains.clone();
    domains.extend_from_slice(&cli.domain.domains_system);
    domains.extend_from_slice(&cli.domain.domains_app);

    if domains.is_empty() {
        return Err(anyhow!(
            "No domains to serve specified (use --domain/--domain-system/--domain-app)"
        ));
    }

    // Install crypto-provider
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .expect("unable to install rustls crypto provider");

    // Prepare some general stuff
    let token = CancellationToken::new();
    let registry = Registry::new();
    let dns_resolver = http::dns::Resolver::new((&cli.dns).into());
    let http_client = Arc::new(http::ReqwestClient::new(
        (&cli.http_client).into(),
        dns_resolver.clone(),
    )?);

    // List of cancellable tasks to execute & track
    let mut tasks = TaskManager::new();

    // Handle SIGTERM/SIGHUP and Ctrl+C
    // Cancelling a token cancels all of its clones too
    let handler_token = token.clone();
    ctrlc::set_handler(move || handler_token.cancel())?;

    // Prepare certificate storage
    let storage = Arc::new(Storage::new());

    // Prepare canister resolver to infer canister_id from requests
    let canister_resolver = CanisterResolver::new(
        domains.clone(),
        cli.domain.canister_aliases.clone(),
        storage.clone() as Arc<dyn LooksupCustomDomain>,
    )?;

    // Create a router
    let router = routing::setup_router(
        cli,
        &mut tasks,
        http_client.clone(),
        &registry,
        Arc::new(canister_resolver) as Arc<dyn ResolvesCanister>,
    )?;

    // Set up HTTP
    let http_server = Arc::new(http::Server::new(
        cli.http_server.http,
        router.clone(),
        (&cli.http_server).into(),
        None,
    ));
    tasks.add("http_server", http_server);

    // Set up HTTPS
    let rustls_cfg = tls::setup(
        cli,
        &mut tasks,
        domains,
        http_client.clone(),
        storage.clone(),
        storage.clone(),
        Arc::new(dns_resolver),
    )
    .await
    .context("unable to setup TLS")?;

    let https_server = Arc::new(http::Server::new(
        cli.http_server.https,
        router,
        (&cli.http_server).into(),
        Some(rustls_cfg),
    ));
    tasks.add("https_server", https_server);

    // Setup metrics
    if let Some(addr) = cli.metrics.listen {
        let router = metrics::setup(&registry, &mut tasks);

        let srv = Arc::new(http::Server::new(
            addr,
            router,
            (&cli.http_server).into(),
            None,
        ));
        tasks.add("metrics_server", srv);
    }

    // Spawn & track runners
    tasks.start(&token);

    warn!("Service is running, waiting for the shutdown signal");
    token.cancelled().await;

    warn!("Shutdown signal received, cleaning up");
    tasks.stop().await;

    Ok(())
}
