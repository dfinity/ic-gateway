use anyhow::Error;
use async_trait::async_trait;
use prometheus::Registry;
use rustls::sign::CertifiedKey;
use std::sync::Arc;
use tokio_util::{sync::CancellationToken, task::TaskTracker};
use tracing::{error, warn};

use crate::{
    cli::Cli,
    http::{server, ReqwestClient, Server},
    routing::{
        self,
        canister::{CanisterResolver, ResolvesCanister},
    },
    tls::{
        self,
        cert::{storage::StoresCertificates, LooksupCustomDomain, Storage},
        resolver::ResolvesServerCert,
    },
};

pub const SERVICE_NAME: &str = "ic_gateway";
pub const AUTHOR_NAME: &str = "Boundary Node Team <boundary-nodes@dfinity.org>";

// Long running task that can be cancelled by a token
#[async_trait]
pub trait Run: Send + Sync {
    async fn run(&self, token: CancellationToken) -> Result<(), Error>;
}

pub async fn main(cli: &Cli) -> Result<(), Error> {
    let token = CancellationToken::new();
    let tracker = TaskTracker::new();

    let registry = Registry::new();

    let http_client = Arc::new(ReqwestClient::new(cli)?);

    // Handle SIGTERM/SIGHUP and Ctrl+C
    // Cancelling a token cancels all of its clones too
    let handler_token = token.clone();
    ctrlc::set_handler(move || handler_token.cancel())?;

    // Make a list of all supported domains
    let mut domains = cli.domain.domains_system.clone();
    domains.extend(cli.domain.domains_app.clone());

    let storage = Arc::new(Storage::new());
    let canister_resolver = CanisterResolver::new(
        domains,
        cli.domain.canister_aliases.clone(),
        storage.clone() as Arc<dyn LooksupCustomDomain>,
    )?;

    // List of cancellable tasks to execute & watch
    let mut runners: Vec<(String, Arc<dyn Run>)> = vec![];

    // Create a router
    let (router, denylist_runner) = routing::setup_router(
        cli,
        http_client.clone(),
        &registry,
        Arc::new(canister_resolver) as Arc<dyn ResolvesCanister>,
    )?;
    if let Some(v) = denylist_runner {
        runners.push(("denylist_updater".into(), v));
    }

    let server_options = server::Options::from(&cli.http_server);
    // Set up HTTP
    let http_server = Arc::new(Server::new(
        cli.http_server.http,
        router.clone(),
        server_options,
        None,
    )) as Arc<dyn Run>;
    runners.push(("http_server".into(), http_server));

    // Set up HTTPS
    let (aggregator, rustls_cfg) = tls::setup(
        cli,
        http_client.clone(),
        storage.clone() as Arc<dyn StoresCertificates<Arc<CertifiedKey>>>,
        storage.clone() as Arc<dyn ResolvesServerCert>,
    )?;
    runners.push(("aggregator".into(), aggregator));

    let https_server = Arc::new(Server::new(
        cli.http_server.https,
        router,
        server_options,
        Some(rustls_cfg),
    )) as Arc<dyn Run>;
    runners.push(("https_server".into(), https_server));

    // Spawn runners
    for (name, obj) in runners {
        let token = token.child_token();
        tracker.spawn(async move {
            if let Err(e) = obj.run(token).await {
                error!("Runner '{name}' exited with an error: {e}");
            }
        });
    }

    warn!("Service is running, waiting for the shutdown signal");
    token.cancelled().await;

    warn!("Shutdown signal received, cleaning up");
    tracker.close();
    tracker.wait().await;

    Ok(())
}
