use std::{error::Error as StdError, sync::Arc};

use anyhow::{anyhow, Error};
use async_trait::async_trait;
use prometheus::Registry;
use rustls::sign::CertifiedKey;
use tokio_util::{sync::CancellationToken, task::TaskTracker};
use tracing::{error, warn};

use crate::{
    cli::Cli,
    http, metrics,
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
pub struct Runner(pub String, pub Arc<dyn Run>);

#[async_trait]
impl Run for http::Server {
    async fn run(&self, token: CancellationToken) -> Result<(), Error> {
        self.serve(token).await
    }
}

pub fn error_source<E: StdError + 'static>(error: &impl StdError) -> Option<&E> {
    let mut source = error.source();
    while let Some(err) = source {
        if let Some(v) = err.downcast_ref() {
            return Some(v);
        }

        source = err.source();
    }

    None
}

pub async fn main(cli: &Cli) -> Result<(), Error> {
    // Install crypto-provider
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .expect("unable to install rustls crypto provider");

    // Prepare some general stuff
    let token = CancellationToken::new();
    let tracker = TaskTracker::new();
    let registry = Registry::new();
    let http_client = Arc::new(http::ReqwestClient::new(cli.into())?);

    // List of cancellable tasks to execute & track
    let mut runners: Vec<Runner> = vec![];

    // Handle SIGTERM/SIGHUP and Ctrl+C
    // Cancelling a token cancels all of its clones too
    let handler_token = token.clone();
    ctrlc::set_handler(move || handler_token.cancel())?;

    // Make a list of all supported domains
    let mut domains = cli.domain.domains.clone();
    domains.extend_from_slice(&cli.domain.domains_system);
    domains.extend_from_slice(&cli.domain.domains_app);

    if domains.is_empty() {
        return Err(anyhow!(
            "No domains to serve specified (use --domain/--domain-system/--domain-app)"
        ));
    }

    // Prepare certificate storage
    let storage = Arc::new(Storage::new());

    // Prepare canister resolver to infer canister_id from requests
    let canister_resolver = CanisterResolver::new(
        domains.clone(),
        cli.domain.canister_aliases.clone(),
        storage.clone() as Arc<dyn LooksupCustomDomain>,
    )?;

    // Create a router
    let (router, denylist_runner) = routing::setup_router(
        cli,
        http_client.clone(),
        &registry,
        Arc::new(canister_resolver) as Arc<dyn ResolvesCanister>,
    )?;
    if let Some(v) = denylist_runner {
        runners.push(Runner("denylist_updater".into(), v));
    }

    // Set up HTTP
    let http_server = Arc::new(http::Server::new(
        cli.http_server.http,
        router.clone(),
        (&cli.http_server).into(),
        None,
    )) as Arc<dyn Run>;
    runners.push(Runner("http_server".into(), http_server));

    // Set up HTTPS
    let (tls_runners, rustls_cfg) = tls::setup(
        cli,
        domains,
        http_client.clone(),
        storage.clone() as Arc<dyn StoresCertificates<Arc<CertifiedKey>>>,
        storage.clone() as Arc<dyn ResolvesServerCert>,
    )?;
    runners.extend(tls_runners);

    let https_server = Arc::new(http::Server::new(
        cli.http_server.https,
        router,
        (&cli.http_server).into(),
        Some(rustls_cfg),
    )) as Arc<dyn Run>;
    runners.push(Runner("https_server".into(), https_server));

    // Setup metrics
    if let Some(addr) = cli.metrics.listen {
        let (router, runner) = metrics::setup(&registry);
        runners.push(Runner("metrics_runner".into(), runner));

        let srv = Arc::new(http::Server::new(
            addr,
            router,
            (&cli.http_server).into(),
            None,
        ));
        runners.push(Runner("metrics_server".into(), srv as Arc<dyn Run>));
    }

    // Spawn & track runners
    for r in runners {
        let token = token.child_token();
        tracker.spawn(async move {
            if let Err(e) = r.1.run(token).await {
                error!("Runner '{}' exited with an error: {e}", r.0);
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
