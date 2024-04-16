use anyhow::Error;
use tokio_util::{sync::CancellationToken, task::TaskTracker};
use tracing::{error, warn};

use crate::{cli::Cli, http::server::Server};

pub const SERVICE_NAME: &str = "ic_gateway";
pub const AUTHOR_NAME: &str = "Boundary Node Team <boundary-nodes@dfinity.org>";

pub async fn main(cli: Cli) -> Result<(), Error> {
    let token = CancellationToken::new();
    let tracker = TaskTracker::new();

    // Handle SIGTERM/SIGHUP and Ctrl+C
    // Cancelling a token cancels all of its clones too, except the ones from .child_token()
    let handler_token = token.clone();
    ctrlc::set_handler(move || handler_token.cancel())?;

    let router = axum::Router::new().route("/", axum::routing::get(|| async { "Hello, World!" }));

    let http_server = Server::new(
        cli.http_server.http,
        cli.http_server.backlog,
        router,
        token.child_token(),
        None,
    );

    tracker.spawn(async move {
        match http_server.start().await {
            Ok(()) => {}
            Err(e) => {
                error!("Unable to start server: {e}");
            }
        };
    });

    warn!("Service is running, waiting for the shutdown signal");
    token.cancelled().await;
    warn!("Shutdown signal received, cleaning up");
    tracker.close();
    tracker.wait().await;

    Ok(())
}
