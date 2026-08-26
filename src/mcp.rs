use std::{
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Error, anyhow};
use async_trait::async_trait;
use axum::{
    Router,
    extract::{Request, State},
    middleware::{Next, from_fn_with_state},
    response::{IntoResponse, Redirect, Response},
};
use ic_bn_lib::{
    http::extract_authority,
    tasks::{Run, TaskManager},
};
use imcp2::{
    Agent, IiInstance, McpConfig, McpServer, SharedClients, auth_callbacks_router,
    metrics::{Metrics, write_request_metrics},
};
use prometheus::Registry;
use strum::{Display, EnumString};
use tokio_util::sync::CancellationToken;
use tower::ServiceExt;

#[derive(EnumString, Clone, Copy, Display)]
#[strum(serialize_all = "snake_case")]
pub enum IiType {
    Prod,
    Beta,
}

use crate::cli::McpCli;

struct McpWrapper(McpServer);

#[async_trait]
impl Run for McpWrapper {
    async fn run(&self, token: CancellationToken) -> Result<(), Error> {
        self.0.spawn_session_reaper();
        token.cancelled().await;
        self.0.shutdown();
        Ok(())
    }
}

pub struct McpState {
    hostname: String,
    router: Router,
}

pub async fn middleware(
    State(state): State<Arc<McpState>>,
    request: Request,
    next: Next,
) -> Response {
    // If the request is for the MCP hostname, route it to the MCP router directly
    if let Some(authority) = extract_authority(&request)
        && authority == state.hostname
    {
        return state.router.clone().oneshot(request).await.into_response();
    }

    next.run(request).await.into_response()
}

/// Inject MCP routes into Router
pub fn setup_mcp(
    cli: &McpCli,
    agent: Agent,
    registry: &Registry,
    tasks: &mut TaskManager,
) -> Result<McpState, Error> {
    let ii_instance = match cli.mcp_ii_instance.as_ref().unwrap() {
        IiType::Beta => IiInstance::beta(),
        IiType::Prod => IiInstance::prod(),
    }
    .map_err(Error::msg)?;

    let state_dir = cli
        .mcp_state_dir
        .clone()
        .ok_or_else(|| anyhow!("MCP State directory not specified"))?;

    let config = McpConfig {
        agent,
        instance: ii_instance,
        public_url: cli
            .mcp_public_url
            .as_ref()
            .ok_or_else(|| anyhow!("MCP Public URL not specified"))?
            .to_string()
            .trim_end_matches('/')
            .into(),
        mcp_path: cli.mcp_url_path.clone(),
        clients: SharedClients::load(&state_dir),
        state_dir,
        require_resource: true,
    };

    let mcp = McpServer::new(config);

    let metrics = Metrics::new(
        registry,
        env!("CARGO_PKG_VERSION"),
        option_env!("GIT_SHA").unwrap_or("unknown"),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs()),
        &[&mcp],
    )
    .context("unable to create MCP metrics")?;

    let mcp_redirect_url = cli.mcp_root_redirect.to_string();
    let hostname = cli
        .mcp_public_url
        .clone()
        .unwrap()
        .host_str()
        .unwrap()
        .to_string();

    let router = Router::new()
        .nest_service(mcp.mcp_path(), mcp.mcp_router())
        .merge(mcp.well_known_router())
        .merge(mcp.root_well_known_router())
        .merge(auth_callbacks_router(&[&mcp]))
        .fallback(|| async move { Redirect::permanent(&mcp_redirect_url) })
        .layer(from_fn_with_state(metrics, write_request_metrics));

    tasks.add("mcp", Arc::new(McpWrapper(mcp)));

    Ok(McpState { hostname, router })
}
