use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Error, anyhow};
use axum::{Router, middleware::from_fn_with_state};
use imcp2::{
    Agent, IiInstance, McpConfig, McpServer, SharedClients, auth_callbacks_router,
    metrics::{Metrics, write_request_metrics},
};
use prometheus::Registry;
use strum::{Display, EnumString};

#[derive(EnumString, Clone, Copy, Display)]
#[strum(serialize_all = "snake_case")]
pub enum IiType {
    Prod,
    Beta,
}

use crate::cli::McpCli;

/// Inject MCP routes into Router
pub fn setup_mcp(
    cli: &McpCli,
    agent: Agent,
    router: Router,
    registry: &Registry,
) -> Result<(Router, McpServer), Error> {
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
    mcp.spawn_session_reaper();

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

    let router = router
        .nest_service(mcp.mcp_path(), mcp.mcp_router())
        .merge(mcp.well_known_router())
        .merge(mcp.root_well_known_router())
        .merge(auth_callbacks_router(&[&mcp]))
        .layer(from_fn_with_state(metrics, write_request_metrics));

    Ok((router, mcp))
}
