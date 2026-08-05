use anyhow::{Error, anyhow};
use axum::Router;
use imcp2::{Agent, IiInstance, McpConfig, McpServer, SharedClients, auth_callbacks_router};
use strum::{Display, EnumString};

#[derive(EnumString, Clone, Copy, Display)]
#[strum(serialize_all = "snake_case")]
pub enum IiType {
    Prod,
    Beta,
}

use crate::cli::McpCli;

/// Inject MCP routes into Router
pub fn setup_mcp(cli: &McpCli, agent: Agent, router: Router) -> Result<(Router, McpServer), Error> {
    let ii_instance = match cli.mcp_ii_instance.as_ref().unwrap() {
        IiType::Beta => IiInstance::beta(),
        IiType::Prod => IiInstance::prod(),
    }
    .map_err(Error::msg)?;

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
        mcp_path: cli.mcp_path.clone(),
        clients: SharedClients::load(),
    };

    let mcp = McpServer::new(config);
    mcp.spawn_session_reaper();

    let router = router
        .nest_service(mcp.mcp_path(), mcp.mcp_router())
        .merge(mcp.well_known_router())
        .merge(mcp.root_well_known_router())
        .merge(auth_callbacks_router(&[&mcp]));

    Ok((router, mcp))
}
