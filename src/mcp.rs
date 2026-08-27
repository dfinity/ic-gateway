use std::{
    fmt::Display,
    str::FromStr,
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
use candid::Principal;
use ic_bn_lib::{
    http::extract_authority,
    tasks::{Run, TaskManager},
};
use imcp2::{
    Agent, IiInstance, McpConfig, McpServer, SharedClients, auth_callbacks_router,
    metrics::{Metrics, write_request_metrics},
};
use itertools::Itertools;
use prometheus::Registry;
use tokio_util::sync::CancellationToken;
use tower::ServiceExt;
use url::Url;

use crate::cli::McpCli;

#[derive(Clone)]
pub enum IiType {
    Prod,
    Beta,
    Custom(IiInstance),
}

impl Display for IiType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Prod => write!(f, "prod"),
            Self::Beta => write!(f, "beta"),
            Self::Custom(instance) => write!(
                f,
                "{}:{}:{}",
                instance.name, instance.ii_canister, instance.ii_url
            ),
        }
    }
}

impl FromStr for IiType {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "prod" => Self::Prod,
            "beta" => Self::Beta,
            _ => {
                let (canister_id, url) = s.splitn(2, ':').collect_tuple().ok_or_else(|| {
                    anyhow!("invalid custom II instance format, expected canister_id:url")
                })?;

                let canister_id =
                    Principal::from_str(canister_id).context("invalid canister id")?;
                let url = Url::parse(url).context("invalid URL")?;

                Self::Custom(IiInstance {
                    name: "custom",
                    ii_canister: canister_id,
                    ii_url: url.to_string(),
                })
            }
        })
    }
}

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
        && authority.eq_ignore_ascii_case(&state.hostname)
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
        IiType::Beta => IiInstance::beta().map_err(Error::msg)?,
        IiType::Prod => IiInstance::prod().map_err(Error::msg)?,
        IiType::Custom(instance) => instance.clone(),
    };

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
        .as_ref()
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

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_ii_type_from_str_prod() {
        assert!(matches!(IiType::from_str("prod").unwrap(), IiType::Prod));
    }

    #[test]
    fn test_ii_type_from_str_beta() {
        assert!(matches!(IiType::from_str("beta").unwrap(), IiType::Beta));
    }

    #[test]
    fn test_ii_type_from_str_custom() {
        let s = "aaaaa-aa:https://example.com";
        let ii_type = IiType::from_str(s).unwrap();

        let IiType::Custom(instance) = ii_type else {
            panic!("expected IiType::Custom");
        };

        assert_eq!(instance.name, "custom");
        assert_eq!(
            instance.ii_canister,
            Principal::from_str("aaaaa-aa").unwrap()
        );
        assert_eq!(instance.ii_url, "https://example.com/");
    }

    #[test]
    fn test_ii_type_from_str_custom_invalid_format() {
        assert!(IiType::from_str("no-colon-here").is_err());
    }

    #[test]
    fn test_ii_type_from_str_custom_invalid_canister_id() {
        assert!(IiType::from_str("not-a-canister-id:https://example.com").is_err());
    }

    #[test]
    fn test_ii_type_from_str_custom_invalid_url() {
        assert!(IiType::from_str("aaaaa-aa:not a url").is_err());
    }
}
