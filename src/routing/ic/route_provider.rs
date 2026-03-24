use std::{sync::Arc, time::Duration};

use anyhow::anyhow;
use derive_new::new;
use ic_bn_lib::ic_agent::agent::route_provider::{
    RoundRobinRouteProvider, RouteProvider,
    dynamic_routing::{dynamic_route_provider::DynamicRouteProviderBuilder, node::Node},
};
use ic_bn_lib_common::traits::Healthy;
use tokio::time::{sleep, timeout};
use tracing::{info, warn};
use url::Url;

use crate::Cli;

/// Provides Healthy trait for the RouteProvider
#[derive(new, Debug)]
pub struct RouteProviderWrapper(Arc<dyn RouteProvider>);

impl Healthy for RouteProviderWrapper {
    fn healthy(&self) -> bool {
        // Returns true for route providers that support health checks if at least one node is healthy,
        // otherwise for providers that don't support health checks (e.g., RoundRobinRouteProvider) it just returns true.
        self.0
            .routes_stats()
            .healthy
            .map_or(true, |healthy_nodes| healthy_nodes > 0)
    }
}

/// Creates a route provider to use with Agent
pub async fn setup_route_provider(
    cli: &Cli,
    reqwest_client: reqwest::Client,
) -> anyhow::Result<Arc<dyn RouteProvider>> {
    let urls_str = cli.ic.ic_url.iter().map(Url::as_str).collect::<Vec<_>>();

    let route_provider = if cli.ic.ic_use_discovery {
        let api_seed_nodes = cli
            .ic
            .ic_url
            .iter()
            .filter_map(|url| url.domain())
            .map(|url| Node::new(url).unwrap())
            .collect::<Vec<_>>();

        info!("Using dynamically discovered routing URLs, seed API URLs {urls_str:?}");

        if api_seed_nodes.is_empty() {
            return Err(anyhow!("Seed list of API Nodes can't be empty"));
        }

        let route_provider = {
            if let Some(k) = cli.ic.ic_use_k_top_api_nodes {
                info!("Using up to k_top={k} API Nodes with best score for dynamic routing");
            }

            let route_provider = DynamicRouteProviderBuilder::new(
                api_seed_nodes,
                Arc::new(reqwest_client),
                cli.ic.ic_use_k_top_api_nodes,
            )
            .build();

            Arc::new(route_provider)
        };

        route_provider as Arc<dyn RouteProvider>
    } else {
        info!("Using static URLs {urls_str:?} for routing");

        Arc::new(RoundRobinRouteProvider::new(urls_str)?)
    };

    let wrapper = RouteProviderWrapper::new(route_provider.clone());
    if timeout(Duration::from_secs(120), async {
        while !wrapper.healthy() {
            sleep(Duration::from_secs(1)).await;
        }
    })
    .await
    .is_err()
    {
        warn!("Route provider did not become healthy within 2 minutes, continuing anyway");
    }

    Ok(route_provider)
}
