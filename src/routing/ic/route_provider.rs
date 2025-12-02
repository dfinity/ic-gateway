use std::sync::Arc;

use anyhow::anyhow;
use candid::Principal;
use derive_new::new;
use ic_bn_lib::ic_agent::agent::{
    http_transport::reqwest_transport::reqwest::Client as AgentClient,
    route_provider::{
        RoundRobinRouteProvider, RouteProvider,
        dynamic_routing::{
            dynamic_route_provider::DynamicRouteProviderBuilder, node::Node,
            snapshot::latency_based_routing::LatencyRoutingSnapshot,
        },
    },
};
use ic_bn_lib_common::traits::Healthy;
use tracing::info;
use url::Url;

use crate::{
    Cli,
    routing::ic::{
        health_check::{CHECK_TIMEOUT, HealthChecker},
        nodes_fetcher::{MAINNET_ROOT_SUBNET_ID, NodesFetcher},
    },
};

/// Provides Healthy trait for the RouteProvider
#[derive(new, Debug)]
pub struct RouteProviderWrapper(Arc<dyn RouteProvider>);

impl Healthy for RouteProviderWrapper {
    fn healthy(&self) -> bool {
        // We're healthy if there's at least one healthy Boundary Node
        self.0.routes_stats().healthy.unwrap_or_default() > 0
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
            let snapshot =
                cli.ic
                    .ic_use_k_top_api_nodes
                    .map_or_else(LatencyRoutingSnapshot::new, |k| {
                        info!(
                            "Using up to k_top={k} API Nodes with best score for dynamic routing"
                        );
                        LatencyRoutingSnapshot::new().set_k_top_nodes(k)
                    });

            // This temporary client is only needed for the instantiation. It is later overridden by the checker/fetcher accepting the reqwest_client.
            let tmp_client = AgentClient::builder()
                .build()
                .expect("failed to build the client");
            let checker = HealthChecker::new(reqwest_client.clone(), CHECK_TIMEOUT);
            let subnet_id = Principal::from_text(MAINNET_ROOT_SUBNET_ID).unwrap();
            let fetcher = NodesFetcher::new(reqwest_client, subnet_id, None);
            let route_provider =
                DynamicRouteProviderBuilder::new(snapshot, api_seed_nodes, Arc::new(tmp_client))
                    .with_checker(Arc::new(checker))
                    .with_fetcher(Arc::new(fetcher))
                    .build()
                    .await;

            Arc::new(route_provider)
        };

        route_provider as Arc<dyn RouteProvider>
    } else {
        info!("Using static URLs {urls_str:?} for routing");

        Arc::new(RoundRobinRouteProvider::new(urls_str)?)
    };

    Ok(route_provider)
}
