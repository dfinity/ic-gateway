use std::sync::Arc;

use anyhow::anyhow;
use candid::Principal;
use ic_agent::agent::http_transport::reqwest_transport::reqwest::Client as AgentClient;
use ic_agent::agent::http_transport::{
    dynamic_routing::{
        dynamic_route_provider::DynamicRouteProviderBuilder, node::Node,
        snapshot::latency_based_routing::LatencyRoutingSnapshot,
    },
    route_provider::{RoundRobinRouteProvider, RouteProvider},
};
use tracing::info;
use url::Url;

use crate::routing::ic::{
    health_check::{HealthChecker, CHECK_TIMEOUT},
    nodes_fetcher::{NodesFetcher, MAINNET_ROOT_SUBNET_ID},
};

pub async fn setup_route_provider(
    urls: &[Url],
    ic_use_discovery: bool,
    reqwest_client: reqwest::Client,
) -> anyhow::Result<Arc<dyn RouteProvider>> {
    let urls_str = urls.iter().map(Url::as_str).collect::<Vec<_>>();

    let route_provider = if ic_use_discovery {
        let api_seed_nodes = urls
            .iter()
            .filter_map(|url| url.domain())
            .map(|url| Node::new(url).unwrap())
            .collect::<Vec<_>>();

        info!("Using dynamically discovered routing URLs, seed API URLs {urls_str:?}");

        if api_seed_nodes.is_empty() {
            return Err(anyhow!("Seed list of API Nodes can't be empty"));
        }

        let route_provider = {
            let snapshot = LatencyRoutingSnapshot::new();
            // This temporary client is only needed for the instantiation. It is later overridden by the checker/fetcher accepting the reqwest_client.
            let tmp_client = AgentClient::builder()
                .build()
                .expect("failed to build the client");
            let checker = HealthChecker::new(reqwest_client.clone(), CHECK_TIMEOUT);
            let subnet_id = Principal::from_text(MAINNET_ROOT_SUBNET_ID).unwrap();
            let fetcher = NodesFetcher::new(reqwest_client, subnet_id, None);
            let route_provider =
                DynamicRouteProviderBuilder::new(snapshot, api_seed_nodes, tmp_client)
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
