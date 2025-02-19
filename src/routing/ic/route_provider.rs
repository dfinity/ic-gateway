use std::sync::Arc;

use anyhow::anyhow;
use axum::async_trait;
use candid::Principal;
use ic_agent::agent::http_transport::reqwest_transport::reqwest::Client as AgentClient;
use ic_agent::agent::route_provider::{
    dynamic_routing::{
        dynamic_route_provider::DynamicRouteProviderBuilder, node::Node,
        snapshot::latency_based_routing::LatencyRoutingSnapshot,
    },
    RoundRobinRouteProvider, RouteProvider,
};
use ic_bn_lib::tasks::Run;
use prometheus::{register_int_gauge_with_registry, IntGauge, Registry};
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};
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

struct ApiBoundaryNodesMetrics {
    total_nodes: IntGauge,
    healthy_nodes: IntGauge,
}

pub struct ApiBoundaryNodesStats {
    _route_provider: Arc<dyn RouteProvider>,
    metrics: ApiBoundaryNodesMetrics,
}

impl ApiBoundaryNodesMetrics {
    fn new(registry: &Registry) -> Self {
        Self {
            total_nodes: register_int_gauge_with_registry!(
                format!("total_api_boundary_nodes"),
                format!(
                    "Total number of existing API boundary nodes (both healthy and unhealthy)."
                ),
                registry
            )
            .unwrap(),

            healthy_nodes: register_int_gauge_with_registry!(
                format!("healthy_api_boundary_nodes"),
                format!("Number of currently healthy API boundary nodes"),
                registry,
            )
            .unwrap(),
        }
    }
}

impl ApiBoundaryNodesStats {
    pub fn new(route_provider: Arc<dyn RouteProvider>, registry: &Registry) -> Self {
        Self {
            _route_provider: route_provider,
            metrics: ApiBoundaryNodesMetrics::new(registry),
        }
    }
}

#[async_trait]
impl Run for ApiBoundaryNodesStats {
    async fn run(&self, _: CancellationToken) -> Result<(), anyhow::Error> {
        self.metrics.total_nodes.set(1_i64);
        self.metrics.healthy_nodes.set(1_i64);
        // TODO: remove this line
        warn!("Running the ApiBoundaryNodesStats");
        Ok(())
    }
}
