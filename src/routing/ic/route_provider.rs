use std::{sync::Arc, time::Duration};

use anyhow::anyhow;
use candid::Principal;
use discower_bowndary::{
    check::HealthCheck,
    fetch::{NodesFetcher, NodesFetcherImpl},
    node::Node,
    route_provider::HealthCheckRouteProvider,
    snapshot_health_based::HealthBasedSnapshot,
    transport::TransportProvider,
};
use ic_agent::agent::http_transport::route_provider::{RoundRobinRouteProvider, RouteProvider};
use tracing::info;
use url::Url;

use crate::{
    http::Client,
    routing::ic::{health_check::HealthChecker, transport::ReqwestTransportProvider},
    tasks::TaskManager,
};

const MAINNET_ROOT_SUBNET_ID: &str =
    "tdb26-jop6k-aogll-7ltgs-eruif-6kk7m-qpktf-gdiqx-mxtrf-vb5e6-eqe";
const API_NODES_FETCH_PERIOD: Duration = Duration::from_secs(10);
const API_NODE_HEALTH_TIMEOUT: Duration = Duration::from_secs(2);
const API_NODE_HEALTH_CHECK_PERIOD: Duration = Duration::from_secs(1);

pub fn setup_route_provider(
    urls: &[Url],
    http_client: &Arc<dyn Client>,
    task_manager: &mut TaskManager,
    ic_use_discovery: bool,
) -> anyhow::Result<Arc<dyn RouteProvider>> {
    let urls_str = urls.iter().map(Url::as_str).collect::<Vec<_>>();

    let route_provider = if ic_use_discovery {
        let api_seed_nodes = urls
            .iter()
            .filter_map(|url| url.domain())
            .map(Node::new)
            .collect::<Vec<_>>();

        info!("Using dynamically discovered routing URLs, seed API URLs {urls_str:?}");

        if api_seed_nodes.is_empty() {
            return Err(anyhow!("Seed list of API Nodes can't be empty"));
        }

        let route_provider = {
            let transport_provider = Arc::new(ReqwestTransportProvider::new(http_client.clone()))
                as Arc<dyn TransportProvider>;

            let subnet_id = Principal::from_text(MAINNET_ROOT_SUBNET_ID).unwrap();
            let fetcher = Arc::new(NodesFetcherImpl::new(transport_provider, subnet_id));
            let checker = Arc::new(HealthChecker::new(
                http_client.clone(),
                API_NODE_HEALTH_TIMEOUT,
            ));
            let snapshot = HealthBasedSnapshot::new();

            let route_provider = HealthCheckRouteProvider::new(
                snapshot,
                Arc::clone(&fetcher) as Arc<dyn NodesFetcher>,
                API_NODES_FETCH_PERIOD,
                Arc::clone(&checker) as Arc<dyn HealthCheck>,
                API_NODE_HEALTH_CHECK_PERIOD,
                api_seed_nodes,
            );
            Arc::new(route_provider)
        };

        // Start route_provider as a task, which will terminate the service gracefully.
        task_manager.add("route_provider", route_provider.clone());

        route_provider as Arc<dyn RouteProvider>
    } else {
        info!("Using static URLs {urls_str:?} for routing");

        Arc::new(RoundRobinRouteProvider::new(urls_str)?)
    };

    Ok(route_provider)
}
