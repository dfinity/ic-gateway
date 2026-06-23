use std::{
    fmt::{Debug, Display},
    sync::Arc,
    time::Duration,
};

use anyhow::anyhow;
use arc_swap::ArcSwapOption;
use derive_new::new;
use fqdn::FQDN;
use ic_bn_lib::ic_agent::{
    AgentError,
    agent::route_provider::{RouteProvider, RoutesStats},
};
use prometheus::{IntCounterVec, Registry, register_int_counter_vec_with_registry};
use tokio::{select, sync::watch};
use tokio_util::{sync::CancellationToken, task::TaskTracker};
use tracing::{info, warn};
use url::Url;

use crate::routing::ic::route_provider::{
    ChecksHealth, FetchesNodes, NodeList, RouteError,
    fetcher::FetcherManager,
    health::HealthCheckManager,
    routes::{RouteSnapshot, RoutesManager},
};

#[derive(Clone)]
pub struct Metrics {
    nodes_picked: IntCounterVec,
}

impl Metrics {
    pub fn new(registry: &Registry) -> Self {
        Self {
            nodes_picked: register_int_counter_vec_with_registry!(
                format!("route_provider_nodes_picked"),
                format!("Counts the number of times each node was picked as a route"),
                &["node"],
                registry
            )
            .unwrap(),
        }
    }
}

/// Handles incoming updates of the node list on behalf of [`DynamicRouteProvider`]
#[derive(new)]
#[allow(clippy::struct_field_names)]
pub struct RouteProviderManager {
    node_list: Arc<ArcSwapOption<NodeList>>,
    node_list_rx: watch::Receiver<NodeList>,
}

impl Display for RouteProviderManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "RouteProviderManager")
    }
}

impl Debug for RouteProviderManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self}")
    }
}

impl RouteProviderManager {
    async fn run(mut self, token: CancellationToken) {
        warn!("{self}: Started");

        loop {
            select! {
                // Process updates to the node list
                Ok(()) = self.node_list_rx.changed() => {
                    let node_list = self.node_list_rx.borrow_and_update().clone();
                    info!("{self}: Got a new list of nodes ({}), storing", node_list.len());
                    self.node_list.store(Some(Arc::new(node_list.clone())));
                }

                () = token.cancelled() => {
                    break;
                }
            }
        }

        warn!("{self}: Shutting down");
    }
}

pub struct DynamicRouteProvider {
    node_list: Arc<ArcSwapOption<NodeList>>,
    routes: Arc<ArcSwapOption<RouteSnapshot>>,
    token: CancellationToken,
    tracker: TaskTracker,
    metrics: Metrics,
}

impl Display for DynamicRouteProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "DynamicRouteProvider")
    }
}

impl Debug for DynamicRouteProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self}")
    }
}

impl DynamicRouteProvider {
    // TODO: Create a builder
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        seed_list: Vec<FQDN>,
        health_checker: Arc<dyn ChecksHealth>,
        fetcher_factory: impl FnOnce(Arc<Self>) -> Result<Arc<dyn FetchesNodes>, RouteError>,
        k_top: Option<usize>,
        ewma_alpha: f64,
        reliability_weight: f64,
        node_fetch_interval: Duration,
        health_check_interval: Duration,
        idle_period: Duration,
        registry: &Registry,
    ) -> Result<Arc<Self>, RouteError> {
        if seed_list.is_empty() {
            return Err(RouteError::Other(anyhow!("Seed list should not be empty")));
        }

        if !(0.0..=1.0).contains(&ewma_alpha) {
            return Err(RouteError::Other(anyhow!(
                "ewma_alpha must be in 0.0..=1.0 range"
            )));
        }

        if !(0.0..=1.0).contains(&reliability_weight) {
            return Err(RouteError::Other(anyhow!(
                "reliability_weight must be in 0.0..=1.0 range"
            )));
        }

        let token = CancellationToken::new();
        let routes = Arc::new(ArcSwapOption::empty());
        let node_list = Arc::new(ArcSwapOption::empty());

        let tracker = TaskTracker::new();
        let route_provider = Arc::new(Self {
            node_list: node_list.clone(),
            routes: routes.clone(),
            token: token.clone(),
            tracker: tracker.clone(),
            metrics: Metrics::new(registry),
        });

        // [`NodeList`] distribution channels - initialize with a seed list & mark it as changed to trigger updates
        let (node_list_tx, mut node_list_rx) = watch::channel(NodeList::new(seed_list));
        node_list_rx.mark_changed();

        // Start node fetcher
        let fetcher_manager = FetcherManager::new(
            fetcher_factory(route_provider.clone())?,
            node_list_tx,
            registry,
        );
        tracker.spawn(fetcher_manager.run(node_fetch_interval, token.child_token()));

        // Start route provider manager
        let route_provider_manager = RouteProviderManager::new(node_list, node_list_rx.clone());
        tracker.spawn(route_provider_manager.run(token.child_token()));

        // Start health checking
        let (healthy_nodes_tx, healthy_nodes_rx) = watch::channel(vec![]);
        let health_check_manager = HealthCheckManager::new(
            health_checker,
            health_check_interval,
            idle_period,
            node_list_rx,
            healthy_nodes_tx,
            ewma_alpha,
            registry,
        );
        tracker.spawn(health_check_manager.run(token.child_token()));

        // Start route manager
        let routes_manager = RoutesManager::new(
            healthy_nodes_rx,
            routes,
            k_top,
            reliability_weight,
            registry,
        );
        tracker.spawn(routes_manager.run(token.child_token()));

        Ok(route_provider)
    }

    /// Tells all actors to stop & waits for them to finish
    pub async fn stop(&self) {
        self.token.cancel();
        self.tracker.close();
        self.tracker.wait().await;
    }
}

impl RouteProvider for DynamicRouteProvider {
    fn n_ordered_routes(&self, n: usize) -> Result<Vec<Url>, AgentError> {
        let Some(snapshot) = self.routes.load_full() else {
            return Err(AgentError::RouteProviderError(
                "No healthy routes available".into(),
            ));
        };

        let n = snapshot.urls.len().min(n);
        let mut top_n = Vec::with_capacity(n);
        for x in &snapshot.urls[..n] {
            top_n.push(x.clone());
        }

        Ok(top_n)
    }

    fn route(&self) -> Result<Url, AgentError> {
        let Some(snapshot) = self.routes.load_full() else {
            return Err(AgentError::RouteProviderError(
                "No healthy routes available".into(),
            ));
        };

        let url = snapshot.wrr.next().clone();
        let hostname = url.authority();
        self.metrics
            .nodes_picked
            .with_label_values(&[hostname])
            .inc();

        Ok(url)
    }

    fn routes_stats(&self) -> RoutesStats {
        RoutesStats {
            total: self.node_list.load_full().map_or(0, |x| x.len()),
            healthy: self.routes.load_full().map(|x| x.urls.len()),
        }
    }
}

#[cfg(test)]
mod test {
    use ahash::AHashMap;
    use async_trait::async_trait;
    use tokio::sync::Semaphore;

    use crate::routing::ic::route_provider::{HealthCheckResult, Node};
    use fqdn::fqdn;

    use super::*;

    #[derive(Debug)]
    struct TestFetcher(Arc<Semaphore>);

    #[async_trait]
    impl FetchesNodes for TestFetcher {
        async fn fetch_nodes(&self) -> Result<Vec<String>, RouteError> {
            let _ = self.0.acquire().await.unwrap();

            Ok(vec![
                "node1".into(),
                "node2".into(),
                "node3".into(),
                "node4".into(),
                "".into(),
                ".".into(),
            ])
        }
    }

    #[derive(Debug)]
    struct TestHealthChecker;

    #[async_trait]
    impl ChecksHealth for TestHealthChecker {
        async fn health_check(&self, node: &Node) -> HealthCheckResult {
            if node.hostname == fqdn!("seed_node1") {
                return HealthCheckResult {
                    healthy: true,
                    latency: Duration::from_millis(30),
                };
            }

            if node.hostname == fqdn!("node1") {
                return HealthCheckResult {
                    healthy: true,
                    latency: Duration::from_millis(30),
                };
            }

            if node.hostname == fqdn!("node2") {
                return HealthCheckResult {
                    healthy: true,
                    latency: Duration::from_millis(20),
                };
            }

            if node.hostname == fqdn!("node3") {
                return HealthCheckResult {
                    healthy: true,
                    latency: Duration::from_millis(10),
                };
            }

            return HealthCheckResult {
                healthy: false,
                latency: Duration::from_millis(0),
            };
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_route_provider() {
        let sem = Arc::new(Semaphore::new(0));
        let fetcher = Arc::new(TestFetcher(sem.clone()));
        let checker = Arc::new(TestHealthChecker);

        let rp = DynamicRouteProvider::new(
            vec![fqdn!("seed_node1"), fqdn!("seed_node2")],
            checker,
            |_| Ok(fetcher),
            None,
            0.5,
            0.9,
            Duration::from_millis(1),
            Duration::from_millis(1),
            Duration::from_secs(5),
            &Registry::new(),
        )
        .unwrap();

        let urls = loop {
            if let Ok(v) = rp.n_ordered_routes(100) {
                break v;
            }

            tokio::time::sleep(Duration::from_millis(1)).await;
        };

        // Initially there should only be a single alive seed node,
        // while the fetcher is blocked by a semaphore.
        assert_eq!(urls, vec!["https://seed_node1/".parse().unwrap()]);
        assert_eq!(rp.routes_stats(), RoutesStats::new(2, Some(1)));

        // Reset the state
        rp.node_list.store(None);
        rp.routes.store(None);

        // Allow fetcher to proceeed
        sem.add_permits(1);

        let urls = loop {
            if let Ok(v) = rp.n_ordered_routes(100) {
                break v;
            }

            tokio::time::sleep(Duration::from_millis(1)).await;
        };

        // Now the seed nodes should be gone and only alive fetched nodes are present
        // in the correct order
        assert_eq!(
            urls,
            vec![
                "https://node3/".parse().unwrap(),
                "https://node2/".parse().unwrap(),
                "https://node1/".parse().unwrap()
            ]
        );
        assert_eq!(rp.routes_stats(), RoutesStats::new(4, Some(3)));

        // Make sure we get requested number of routes
        assert_eq!(
            rp.n_ordered_routes(2).unwrap(),
            vec![
                "https://node3/".parse().unwrap(),
                "https://node2/".parse().unwrap(),
            ],
        );

        let mut hits = AHashMap::new();

        // Do 1k route selections
        for _ in 0..1000 {
            hits.entry(rp.route().unwrap().to_string())
                .and_modify(|x| *x += 1)
                .or_insert(1);
        }

        // Make sure that we get the distribution according to the weights.
        // Should be roughly 3:2:1 ratio.
        assert_eq!(hits["https://node3/"], 497);
        assert_eq!(hits["https://node2/"], 337);
        assert_eq!(hits["https://node1/"], 166);
    }
}
