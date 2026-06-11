use std::{
    fmt::Display,
    sync::Arc,
    time::{Duration, Instant},
};

use ahash::AHashMap;
use async_trait::async_trait;
use derive_new::new;
use fqdn::FQDN;
use futures::future::join_all;
use http::Method;
use ic_bn_lib::http::shed::ewma::EWMA;
use ic_bn_lib_common::traits::http::Client;
use tokio::{
    select,
    sync::{mpsc, watch},
    task::JoinHandle,
    time::Interval,
};
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use crate::routing::ic::route_provider::{
    ChecksHealth, HealthCheckResult, HealthyNode, Node, NodeList,
};

#[derive(Debug)]
pub struct HttpHealthChecker {
    client: Arc<dyn Client>,
}

impl Display for HttpHealthChecker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "HttpHealthChecker")
    }
}

#[async_trait]
impl ChecksHealth for HttpHealthChecker {
    async fn health_check(&self, node: &Node) -> HealthCheckResult {
        let req = reqwest::Request::new(Method::GET, node.url_health.clone());
        let start = Instant::now();
        let resp = self.client.execute(req).await;
        let latency = start.elapsed();

        let healthy = match resp {
            Err(e) => {
                info!("{self}: {node}: Health check failed: {e:#}");
                false
            }

            Ok(v) => {
                if v.status().is_success() {
                    true
                } else {
                    info!(
                        "{self}: {node}: Health check failed: bad status code {}",
                        v.status()
                    );
                    false
                }
            }
        };

        HealthCheckResult { latency, healthy }
    }
}

/// Runs health checks agains a single node and sends back the results
#[derive(Debug, new)]
pub struct HealthCheckActor {
    node: Arc<Node>,
    checker: Arc<dyn ChecksHealth>,
    tx: mpsc::Sender<(Arc<Node>, HealthCheckResult)>,
}

impl Display for HealthCheckActor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "HealthCheckActor({})", self.node.hostname)
    }
}

impl HealthCheckActor {
    async fn run(self, interval: Duration, token: CancellationToken) {
        let mut int = tokio::time::interval(interval);
        int.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        info!("{self}: Started");
        loop {
            select! {
                res = self.checker.health_check(&self.node) => {
                    self.tx.send((self.node.clone(), res)).await.ok();
                }
                () = token.cancelled() => {
                    break;
                }
            }

            select! {
                _ = int.tick() => {}
                () = token.cancelled() => {
                    break;
                }
            }
        }

        info!("{self}: Shutting down");
    }
}

pub struct NodeState {
    node: Arc<Node>,
    healthy: Option<bool>,
    reliability: EWMA,
    latency: EWMA,
    token: CancellationToken,
    handle: JoinHandle<()>,
}

impl NodeState {
    async fn stop_actor(self) {
        self.token.cancel();
        self.handle.await.ok();
    }
}

/// Manages HealthCheckActors
pub struct HealthCheckManager {
    nodes: AHashMap<FQDN, NodeState>,
    checker: Arc<dyn ChecksHealth>,
    check_interval: Duration,
    tx: mpsc::Sender<(Arc<Node>, HealthCheckResult)>,
    rx: mpsc::Receiver<(Arc<Node>, HealthCheckResult)>,
    node_list_rx: watch::Receiver<NodeList>,
    healthy_nodes_tx: watch::Sender<Vec<HealthyNode>>,
    idle_interval: Interval,
    ewma_alpha: f64,
}

impl Display for HealthCheckManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "HealthCheckManager")
    }
}

impl HealthCheckManager {
    fn new(
        checker: Arc<dyn ChecksHealth>,
        check_interval: Duration,
        idle_period: Duration,
        node_list_rx: watch::Receiver<NodeList>,
        healthy_nodes_tx: watch::Sender<Vec<HealthyNode>>,
        ewma_alpha: f64,
    ) -> Self {
        let (tx, rx) = mpsc::channel(1024);
        let mut idle_interval = tokio::time::interval(idle_period);
        idle_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        Self {
            nodes: AHashMap::new(),
            checker,
            check_interval,
            rx,
            tx,
            node_list_rx,
            healthy_nodes_tx,
            idle_interval,
            ewma_alpha,
        }
    }

    fn start_actor(&mut self, node: FQDN) {
        let node = Arc::new(Node::new(node));
        let actor = HealthCheckActor::new(node.clone(), self.checker.clone(), self.tx.clone());
        let token = CancellationToken::new();
        let handle = tokio::spawn(actor.run(self.check_interval, token.child_token()));

        let state = NodeState {
            node: node.clone(),
            healthy: None,
            reliability: EWMA::new(self.ewma_alpha),
            latency: EWMA::new(self.ewma_alpha),
            token,
            handle,
        };

        self.nodes.insert(node.hostname.clone(), state);
    }

    /// Starts & stops actors to match the new list of nodes
    async fn update_node_list(&mut self, node_list: NodeList) {
        let start = Instant::now();
        // First extract the nodes that are gone and we need to stop the actors
        let to_stop = self
            .nodes
            .extract_if(|k, _v| !node_list.contains(k))
            .map(|x| x.1)
            .collect::<Vec<_>>();

        // Then make a list of new nodes that we need to start actors for
        let to_start = node_list
            .into_iter()
            .filter_map(|x| (!self.nodes.contains_key(&x)).then_some(x))
            .collect::<Vec<_>>();

        warn!(
            "{self}: Updating node list: {} to start, {} to stop",
            to_start.len(),
            to_stop.len()
        );

        // If we removed some nodes & didn't add anything - trigger an implicit update of healthy nodes.
        // Otherwise removed nodes will be still available until some other node changes health status.
        // If some nodes were added - then the update will come in order once their healthchecks are done.
        if !to_stop.is_empty() && to_start.is_empty() {
            self.send_healthy_nodes();
        }

        // Start & stop actors
        join_all(to_stop.into_iter().map(|x| x.stop_actor())).await;
        for node in to_start {
            self.start_actor(node);
        }

        warn!(
            "{self}: Node list updated in {}s",
            start.elapsed().as_secs_f64()
        );
    }

    /// Sends an updated list of healthy nodes to the receiver
    fn send_healthy_nodes(&mut self) {
        // Do not send a list if we haven't yet got initial health check results
        // from all nodes
        if self.nodes.values().any(|x| x.healthy.is_none()) {
            return;
        }

        let healthy_nodes = self
            .nodes
            .values()
            .filter_map(|x| {
                x.healthy.is_some_and(|x| x).then_some(HealthyNode {
                    node: x.node.clone(),
                    reliability: x.reliability.get().unwrap_or(0.0),
                    latency: x.latency.get().unwrap_or(f64::MAX),
                })
            })
            .collect();

        self.healthy_nodes_tx.send_replace(healthy_nodes);
        // Reset the idle timer so that we don't update too soon again
        self.idle_interval.reset();
    }

    fn update_node_state(&mut self, node: &Arc<Node>, status: &HealthCheckResult) -> bool {
        // Ignore messages from missing nodes (might be buffered from actors that are stopped already)
        let Some(state) = self.nodes.get_mut(&node.hostname) else {
            return false;
        };

        let state_changed = state.healthy.is_none_or(|x| x != status.healthy);

        state.healthy = Some(status.healthy);
        state.reliability.add(f64::from(status.healthy));
        state.latency.add(status.latency.as_secs_f64());

        state_changed
    }

    async fn stop(self) {
        warn!(
            "{self}: Shutting down, stopping {} actors",
            self.nodes.len()
        );

        join_all(self.nodes.into_values().map(|x| x.stop_actor())).await;
    }

    async fn run(mut self, token: CancellationToken) {
        info!("{self}: Started");
        loop {
            select! {
                // Process updates to the node list
                Ok(()) = self.node_list_rx.changed() => {
                    let node_list = self.node_list_rx.borrow_and_update().clone();
                    self.update_node_list(node_list).await;
                }

                // Process update to the node's health state
                Some((node, status)) = self.rx.recv() => {
                    if self.update_node_state(&node, &status) {
                        self.send_healthy_nodes();
                    }
                }

                // Periodically send the list of nodes even if there were no health changes.
                // This allows to take the changes in the latency into account.
                _ = self.idle_interval.tick() => {
                    self.send_healthy_nodes();
                }

                () = token.cancelled() => {
                    break;
                }
            }
        }

        self.stop().await;
    }
}

#[cfg(test)]
mod test {
    use fqdn::fqdn;
    use std::sync::atomic::AtomicUsize;

    use super::*;

    #[derive(Debug, Default)]
    struct TestHealthChecker(AtomicUsize);

    #[async_trait]
    impl ChecksHealth for TestHealthChecker {
        async fn health_check(&self, node: &Node) -> HealthCheckResult {
            if node.hostname == fqdn!("always.healthy") {
                return HealthCheckResult {
                    healthy: true,
                    latency: Duration::from_millis(1),
                };
            }

            let v = self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            // For a few checks everything should be alive
            if v < 3 {
                return HealthCheckResult {
                    healthy: true,
                    latency: Duration::from_millis(10),
                };
            }

            if node.hostname == fqdn!("dead.beef") {
                return HealthCheckResult {
                    healthy: false,
                    latency: Duration::from_millis(10),
                };
            }

            return HealthCheckResult {
                healthy: true,
                latency: Duration::from_millis(10),
            };
        }
    }

    #[tokio::test]
    async fn test_health_check_manager() {
        let checker = Arc::new(TestHealthChecker::default());
        let (node_list_tx, node_list_rx) = watch::channel(NodeList::new(vec![]));
        let (healthy_nodes_tx, mut healthy_nodes_rx) = watch::channel(vec![]);

        let manager = HealthCheckManager::new(
            checker,
            Duration::from_millis(50),
            Duration::from_secs(10),
            node_list_rx,
            healthy_nodes_tx,
            0.5,
        );
        let token = CancellationToken::new();
        let handle = tokio::spawn(manager.run(token.child_token()));

        // Send a new node list
        node_list_tx.send_replace(NodeList::new(vec![fqdn!("always.healthy")]));

        // Wait for a healthy node list
        healthy_nodes_rx.changed().await.unwrap();
        let list = healthy_nodes_rx.borrow_and_update().clone();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].node.hostname, fqdn!("always.healthy"));

        // Send a new node list
        node_list_tx.send_replace(NodeList::new(vec![fqdn!("foo.bar"), fqdn!("dead.beef")]));

        // Initially both should be healthy
        healthy_nodes_rx.changed().await.unwrap();
        let list = healthy_nodes_rx.borrow_and_update().clone();
        assert_eq!(list.len(), 2);
        list.iter()
            .find(|x| x.node.hostname == fqdn!("foo.bar"))
            .unwrap();
        list.iter()
            .find(|x| x.node.hostname == fqdn!("dead.beef"))
            .unwrap();

        // Then only one
        healthy_nodes_rx.changed().await.unwrap();
        let list = healthy_nodes_rx.borrow_and_update().clone();
        assert_eq!(list.len(), 1);
        list.iter()
            .find(|x| x.node.hostname == fqdn!("foo.bar"))
            .unwrap();

        // Send a new node list
        node_list_tx.send_replace(NodeList::new(vec![fqdn!("dead.beef")]));

        // All nodes are dead
        healthy_nodes_rx.changed().await.unwrap();
        let list = healthy_nodes_rx.borrow_and_update().clone();
        assert_eq!(list.len(), 0);

        // Check that it shuts down correctly
        token.cancel();
        handle.await.unwrap();
    }
}
