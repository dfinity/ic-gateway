use std::{
    fmt::{Debug, Display},
    sync::Arc,
};

use arc_swap::ArcSwapOption;
use derive_new::new;
use tokio::{select, sync::watch};
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};
use url::Url;

use crate::routing::ic::route_provider::{HealthyNode, wrr::Wrr};

/// Snapshot of the routes
pub struct RouteSnapshot {
    pub urls: Vec<Url>,
    pub wrr: Wrr<Url>,
}

/// A single route & its weight
#[derive(Clone, PartialEq, Eq)]
struct Route {
    url: Url,
    weight: usize,
}

impl Display for Route {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}({})", self.url.as_str(), self.weight)
    }
}

impl Debug for Route {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self}")
    }
}

/// Manages healthy routes & sorts them according to their usability
#[derive(new)]
pub struct RoutesManager {
    healthy_nodes_rx: watch::Receiver<Vec<HealthyNode>>,
    routes: Arc<ArcSwapOption<RouteSnapshot>>,
    k_top: Option<usize>,
    reliability_weight: f64,
}

impl Debug for RoutesManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self}")
    }
}

impl Display for RoutesManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "RoutesManager")
    }
}

impl RoutesManager {
    #[allow(clippy::cast_sign_loss)]
    #[allow(clippy::cast_possible_truncation)]
    fn update_routes(&self, mut list: Vec<HealthyNode>) {
        if list.is_empty() {
            self.routes.store(None);
            return;
        }

        let min_latency = list
            .iter()
            .map(|x| x.latency)
            .reduce(f64::min)
            .unwrap_or(0.0);
        let max_latency = list
            .iter()
            .map(|x| x.latency)
            .reduce(f64::max)
            .unwrap_or(f64::MAX);

        let mut routes = Vec::with_capacity(list.len());
        for x in &mut list {
            // Normalize latency to 0.0..1.0 range
            if max_latency - min_latency > 0.0 {
                x.latency = (x.latency - min_latency) / (max_latency - min_latency);
            }

            // Compute weighted score.
            // Invert reliability so that 0.0 is the most reliable - to match latency.
            let score = self.reliability_weight.mul_add(
                1.0 - x.reliability,
                (1.0 - self.reliability_weight) * x.latency,
            );

            // Convert score to an integer weight and scale it to the inverted 0..100 range.
            // That is - the higher the weight the more preffered the route is.
            let weight = 100 - (score * 100.0) as usize;

            routes.push(Route {
                url: x.node.url.clone(),
                weight,
            });
        }

        // Sort routes by weight in descending order
        routes.sort_by_key(|b| std::cmp::Reverse(b.weight));

        // Truncate to top k nodes if configured
        if let Some(k) = self.k_top {
            routes.truncate(k);
        }

        // Create & store the snapshot
        let urls = routes.clone().into_iter().map(|x| x.url).collect();
        let urls_weights = routes
            .clone()
            .into_iter()
            .map(|x| (x.weight, x.url))
            .collect();

        let snapshot = RouteSnapshot {
            urls,
            wrr: Wrr::new(urls_weights),
        };

        self.routes.store(Some(Arc::new(snapshot)));
    }

    pub async fn run(mut self, token: CancellationToken) {
        warn!("{self}: Started");

        loop {
            select! {
                Ok(()) = self.healthy_nodes_rx.changed() => {
                    let list = self.healthy_nodes_rx.borrow_and_update().clone();
                    info!("{self}: Got new list of healthy nodes: {list:?}");
                    self.update_routes(list);
                }

                () = token.cancelled() => {
                    break;
                }
            }
        }

        warn!("{self}: Shutting down");
    }
}

#[cfg(test)]
mod test {
    use std::time::Duration;

    use arc_swap::ArcSwapOption;
    use fqdn::fqdn;
    use tokio::sync::watch;

    use crate::routing::ic::route_provider::Node;

    use super::*;

    #[tokio::test]
    async fn test_routes_manager() {
        let nodes = vec![
            HealthyNode {
                node: Arc::new(Node::new(fqdn!("node1"))),
                reliability: 1.0,
                latency: 0.1,
            },
            HealthyNode {
                node: Arc::new(Node::new(fqdn!("node2"))),
                reliability: 0.8,
                latency: 0.11,
            },
            HealthyNode {
                node: Arc::new(Node::new(fqdn!("node3"))),
                reliability: 0.9,
                latency: 0.12,
            },
            HealthyNode {
                node: Arc::new(Node::new(fqdn!("node4"))),
                reliability: 1.0,
                latency: 0.15,
            },
            HealthyNode {
                node: Arc::new(Node::new(fqdn!("node5"))),
                reliability: 1.0,
                latency: 0.5,
            },
        ];

        // Check with k_top=3
        let routes = Arc::new(ArcSwapOption::empty());
        let (tx, rx) = watch::channel(vec![]);
        let token = CancellationToken::new();
        let manager = RoutesManager::new(rx, routes.clone(), Some(3), 0.9);
        let handle = tokio::spawn(manager.run(token.child_token()));

        // Send nodes
        tx.send_replace(nodes.clone());

        // Poll for routes publishing
        loop {
            if let Some(v) = routes.load_full() {
                assert_eq!(
                    *v.urls,
                    vec![
                        "https://node1/".parse().unwrap(),
                        "https://node4/".parse().unwrap(),
                        "https://node3/".parse().unwrap(),
                    ]
                );

                break;
            }

            tokio::time::sleep(Duration::from_millis(1)).await;
        }

        token.cancel();
        handle.await.unwrap();

        routes.store(None);

        // Test w/o k_top - publishes all nodes
        let (tx, rx) = watch::channel(vec![]);
        let token = CancellationToken::new();
        let manager = RoutesManager::new(rx, routes.clone(), None, 0.9);
        let handle = tokio::spawn(manager.run(token.child_token()));

        // Send nodes
        tx.send_replace(nodes);

        // Poll for routes publishing
        loop {
            if let Some(v) = routes.load_full() {
                assert_eq!(
                    *v.urls,
                    vec![
                        "https://node1/".parse().unwrap(),
                        "https://node4/".parse().unwrap(),
                        "https://node3/".parse().unwrap(),
                        "https://node5/".parse().unwrap(),
                        "https://node2/".parse().unwrap(),
                    ]
                );

                break;
            }

            tokio::time::sleep(Duration::from_millis(1)).await;
        }

        token.cancel();
        handle.await.unwrap();
    }
}
