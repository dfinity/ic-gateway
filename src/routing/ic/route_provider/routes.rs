use std::{
    fmt::{Debug, Display},
    sync::Arc,
    vec,
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

impl RouteSnapshot {
    pub fn new(items: Vec<(usize, Url)>) -> Self {
        Self {
            urls: items.iter().map(|x| x.1.clone()).collect(),
            wrr: Wrr::new(items),
        }
    }
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

/// Calculates standard deviation
#[allow(clippy::cast_precision_loss)]
fn calc_stddev(data: impl ExactSizeIterator<Item = f64> + Clone) -> Option<f64> {
    let len = data.len();
    if len < 2 {
        return None; // Standard deviation requires at least two data points
    }

    let mean: f64 = data.clone().sum::<f64>() / len as f64;

    let variance: f64 = data
        .map(|x| {
            let diff = x - mean;
            diff * diff
        })
        .sum::<f64>()
        / (len - 1) as f64;

    Some(variance.sqrt())
}

impl RoutesManager {
    #[allow(clippy::cast_sign_loss)]
    #[allow(clippy::cast_possible_truncation)]
    #[allow(clippy::cast_precision_loss)]
    fn update_routes(&self, mut list: Vec<HealthyNode>) {
        if list.is_empty() {
            self.routes.store(None);
            return;
        }

        // Scale the latency into the 0.0..1.0 range
        let max_latency = list
            .iter()
            .map(|x| x.latency_us)
            .reduce(f64::max)
            .unwrap_or(f64::MAX);

        for x in &mut list {
            x.latency_us /= max_latency;
        }

        // Compute the stddev
        let (Some(stddev_latency), Some(stddev_reliability)) = (
            calc_stddev(list.iter().map(|x| x.latency_us)),
            calc_stddev(list.iter().map(|x| x.reliability)),
        ) else {
            // If we can't calculate stddev, then there's exactly one node in the list
            // (case with zero nodes is handled earlier) - just use it.
            let snapshot = RouteSnapshot::new(vec![(1, list[0].node.url.clone())]);
            self.routes.store(Some(Arc::new(snapshot)));
            return;
        };

        // Calculate dynamic weights
        let reliability_weight = self.reliability_weight * stddev_reliability;
        let latency_weight = (1.0 - self.reliability_weight) * stddev_latency;

        for x in &mut list {
            // Compute weighted score while inverting the reliability so that it follows the same
            // direction as latency (lower - better).
            // Store the score in `reliability` to avoid allocating a separate vector.
            x.reliability =
                (1.0 - x.reliability).mul_add(reliability_weight, x.latency_us * latency_weight);
        }

        // Sum-normalize the scores & compute the weight in 0..100 range.
        let score_sum = list.iter().map(|x| x.reliability).sum::<f64>();
        let mut routes = Vec::with_capacity(list.len());
        for x in &mut list {
            let weight = ((x.reliability / score_sum) * 100.0) as usize;

            routes.push(Route {
                url: x.node.url.clone(),
                weight,
            });
        }

        // Invert the weights so that the node with the better score gets the highest weight
        let (min_weight, max_weight) = (
            routes.iter().map(|x| x.weight).min().unwrap_or(0),
            routes.iter().map(|x| x.weight).max().unwrap_or(usize::MAX),
        );
        for x in &mut routes {
            x.weight = max_weight + min_weight - x.weight;
        }

        // Sort routes by weight in descending order
        routes.sort_by_key(|b| std::cmp::Reverse(b.weight));

        // Truncate to top k nodes if configured
        if let Some(k) = self.k_top {
            routes.truncate(k);
        }

        // Create & store the snapshot
        info!("{self}: New route snapshot stored: {routes:?}");
        let urls_weights = routes.into_iter().map(|x| (x.weight, x.url)).collect();
        let snapshot = RouteSnapshot::new(urls_weights);
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
                latency_us: 100.0,
            },
            HealthyNode {
                node: Arc::new(Node::new(fqdn!("node2"))),
                reliability: 0.8,
                latency_us: 110.0,
            },
            HealthyNode {
                node: Arc::new(Node::new(fqdn!("node3"))),
                reliability: 0.9,
                latency_us: 120.0,
            },
            HealthyNode {
                node: Arc::new(Node::new(fqdn!("node4"))),
                reliability: 1.0,
                latency_us: 130.0,
            },
            HealthyNode {
                node: Arc::new(Node::new(fqdn!("node5"))),
                reliability: 1.0,
                latency_us: 500.0,
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
                        "https://node2/".parse().unwrap(),
                        "https://node5/".parse().unwrap(),
                    ]
                );

                break;
            }

            tokio::time::sleep(Duration::from_millis(1)).await;
        }

        // Check a single node edge case
        routes.store(None);

        tx.send_replace(vec![HealthyNode {
            node: Arc::new(Node::new(fqdn!("lonely"))),
            reliability: 1.0,
            latency_us: 100.0,
        }]);

        // Poll for routes publishing
        loop {
            if let Some(v) = routes.load_full() {
                assert_eq!(*v.urls, vec!["https://lonely/".parse().unwrap(),]);

                break;
            }

            tokio::time::sleep(Duration::from_millis(1)).await;
        }

        // Check the edge case when there are no healhy nodes
        tx.send_replace(vec![]);

        // Poll for routes publishing - should become None
        loop {
            if routes.load_full().is_none() {
                break;
            }

            tokio::time::sleep(Duration::from_millis(1)).await;
        }

        token.cancel();
        handle.await.unwrap();
    }
}
