use std::fmt::{Debug, Display};

use arc_swap::ArcSwapOption;
use derive_new::new;
use tokio::{select, sync::watch};
use tokio_util::sync::CancellationToken;
use tracing::warn;
use url::Url;

use crate::routing::ic::route_provider::HealthyNode;

pub struct Route {
    url: Url,
    score: f64,
}

/// Manages healthy routes & sorts them according to their usability
#[derive(new)]
pub struct RoutesManager {
    healthy_nodes_rx: watch::Receiver<Vec<HealthyNode>>,
    routes: ArcSwapOption<Vec<Route>>,
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
    fn update_routes(&self, mut list: Vec<HealthyNode>) {
        // Normalize latency to an inverted 0.0..1.0 range,
        // where 1.0 is the lowest latency and 0.0 is the highest
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

        for x in &mut list {
            x.latency = 1.0 - (x.latency - min_latency) / (max_latency - min_latency);
        }
    }

    async fn run(mut self, token: CancellationToken) {
        warn!("{self}: Started");

        loop {
            select! {
                Ok(()) = self.healthy_nodes_rx.changed() => {
                    let list = self.healthy_nodes_rx.borrow_and_update().clone();
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
