use std::{
    collections::hash_set::IntoIter,
    fmt::{Debug, Display, write},
    ops::{Deref, DerefMut},
    sync::Arc,
    time::Duration,
};

use ahash::{AHashSet, HashSet};
use anyhow::{anyhow, bail};
use async_trait::async_trait;
use derive_new::new;
use fqdn::{FQDN, Fqdn};
use http::StatusCode;
use ic_bn_lib::ic_agent::agent::route_provider::{RoundRobinRouteProvider, RouteProvider};
use ic_bn_lib_common::traits::Healthy;
use itertools::Itertools;
use tokio::time::{sleep, timeout};
use tracing::{info, warn};
use url::Url;

use crate::Cli;

pub mod fetcher;
pub mod health;
pub mod routes;

#[derive(Debug, thiserror::Error)]
pub enum RouteError {
    #[error("Unable to fetch nodes: {0}")]
    UnableToFetchNodes(String),
    #[error("{0}")]
    Other(#[from] anyhow::Error),
}

#[derive(Debug, Clone)]
pub struct HealthyNode {
    node: Arc<Node>,
    reliability: f64,
    latency: f64,
}

#[derive(Default, Clone, PartialEq, Eq)]
pub struct NodeList(AHashSet<FQDN>);

impl NodeList {
    fn new(iter: impl IntoIterator<Item = FQDN>) -> Self {
        Self(AHashSet::from_iter(iter))
    }
}

impl Deref for NodeList {
    type Target = HashSet<FQDN>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for NodeList {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl Debug for NodeList {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self}")
    }
}

impl Display for NodeList {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for (i, node) in self.0.iter().enumerate() {
            if i < self.0.len() - 1 {
                write!(f, "{node}, ")?;
            } else {
                write!(f, "{node}")?;
            }
        }

        Ok(())
    }
}

impl IntoIterator for NodeList {
    type IntoIter = IntoIter<FQDN>;
    type Item = FQDN;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Node {
    hostname: FQDN,
    url: Url,
    url_health: Url,
}

impl Node {
    fn new(hostname: FQDN) -> Self {
        let url = format!("https://{hostname}").parse().unwrap();
        let url_health = format!("https://{hostname}/health").parse().unwrap();

        Self {
            hostname,
            url,
            url_health,
        }
    }
}

impl Debug for Node {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self}")
    }
}

impl Display for Node {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.hostname)
    }
}

/// Result of a node health check
#[derive(Debug, Clone)]
pub struct HealthCheckResult {
    latency: Duration,
    healthy: bool,
}

#[async_trait]
pub trait FetchesNodes: Send + Sync + Debug {
    async fn fetch_nodes(&self) -> Result<NodeList, RouteError>;
}

#[async_trait]
pub trait ChecksHealth: Send + Sync + Debug {
    async fn health_check(&self, url: &Node) -> HealthCheckResult;
}

/// Creates a route provider to use with Agent
pub async fn setup_route_provider(
    cli: &Cli,
    reqwest_client: reqwest::Client,
) -> anyhow::Result<Arc<dyn RouteProvider>> {
    bail!("foo")
}

/// Provides Healthy trait for the `RouteProvider`
#[derive(new, Debug)]
pub struct RouteProviderWrapper(Arc<dyn RouteProvider>);

impl Healthy for RouteProviderWrapper {
    fn healthy(&self) -> bool {
        // Returns true for route providers that support health checks if at least one node is healthy,
        // otherwise for providers that don't support health checks (e.g., RoundRobinRouteProvider) it just returns true.
        self.0
            .routes_stats()
            .healthy
            .is_none_or(|healthy_nodes| healthy_nodes > 0)
    }
}

// /// Creates a route provider to use with Agent
// pub async fn setup_route_provider(
//     cli: &Cli,
//     reqwest_client: reqwest::Client,
// ) -> anyhow::Result<Arc<dyn RouteProvider>> {
//     let urls_str = cli.ic.ic_url.iter().map(Url::as_str).collect::<Vec<_>>();

//     let route_provider = if cli.ic.ic_use_discovery {
//         let api_seed_nodes = cli
//             .ic
//             .ic_url
//             .iter()
//             .filter_map(|url| url.domain())
//             .map(|url| Node::new(url).unwrap())
//             .collect::<Vec<_>>();

//         info!("Using dynamically discovered routing URLs, seed API URLs {urls_str:?}");

//         if api_seed_nodes.is_empty() {
//             return Err(anyhow!("Seed list of API Nodes can't be empty"));
//         }

//         let route_provider = {
//             if let Some(k) = cli.ic.ic_use_k_top_api_nodes {
//                 info!("Using up to k_top={k} API Nodes with best score for dynamic routing");
//             }

//             let route_provider = DynamicRouteProviderBuilder::new(
//                 api_seed_nodes,
//                 Arc::new(reqwest_client),
//                 cli.ic.ic_use_k_top_api_nodes,
//             )
//             .build();

//             Arc::new(route_provider)
//         };

//         route_provider as Arc<dyn RouteProvider>
//     } else {
//         info!("Using static URLs {urls_str:?} for routing");

//         Arc::new(RoundRobinRouteProvider::new(urls_str)?)
//     };

//     let wrapper = RouteProviderWrapper::new(route_provider.clone());
//     if timeout(Duration::from_mins(2), async {
//         while !wrapper.healthy() {
//             sleep(Duration::from_secs(1)).await;
//         }
//     })
//     .await
//     .is_err()
//     {
//         warn!("Route provider did not become healthy within 2 minutes, continuing anyway");
//     }

//     Ok(route_provider)
// }
