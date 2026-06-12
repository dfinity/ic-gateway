use std::{
    collections::hash_set::IntoIter,
    fmt::{Debug, Display},
    ops::{Deref, DerefMut},
    sync::Arc,
    time::Duration,
};

use ahash::{AHashSet, HashSet};
use anyhow::Context;
use async_trait::async_trait;
use bytes::Bytes;
use derive_new::new;
use fqdn::FQDN;
use http::Uri;
use http_body_util::Full;
use ic_bn_lib::ic_agent::agent::{
    HttpService,
    route_provider::{RoundRobinRouteProvider, RouteProvider},
};
use ic_bn_lib_common::traits::{Healthy, http::ClientHttp};
use tokio::fs;
use url::Url;

use crate::{
    Cli,
    routing::ic::route_provider::{
        fetcher::AgentFetcher, health::HttpHealthChecker, provider::DynamicRouteProvider,
    },
};

pub mod fetcher;
pub mod health;
pub mod provider;
pub mod routes;
pub mod wrr;

#[derive(Debug, thiserror::Error)]
pub enum RouteError {
    #[error("Unable to fetch nodes: {0}")]
    UnableToFetchNodes(String),
    #[error("{0}")]
    Other(#[from] anyhow::Error),
}

/// Node with stats after a successful health check
#[derive(Clone)]
pub struct HealthyNode {
    node: Arc<Node>,
    reliability: f64,
    latency: f64,
}

impl Display for HealthyNode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}({:.2}/{:.2}s)",
            self.node, self.reliability, self.latency
        )
    }
}

impl Debug for HealthyNode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self}")
    }
}

/// A list of all API BNs
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

#[derive(Clone, PartialEq, Eq)]
pub struct Node {
    hostname: FQDN,
    url: Url,
    uri_health: Uri,
}

impl Node {
    fn new(hostname: FQDN) -> Self {
        // SAFETY: This always succeeds for an FQDN if it is not empty
        let url = format!("https://{hostname}").parse().unwrap();
        let uri_health = format!("https://{hostname}/health").parse().unwrap();

        Self {
            hostname,
            url,
            uri_health,
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

/// Fetches a list of API BNs
#[async_trait]
pub trait FetchesNodes: Send + Sync + Debug {
    async fn fetch_nodes(&self) -> Result<Vec<String>, RouteError>;
}

/// Result of a node health check
#[derive(Debug, Clone)]
pub struct HealthCheckResult {
    latency: Duration,
    healthy: bool,
}

/// Checks health of a given node
#[async_trait]
pub trait ChecksHealth: Send + Sync + Debug {
    async fn health_check(&self, url: &Node) -> HealthCheckResult;
}

/// Creates a route provider to use with Agent
pub async fn setup_route_provider(
    cli: &Cli,
    http_client: Arc<dyn ClientHttp<Full<Bytes>>>,
    http_service: Arc<dyn HttpService>,
) -> anyhow::Result<Arc<dyn RouteProvider>> {
    let health_checker = Arc::new(HttpHealthChecker::new(http_client.clone()));

    let route_provider = if cli.ic.ic_use_discovery {
        let root_key = if let Some(v) = &cli.ic.ic_root_key {
            Some(fs::read(v).await.context("unable to read IC root key")?)
        } else {
            None
        };

        let seed_list = cli
            .ic
            .ic_url
            .clone()
            .into_iter()
            .map(|x| FQDN::from_ascii_str(x.authority()))
            .collect::<Result<Vec<_>, _>>()?;

        DynamicRouteProvider::new(
            seed_list,
            health_checker,
            |x| Ok(Arc::new(AgentFetcher::new(x, http_service, root_key)?)),
            cli.ic.ic_use_k_top_api_nodes,
            0.5,
            0.9,
            Duration::from_mins(10),
            Duration::from_secs(1),
            cli.ic.ic_discovery_idle_interval,
        )? as Arc<dyn RouteProvider>
    } else {
        Arc::new(RoundRobinRouteProvider::new(cli.ic.ic_url.clone())?)
    };

    Ok(route_provider)
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
