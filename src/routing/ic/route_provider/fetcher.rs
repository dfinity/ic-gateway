use std::{
    fmt::{Debug, Display},
    str::FromStr,
    sync::Arc,
    time::Duration,
};

use anyhow::Context;
use async_trait::async_trait;
use fqdn::FQDN;
use ic_bn_lib::ic_agent::{
    Agent,
    agent::{HttpService, route_provider::RouteProvider},
};
use tokio::{select, sync::watch};
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use crate::routing::ic::{
    MAINNET_ROOT_SUBNET_ID,
    route_provider::{FetchesNodes, NodeList, RouteError},
};

/// Fetches a list of API BN nodes using an IC Agent
#[derive(Debug)]
pub struct AgentFetcher {
    agent: Agent,
}

impl AgentFetcher {
    pub fn new(
        route_provider: Arc<dyn RouteProvider>,
        http_service: Arc<dyn HttpService>,
        root_key: Option<Vec<u8>>,
    ) -> Result<Self, RouteError> {
        let agent = Agent::builder()
            .with_arc_http_middleware(http_service)
            .with_arc_route_provider(route_provider)
            .build()
            .context("unable to build Agent")?;

        if let Some(v) = root_key {
            agent.set_root_key(v);
        }

        Ok(Self { agent })
    }
}

#[async_trait]
impl FetchesNodes for AgentFetcher {
    async fn fetch_nodes(&self) -> Result<Vec<String>, RouteError> {
        let api_bns = self
            .agent
            .fetch_api_boundary_nodes_by_subnet_id(MAINNET_ROOT_SUBNET_ID)
            .await
            .map_err(|e| RouteError::UnableToFetchNodes(format!("{e:#}")))?;

        Ok(api_bns.into_iter().map(|x| x.domain).collect())
    }
}

pub struct FetcherManager {
    fetcher: Arc<dyn FetchesNodes>,
    tx: watch::Sender<NodeList>,
    snapshot: NodeList,
}

impl Display for FetcherManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "FetcherManager")
    }
}

impl Debug for FetcherManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self}")
    }
}

impl FetcherManager {
    pub fn new(fetcher: Arc<dyn FetchesNodes>, tx: watch::Sender<NodeList>) -> Self {
        Self {
            fetcher,
            tx,
            snapshot: NodeList::default(),
        }
    }

    async fn refresh(&mut self) -> Result<(), RouteError> {
        let nodes = self.fetcher.fetch_nodes().await?;

        // Safeguard against a case when (for whatever reason) an empty node list is fetched.
        // If we remove all nodes, then we'll end up in a deadlock situation: we can't fetch a new (correct)
        // list because there are no nodes anymore to handle the next fetch request.
        if nodes.is_empty() {
            return Err(RouteError::EmptyNodeList);
        }

        let node_list = NodeList::new(nodes.iter().filter_map(|x| {
            // Hostname should be a valid FQDN & have at least one label
            let hostname = FQDN::from_str(x).ok()?;
            (hostname.depth() > 0).then_some(hostname)
        }));

        info!(
            "{self}: Got a list of API BNs ({}, {} invalid skipped): {node_list:?}",
            node_list.len(),
            nodes.len() - node_list.len()
        );

        // Check if the new list is different
        if self.snapshot != node_list {
            warn!(
                "{self}: List of API BNs changed: {} nodes, (old: {}, new: {node_list}), publishing",
                node_list.len(),
                self.snapshot,
            );

            self.snapshot.clone_from(&node_list);
            self.tx.send_replace(node_list);
        }

        Ok(())
    }

    pub async fn run(mut self, interval: Duration, token: CancellationToken) {
        // Run the fetches aggressively until bootstrapped.
        // This usually takes only a few seconds to succeed.
        let mut int = tokio::time::interval(Duration::from_secs(1));
        int.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            if let Err(e) = self.refresh().await {
                warn!("{self}: Refresh error: {e:#}");
            } else if int.period() != interval {
                // We've got our first successful fetch, use normal interval now
                int = tokio::time::interval(interval);
                int.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            }

            select! {
                _ = int.tick() => {}
                () = token.cancelled() => {
                    warn!("{self}: Shutting down");
                    break;
                }
            }
        }
    }
}

#[cfg(test)]
mod test {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use fqdn::fqdn;

    use super::*;
    use crate::routing::ic::route_provider::{FetchesNodes, RouteError};

    #[derive(Default, Debug)]
    struct TestFetcher(AtomicUsize);

    #[async_trait]
    impl FetchesNodes for TestFetcher {
        async fn fetch_nodes(&self) -> Result<Vec<String>, RouteError> {
            let v = self.0.fetch_add(1, Ordering::SeqCst);

            if v == 0 {
                Ok(vec!["foo.bar".into(), ".".into()])
            } else if v == 1 {
                Err(RouteError::UnableToFetchNodes("foo".into()))
            } else if v == 2 {
                Ok(vec!["dead.beef".into(), "bar.baz".into()])
            } else if v == 3 {
                Ok(vec!["bar.baz".into(), "dead.beef".into()])
            } else {
                Ok(vec![])
            }
        }
    }

    #[tokio::test]
    async fn test_fetcher() {
        let fetcher = TestFetcher::default();
        let (tx, mut rx) = watch::channel(NodeList::new(vec![]));
        let mut manager = FetcherManager::new(Arc::new(fetcher), tx);

        // Consume the initial value
        assert!(rx.borrow_and_update().is_empty());

        // 1st run 1 node, "." is skipped
        manager.refresh().await.unwrap();
        rx.changed().await.unwrap();
        assert_eq!(
            rx.borrow_and_update().clone(),
            NodeList::new(vec![fqdn!("foo.bar")])
        );

        // 2nd run fails, data should remain the sanme
        assert!(manager.refresh().await.is_err());
        assert!(!rx.has_changed().unwrap());
        assert_eq!(
            rx.borrow_and_update().clone(),
            NodeList::new(vec![fqdn!("foo.bar")])
        );

        // 3rd run 2 nodes, sorted
        manager.refresh().await.unwrap();
        rx.changed().await.unwrap();
        assert_eq!(
            rx.borrow_and_update().clone(),
            NodeList::new(vec![fqdn!("bar.baz"), fqdn!("dead.beef")])
        );

        // 4th run data is the same, so shouldn't send over channel
        manager.refresh().await.unwrap();
        assert!(!rx.has_changed().unwrap());
        assert_eq!(
            rx.borrow_and_update().clone(),
            NodeList::new(vec![fqdn!("bar.baz"), fqdn!("dead.beef")])
        );

        // 5th run empty list, should fail the refresh.
        // data should remain the same.
        assert!(manager.refresh().await.is_err());
        assert!(!rx.has_changed().unwrap());
        assert_eq!(
            rx.borrow_and_update().clone(),
            NodeList::new(vec![fqdn!("bar.baz"), fqdn!("dead.beef")])
        );
    }
}
