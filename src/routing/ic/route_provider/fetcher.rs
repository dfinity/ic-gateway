use std::{fmt::Display, str::FromStr, sync::Arc, time::Duration};

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
    async fn fetch_nodes(&self) -> Result<NodeList, RouteError> {
        let api_bns = self
            .agent
            .fetch_api_boundary_nodes_by_subnet_id(MAINNET_ROOT_SUBNET_ID)
            .await
            .map_err(|e| RouteError::UnableToFetchNodes(format!("{e:#}")))?;

        Ok(NodeList::new(
            // Filter out the API BNs with incorrect domains
            api_bns
                .into_iter()
                .filter_map(|x| FQDN::from_str(&x.domain).ok()),
        ))
    }
}

#[derive(Debug)]
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

impl FetcherManager {
    fn new(fetcher: Arc<dyn FetchesNodes>, tx: watch::Sender<NodeList>) -> Self {
        Self {
            fetcher,
            tx,
            snapshot: NodeList::default(),
        }
    }

    async fn refresh(&mut self) -> Result<(), RouteError> {
        let nodes = self.fetcher.fetch_nodes().await?;
        info!("{self}: Got a list of API BNs: {nodes}");

        // Check if the new list is different
        if self.snapshot != nodes {
            warn!(
                "{self}: List of API BNs changed ({}), publishing",
                nodes.len()
            );
            warn!("{self}: New node list: {nodes}");
            self.snapshot.clone_from(&nodes);
            self.tx.send_replace(nodes);
        }

        Ok(())
    }

    async fn run(&mut self, interval: Duration, token: CancellationToken) {
        let mut int = tokio::time::interval(interval);
        int.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            if let Err(e) = self.refresh().await {
                warn!("{self}: Refresh error: {e:#}");
            };

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
        async fn fetch_nodes(&self) -> Result<NodeList, RouteError> {
            let v = self.0.fetch_add(1, Ordering::SeqCst);

            if v == 0 {
                Ok(NodeList::new(vec![fqdn!("foo.bar")]))
            } else if v == 1 {
                Err(RouteError::UnableToFetchNodes("foo".into()))
            } else if v == 2 {
                Ok(NodeList::new(vec![fqdn!("dead.beef"), fqdn!("bar.baz")]))
            } else {
                Ok(NodeList::new(vec![fqdn!("bar.baz"), fqdn!("dead.beef")]))
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

        // 1st run 1 node
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
    }
}
