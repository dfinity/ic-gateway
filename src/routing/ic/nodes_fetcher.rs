use async_trait::async_trait;
use candid::Principal;
use derive_new::new;
use ic_bn_lib::ic_agent::{
    Agent,
    agent::route_provider::dynamic_routing::{
        dynamic_route_provider::DynamicRouteProviderError, node::Node, nodes_fetch::Fetch,
    },
};
use reqwest::Client;
use url::Url;

pub const MAINNET_ROOT_SUBNET_ID: &str =
    "tdb26-jop6k-aogll-7ltgs-eruif-6kk7m-qpktf-gdiqx-mxtrf-vb5e6-eqe";

/// A struct representing the fetcher of the nodes from the topology.
#[derive(Debug, new)]
pub struct NodesFetcher {
    http_client: Client,
    subnet_id: Principal,
    // By default, the nodes fetcher is configured to talk to the mainnet of Internet Computer, and verifies responses using a hard-coded public key.
    // However, for testnets one can set up a custom public key.
    root_key: Option<Vec<u8>>,
}

#[async_trait]
impl Fetch for NodesFetcher {
    async fn fetch(&self, url: Url) -> Result<Vec<Node>, DynamicRouteProviderError> {
        let agent = Agent::builder()
            .with_http_client(self.http_client.clone())
            .with_url(url)
            .build()
            .map_err(|err| {
                DynamicRouteProviderError::NodesFetchError(format!(
                    "Failed to build the agent: {err}"
                ))
            })?;

        if let Some(key) = self.root_key.clone() {
            agent.set_root_key(key);
        }

        let api_bns = agent
            .fetch_api_boundary_nodes_by_subnet_id(self.subnet_id)
            .await
            .map_err(|err| {
                DynamicRouteProviderError::NodesFetchError(format!(
                    "Failed to fetch API nodes: {err}"
                ))
            })?;

        // If some API BNs have invalid domain names, they are discarded.
        let nodes = api_bns
            .into_iter()
            .filter_map(|api_node| api_node.try_into().ok())
            .collect();
        return Ok(nodes);
    }
}
