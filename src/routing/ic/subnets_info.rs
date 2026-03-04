use std::sync::Arc;

use ahash::{AHashMap, AHashSet};
use anyhow::{Context, Error};
use arc_swap::ArcSwap;
use async_trait::async_trait;
use candid::Principal;
use ic_bn_lib::ic_agent::{
    Agent,
    hash_tree::{Label, LookupResult, SubtreeLookupResult},
};
use ic_bn_lib_common::traits::Run;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

/// The type of an IC subnet as reported in the NNS state tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubnetType {
    Application,
    System,
    VerifiedApplication,
    CloudEngine,
}

impl SubnetType {
    fn from_bytes(bytes: &[u8]) -> Option<Self> {
        match bytes {
            b"application" => Some(Self::Application),
            b"system" => Some(Self::System),
            b"verified_application" => Some(Self::VerifiedApplication),
            b"cloud_engine" => Some(Self::CloudEngine),
            _ => None,
        }
    }
}

/// Snapshot of the NNS routing table and subnet types.
///
/// Populated from the NNS state tree by [`SubnetsInfoFetcher`].
#[derive(Default)]
pub struct SubnetsInfo {
    /// Sorted by `lo` for binary-search lookups.
    /// Each entry is `(lo, hi, subnet_id)`.
    canister_ranges: Vec<(Principal, Principal, Principal)>,
    /// Maps each subnet ID to its type.
    subnet_types: AHashMap<Principal, SubnetType>,
}

impl SubnetsInfo {
    /// Returns the type of the subnet that owns `canister_id`, or `None` if
    /// the canister is not covered by any known range.
    pub fn subnet_type(&self, canister_id: Principal) -> Option<SubnetType> {
        let pos = self
            .canister_ranges
            .partition_point(|(lo, _, _)| *lo <= canister_id);
        if pos > 0 {
            let (lo, hi, subnet_id) = &self.canister_ranges[pos - 1];
            if canister_id >= *lo && canister_id <= *hi {
                return self.subnet_types.get(subnet_id).copied();
            }
        }
        None
    }
}

#[cfg(test)]
impl SubnetsInfo {
    /// Constructs a snapshot from raw data for use in tests.
    /// `canister_ranges` need not be pre-sorted.
    pub fn new(
        mut canister_ranges: Vec<(Principal, Principal, Principal)>,
        subnet_types: AHashMap<Principal, SubnetType>,
    ) -> Self {
        canister_ranges.sort_unstable_by_key(|(lo, _, _)| *lo);
        Self {
            canister_ranges,
            subnet_types,
        }
    }
}

/// Fetches the full NNS routing table and subnet types, storing the result in
/// a shared [`SubnetsInfo`] updated on each run.
///
/// NNS `read_state` round trips performed per update cycle:
/// 1. Read `/subnet` to discover all subnet IDs and their types.
/// 2. Read `/canister_ranges/<id>` once per subnet (sequential).
pub struct SubnetsInfoFetcher {
    agent: Arc<Agent>,
    root_subnet_id: Principal,
    pub info: Arc<ArcSwap<SubnetsInfo>>,
}

impl SubnetsInfoFetcher {
    pub fn new(agent: Arc<Agent>, root_subnet_id: Principal) -> Self {
        Self {
            agent,
            root_subnet_id,
            info: Arc::new(ArcSwap::from_pointee(SubnetsInfo::default())),
        }
    }

    async fn fetch_subnets(
        &self,
    ) -> Result<(Vec<Principal>, AHashMap<Principal, SubnetType>), Error> {
        let cert = self
            .agent
            .read_subnet_state_raw(vec![vec!["subnet".into()]], self.root_subnet_id)
            .await
            .context("failed to read /subnet from NNS")?;

        let subnet_tree = match cert.tree.lookup_subtree([b"subnet".as_ref()]) {
            SubtreeLookupResult::Found(t) => t,
            _ => return Ok((vec![], AHashMap::new())),
        };

        // list_paths() returns one entry per leaf, so the same subnet ID appears
        // multiple times (once per sub-key: "type", "public_key", "node/...",
        // etc.).  The AHashSet deduplicates them.
        let subnet_ids: AHashSet<Principal> = subnet_tree
            .list_paths()
            .iter()
            .filter(|p| !p.is_empty())
            .map(|p| Principal::from_slice(p[0].as_bytes()))
            .collect();

        let mut subnet_types: AHashMap<Principal, SubnetType> = AHashMap::new();
        for &subnet_id in &subnet_ids {
            let subnet_type = match cert.tree.lookup_path([
                b"subnet".as_ref(),
                subnet_id.as_slice(),
                b"type",
            ]) {
                LookupResult::Found(type_bytes) => match SubnetType::from_bytes(type_bytes) {
                    Some(t) => t,
                    None => {
                        warn!(
                            "Unknown subnet type {:?} for subnet {subnet_id}",
                            String::from_utf8_lossy(type_bytes)
                        );
                        continue;
                    }
                },
                _ => continue,
            };
            subnet_types.insert(subnet_id, subnet_type);
        }

        Ok((subnet_ids.into_iter().collect(), subnet_types))
    }

    async fn fetch_canister_ranges(
        &self,
        subnet_ids: &[Principal],
    ) -> Result<Vec<(Principal, Principal, Principal)>, Error> {
        // The subtree structure is:
        //   canister_ranges/<subnet_id>/<chunk_start_bytes> = <cbor blob>
        let mut canister_ranges: Vec<(Principal, Principal, Principal)> = Vec::new();

        for &subnet_id in subnet_ids {
            let cert = self
                .agent
                .read_subnet_state_raw(
                    vec![vec![
                        "canister_ranges".into(),
                        Label::from_bytes(subnet_id.as_slice()),
                    ]],
                    self.root_subnet_id,
                )
                .await
                .with_context(|| {
                    format!("failed to read canister_ranges for subnet {subnet_id}")
                })?;

            let subnet_ranges_tree = match cert
                .tree
                .lookup_subtree([b"canister_ranges".as_ref(), subnet_id.as_slice()])
            {
                SubtreeLookupResult::Found(t) => t,
                _ => continue,
            };

            for chunk_path in subnet_ranges_tree.list_paths() {
                if chunk_path.is_empty() {
                    continue;
                }
                if let LookupResult::Found(chunk_bytes) =
                    subnet_ranges_tree.lookup_path([chunk_path[0].as_bytes()])
                {
                    // The shard is CBOR-encoded as: tagged<[*[principal principal]]>
                    // where tagged<t> = #6.55799(t) (self-describing CBOR tag).
                    // serde_cbor 0.11 unwraps tag 55799 transparently.
                    match serde_cbor::from_slice::<Vec<[Principal; 2]>>(chunk_bytes) {
                        Ok(ranges) => canister_ranges
                            .extend(ranges.into_iter().map(|[lo, hi]| (lo, hi, subnet_id))),
                        Err(e) => {
                            warn!(
                                "Failed to decode canister ranges for subnet {subnet_id}: {e:#}"
                            );
                        }
                    }
                }
            }
        }

        // Sort by range start so subnet_type() can binary-search.
        canister_ranges.sort_unstable_by_key(|(lo, _, _)| *lo);

        Ok(canister_ranges)
    }

    async fn fetch(&self) -> Result<SubnetsInfo, Error> {
        let (subnet_ids, subnet_types) = self.fetch_subnets().await?;

        if subnet_ids.is_empty() {
            return Ok(SubnetsInfo::default());
        }

        let canister_ranges = self.fetch_canister_ranges(&subnet_ids).await?;

        Ok(SubnetsInfo {
            canister_ranges,
            subnet_types,
        })
    }
}

#[async_trait]
impl Run for SubnetsInfoFetcher {
    async fn run(&self, _token: CancellationToken) -> Result<(), Error> {
        let subnets_info = self.fetch().await?;
        info!(
            subnets = subnets_info.subnet_types.len(),
            ranges = subnets_info.canister_ranges.len(),
            "Subnet info updated"
        );
        self.info.store(Arc::new(subnets_info));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test::NNS_SUBNET_ID;
    use httptest::{Expectation, Server, matchers::*, responders::*};
    use ic_transport_types::ReadStateResponse;
    use std::time::Duration;
    
    const SUBNET_BIN: &[u8] = include_bytes!("testdata/subnet.bin");
    const NNS_RANGES_BIN: &[u8] = include_bytes!("testdata/nns_canister_ranges.bin");

    /// Wraps raw certificate bytes (as saved by `--save-certs`) into the
    /// CBOR-encoded `ReadStateResponse` body that the IC HTTP API returns.
    fn read_state_response(cert_bytes: &[u8]) -> Vec<u8> {
        let resp = ReadStateResponse {
            certificate: cert_bytes.to_vec(),
        };
        serde_cbor::to_vec(&resp).expect("failed to encode ReadStateResponse")
    }

    /// Creates a `SubnetsInfoFetcher` backed by a real `Agent` that talks to
    /// the given mock `Server`.  Uses a very large ingress-expiry window so
    /// that captured mainnet certificates (which carry old timestamps) still
    /// pass the agent's timestamp check — the same technique used by
    /// `make_untimed_agent` in ic-agent's own test suite.
    fn make_fetcher(server: &Server, root_subnet_id: Principal) -> SubnetsInfoFetcher {
        let agent = Agent::builder()
            .with_url(server.url_str("/"))
            .with_ingress_expiry(Duration::from_secs(u32::MAX as u64))
            .build()
            .expect("failed to build agent");

        SubnetsInfoFetcher::new(Arc::new(agent), root_subnet_id)
    }

    #[tokio::test]
    async fn fetch_subnets_returns_all_subnet_ids() {
        let root_id = Principal::from_text(NNS_SUBNET_ID).unwrap();
        let path = format!("/api/v3/subnet/{NNS_SUBNET_ID}/read_state");

        let server = Server::run();
        server.expect(
            Expectation::matching(request::method_path("POST", path))
                .respond_with(
                    status_code(200)
                        .append_header("Content-Type", "application/cbor")
                        .body(read_state_response(SUBNET_BIN)),
                ),
        );

        let fetcher = make_fetcher(&server, root_id);
        let (ids, _types) = fetcher.fetch_subnets().await.unwrap();

        assert!(
            ids.contains(&root_id),
            "NNS subnet missing from id list"
        );
    }

    #[tokio::test]
    async fn fetch_subnets_types_are_consistent() {
        let root_id = Principal::from_text(NNS_SUBNET_ID).unwrap();
        let path = format!("/api/v3/subnet/{NNS_SUBNET_ID}/read_state");

        let server = Server::run();
        server.expect(
            Expectation::matching(request::method_path("POST", path))
                .respond_with(
                    status_code(200)
                        .append_header("Content-Type", "application/cbor")
                        .body(read_state_response(SUBNET_BIN)),
                ),
        );

        let fetcher = make_fetcher(&server, root_id);
        let (ids, types) = fetcher.fetch_subnets().await.unwrap();

        for (id, _t) in &types {
            assert!(
                ids.contains(id),
                "type entry for {id} has no matching subnet ID"
            );
        }
    }

    #[tokio::test]
    async fn fetch_canister_ranges_nns_subnet() {
        let root_id = Principal::from_text(NNS_SUBNET_ID).unwrap();
        let path = format!("/api/v3/subnet/{NNS_SUBNET_ID}/read_state");

        let server = Server::run();
        server.expect(
            Expectation::matching(request::method_path("POST", path))
                .respond_with(
                    status_code(200)
                        .append_header("Content-Type", "application/cbor")
                        .body(read_state_response(NNS_RANGES_BIN)),
                ),
        );

        let fetcher = make_fetcher(&server, root_id);
        let ranges = fetcher.fetch_canister_ranges(&[root_id]).await.unwrap();

        assert!(!ranges.is_empty(), "NNS subnet must have at least one canister range");
        for (lo, hi, sid) in &ranges {
            assert!(lo <= hi, "lo > hi in NNS canister range");
            assert_eq!(sid, &root_id, "subnet_id mismatch in range entry");
        }
        for w in ranges.windows(2) {
            assert!(w[0].0 <= w[1].0, "ranges not sorted by lo");
        }
    }
}
