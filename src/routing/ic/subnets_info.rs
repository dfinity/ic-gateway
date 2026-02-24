use std::sync::Arc;

use ahash::{AHashMap, AHashSet};
use anyhow::{Context, Error, anyhow};
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
/// Three NNS `read_state` round trips are performed per update cycle:
/// 1. Read `/subnet` to discover all subnet IDs.
/// 2. Read `/canister_ranges` and `/subnet/<id>/type` in parallel for all
///    discovered subnets.
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

    /// Reads the `/subnet` subtree and returns the list of all known subnet IDs.
    async fn fetch_subnet_ids(&self) -> Result<Vec<Principal>, Error> {
        let cert = self
            .agent
            .read_subnet_state_raw(
                vec![vec!["subnet".into()]],
                self.root_subnet_id,
            )
            .await
            .context("failed to read /subnet from NNS")?;

        let subnet_tree = match cert.tree.lookup_subtree([b"subnet".as_ref()]) {
            SubtreeLookupResult::Found(t) => t,
            _ => return Ok(vec![]),
        };

        // Each top-level path component is a subnet ID; deduplicate because
        // list_paths() returns one entry per leaf.
        let subnet_ids: AHashSet<Principal> = subnet_tree
            .list_paths()
            .iter()
            .filter(|p| !p.is_empty())
            .map(|p| Principal::from_slice(p[0].as_bytes()))
            .collect();

        Ok(subnet_ids.into_iter().collect())
    }

    /// Reads `/canister_ranges` from the NNS state tree and decodes all
    /// CBOR-encoded range chunks for the given subnet IDs into a sorted
    /// routing table.
    async fn fetch_canister_ranges(
        &self,
        subnet_ids: &[Principal],
    ) -> Result<Vec<(Principal, Principal, Principal)>, Error> {
        // The subtree structure is:
        //   canister_ranges/<subnet_id_bytes>/<chunk_start_bytes> = <cbor blob>
        let cert = self
            .agent
            .read_subnet_state_raw(
                vec![vec!["canister_ranges".into()]],
                self.root_subnet_id,
            )
            .await
            .context("failed to read /canister_ranges from NNS")?;

        let ranges_tree = match cert.tree.lookup_subtree([b"canister_ranges".as_ref()]) {
            SubtreeLookupResult::Found(t) => t,
            _ => return Err(anyhow!("/canister_ranges not found in NNS state tree")),
        };

        let mut canister_ranges: Vec<(Principal, Principal, Principal)> = Vec::new();

        for &subnet_id in subnet_ids {
            let subnet_ranges_tree =
                match ranges_tree.lookup_subtree([subnet_id.as_slice()]) {
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

    /// Batch-requests `/subnet/<id>/type` for each of the given subnet IDs and
    /// returns a map from subnet ID to its type.
    async fn fetch_subnet_types(
        &self,
        subnet_ids: &[Principal],
    ) -> Result<AHashMap<Principal, SubnetType>, Error> {
        let type_paths: Vec<Vec<Label<Vec<u8>>>> = subnet_ids
            .iter()
            .map(|id| {
                vec!["subnet".into(), Label::from_bytes(id.as_slice()), "type".into()]
            })
            .collect();

        let cert = self
            .agent
            .read_subnet_state_raw(type_paths, self.root_subnet_id)
            .await
            .context("failed to read subnet types from NNS")?;

        let mut subnet_types: AHashMap<Principal, SubnetType> = AHashMap::new();

        for &subnet_id in subnet_ids {
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
                            std::str::from_utf8(type_bytes).unwrap_or("<invalid utf8>")
                        );
                        continue;
                    }
                },
                _ => continue,
            };

            subnet_types.insert(subnet_id, subnet_type);
        }

        Ok(subnet_types)
    }

    async fn fetch(&self) -> Result<SubnetsInfo, Error> {
        let subnet_ids = self.fetch_subnet_ids().await?;

        if subnet_ids.is_empty() {
            return Ok(SubnetsInfo::default());
        }

        let (canister_ranges, subnet_types) = tokio::try_join!(
            self.fetch_canister_ranges(&subnet_ids),
            self.fetch_subnet_types(&subnet_ids),
        )?;

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
