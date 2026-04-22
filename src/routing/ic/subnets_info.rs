use std::{fmt, sync::Arc, time::Duration};

use ahash::{AHashMap, AHashSet};
use anyhow::{Context, Error};
use arc_swap::ArcSwapOption;
use async_trait::async_trait;
use candid::Principal;
use ic_bn_lib::ic_agent::{
    Agent, agent::SubnetType as AgentSubnetType, hash_tree::SubtreeLookupResult,
};
use ic_bn_lib_common::traits::{Healthy, Run};
use tokio_util::sync::CancellationToken;
use tracing::warn;

/// Retry interval used when no snapshot has been fetched yet and we are in the
/// aggressive boot-strap loop.
const AGGRESSIVE_RETRY_INTERVAL: Duration = Duration::from_secs(5);

/// The type of an IC subnet as reported in the NNS state tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubnetType {
    Application,
    System,
    VerifiedApplication,
    CloudEngine,
    Unknown,
}

impl From<Option<&AgentSubnetType>> for SubnetType {
    fn from(t: Option<&AgentSubnetType>) -> Self {
        match t {
            Some(AgentSubnetType::Application) => Self::Application,
            Some(AgentSubnetType::System) => Self::System,
            Some(AgentSubnetType::VerifiedApplication) => Self::VerifiedApplication,
            Some(AgentSubnetType::CloudEngine) => Self::CloudEngine,
            Some(AgentSubnetType::Unknown(_)) | None => Self::Unknown,
        }
    }
}

/// A single NNS routing entry: a contiguous canister-ID range assigned to a
/// specific subnet, with the subnet's type embedded to avoid a secondary lookup.
#[derive(Clone, Copy)]
struct CanisterRange {
    range_start: Principal,
    range_end: Principal,
    _subnet_id: Principal,
    subnet_type: SubnetType,
}

/// Snapshot of the NNS routing table and subnet types.
///
/// Populated from the NNS state tree by [`SubnetsInfoFetcher`].
pub struct SubnetsInfo {
    /// Sorted by `range_start` for binary-search lookups.
    ranges: Vec<CanisterRange>,
}

impl SubnetsInfo {
    /// Returns the type of the subnet that owns `canister_id`, or `None` if
    /// the canister is not covered by any known range.
    pub fn subnet_type(&self, canister_id: Principal) -> Option<SubnetType> {
        let id = canister_id.as_slice();
        let idx = match self
            .ranges
            .binary_search_by(|r| r.range_start.as_slice().cmp(id))
        {
            Ok(i) => i,            // exact match on range_start
            Err(0) => return None, // before all ranges
            Err(i) => i - 1,       // candidate is the range just below the insertion point
        };
        let r = &self.ranges[idx];
        if id <= r.range_end.as_slice() {
            Some(r.subnet_type)
        } else {
            None
        }
    }
}

impl SubnetsInfo {
    /// Constructs a snapshot from raw range tuples and a subnet-type map,
    /// joining them by subnet ID so that each range entry carries its type
    /// directly. Ranges whose subnet has no known type default to
    /// [`SubnetType::Unknown`]. The resulting list is sorted by `range_start`
    /// to uphold the binary-search invariant required by [`Self::subnet_type`].
    pub(crate) fn new(
        canister_ranges: Vec<(Principal, Principal, Principal)>,
        subnet_types: AHashMap<Principal, SubnetType>,
    ) -> Self {
        let mut ranges: Vec<CanisterRange> = canister_ranges
            .into_iter()
            .map(|(lo, hi, subnet_id)| {
                let subnet_type = subnet_types
                    .get(&subnet_id)
                    .copied()
                    .unwrap_or(SubnetType::Unknown);
                CanisterRange {
                    range_start: lo,
                    range_end: hi,
                    _subnet_id: subnet_id,
                    subnet_type,
                }
            })
            .collect();
        ranges.sort_unstable_by(|a, b| a.range_start.as_slice().cmp(b.range_start.as_slice()));
        Self { ranges }
    }
}

/// Fetches the full routing table and subnet types, storing the result in
/// a shared [`SubnetsInfo`] updated on each run.
///
/// Round trips performed per update cycle:
/// 1. Read NNS `/subnet` to discover all subnet IDs.
/// 2. Concurrently call `fetch_subnet_by_id` for each subnet, fetching both
///    its type and canister ranges directly from the subnet.
pub struct SubnetsInfoFetcher {
    agent: Arc<Agent>,
    root_subnet_id: Principal,
    /// `None` until the first fully-clean fetch completes; holds the last
    /// fully-clean snapshot thereafter.
    pub info: Arc<ArcSwapOption<SubnetsInfo>>,
}

impl fmt::Debug for SubnetsInfoFetcher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SubnetsInfoFetcher")
    }
}

impl Healthy for SubnetsInfoFetcher {
    fn healthy(&self) -> bool {
        self.info.load().is_some()
    }
}

impl SubnetsInfoFetcher {
    pub fn new(agent: Arc<Agent>, root_subnet_id: Principal) -> Self {
        Self {
            agent,
            root_subnet_id,
            info: Arc::new(ArcSwapOption::empty()),
        }
    }

    /// Returns the list of all subnet IDs as reported by the NNS state tree.
    async fn fetch_subnet_ids(&self) -> Result<Vec<Principal>, Error> {
        let cert = self
            .agent
            .read_subnet_state_raw(vec![vec!["subnet".into()]], self.root_subnet_id)
            .await
            .context("failed to read /subnet from NNS")?;

        let subnet_tree = match cert.tree.lookup_subtree([b"subnet".as_ref()]) {
            SubtreeLookupResult::Found(t) => t,
            _ => {
                return Err(anyhow::anyhow!(
                    "/subnet subtree not found in NNS state tree"
                ));
            }
        };

        // list_paths() returns one entry per leaf, so the same subnet ID appears
        // multiple times (once per sub-key: "type", "public_key", "node/...",
        // etc.).  The AHashSet deduplicates them.
        let subnet_ids: AHashSet<Principal> = subnet_tree
            .list_paths()
            .iter()
            .filter(|p| !p.is_empty())
            .map(|p| {
                Principal::try_from_slice(p[0].as_bytes())
                    .context("malformed subnet ID in NNS tree")
            })
            .collect::<Result<_, _>>()?;

        Ok(subnet_ids.into_iter().collect())
    }

    /// Fetches a fresh snapshot of the full routing table.
    async fn fetch(&self) -> Result<SubnetsInfo, Error> {
        let subnet_ids = self.fetch_subnet_ids().await?;

        let futures = subnet_ids.iter().map(|&subnet_id| async move {
            let subnet = self
                .agent
                .fetch_subnet_by_id(&subnet_id)
                .await
                .with_context(|| format!("failed to fetch subnet info for {subnet_id}"))?;

            let ranges: Vec<(Principal, Principal, Principal)> = subnet
                .iter_canister_ranges()
                .map(|r| (*r.start(), *r.end(), subnet_id))
                .collect();

            let subnet_type = SubnetType::from(subnet.subnet_type());
            if subnet_type == SubnetType::Unknown {
                return Err(anyhow::anyhow!(
                    "invalid subnet type for subnet {subnet_id}"
                ));
            }

            Ok::<_, Error>((subnet_id, ranges, subnet_type))
        });

        let mut canister_ranges = Vec::new();
        let mut subnet_types = AHashMap::new();
        for (subnet_id, ranges, subnet_type) in futures::future::try_join_all(futures).await? {
            canister_ranges.extend(ranges);
            subnet_types.insert(subnet_id, subnet_type);
        }

        Ok(SubnetsInfo::new(canister_ranges, subnet_types))
    }
}

#[async_trait]
impl Run for SubnetsInfoFetcher {
    async fn run(&self, token: CancellationToken) -> Result<(), Error> {
        // If we already have a snapshot the normal polling cadence is sufficient.
        if self.info.load().is_some() {
            let info = self.fetch().await?;
            self.info.store(Some(Arc::new(info)));
            return Ok(());
        }

        // No snapshot yet: retry aggressively until the first successful fetch
        // or until the shutdown token fires.
        loop {
            match self.fetch().await {
                Ok(info) => {
                    self.info.store(Some(Arc::new(info)));
                    return Ok(());
                }
                Err(e) => {
                    warn!(
                        "SubnetsInfoFetcher: initial fetch failed, retrying in {AGGRESSIVE_RETRY_INTERVAL:?}: {e:#}"
                    );
                }
            }

            tokio::select! {
                () = token.cancelled() => return Ok(()),
                () = tokio::time::sleep(AGGRESSIVE_RETRY_INTERVAL) => {}
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test::TEST_ROOT_SUBNET_ID;
    use httptest::{Expectation, Server, matchers::*, responders::*};
    use ic_bn_lib_common::principal;

    fn make_fetcher(server: &Server, root_subnet_id: Principal) -> SubnetsInfoFetcher {
        let agent = Agent::builder()
            .with_url(server.url_str("/"))
            .build()
            .expect("failed to build agent");

        SubnetsInfoFetcher::new(Arc::new(agent), root_subnet_id)
    }

    #[test]
    fn subnet_type_lookup() {
        let subnet_sys = Principal::from_slice(&[0xAA]);
        let subnet_app = Principal::from_slice(&[0xBB]);

        // system range:  [0x10, 0x17]
        // gap:           [0x18, 0x1F]
        // app range:     [0x20, 0x2F]
        let lo_sys = Principal::from_slice(&[0x10]);
        let hi_sys = Principal::from_slice(&[0x17]);
        let lo_app = Principal::from_slice(&[0x20]);
        let hi_app = Principal::from_slice(&[0x2F]);

        let ranges = vec![(lo_sys, hi_sys, subnet_sys), (lo_app, hi_app, subnet_app)];
        let mut types = AHashMap::new();
        types.insert(subnet_sys, SubnetType::System);
        types.insert(subnet_app, SubnetType::Application);

        let store = ArcSwapOption::empty();
        store.store(Some(Arc::new(SubnetsInfo::new(ranges, types))));
        let info = store.load();
        let info = info.as_ref().unwrap();

        // mid-range hits
        assert_eq!(
            info.subnet_type(Principal::from_slice(&[0x13])),
            Some(SubnetType::System)
        );
        assert_eq!(
            info.subnet_type(Principal::from_slice(&[0x25])),
            Some(SubnetType::Application)
        );
        // exact boundary hits
        assert_eq!(info.subnet_type(lo_sys), Some(SubnetType::System));
        assert_eq!(info.subnet_type(hi_sys), Some(SubnetType::System));
        assert_eq!(info.subnet_type(lo_app), Some(SubnetType::Application));
        assert_eq!(info.subnet_type(hi_app), Some(SubnetType::Application));
        // outside all ranges
        assert_eq!(info.subnet_type(Principal::from_slice(&[0x05])), None);
        assert_eq!(info.subnet_type(Principal::from_slice(&[0x35])), None);
        // gap between the two ranges
        assert_eq!(info.subnet_type(Principal::from_slice(&[0x19])), None);
    }

    #[tokio::test]
    async fn fetch_error_leaves_info_as_none() {
        let root_id = principal!(TEST_ROOT_SUBNET_ID);
        let path = format!("/api/v3/subnet/{TEST_ROOT_SUBNET_ID}/read_state");

        let server = Server::run();
        server.expect(
            Expectation::matching(request::method_path("POST", path))
                .respond_with(status_code(500)),
        );

        let fetcher = make_fetcher(&server, root_id);
        assert!(fetcher.fetch().await.is_err());
        assert!(
            fetcher.info.load().is_none(),
            "info must stay None when fetch fails"
        );
    }

    #[tokio::test]
    async fn fetch_error_preserves_previous_snapshot() {
        let root_id = principal!(TEST_ROOT_SUBNET_ID);
        let path = format!("/api/v3/subnet/{TEST_ROOT_SUBNET_ID}/read_state");

        let server = Server::run();
        server.expect(
            Expectation::matching(request::method_path("POST", path))
                .respond_with(status_code(500)),
        );

        let fetcher = make_fetcher(&server, root_id);

        // Seed a known snapshot directly, simulating a previously successful fetch.
        let seed = SubnetsInfo::new(vec![], AHashMap::new());
        fetcher.info.store(Some(Arc::new(seed)));

        assert!(fetcher.fetch().await.is_err(), "fetch must fail");
        assert!(
            fetcher.info.load().is_some(),
            "info must still be Some after a failed fetch"
        );
    }
}
