use std::{fmt, sync::Arc};

use ahash::{AHashMap, AHashSet};
use anyhow::{Context, Error};
use arc_swap::ArcSwapOption;
use async_trait::async_trait;
use candid::Principal;
use ic_bn_lib::ic_agent::{
    Agent,
    hash_tree::{Label, LookupResult, SubtreeLookupResult},
};
use ic_bn_lib_common::traits::{Healthy, Run};
use tokio_util::sync::CancellationToken;

/// The type of an IC subnet as reported in the NNS state tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubnetType {
    Application,
    System,
    VerifiedApplication,
    CloudEngine,
    Unknown,
}

impl From<&[u8]> for SubnetType {
    fn from(bytes: &[u8]) -> Self {
        match bytes {
            b"application" => Self::Application,
            b"system" => Self::System,
            b"verified_application" => Self::VerifiedApplication,
            b"cloud_engine" => Self::CloudEngine,
            _ => Self::Unknown,
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
    /// directly. Ranges whose subnet has no known type are silently dropped.
    /// The resulting list is sorted by `range_start` to uphold the
    /// binary-search invariant required by [`Self::subnet_type`].
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

/// Fetches the full NNS routing table and subnet types, storing the result in
/// a shared [`SubnetsInfo`] updated on each run.
///
/// NNS `read_state` round trips performed per update cycle:
/// 1. Read `/subnet` to discover all subnet IDs and their types.
/// 2. Read `/canister_ranges/<id>` once per subnet (sequential).
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

    /// Returns the subnet-type map.
    async fn fetch_subnets(&self) -> Result<AHashMap<Principal, SubnetType>, Error> {
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

        subnet_ids
            .into_iter()
            .map(|subnet_id| {
                let subnet_type =
                    match cert
                        .tree
                        .lookup_path([b"subnet".as_ref(), subnet_id.as_slice(), b"type"])
                    {
                        LookupResult::Found(type_bytes) => {
                            let t = SubnetType::from(type_bytes);
                            if t == SubnetType::Unknown {
                                return Err(anyhow::anyhow!(
                                    "unknown subnet type {:?} for subnet {subnet_id}",
                                    String::from_utf8_lossy(type_bytes)
                                ));
                            }
                            t
                        }
                        _ => {
                            return Err(anyhow::anyhow!(
                                "missing type for subnet {subnet_id} in NNS tree"
                            ));
                        }
                    };
                Ok((subnet_id, subnet_type))
            })
            .collect()
    }

    async fn fetch_canister_ranges(
        &self,
        subnet_ids: &[Principal],
    ) -> Result<Vec<(Principal, Principal, Principal)>, Error> {
        // The subtree structure is:
        //   canister_ranges/<subnet_id>/<chunk_start_bytes> = <cbor blob>
        //
        // Each subnet requires an independent read_state round trip, so all
        // requests are issued concurrently.
        let futures = subnet_ids.iter().map(|&subnet_id| async move {
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
                _ => {
                    return Err(anyhow::anyhow!(
                        "canister_ranges subtree not found in NNS state tree for subnet {subnet_id}"
                    ));
                }
            };

            // The shard is CBOR-encoded as: tagged<[*[principal principal]]>
            // where tagged<t> = #6.55799(t) (self-describing CBOR tag).
            // serde_cbor 0.11 unwraps tag 55799 transparently.
            let ranges = subnet_ranges_tree
                .list_paths()
                .into_iter()
                .filter(|p| !p.is_empty())
                .map(|chunk_path| {
                    match subnet_ranges_tree.lookup_path([chunk_path[0].as_bytes()]) {
                        LookupResult::Found(chunk_bytes) => serde_cbor::from_slice::<
                            Vec<[Principal; 2]>,
                        >(chunk_bytes)
                        .with_context(|| {
                            format!("failed to decode canister ranges for subnet {subnet_id}")
                        }),
                        _ => Ok(vec![]),
                    }
                })
                .collect::<Result<Vec<_>, _>>()?
                .into_iter()
                .flatten()
                .map(|[lo, hi]| (lo, hi, subnet_id))
                .collect::<Vec<_>>();

            Ok::<_, Error>(ranges)
        });

        let results = futures::future::try_join_all(futures).await?;
        Ok(results.into_iter().flatten().collect())
    }

    /// Fetches a fresh snapshot and stores it only when every step succeeds.
    /// Any error leaves the existing snapshot untouched so stale-but-valid
    /// data continues to be served until the next successful cycle.
    async fn fetch(&self) -> Result<(), Error> {
        let subnet_types = self.fetch_subnets().await?;
        let subnet_ids: Vec<Principal> = subnet_types.keys().copied().collect();
        let canister_ranges = self.fetch_canister_ranges(&subnet_ids).await?;

        self.info.store(Some(Arc::new(SubnetsInfo::new(
            canister_ranges,
            subnet_types,
        ))));

        Ok(())
    }
}

#[async_trait]
impl Run for SubnetsInfoFetcher {
    async fn run(&self, _token: CancellationToken) -> Result<(), Error> {
        self.fetch().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test::TEST_ROOT_SUBNET_ID;
    use httptest::{Expectation, Server, matchers::*, responders::*};
    use ic_bn_lib_common::principal;
    use ic_transport_types::ReadStateResponse;
    use std::time::Duration;

    // To regenerate:
    //   cargo run --bin gen-testdata -- \
    //     --nns-url http://[nns-node-ipv6]:8080 \
    //     --root-subnet-id <root-subnet-principal> \
    //     --save-certs src/routing/ic/testdata
    //
    // REMEMBER to set the root key to the testnet root key that was current when the
    // fixture files in `testdata/` were captured.

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
    /// that captured testnet certificates (which carry old timestamps) still
    /// pass the agent's timestamp check — the same technique used by
    /// `make_untimed_agent` in ic-agent's own test suite.
    ///
    /// The root key is set to the testnet root key that was current when the
    /// fixture files in `testdata/` were captured.
    fn make_fetcher(server: &Server, root_subnet_id: Principal) -> SubnetsInfoFetcher {
        // Root key of the testnet from which subnet.bin / nns_canister_ranges.bin
        // were captured (fetched from /api/v2/status at capture time).
        #[rustfmt::skip]
        const TESTNET_ROOT_KEY: &[u8] = &[
            48, 129, 130, 48, 29, 6, 13, 43, 6, 1, 4, 1, 130, 220, 124, 5, 3, 1, 2, 1, 6, 12,
            43, 6, 1, 4, 1, 130, 220, 124, 5, 3, 2, 1, 3, 97, 0, 176, 207, 13, 8, 204, 235, 27,
            102, 173, 239, 110, 64, 30, 3, 118, 88, 252, 154, 235, 152, 65, 85, 142, 220, 6, 27,
            187, 18, 28, 122, 166, 170, 54, 15, 217, 50, 88, 15, 242, 65, 195, 189, 145, 19, 123,
            129, 240, 219, 8, 250, 205, 255, 205, 179, 252, 42, 9, 37, 36, 206, 123, 56, 77, 251,
            122, 115, 94, 211, 117, 195, 16, 152, 177, 0, 140, 70, 87, 188, 100, 187, 157, 183,
            184, 56, 154, 204, 62, 15, 209, 95, 10, 219, 33, 32, 70, 45,
        ];

        let agent = Agent::builder()
            .with_url(server.url_str("/"))
            .with_ingress_expiry(Duration::from_secs(u32::MAX as u64))
            .build()
            .expect("failed to build agent");

        agent.set_root_key(TESTNET_ROOT_KEY.to_vec());

        SubnetsInfoFetcher::new(Arc::new(agent), root_subnet_id)
    }

    #[tokio::test]
    async fn fetch_subnets_returns_all_subnet_ids() {
        let root_id = principal!(TEST_ROOT_SUBNET_ID);
        let path = format!("/api/v3/subnet/{TEST_ROOT_SUBNET_ID}/read_state");

        let server = Server::run();
        server.expect(
            Expectation::matching(request::method_path("POST", path)).respond_with(
                status_code(200)
                    .append_header("Content-Type", "application/cbor")
                    .body(read_state_response(SUBNET_BIN)),
            ),
        );

        let fetcher = make_fetcher(&server, root_id);
        let types = fetcher.fetch_subnets().await.unwrap();

        assert!(
            types.contains_key(&root_id),
            "NNS subnet missing from id list"
        );
    }

    #[tokio::test]
    async fn fetch_subnets_types_are_consistent() {
        let root_id = principal!(TEST_ROOT_SUBNET_ID);
        let path = format!("/api/v3/subnet/{TEST_ROOT_SUBNET_ID}/read_state");

        let server = Server::run();
        server.expect(
            Expectation::matching(request::method_path("POST", path)).respond_with(
                status_code(200)
                    .append_header("Content-Type", "application/cbor")
                    .body(read_state_response(SUBNET_BIN)),
            ),
        );

        let fetcher = make_fetcher(&server, root_id);
        let types = fetcher.fetch_subnets().await.unwrap();

        assert!(
            !types.is_empty(),
            "subnet types must be populated in testnet fixtures"
        );
        assert_eq!(
            types.get(&root_id).copied(),
            Some(SubnetType::System),
            "NNS subnet must have type 'system'"
        );
    }

    #[tokio::test]
    async fn fetch_canister_ranges_nns_subnet() {
        let root_id = principal!(TEST_ROOT_SUBNET_ID);
        let path = format!("/api/v3/subnet/{TEST_ROOT_SUBNET_ID}/read_state");

        let server = Server::run();
        server.expect(
            Expectation::matching(request::method_path("POST", path)).respond_with(
                status_code(200)
                    .append_header("Content-Type", "application/cbor")
                    .body(read_state_response(NNS_RANGES_BIN)),
            ),
        );

        let fetcher = make_fetcher(&server, root_id);
        let ranges = fetcher.fetch_canister_ranges(&[root_id]).await.unwrap();

        assert!(
            !ranges.is_empty(),
            "NNS subnet must have at least one canister range"
        );
        for (lo, hi, sid) in &ranges {
            assert!(lo <= hi, "lo > hi in NNS canister range");
            assert_eq!(sid, &root_id, "subnet_id mismatch in range entry");
        }
        for w in ranges.windows(2) {
            assert!(w[0].0 <= w[1].0, "ranges not sorted by lo");
        }
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
