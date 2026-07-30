#![allow(clippy::significant_drop_tightening)]

use std::{
    fmt,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use ahash::AHashMap;
use anyhow::{Context, Error, anyhow};
use arc_swap::ArcSwapOption;
use async_trait::async_trait;
use candid::Principal;
pub use ic_bn_lib::ic_agent::agent::SubnetType;
use ic_bn_lib::{
    BoolYesNo,
    health::Healthy,
    ic::{AgentExt, CanisterRange, SubnetData},
    ic_agent::Agent,
    tasks::Run,
};
use prometheus::{
    IntCounterVec, IntGauge, Registry, register_int_counter_vec_with_registry,
    register_int_gauge_with_registry,
};
use tokio::time::interval;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

/// Retry interval used when no snapshot has been fetched yet and we are in the
/// aggressive boot-strap loop.
const AGGRESSIVE_RETRY_INTERVAL: Duration = Duration::from_secs(1);

/// Minimal fraction of the total subnets that need to succeed to consider
/// the whole fetch a success.
const SUCCESS_FRACTION: f64 = 2.0 / 3.0;

#[derive(Clone)]
pub struct Metrics {
    subnets: IntGauge,
    ranges: IntGauge,
    data_fetches: IntCounterVec,
}

impl Metrics {
    pub fn new(registry: &Registry) -> Self {
        Self {
            subnets: register_int_gauge_with_registry!(
                format!("routing_table_manager_subnets"),
                format!("How many subnets are there"),
                registry
            )
            .unwrap(),

            ranges: register_int_gauge_with_registry!(
                format!("routing_table_manager_ranges"),
                format!("How many canister ranges are there"),
                registry
            )
            .unwrap(),

            data_fetches: register_int_counter_vec_with_registry!(
                format!("routing_table_manager_data_fetches"),
                format!("Counts number of per-subnet data fetches"),
                &["subnet_id", "success"],
                registry
            )
            .unwrap(),
        }
    }
}

pub trait LooksUpSubnetType: Send + Sync {
    /// Looks up the type of the subnet that `canister_id` belongs to.
    fn lookup_subnet_type(&self, canister_id: &Principal) -> Option<SubnetType>;
}

/// A single NNS routing entry: a contiguous canister ID range assigned to a
/// specific subnet, with the subnet's type embedded to avoid a secondary lookup.
#[derive(Debug, Clone, PartialEq, Eq)]
struct RoutingEntry {
    range: CanisterRange,
    subnet_type: SubnetType,
}

/// Snapshot of the NNS routing table and subnet types.
///
/// Populated from the NNS state tree by [`RoutingTableManager`].
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SubnetsRoutingTable {
    /// Must be sorted by `range.start` for binary-search lookups.
    ranges: Vec<RoutingEntry>,
}

impl SubnetsRoutingTable {
    /// Creates a new routing table from a list of per-subnet data
    fn new(subnets_data: Vec<SubnetData>) -> Self {
        let mut ranges = Vec::with_capacity(subnets_data.iter().map(|x| x.ranges.len()).sum());
        for data in subnets_data {
            for range in data.ranges {
                ranges.push(RoutingEntry {
                    range,
                    subnet_type: data.subnet_type.clone(),
                });
            }
        }

        ranges.sort_by(|a, b| a.range.start.as_slice().cmp(b.range.start.as_slice()));
        Self { ranges }
    }
}

impl LooksUpSubnetType for SubnetsRoutingTable {
    fn lookup_subnet_type(&self, canister_id: &Principal) -> Option<SubnetType> {
        let id = canister_id.as_slice();

        let idx = match self
            .ranges
            .binary_search_by(|r| r.range.start.as_slice().cmp(id))
        {
            // Exact match on range_start
            Ok(i) => i,
            // Before all ranges
            Err(0) => return None,
            // Candidate is the range just below the insertion point
            Err(i) => i - 1,
        };

        let r = &self.ranges[idx];
        if id <= r.range.end.as_slice() {
            Some(r.subnet_type.clone())
        } else {
            None
        }
    }
}

/// Fetches the full routing table and subnet types.
///
/// Round trips performed per update cycle:
/// 1. Read NNS `/subnet` to discover all subnet IDs.
/// 2. Concurrently call `fetch_subnet_by_id` for each subnet, fetching both
///    its type and canister ranges directly from the subnet.
pub struct RoutingTableManager {
    subnet_info_fetcher: Arc<dyn AgentExt + Send + Sync + 'static>,
    root_subnet_id: Principal,
    snapshot: Mutex<AHashMap<Principal, SubnetData>>,
    /// `None` until the first successful fetch
    routing_table: Arc<ArcSwapOption<SubnetsRoutingTable>>,
    interval: Duration,
    metrics: Metrics,
}

impl fmt::Debug for RoutingTableManager {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RoutingTableManager")
    }
}

impl fmt::Display for RoutingTableManager {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RoutingTableManager")
    }
}

impl Healthy for RoutingTableManager {
    fn healthy(&self) -> bool {
        self.routing_table.load().is_some()
    }
}

impl LooksUpSubnetType for RoutingTableManager {
    fn lookup_subnet_type(&self, canister_id: &Principal) -> Option<SubnetType> {
        self.routing_table
            .load_full()?
            .lookup_subnet_type(canister_id)
    }
}

impl RoutingTableManager {
    pub fn new(
        agent: Agent,
        root_subnet_id: Principal,
        interval: Duration,
        registry: &Registry,
    ) -> Self {
        Self::new_with_fetcher(Arc::new(agent), root_subnet_id, interval, registry)
    }

    fn new_with_fetcher(
        fetcher: Arc<dyn AgentExt + Send + Sync + 'static>,
        root_subnet_id: Principal,
        interval: Duration,
        registry: &Registry,
    ) -> Self {
        assert!(
            interval > Duration::ZERO,
            "Refresh interval should not be zero"
        );

        Self {
            subnet_info_fetcher: fetcher,
            root_subnet_id,
            snapshot: Mutex::new(AHashMap::with_capacity(128)),
            routing_table: Arc::new(ArcSwapOption::empty()),
            interval,
            metrics: Metrics::new(registry),
        }
    }

    /// Update the local snapshot with the fresh per-subnet data
    #[allow(clippy::cast_possible_wrap)]
    async fn refresh_snapshot(&self) -> Result<usize, Error> {
        // Fetch the per-subnet data concurrently
        let start = Instant::now();
        let results = self
            .subnet_info_fetcher
            .fetch_all_subnets_data(self.root_subnet_id, Some(80))
            .await
            .context("unable to fetch subnets data")?;
        let dur = start.elapsed();
        let subnets_count = results.len();
        self.metrics.subnets.set(subnets_count as i64);

        let mut snapshot = self.snapshot.lock().unwrap();
        // Remove any subnets that are already gone from the list
        snapshot.retain(|x, _| results.contains_key(x));

        // Insert/update the new data that was fetched.
        // If there was an error - the older data will stay in the snapshot.
        let mut ok = 0;
        for (subnet_id, res) in results {
            let subnet_id_str = subnet_id.to_string();
            self.metrics
                .data_fetches
                .with_label_values(&[subnet_id_str.as_str(), res.is_ok().yesno()])
                .inc();

            match res {
                Ok(data) => {
                    ok += 1;
                    snapshot.insert(subnet_id, data);
                }
                Err(e) => {
                    warn!("{self}: {subnet_id}: error fetching data: {e:#}");
                }
            }
        }

        info!(
            "{self}: Successfully loaded data for {ok}/{subnets_count} subnets in {}s",
            dur.as_secs_f64()
        );

        Ok(subnets_count)
    }

    /// Tries to update the routing table by refreshing the per-subnet data
    #[allow(clippy::cast_precision_loss)]
    #[allow(clippy::cast_possible_wrap)]
    async fn update_routing_table(&self) -> Result<(), Error> {
        let subnets_count = self
            .refresh_snapshot()
            .await
            .context("unablt to refresh snapshot")?;
        let snapshot = self.snapshot.lock().unwrap();

        // Check if we already have enough valid subnet data.
        // We consider even the older data, fetched in the previous cycles, good enough.
        // That is, if we have *some* info for at least SUCCESS_FRACTION subnets,
        // then we're good to publish a new routing table.
        // Some info is better than no info in this case, since it anyway changes very rarely.
        let fraction = (snapshot.len() as f64) / (subnets_count as f64);
        if fraction < SUCCESS_FRACTION {
            return Err(anyhow!(
                "Less than {SUCCESS_FRACTION} of the subnets were successfully fetched: {fraction}"
            ));
        }

        // Construct new routing table
        let routing_table = Arc::new(SubnetsRoutingTable::new(
            snapshot.clone().into_values().collect(),
        ));

        // Check if the new table is different
        if let Some(v) = self.routing_table.load_full()
            && routing_table == v
        {
            info!("{self}: Routing table unchanged");
            return Ok(());
        }

        warn!(
            "{self}: New routing table applied ({} ranges)",
            routing_table.ranges.len()
        );

        self.metrics.ranges.set(routing_table.ranges.len() as i64);
        self.routing_table.store(Some(routing_table));
        Ok(())
    }
}

#[async_trait]
impl Run for RoutingTableManager {
    async fn run(&self, token: CancellationToken) -> Result<(), Error> {
        warn!(
            "{self}: Bootstrapping: polling every {}s",
            AGGRESSIVE_RETRY_INTERVAL.as_secs()
        );

        // Initially poll using an aggressive interval
        let mut int = interval(AGGRESSIVE_RETRY_INTERVAL);
        int.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            match self.update_routing_table().await {
                Ok(()) => {
                    // We have bootstrapped - switch to the normal polling interval
                    if int.period() != self.interval {
                        warn!(
                            "{self}: Bootstrapped: got {} subnets, will poll now every {}s",
                            self.snapshot.lock().unwrap().len(),
                            self.interval.as_secs()
                        );

                        int = interval(self.interval);
                        int.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                        int.reset();
                    }
                }

                Err(e) => {
                    warn!("{self}: Update failed: {e:#}");
                }
            }

            tokio::select! {
                () = token.cancelled() => {
                    warn!("{self}: Shutting down");
                    return Ok(());
                }

                _ = int.tick() => {}
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use ahash::AHashSet;
    use ic_bn_lib::{MAINNET_ROOT_SUBNET_ID, ic_agent::AgentError, principal};

    use super::*;

    fn create_data() -> AHashMap<Principal, SubnetData> {
        AHashMap::from_iter([
            (
                principal!("uqzsh-gqaaa-aaaaq-qaada-cai"),
                SubnetData {
                    ranges: vec![
                        CanisterRange {
                            start: Principal::from_slice(&[0x10]),
                            end: Principal::from_slice(&[0x15]),
                        },
                        CanisterRange {
                            start: Principal::from_slice(&[0x20]),
                            end: Principal::from_slice(&[0x25]),
                        },
                    ],
                    subnet_type: SubnetType::Application,
                },
            ),
            (
                principal!("gjxif-ryaaa-aaaad-ae4ka-cai"),
                SubnetData {
                    ranges: vec![CanisterRange {
                        start: Principal::from_slice(&[0x30]),
                        end: Principal::from_slice(&[0x35]),
                    }],
                    subnet_type: SubnetType::System,
                },
            ),
            (
                principal!("6hsbt-vqaaa-aaaaf-aaafq-cai"),
                SubnetData {
                    ranges: vec![CanisterRange {
                        start: Principal::from_slice(&[0x40]),
                        end: Principal::from_slice(&[0x45]),
                    }],
                    subnet_type: SubnetType::CloudEngine,
                },
            ),
        ])
    }

    #[derive(Default)]
    struct TestSubnetInfoFetcher(AtomicUsize);

    #[async_trait]
    impl AgentExt for TestSubnetInfoFetcher {
        // Not used by `RoutingTableManager`, which calls `fetch_all_subnets_data` directly.
        async fn fetch_subnet_ids(
            &self,
            _root_subnet_id: Principal,
        ) -> Result<AHashSet<Principal>, AgentError> {
            unimplemented!()
        }

        // Not used by `RoutingTableManager`, which calls `fetch_all_subnets_data` directly.
        async fn fetch_subnet_data(
            &self,
            _subnet_id: &Principal,
        ) -> Result<SubnetData, AgentError> {
            unimplemented!()
        }

        async fn fetch_all_subnets_data(
            &self,
            _root_subnet_id: Principal,
            _concurrency: Option<usize>,
        ) -> Result<AHashMap<Principal, Result<SubnetData, AgentError>>, AgentError> {
            let v = self.0.fetch_add(1, Ordering::SeqCst);

            let subnet_ids = if v == 0 {
                return Err(AgentError::MessageError("foo".into()));
            } else if v == 1 {
                AHashSet::from_iter([
                    principal!("uqzsh-gqaaa-aaaaq-qaada-cai"),
                    principal!("gjxif-ryaaa-aaaad-ae4ka-cai"),
                    principal!("aaaaa-aa"),
                    principal!("lusdn-iiaaa-aaaam-qivpa-cai"),
                ])
            } else if v == 2 {
                AHashSet::from_iter([
                    principal!("uqzsh-gqaaa-aaaaq-qaada-cai"),
                    principal!("gjxif-ryaaa-aaaad-ae4ka-cai"),
                    principal!("6hsbt-vqaaa-aaaaf-aaafq-cai"),
                    principal!("lusdn-iiaaa-aaaam-qivpa-cai"),
                ])
            } else if v == 3 {
                AHashSet::from_iter([
                    principal!("uqzsh-gqaaa-aaaaq-qaada-cai"),
                    principal!("gjxif-ryaaa-aaaad-ae4ka-cai"),
                    principal!("lusdn-iiaaa-aaaam-qivpa-cai"),
                ])
            } else {
                return Err(AgentError::MessageError("foo".into()));
            };

            let data = create_data();
            Ok(subnet_ids
                .into_iter()
                .map(|id| {
                    let res = data
                        .get(&id)
                        .cloned()
                        .ok_or_else(|| AgentError::MessageError("foo".into()));
                    (id, res)
                })
                .collect())
        }
    }

    #[test]
    fn subnet_type_lookup() {
        // system:  [0x10, 0x17]
        // gap:     [0x18, 0x1F]
        // app:     [0x20, 0x2F]

        let system_low = Principal::from_slice(&[0x10]);
        let system_high = Principal::from_slice(&[0x17]);
        let app_low = Principal::from_slice(&[0x20]);
        let app_high = Principal::from_slice(&[0x2F]);

        let subnets_data = vec![
            SubnetData {
                ranges: vec![CanisterRange {
                    start: system_low,
                    end: system_high,
                }],
                subnet_type: SubnetType::System,
            },
            SubnetData {
                ranges: vec![CanisterRange {
                    start: app_low,
                    end: app_high,
                }],
                subnet_type: SubnetType::Application,
            },
        ];

        let rt = SubnetsRoutingTable::new(subnets_data);

        // mid-range hits
        assert_eq!(
            rt.lookup_subnet_type(&Principal::from_slice(&[0x13])),
            Some(SubnetType::System)
        );
        assert_eq!(
            rt.lookup_subnet_type(&Principal::from_slice(&[0x25])),
            Some(SubnetType::Application)
        );
        // exact boundary hits
        assert_eq!(rt.lookup_subnet_type(&system_low), Some(SubnetType::System));
        assert_eq!(
            rt.lookup_subnet_type(&system_high),
            Some(SubnetType::System)
        );
        assert_eq!(
            rt.lookup_subnet_type(&app_low),
            Some(SubnetType::Application)
        );
        assert_eq!(
            rt.lookup_subnet_type(&app_high),
            Some(SubnetType::Application)
        );
        // outside all ranges
        assert_eq!(rt.lookup_subnet_type(&Principal::from_slice(&[0x05])), None);
        assert_eq!(rt.lookup_subnet_type(&Principal::from_slice(&[0x35])), None);
        // gap between the two ranges
        assert_eq!(rt.lookup_subnet_type(&Principal::from_slice(&[0x19])), None);
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)] // clippy is stupid
    async fn test_routing_table_manager() {
        let fetcher = TestSubnetInfoFetcher::default();
        let manager = RoutingTableManager::new_with_fetcher(
            Arc::new(fetcher),
            MAINNET_ROOT_SUBNET_ID,
            Duration::MAX,
            &Registry::new(),
        );

        // 1st update should fail due to failed fetch_subnet_ids
        assert!(manager.update_routing_table().await.is_err());
        // 2nd update should also fail due to only 50% of subnets data fetched
        assert!(manager.update_routing_table().await.is_err());

        // 3rd should succeed for 3/4 of subnets
        manager.update_routing_table().await.unwrap();

        let data = create_data();

        // Check first that the snapshot is correct
        let snap = manager.snapshot.lock().unwrap();
        assert_eq!(snap.len(), 3);
        assert_eq!(
            snap.get(&principal!("uqzsh-gqaaa-aaaaq-qaada-cai"))
                .unwrap(),
            data.get(&principal!("uqzsh-gqaaa-aaaaq-qaada-cai"))
                .unwrap(),
        );
        assert_eq!(
            snap.get(&principal!("gjxif-ryaaa-aaaad-ae4ka-cai"))
                .unwrap(),
            data.get(&principal!("gjxif-ryaaa-aaaad-ae4ka-cai"))
                .unwrap()
        );
        assert_eq!(
            snap.get(&principal!("6hsbt-vqaaa-aaaaf-aaafq-cai"))
                .unwrap(),
            data.get(&principal!("6hsbt-vqaaa-aaaaf-aaafq-cai"))
                .unwrap()
        );

        // Check that the lookups are ok
        for (canister, typ) in [
            (Principal::from_slice(&[0x09]), None),
            (
                Principal::from_slice(&[0x10]),
                Some(SubnetType::Application),
            ),
            (
                Principal::from_slice(&[0x20]),
                Some(SubnetType::Application),
            ),
            (Principal::from_slice(&[0x30]), Some(SubnetType::System)),
            (
                Principal::from_slice(&[0x40]),
                Some(SubnetType::CloudEngine),
            ),
            (Principal::from_slice(&[0x46]), None),
        ] {
            assert_eq!(manager.lookup_subnet_type(&canister), typ);
        }
        drop(snap);

        // 4th should also succeed, but yields one subnet less
        manager.update_routing_table().await.unwrap();

        // Check first that the snapshot is correct - only 2 subnets
        let snap = manager.snapshot.lock().unwrap();
        assert_eq!(snap.len(), 2);
        assert_eq!(
            snap.get(&principal!("uqzsh-gqaaa-aaaaq-qaada-cai"))
                .unwrap(),
            data.get(&principal!("uqzsh-gqaaa-aaaaq-qaada-cai"))
                .unwrap(),
        );
        assert_eq!(
            snap.get(&principal!("gjxif-ryaaa-aaaad-ae4ka-cai"))
                .unwrap(),
            data.get(&principal!("gjxif-ryaaa-aaaad-ae4ka-cai"))
                .unwrap()
        );

        // Check that the lookups are ok
        for (canister, typ) in [
            (Principal::from_slice(&[0x09]), None),
            (
                Principal::from_slice(&[0x10]),
                Some(SubnetType::Application),
            ),
            (
                Principal::from_slice(&[0x20]),
                Some(SubnetType::Application),
            ),
            (Principal::from_slice(&[0x30]), Some(SubnetType::System)),
            // 3rd subnet is gone
            (Principal::from_slice(&[0x40]), None),
        ] {
            assert_eq!(manager.lookup_subnet_type(&canister), typ);
        }

        drop(snap);

        // 5th update should fail the fetch_subnet_ids,
        // but we should still be able to use the same old data.
        assert!(manager.update_routing_table().await.is_err());

        // Check first that the snapshot is correct - only 2 subnets
        let snap = manager.snapshot.lock().unwrap();
        assert_eq!(snap.len(), 2);
        assert_eq!(
            snap.get(&principal!("uqzsh-gqaaa-aaaaq-qaada-cai"))
                .unwrap(),
            data.get(&principal!("uqzsh-gqaaa-aaaaq-qaada-cai"))
                .unwrap(),
        );
        assert_eq!(
            snap.get(&principal!("gjxif-ryaaa-aaaad-ae4ka-cai"))
                .unwrap(),
            data.get(&principal!("gjxif-ryaaa-aaaad-ae4ka-cai"))
                .unwrap()
        );

        // Check that the lookups are ok
        for (canister, typ) in [
            (Principal::from_slice(&[0x09]), None),
            (
                Principal::from_slice(&[0x10]),
                Some(SubnetType::Application),
            ),
            (
                Principal::from_slice(&[0x20]),
                Some(SubnetType::Application),
            ),
            (Principal::from_slice(&[0x30]), Some(SubnetType::System)),
            // 3rd subnet is gone
            (Principal::from_slice(&[0x40]), None),
        ] {
            assert_eq!(manager.lookup_subnet_type(&canister), typ);
        }

        drop(snap);
    }
}
