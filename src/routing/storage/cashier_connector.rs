use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use anyhow::Error;
use async_trait::async_trait;
use candid::{Int, Nat, Principal};
use ic_bn_lib_common::traits::{Healthy, Run};
use tokio::sync::RwLock;
use tokio_util::sync::CancellationToken;
use tracing::warn;

use super::cashier_client::CashierClient;
use super::cashier_types::*;
use super::types::ONE_MIB;

const BUDGET_TTL: Duration = Duration::from_secs(30);
const BUDGET_REFRESH_DELAY: Duration = Duration::from_secs(5);

#[derive(Debug, Clone)]
pub enum BillingError {
    OwnerNotFound,
    InsufficientBalance,
    CashierUnavailable(String),
}

impl std::fmt::Display for BillingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::OwnerNotFound => write!(f, "owner not found"),
            Self::InsufficientBalance => write!(f, "insufficient balance"),
            Self::CashierUnavailable(e) => write!(f, "cashier unavailable: {e}"),
        }
    }
}

struct CachedBudget {
    budget: GatewayBudget,
    fetched_at: Instant,
}

struct OwnerUsage {
    counters: UsageCounters,
    dirty: bool,
}

impl OwnerUsage {
    fn new() -> Self {
        Self {
            counters: UsageCounters {
                bytes_downloaded: Nat::from(0u64),
                bytes_uploaded: Nat::from(0u64),
                write_requests: 0,
                read_requests: 0,
            },
            dirty: false,
        }
    }
}

/// Billing wrapper around [`CashierClient`].
///
/// Caches per-owner budgets, charges operations locally, and periodically
/// flushes accumulated usage counters to the cashier canister.
pub struct CashierConnector {
    client: Arc<CashierClient>,
    gateway_id: GatewayId,
    pricelist: Pricelist,
    budgets: RwLock<HashMap<Principal, CachedBudget>>,
    usage: RwLock<HashMap<Principal, OwnerUsage>>,
    healthy: AtomicBool,
}

impl fmt::Debug for CashierConnector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CashierConnector")
            .field("gateway_id", &self.gateway_id.principal)
            .field("healthy", &self.healthy.load(Ordering::Relaxed))
            .finish()
    }
}

impl CashierConnector {
    pub async fn new(client: Arc<CashierClient>, gateway_name: Option<String>) -> Result<Self, Error> {
        let principal = client.principal()?;
        let pricelist = client.pricelist_v1().await?;
        let gateway_id = GatewayId {
            principal,
            name: gateway_name,
        };

        warn!(
            gateway = %gateway_id.principal,
            cashier = %client.canister_id(),
            "CashierConnector initialized"
        );

        Ok(Self {
            client,
            gateway_id,
            pricelist,
            budgets: RwLock::new(HashMap::new()),
            usage: RwLock::new(HashMap::new()),
            healthy: AtomicBool::new(true),
        })
    }

    // -----------------------------------------------------------------------
    // Charge methods
    // -----------------------------------------------------------------------

    pub async fn charge_blob_tree_upload(&self, owner: &Principal) -> Result<(), BillingError> {
        let cost = self.compute_cost(ONE_MIB as u64, 0, 0, 1);
        self.consume_budget(owner, cost).await?;
        self.record_usage(owner, ONE_MIB as u64, 0, 0, 1).await;
        Ok(())
    }

    pub async fn charge_chunk_upload(&self, owner: &Principal) -> Result<(), BillingError> {
        let cost = self.compute_cost(ONE_MIB as u64, 0, 0, 1);
        self.consume_budget(owner, cost).await?;
        self.record_usage(owner, ONE_MIB as u64, 0, 0, 1).await;
        Ok(())
    }

    pub async fn charge_blob_tree_download(&self, owner: &Principal) -> Result<(), BillingError> {
        let cost = self.compute_cost(0, ONE_MIB as u64, 1, 0);
        self.consume_budget(owner, cost).await?;
        self.record_usage(owner, 0, ONE_MIB as u64, 1, 0).await;
        Ok(())
    }

    pub async fn charge_chunk_download(&self, owner: &Principal) -> Result<(), BillingError> {
        let cost = self.compute_cost(0, ONE_MIB as u64, 1, 0);
        self.consume_budget(owner, cost).await?;
        self.record_usage(owner, 0, ONE_MIB as u64, 1, 0).await;
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Usage reporting
    // -----------------------------------------------------------------------

    /// Flush accumulated usage counters to the cashier canister.
    async fn report_usage(&self) {
        if let Err(e) = self.flush_usage().await {
            self.healthy.store(false, Ordering::Relaxed);
            warn!("Failed to report usage to cashier: {e}");
        } else {
            self.healthy.store(true, Ordering::Relaxed);
        }
    }

    async fn flush_usage(&self) -> Result<(), Error> {
        let batch = {
            let mut usage = self.usage.write().await;
            let mut batch = Vec::new();
            for (owner, ou) in usage.iter_mut() {
                if ou.dirty {
                    batch.push(StorageSetUsageRequest {
                        owner: *owner,
                        usage: ou.counters.clone(),
                    });
                    ou.dirty = false;
                }
            }
            batch
        };

        if batch.is_empty() {
            return Ok(());
        }

        let request = StorageSetUsageBatchRequest {
            gateway_id: self.gateway_id.clone(),
            counters: batch,
        };

        match self.client.storage_usage_set_batch_v1(&request).await? {
            StorageSetUsageBatchResult::Ok(resp) => {
                let mut budgets = self.budgets.write().await;
                for (principal, budget) in resp.budgets {
                    budgets.insert(
                        principal,
                        CachedBudget {
                            budget,
                            fetched_at: Instant::now(),
                        },
                    );
                }
            }
            StorageSetUsageBatchResult::Err(e) => {
                warn!("Cashier rejected usage report: {e:?}");
            }
        }

        Ok(())
    }

    // -----------------------------------------------------------------------
    // Internals
    // -----------------------------------------------------------------------

    fn compute_cost(
        &self,
        bytes_uploaded: u64,
        bytes_downloaded: u64,
        read_requests: u64,
        write_requests: u64,
    ) -> i64 {
        let p = &self.pricelist.counters;
        price_component(&p.bytes_uploaded_price, bytes_uploaded)
            + price_component(&p.bytes_downloaded_price, bytes_downloaded)
            + price_component(&p.read_request_price, read_requests)
            + price_component(&p.write_request_price, write_requests)
    }

    async fn consume_budget(&self, owner: &Principal, cost: i64) -> Result<(), BillingError> {
        {
            let mut budgets = self.budgets.write().await;
            if let Some(cached) = budgets.get_mut(owner) {
                if cached.fetched_at.elapsed() < BUDGET_TTL {
                    return self.try_debit(cached, cost);
                }
                if cached.fetched_at.elapsed() < BUDGET_REFRESH_DELAY {
                    return self.try_debit(cached, cost);
                }
            }
        }

        let fresh = self.fetch_budget(owner).await?;
        let mut budgets = self.budgets.write().await;
        budgets.insert(
            *owner,
            CachedBudget {
                budget: fresh,
                fetched_at: Instant::now(),
            },
        );
        let cached = budgets.get_mut(owner).unwrap();
        self.try_debit(cached, cost)
    }

    fn try_debit(&self, cached: &mut CachedBudget, cost: i64) -> Result<(), BillingError> {
        let credit = int_to_i64(&cached.budget.available_credit);
        if credit >= cost {
            cached.budget.available_credit = Int::from(credit - cost);
            Ok(())
        } else {
            Err(BillingError::InsufficientBalance)
        }
    }

    async fn fetch_budget(&self, owner: &Principal) -> Result<GatewayBudget, BillingError> {
        let request = GetBudgetRequestV1 {
            gateway_id: Some(self.gateway_id.clone()),
            owner_id: *owner,
        };

        let result = self
            .client
            .budget_get_v1(&request)
            .await
            .map_err(|e| BillingError::CashierUnavailable(e.to_string()))?;

        match result {
            GetBudgetResult::Ok(resp) => Ok(resp.budget),
            GetBudgetResult::Err(GetBudgetError::OwnerNotFound) => Err(BillingError::OwnerNotFound),
            GetBudgetResult::Err(GetBudgetError::GatewayNotFound(_)) => {
                Err(BillingError::CashierUnavailable("gateway not found".to_string()))
            }
        }
    }

    async fn record_usage(
        &self,
        owner: &Principal,
        bytes_up: u64,
        bytes_down: u64,
        reads: u64,
        writes: u64,
    ) {
        let mut usage = self.usage.write().await;
        let entry = usage.entry(*owner).or_insert_with(OwnerUsage::new);
        entry.counters.bytes_uploaded += Nat::from(bytes_up);
        entry.counters.bytes_downloaded += Nat::from(bytes_down);
        entry.counters.read_requests += reads;
        entry.counters.write_requests += writes;
        entry.dirty = true;
    }
}

#[async_trait]
impl Run for CashierConnector {
    async fn run(&self, _token: CancellationToken) -> Result<(), Error> {
        self.report_usage().await;
        Ok(())
    }
}

impl Healthy for CashierConnector {
    fn healthy(&self) -> bool { self.healthy.load(Ordering::Relaxed) }
}

fn int_to_i64(v: &Int) -> i64 {
    // Int is arbitrary precision; clamp to i64 range for local budget math.
    v.0.to_string().parse::<i64>().unwrap_or(i64::MAX)
}

fn factor_divisor(f: &Factor) -> u64 {
    match f {
        Factor::U => 1,
        Factor::K => 1_000,
        Factor::M => 1_000_000,
        Factor::G => 1_000_000_000,
        Factor::T => 1_000_000_000_000,
        Factor::Ki => 1_024,
        Factor::Mi => 1_048_576,
        Factor::Gi => 1_073_741_824,
        Factor::Ti => 1_099_511_627_776,
    }
}

fn price_component(price: &PricePerBillingUnit, quantity: u64) -> i64 {
    if quantity == 0 {
        return 0;
    }
    let cost = int_to_i64(&price.cost);
    let divisor = factor_divisor(&price.per) as i64;
    if divisor == 0 {
        return 0;
    }
    (quantity as i64 * cost) / divisor
}
