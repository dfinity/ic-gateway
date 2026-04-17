use std::sync::Arc;

use anyhow::{Context, Error};
use candid::{Decode, Principal};
use ic_bn_lib::ic_agent::Agent;
use tracing::warn;

use super::types::*;

/// Client for calling the cashier canister using the gateway's existing Agent.
///
/// Provides the same 4 methods that the object-storage gateway needs:
/// - `whoami` (query) — verify the caller is a registered gateway
/// - `pricelist_v1` (query) — load pricing for cost calculation
/// - `budget_get_v1` (query) — check per-owner credit/budget
/// - `storage_usage_set_batch_v1` (update) — report usage counters
pub struct CashierClient {
    agent: Arc<Agent>,
    canister_id: Principal,
}

impl CashierClient {
    pub fn new(agent: Arc<Agent>, canister_id: Principal) -> Self {
        Self { agent, canister_id }
    }

    pub fn canister_id(&self) -> &Principal {
        &self.canister_id
    }

    /// Query: returns information about the caller (gateway registration check).
    pub async fn whoami(&self) -> Result<Whoami, Error> {
        let encoded_args =
            candid::encode_args(()).context("failed to encode whoami args")?;

        let response_bytes = self
            .agent
            .query(&self.canister_id, "whoami")
            .with_arg(encoded_args)
            .call()
            .await
            .context("whoami query failed")?;

        let response =
            Decode!(&response_bytes, Whoami).context("failed to decode whoami response")?;
        Ok(response)
    }

    /// Query: returns the pricing for storage operations.
    pub async fn pricelist_v1(&self) -> Result<Pricelist, Error> {
        let encoded_args =
            candid::encode_args(()).context("failed to encode pricelist args")?;

        let response_bytes = self
            .agent
            .query(&self.canister_id, "pricelist_v1")
            .with_arg(encoded_args)
            .call()
            .await
            .context("pricelist_v1 query failed")?;

        let response =
            Decode!(&response_bytes, Pricelist).context("failed to decode pricelist response")?;
        Ok(response)
    }

    /// Query: returns the budget for a given owner on this gateway.
    pub async fn budget_get_v1(
        &self,
        request: &GetBudgetRequestV1,
    ) -> Result<GetBudgetResult, Error> {
        let encoded_args =
            candid::encode_args((request,)).context("failed to encode budget_get_v1 args")?;

        let response_bytes = self
            .agent
            .query(&self.canister_id, "budget_get_v1")
            .with_arg(encoded_args)
            .call()
            .await
            .context("budget_get_v1 query failed")?;

        let response = Decode!(&response_bytes, GetBudgetResult)
            .context("failed to decode budget_get_v1 response")?;
        Ok(response)
    }

    /// Update: reports usage counters for one or more owners, returns updated budgets.
    pub async fn storage_usage_set_batch_v1(
        &self,
        request: &StorageSetUsageBatchRequest,
    ) -> Result<StorageSetUsageBatchResult, Error> {
        let encoded_args = candid::encode_args((request,))
            .context("failed to encode storage_usage_set_batch_v1 args")?;

        let response_bytes = self
            .agent
            .update(&self.canister_id, "storage_usage_set_batch_v1")
            .with_arg(encoded_args)
            .call_and_wait()
            .await
            .context("storage_usage_set_batch_v1 update failed")?;

        let response = Decode!(&response_bytes, StorageSetUsageBatchResult)
            .context("failed to decode storage_usage_set_batch_v1 response")?;
        Ok(response)
    }

    /// Health check: calls whoami and verifies this agent is registered as a gateway.
    pub async fn health_check(&self) -> Result<(), Error> {
        let me = self.whoami().await?;
        if !me.am_gateway {
            anyhow::bail!(
                "caller {} is not registered as a gateway on cashier {}",
                me.caller_principal,
                me.cashier_principal
            );
        }
        warn!(
            caller = %me.caller_principal,
            cashier = %me.cashier_principal,
            "Cashier health check passed: registered as gateway"
        );
        Ok(())
    }
}
