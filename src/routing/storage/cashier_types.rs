use candid::{CandidType, Deserialize, Int, Nat, Principal};

#[derive(CandidType, Deserialize, Clone, Debug)]
pub enum Factor {
    G,
    K,
    M,
    T,
    U,
    Gi,
    Ki,
    Mi,
    Ti,
}

#[derive(CandidType, Deserialize, Clone, Debug)]
pub struct PricePerBillingUnit {
    pub per: Factor,
    pub cost: Int,
}

#[derive(CandidType, Deserialize, Clone, Debug)]
pub struct LevelPrices {
    pub bytes_stored: PricePerBillingUnit,
}

#[derive(CandidType, Deserialize, Clone, Debug)]
pub struct UsagePrices {
    pub read_request_price: PricePerBillingUnit,
    pub bytes_downloaded_price: PricePerBillingUnit,
    pub bytes_uploaded_price: PricePerBillingUnit,
    pub write_request_price: PricePerBillingUnit,
}

#[derive(CandidType, Deserialize, Clone, Debug)]
pub struct Pricelist {
    pub gauges: LevelPrices,
    pub counters: UsagePrices,
}

#[derive(CandidType, Deserialize, Clone, Debug)]
pub struct GatewayId {
    pub principal: Principal,
    pub name: Option<String>,
}

#[derive(CandidType, Deserialize, Clone, Debug)]
pub struct UsageCounters {
    pub bytes_downloaded: Nat,
    pub bytes_uploaded: Nat,
    pub write_requests: u64,
    pub read_requests: u64,
}

#[derive(CandidType, Deserialize, Clone, Debug)]
pub struct GatewayBudget {
    pub available_credit: Int,
}

#[derive(CandidType, Deserialize, Clone, Debug)]
pub struct GetBudgetRequestV1 {
    pub gateway_id: Option<GatewayId>,
    pub owner_id: Principal,
}

#[derive(CandidType, Deserialize, Clone, Debug)]
pub struct GetBudgetResponseV1 {
    pub usage: UsageCounters,
    pub budget: GatewayBudget,
}

#[derive(CandidType, Deserialize, Clone, Debug)]
pub enum GetBudgetError {
    GatewayNotFound(GatewayId),
    OwnerNotFound,
}

#[derive(CandidType, Deserialize, Clone, Debug)]
pub enum GetBudgetResult {
    Ok(GetBudgetResponseV1),
    Err(GetBudgetError),
}

#[derive(CandidType, Deserialize, Clone, Debug)]
pub struct StorageSetUsageRequest {
    pub owner: Principal,
    pub usage: UsageCounters,
}

#[derive(CandidType, Deserialize, Clone, Debug)]
pub struct StorageSetUsageBatchRequest {
    pub gateway_id: GatewayId,
    pub counters: Vec<StorageSetUsageRequest>,
}

#[derive(CandidType, Deserialize, Clone, Debug)]
pub struct StorageSetUsageBatchResponse {
    pub budgets: Vec<(Principal, GatewayBudget)>,
}

#[derive(CandidType, Deserialize, Clone, Debug)]
pub enum StorageSetUsageError {
    NotAuthorized(Principal),
    InternalError(String),
}

#[derive(CandidType, Deserialize, Clone, Debug)]
pub enum StorageSetUsageBatchResult {
    Ok(StorageSetUsageBatchResponse),
    Err(StorageSetUsageError),
}
