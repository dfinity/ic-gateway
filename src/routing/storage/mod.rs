pub mod auth;
pub mod bucket;
pub mod cashier_client;
pub mod cashier_connector;
pub mod cashier_types;
pub mod handler;
pub mod wire;

use std::{sync::Arc, time::Duration};

use axum::{
    Router,
    routing::{delete, get, put},
};
use http::HeaderValue;

use crate::routing::{
    error_cause::{BackendError, StorageError},
    middleware::cors,
};

use self::cashier_connector::BillingError;

pub use self::{
    auth::{IngressAuth, IngressAuthImpl},
    bucket::{AWSBucket, BucketLike, S3Config, S3Flavor},
    cashier_client::CashierClient,
    cashier_connector::CashierConnector,
};

// Conversion from storage-local `BillingError` into the shared `StorageError`.
// Kept here (rather than in `error_cause.rs`) so `error_cause` stays
// independent of storage-module internals. `IngressAuth` already returns
// `StorageError` directly, so it needs no conversion.

impl From<&BillingError> for StorageError {
    fn from(e: &BillingError) -> Self {
        match e {
            BillingError::OwnerNotFound { .. } => Self::OwnerNotFound,
            BillingError::InsufficientBalance { .. } => Self::InsufficientBalance,
            BillingError::CashierUnavailable { .. } => {
                Self::Backend(BackendError::Cashier(e.to_string()))
            }
        }
    }
}

pub struct StorageState {
    pub connector: Arc<CashierConnector>,
    pub bucket: Arc<dyn BucketLike>,
    pub ingress_auth: Arc<dyn IngressAuth>,
    pub allowed_delete_owner_hosts: Option<String>,
}

pub fn storage_router(
    state: StorageState,
    cors_max_age: Duration,
    cors_allow_origin: Vec<HeaderValue>,
) -> Router {
    let cors =
        cors::layer(cors_max_age, cors_allow_origin).allow_methods(cors::ALLOW_METHODS_STORAGE);

    Router::new()
        .route(
            "/owner/{owner_id}/blob/{blob_hash}",
            get(handler::get_blob).head(handler::head_blob),
        )
        .route(
            "/owner/{owner_id}/blob_tree/{blob_hash}",
            get(handler::get_blob_tree)
                .put(handler::put_blob_tree)
                .delete(handler::delete_blob_tree_disabled),
        )
        .route(
            "/owner/{owner_id}/chunk/{chunk_hash}",
            get(handler::get_chunk),
        )
        .route(
            "/owner/{owner_id}/blob/{blob_hash}/chunk/{chunk_index}",
            put(handler::put_chunk),
        )
        .route("/owner/{owner_id}", delete(handler::delete_owner))
        .layer(cors)
        .with_state(Arc::new(state))
}
