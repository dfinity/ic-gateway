pub mod handlers;

use std::sync::Arc;

use axum::{
    Router,
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{delete, get, head, put},
};
use http::{Method, header::CONTENT_TYPE};
use ic_bn_lib::hval;
use tower_http::cors::{Any, CorsLayer};

use crate::{
    cashier::{CashierConnector, connector::BillingError},
    s3::bucket::BucketLike,
    storage::auth::{AuthError, IngressAuth},
};

#[derive(Clone)]
pub struct StorageState {
    pub connector: Arc<CashierConnector>,
    pub bucket: Arc<dyn BucketLike>,
    pub ingress_auth: Arc<dyn IngressAuth>,
    pub allowed_delete_owner_hosts: Option<String>,
}

/// Unified error type for all storage API endpoints.
pub enum StorageError {
    BadRequest(String),
    NotFound(&'static str),
    Forbidden(String),
    Unauthorized(String),
    BadGateway(String),
    Internal(String),
    PayloadTooLarge(String),
    RangeNotSatisfiable(u64),
}

impl IntoResponse for StorageError {
    fn into_response(self) -> Response {
        match self {
            Self::BadRequest(msg) => (StatusCode::BAD_REQUEST, msg).into_response(),
            Self::NotFound(msg) => (StatusCode::NOT_FOUND, msg).into_response(),
            Self::Forbidden(msg) => (StatusCode::FORBIDDEN, msg).into_response(),
            Self::Unauthorized(msg) => {
                let mut headers = HeaderMap::new();
                headers.insert(
                    header::WWW_AUTHENTICATE,
                    hval!("X-ICP-Canister-Signature"),
                );
                (StatusCode::UNAUTHORIZED, headers, msg).into_response()
            }
            Self::BadGateway(msg) => (StatusCode::BAD_GATEWAY, msg).into_response(),
            Self::Internal(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg).into_response(),
            Self::PayloadTooLarge(msg) => (StatusCode::PAYLOAD_TOO_LARGE, msg).into_response(),
            Self::RangeNotSatisfiable(total) => (
                StatusCode::RANGE_NOT_SATISFIABLE,
                format!("range not satisfiable; available length: {total}"),
            )
                .into_response(),
        }
    }
}

impl From<&BillingError> for StorageError {
    fn from(e: &BillingError) -> Self {
        match e {
            BillingError::OwnerNotFound | BillingError::InsufficientBalance => {
                Self::Forbidden(e.to_string())
            }
            BillingError::CashierUnavailable(_) => Self::BadGateway(e.to_string()),
        }
    }
}

impl From<&AuthError> for StorageError {
    fn from(e: &AuthError) -> Self {
        match e {
            AuthError::MissingAuth(m) => Self::Unauthorized(m.to_string()),
            AuthError::Forbidden(m) => Self::Forbidden(m.to_string()),
        }
    }
}

pub fn storage_router(state: StorageState) -> Router {
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods([
            Method::GET,
            Method::PUT,
            Method::HEAD,
            Method::DELETE,
            Method::OPTIONS,
        ])
        .allow_headers([CONTENT_TYPE]);

    Router::new()
        .route("/blob", get(handlers::get_blob))
        .route("/blob", head(handlers::head_blob))
        .route("/blob-tree", get(handlers::get_blob_tree))
        .route("/blob-tree", put(handlers::put_blob_tree))
        .route("/blob-tree", delete(handlers::delete_blob_tree_disabled))
        .route("/chunk", get(handlers::get_chunk))
        .route("/chunk", put(handlers::put_chunk))
        .route("/owner", delete(handlers::delete_owner))
        .layer(cors)
        .with_state(state)
}
