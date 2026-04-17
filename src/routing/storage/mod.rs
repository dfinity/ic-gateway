pub mod handlers;

use std::sync::Arc;

use axum::{
    Router,
    routing::{delete, get, head, put},
};
use http::{Method, header::CONTENT_TYPE};
use tower_http::cors::{Any, CorsLayer};

use crate::{cashier::CashierConnector, s3::bucket::BucketLike, storage::auth::IngressAuth};

#[derive(Clone)]
pub struct StorageState {
    pub connector: Arc<CashierConnector>,
    pub bucket: Arc<dyn BucketLike>,
    pub ingress_auth: Arc<dyn IngressAuth>,
    pub allowed_delete_owner_hosts: Option<String>,
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
