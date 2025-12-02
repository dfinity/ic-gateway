use std::sync::Arc;

use axum::{
    extract::{Request, State},
    middleware::Next,
    response::IntoResponse,
};
use ic_bn_lib::http::cache::{Cache, KeyExtractorUriRange};

use crate::routing::error_cause::ErrorCause;

pub async fn middleware(
    State(cache): State<Arc<Cache<KeyExtractorUriRange>>>,
    request: Request,
    next: Next,
) -> Result<impl IntoResponse, ErrorCause> {
    let response = cache
        .process_request(request, next)
        .await
        .map_err(|e| ErrorCause::Other(e.to_string()))?;

    Ok(response)
}
