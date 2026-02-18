use std::sync::Arc;

use axum::{
    extract::{Request, State},
    middleware::Next,
    response::IntoResponse,
};
use ic_bn_lib::http::cache::{Cache, CacheStatus, KeyExtractorUriRange};
use tracing::warn;

use crate::routing::error_cause::ErrorCause;

pub async fn middleware(
    State(cache): State<Arc<Cache<KeyExtractorUriRange>>>,
    request: Request,
    next: Next,
) -> Result<impl IntoResponse, ErrorCause> {
    let url = request.uri().to_string();

    let response = cache
        .process_request(request, next)
        .await
        .map_err(|e| ErrorCause::Other(e.to_string()))?;

    // Log edge cases when we get entries with negative TTL (caching issues)
    if let Some(CacheStatus::Hit(v) | CacheStatus::Miss(v)) =
        response.extensions().get::<CacheStatus>()
        && *v < 0
    {
        warn!("Caching TTL is < 0: {v} (URL {url})");
    }

    Ok(response)
}
