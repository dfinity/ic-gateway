use std::sync::Arc;

use axum::{
    extract::{Request, State},
    middleware::Next,
    response::IntoResponse,
};
use http::header::RANGE;
use sha1::{Digest, Sha1};

use crate::{
    cache::{Cache, Error, KeyExtractor},
    routing::error_cause::ErrorCause,
};

#[derive(Clone, Debug)]
pub struct KeyExtractorUriRange;

impl KeyExtractor for KeyExtractorUriRange {
    type Key = [u8; 20];

    fn extract<T>(&self, request: &Request<T>) -> Result<Self::Key, Error> {
        let authority = request
            .uri()
            .authority()
            .ok_or_else(|| Error::ExtractKey("no authority found".into()))?
            .host()
            .as_bytes();
        let paq = request
            .uri()
            .path_and_query()
            .ok_or_else(|| Error::ExtractKey("no path_and_query found".into()))?
            .as_str()
            .as_bytes();

        // Compute a composite hash
        let mut hash = Sha1::new().chain_update(authority).chain_update(paq);
        if let Some(v) = request.headers().get(RANGE) {
            hash = hash.chain_update(v.as_bytes());
        }

        // Sha1 is a 20 byte hash value.
        let hash: [u8; 20] = hash.finalize().into();
        Ok(hash)
    }
}

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
