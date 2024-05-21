use std::sync::Arc;

use axum::{
    extract::{Extension, Request, State},
    middleware::Next,
    response::IntoResponse,
};

use crate::{
    http::TlsInfo,
    routing::{ErrorCause, RequestCtx},
};

use super::extract_authority;
use crate::routing::canister::ResolvesCanister;

pub async fn middleware(
    State(resolver): State<Arc<dyn ResolvesCanister>>,
    tls_info: Option<Extension<Arc<TlsInfo>>>,
    mut request: Request,
    next: Next,
) -> Result<impl IntoResponse, ErrorCause> {
    // Extract the authority
    let authority = match extract_authority(&request) {
        Some(v) => v,
        None => return Err(ErrorCause::NoAuthority),
    };

    // If it's a TLS request - check that authority matches SNI
    if let Some(v) = tls_info {
        if v.sni != authority {
            return Err(ErrorCause::SNIMismatch);
        }
    }

    // Resolve the canister
    let canister = resolver
        .resolve_canister(&authority)
        .ok_or(ErrorCause::CanisterIdNotFound)?;

    let ctx = Arc::new(RequestCtx {
        authority,
        canister,
    });
    request.extensions_mut().insert(ctx.clone());

    let mut response = next.run(request).await;
    response.extensions_mut().insert(ctx);

    Ok(response)
}
