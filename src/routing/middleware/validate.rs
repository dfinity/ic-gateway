use std::sync::Arc;

use axum::{
    extract::{Extension, Request, State},
    middleware::Next,
    response::IntoResponse,
};

use crate::{
    http::ConnInfo,
    routing::{ErrorCause, RequestCtx},
};

use super::extract_authority;
use crate::routing::canister::ResolvesCanister;

pub async fn middleware(
    Extension(conn_info): Extension<Arc<ConnInfo>>,
    State(resolver): State<Arc<dyn ResolvesCanister>>,
    mut request: Request,
    next: Next,
) -> Result<impl IntoResponse, ErrorCause> {
    let authority = match extract_authority(&request) {
        Some(v) => v,
        None => return Err(ErrorCause::NoAuthority),
    };

    // If it's a TLS request - check that authority matches SNI
    if let Some(v) = &conn_info.tls {
        if v.sni != authority {
            return Err(ErrorCause::SNIMismatch);
        }
    }

    // Resolve the canister
    let canister = resolver
        .resolve_canister(&authority)
        .ok_or(ErrorCause::CanisterIdNotFound)?;

    println!("{:?}", canister.id.to_string());

    let ctx = Arc::new(RequestCtx {
        authority,
        canister,
    });
    request.extensions_mut().insert(ctx);

    Ok(next.run(request).await)
}
