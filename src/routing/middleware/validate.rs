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
use crate::routing::{domain::ResolvesDomain, CanisterId};

pub async fn middleware(
    State(resolver): State<Arc<dyn ResolvesDomain>>,
    tls_info: Option<Extension<Arc<TlsInfo>>>,
    mut request: Request,
    next: Next,
) -> Result<impl IntoResponse, ErrorCause> {
    // Extract the authority
    let authority = match extract_authority(&request) {
        Some(v) => v,
        None => return Err(ErrorCause::NoAuthority),
    };

    // If it's a TLS request - check that the authority matches SNI
    if let Some(v) = tls_info {
        if v.sni != authority {
            return Err(ErrorCause::SNIMismatch);
        }
    }

    // Resolve the domain
    let domain = resolver
        .resolve(&authority)
        .ok_or(ErrorCause::UnknownDomain)?;

    // Inject canister_id separately if it was resolved
    if let Some(v) = domain.canister_id {
        request.extensions_mut().insert(CanisterId(v));
    }

    // Inject request context
    // TODO remove Arc?
    let ctx = Arc::new(RequestCtx {
        authority,
        domain: domain.clone(),
    });
    request.extensions_mut().insert(ctx.clone());

    // Execute the request
    let mut response = next.run(request).await;

    // Inject the same into the response
    response.extensions_mut().insert(ctx);
    if let Some(v) = domain.canister_id {
        response.extensions_mut().insert(CanisterId(v));
    }

    Ok(response)
}
