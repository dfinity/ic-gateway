use std::sync::Arc;

use axum::{
    extract::{Request, State},
    middleware::Next,
    response::IntoResponse,
};

use super::extract_authority;
use crate::routing::{domain::ResolvesDomain, CanisterId, ErrorCause, RequestCtx};

pub async fn middleware(
    State(resolver): State<Arc<dyn ResolvesDomain>>,
    mut request: Request,
    next: Next,
) -> Result<impl IntoResponse, ErrorCause> {
    // Extract the authority
    let Some(authority) = extract_authority(&request) else {
        return Err(ErrorCause::NoAuthority);
    };

    // Resolve the domain
    let lookup = resolver
        .resolve(&authority)
        .ok_or(ErrorCause::UnknownDomain)?;

    // Inject canister_id separately if it was resolved
    if let Some(v) = lookup.canister_id {
        request.extensions_mut().insert(CanisterId(v));
    }

    // Inject request context
    // TODO remove Arc?
    let ctx = Arc::new(RequestCtx {
        authority,
        domain: lookup.domain.clone(),
        verify: lookup.verify,
    });
    request.extensions_mut().insert(ctx.clone());

    // Execute the request
    let mut response = next.run(request).await;

    // Inject the same into the response
    response.extensions_mut().insert(ctx);
    if let Some(v) = lookup.canister_id {
        response.extensions_mut().insert(CanisterId(v));
    }

    Ok(response)
}
