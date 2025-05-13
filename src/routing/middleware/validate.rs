use std::{str::FromStr, sync::Arc};

use anyhow::Error;
use axum::{
    extract::{Request, State},
    middleware::Next,
    response::IntoResponse,
};
use candid::Principal;
use fqdn::FQDN;
use ic_bn_lib::http::extract_authority;
use url::form_urlencoded;

use crate::routing::{CanisterId, ErrorCause, RequestCtx, RequestType, domain::ResolvesDomain};

#[derive(Clone)]
pub struct ValidateState {
    pub resolver: Arc<dyn ResolvesDomain>,
    pub canister_id_from_query_params: bool,
}

pub async fn middleware(
    State(state): State<ValidateState>,
    mut request: Request,
    next: Next,
) -> Result<impl IntoResponse, ErrorCause> {
    // Try to extract the authority
    let Some(authority) = extract_authority(&request).and_then(|x| FQDN::from_str(x).ok()) else {
        return Err(ErrorCause::NoAuthority);
    };

    // Resolve the domain
    let mut lookup = state
        .resolver
        .resolve(&authority)
        .ok_or(ErrorCause::UnknownDomain)?;

    // If configured - try to resolve canister id from query params
    if state.canister_id_from_query_params && lookup.canister_id.is_none() {
        lookup.canister_id = canister_id_from_query_params(&request)
            .map_err(|e| ErrorCause::CanisterIdIncorrect(e.to_string()))?
    }

    // Inject canister_id separately if it was resolved
    if let Some(v) = lookup.canister_id {
        request.extensions_mut().insert(CanisterId(v));
    }

    // Always provided by the preceding middleware so should be safe
    let request_type = request.extensions().get::<RequestType>().copied().unwrap();

    // Inject request context
    let ctx = Arc::new(RequestCtx {
        authority,
        domain: lookup.domain,
        verify: lookup.verify,
        request_type,
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

/// Tries to extract canister id from query params
fn canister_id_from_query_params(request: &Request) -> Result<Option<Principal>, Error> {
    let Some(query) = request.uri().query() else {
        return Ok(None);
    };

    let Some(id) = form_urlencoded::parse(query.as_bytes()).find(|(k, _)| k == "canisterId") else {
        return Ok(None);
    };

    let id = Principal::from_text(id.1)?;
    Ok(Some(id))
}

#[cfg(test)]
mod test {
    use axum::body::Body;
    use ic_bn_lib::principal;

    use super::*;

    #[test]
    fn test_canister_id_from_query_params() {
        // good
        let req = Request::builder()
            .uri("http://foo.bar/?canisterId=aaaaa-aa")
            .body(Body::empty())
            .unwrap();

        assert_eq!(
            canister_id_from_query_params(&req).unwrap(),
            Some(principal!("aaaaa-aa"))
        );

        // with other params
        let req = Request::builder()
            .uri("http://foo.bar/?foo=bar&canisterId=aaaaa-aa")
            .body(Body::empty())
            .unwrap();

        assert_eq!(
            canister_id_from_query_params(&req).unwrap(),
            Some(principal!("aaaaa-aa"))
        );

        // bad
        let req = Request::builder()
            .uri("http://foo.bar/?foo=bar&canisterId=aa")
            .body(Body::empty())
            .unwrap();

        assert!(canister_id_from_query_params(&req).is_err());

        // no param
        let req = Request::builder()
            .uri("http://foo.bar/?foo=bar")
            .body(Body::empty())
            .unwrap();

        assert_eq!(canister_id_from_query_params(&req).unwrap(), None);
    }
}
