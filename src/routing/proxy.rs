use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

use axum::{
    extract::{MatchedPath, OriginalUri, Path, Request, State},
    response::IntoResponse,
};
use candid::Principal;
use derive_new::new;
use http::header::{CONTENT_TYPE, X_CONTENT_TYPE_OPTIONS, X_FRAME_OPTIONS};
use ic_agent::agent::http_transport::route_provider::RouteProvider;
use ic_bn_lib::http::{
    headers::{CONTENT_TYPE_CBOR, X_CONTENT_TYPE_OPTIONS_NO_SNIFF, X_FRAME_OPTIONS_DENY},
    proxy::proxy,
    Client,
};
use regex::Regex;
use url::Url;

use super::{error_cause::ErrorCause, ic::BNResponseMetadata};

lazy_static::lazy_static! {
    pub static ref REGEX_REG_ID: Regex = Regex::new(r"^[a-zA-Z0-9]+$").unwrap();
}

#[derive(new)]
pub struct ApiProxyState {
    http_client: Arc<dyn Client>,
    route_provider: Arc<dyn RouteProvider>,
}

// Proxies /api/v2/... and /api/v3/... endpoints to the IC
pub async fn api_proxy(
    State(state): State<Arc<ApiProxyState>>,
    OriginalUri(original_uri): OriginalUri,
    matched_path: MatchedPath,
    principal: Option<Path<String>>,
    request: Request,
) -> Result<impl IntoResponse, ErrorCause> {
    // Check principal for correctness
    if let Some(v) = principal {
        Principal::from_text(v.0).map_err(|_| ErrorCause::IncorrectPrincipal)?;
    }

    // Obtain the next IC URL from the provider
    let url = state
        .route_provider
        .route()
        .map_err(|e| ErrorCause::Other(format!("unable to obtain route: {e:#}")))?;

    // Append the query URL to the IC url
    let url = url
        .join(original_uri.path())
        .map_err(|e| ErrorCause::MalformedRequest(format!("incorrect URL: {e:#}")))?;

    // Proxy the request
    let mut response = proxy(url, request, &state.http_client)
        .await
        .map_err(ErrorCause::from_backend_error)?;

    // Set the correct content-type for all replies if it's not an error
    // The replica and the API boundary nodes should set these headers. This is just for redundancy.
    if response.status().is_success() {
        response
            .headers_mut()
            .insert(CONTENT_TYPE, CONTENT_TYPE_CBOR);
        response
            .headers_mut()
            .insert(X_CONTENT_TYPE_OPTIONS, X_CONTENT_TYPE_OPTIONS_NO_SNIFF);
        response
            .headers_mut()
            .insert(X_FRAME_OPTIONS, X_FRAME_OPTIONS_DENY);
    }

    let bn_metadata = BNResponseMetadata::from(response.headers_mut());
    response.extensions_mut().insert(bn_metadata);
    response.extensions_mut().insert(matched_path);
    Ok(response)
}

#[derive(new)]
pub struct IssuerProxyState {
    http_client: Arc<dyn Client>,
    issuers: Vec<Url>,
    #[new(default)]
    next: AtomicUsize,
}

// Proxies /registrations endpoint to the certificate issuers if they're defined
pub async fn issuer_proxy(
    State(state): State<Arc<IssuerProxyState>>,
    OriginalUri(original_uri): OriginalUri,
    matched_path: MatchedPath,
    id: Option<Path<String>>,
    request: Request,
) -> Result<impl IntoResponse, ErrorCause> {
    // Validate request ID if it's provided
    if let Some(v) = id {
        if !REGEX_REG_ID.is_match(&v.0) {
            return Err(ErrorCause::MalformedRequest(
                "Incorrect request ID format".into(),
            ));
        }
    }

    // Pick next issuer using round-robin & generate request URL for it
    // TODO should we do retries here?
    let next = state.next.fetch_add(1, Ordering::SeqCst) % state.issuers.len();
    let url = state.issuers[next]
        .clone()
        .join(original_uri.path())
        .map_err(|_| ErrorCause::MalformedRequest("unable to parse path as URL part".into()))?;

    let mut response = proxy(url, request, &state.http_client)
        .await
        .map_err(ErrorCause::from_backend_error)?;

    response.extensions_mut().insert(matched_path);

    Ok(response)
}
