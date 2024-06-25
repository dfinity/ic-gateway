use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

use anyhow::Error;
use axum::{
    body::Body,
    extract::{MatchedPath, OriginalUri, Path, Request, State},
    response::{IntoResponse, Response},
};
use candid::Principal;
use derive_new::new;
use ic_agent::agent::http_transport::route_provider::RouteProvider;
use regex::Regex;
use url::Url;

use super::{body, error_cause::ErrorCause, ic::BNResponseMetadata};
use crate::http::Client;

lazy_static::lazy_static! {
    pub static ref REGEX_REG_ID: Regex = Regex::new(r"^[a-zA-Z0-9]+$").unwrap();
}

// Proxies provided Axum request to a given URL using Reqwest Client trait object and returns Axum response
async fn proxy(
    url: Url,
    request: Request,
    http_client: &Arc<dyn Client>,
) -> Result<Response, Error> {
    // Convert Axum request into Reqwest one
    let (parts, body) = request.into_parts();
    let mut request = reqwest::Request::new(parts.method.clone(), url);
    *request.headers_mut() = parts.headers;
    // Use SyncBodyDataStream wrapper that is Sync (Axum body is !Sync)
    *request.body_mut() = Some(reqwest::Body::wrap_stream(body::SyncBodyDataStream::new(
        body,
    )));

    // Execute the request
    let response = http_client.execute(request).await?;
    let headers = response.headers().clone();

    // Convert the Reqwest response back to the Axum one
    let mut response = Response::builder()
        .status(response.status())
        .body(Body::from_stream(response.bytes_stream()))?;
    *response.headers_mut() = headers;

    Ok(response)
}

#[derive(new)]
pub struct ApiProxyState {
    http_client: Arc<dyn Client>,
    route_provider: Arc<dyn RouteProvider>,
}

// Proxies /api/v2/... endpoints to the IC
pub async fn api_proxy(
    State(state): State<Arc<ApiProxyState>>,
    OriginalUri(uri): OriginalUri,
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
        .join(uri.path())
        .map_err(|e| ErrorCause::MalformedRequest(format!("incorrect URL: {e:#}")))?;

    // Proxy the request
    let mut response = proxy(url, request, &state.http_client)
        .await
        .map_err(ErrorCause::from)?;

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
    OriginalUri(uri): OriginalUri,
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
        .join(uri.path())
        .map_err(|_| ErrorCause::MalformedRequest("unable to parse path as URL part".into()))?;

    let mut response = proxy(url, request, &state.http_client)
        .await
        .map_err(ErrorCause::from)?;

    response.extensions_mut().insert(matched_path);
    Ok(response)
}
