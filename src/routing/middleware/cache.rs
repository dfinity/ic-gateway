use std::{sync::Arc, time::Duration};

use anyhow::{anyhow, Error};
use axum::{
    body::{to_bytes, Body},
    extract::{Request, State},
    middleware::Next,
    response::{IntoResponse, Response},
};
use http::Uri;
use http::{
    header::{CACHE_CONTROL, CONTENT_LENGTH, PRAGMA, RANGE},
    HeaderValue, Method,
};
use http::{request, response};
use moka::future::{Cache as MokaCache, CacheBuilder as MokaCacheBuilder};

use crate::routing::error_cause::ErrorCause;

type FullResponse = response::Response<Vec<u8>>;

// A list of possible Cache-Control directives that ask us not to cache the response
const SKIP_CACHE_DIRECTIVES: &[&str] = &["no-store", "no-cache", "max-age=0"];

#[derive(Debug, Clone, PartialEq, Default)]
pub enum CacheStatus {
    #[default]
    Disabled,
    Bypass(CacheBypassReason),
    Hit,
    Miss,
}

#[derive(Debug, Clone, PartialEq)]
pub enum CacheBypassReason {
    MethodNotCacheable,
    CacheControl,
    SizeUnknown,
    BodyTooBig,
    HTTPError,
}

impl std::fmt::Display for CacheBypassReason {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::MethodNotCacheable => write!(f, "method_not_cacheable"),
            Self::CacheControl => write!(f, "cache_control"),
            Self::SizeUnknown => write!(f, "size_unknown"),
            Self::BodyTooBig => write!(f, "body_too_big"),
            Self::HTTPError => write!(f, "http_error"),
        }
    }
}

// Injects itself into a given response to be accessible by middleware
impl CacheStatus {
    fn with_response(self, mut resp: Response) -> Response {
        resp.extensions_mut().insert(self);
        resp
    }
}

impl std::fmt::Display for CacheStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::Disabled => write!(f, "DISABLED"),
            Self::Bypass(_) => write!(f, "BYPASS"),
            Self::Hit => write!(f, "HIT"),
            Self::Miss => write!(f, "MISS"),
        }
    }
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct CacheKey {
    uri: Uri,
    range: Option<HeaderValue>,
}

pub struct Cache {
    cache: MokaCache<Arc<CacheKey>, FullResponse>,
    max_item_size: u64,
}

// Estimate rough amount of bytes that cache entry takes in memory
fn weigh_entry(_k: &Arc<CacheKey>, _v: &FullResponse) -> u32 {
    let cost = std::mem::size_of::<FullResponse>() + std::mem::size_of::<Arc<CacheKey>>();
    cost as u32
}

impl Cache {
    pub fn new(cache_size: u64, max_item_size: u64, ttl: Duration) -> Result<Self, Error> {
        if max_item_size >= cache_size {
            return Err(anyhow!(
                "Cache item size should be less than whole cache size"
            ));
        }

        Ok(Self {
            max_item_size,
            cache: MokaCacheBuilder::new(cache_size)
                .time_to_live(ttl)
                .weigher(weigh_entry)
                .build(),
        })
    }
}

pub async fn middleware(
    State(cache): State<Arc<Cache>>,
    request: Request,
    next: Next,
) -> Result<impl IntoResponse, ErrorCause> {
    let (request_parts, request_body) = request.into_parts();

    // Inspect request for reasons of bypassing cache lookup.
    let cache_bypass_reason = check_cache_bypass(&request_parts);

    if let Some(reason) = cache_bypass_reason {
        let request = Request::from_parts(request_parts.clone(), request_body);
        return Ok(CacheStatus::Bypass(reason).with_response(next.run(request).await));
    }

    let parts_cloned = request_parts.clone();

    // Assemble cache key.
    let cache_key = CacheKey {
        uri: parts_cloned.uri,
        range: parts_cloned.headers.get(RANGE).cloned(),
    };

    // Use cached response if found.
    if let Some(full_response) = cache.cache.get(&cache_key).await {
        let (parts, body) = full_response.into_parts();
        let response = Response::from_parts(parts, Body::from(body));
        return Ok(CacheStatus::Hit.with_response(response));
    }

    // If response is not cached, we propagate request as is further.
    let request = Request::from_parts(request_parts, request_body);
    let response = next.run(request).await;

    // Do not cache non-2xx responses
    if !response.status().is_success() {
        return Ok(CacheStatus::Bypass(CacheBypassReason::HTTPError).with_response(response));
    }

    let content_length = extract_content_length(&response).map_err(|_| {
        ErrorCause::MalformedResponse("Malformed Content-Length header in response".into())
    })?;

    // Do not cache responses that have no known size (probably streaming etc)
    let body_size = match content_length {
        Some(v) => v,
        None => {
            return Ok(CacheStatus::Bypass(CacheBypassReason::SizeUnknown).with_response(response))
        }
    };

    // Do not cache items larger than configured
    if body_size > cache.max_item_size {
        return Ok(CacheStatus::Bypass(CacheBypassReason::BodyTooBig).with_response(response));
    }

    let (response_parts, response_body) = response.into_parts();
    let mut body_bytes = to_bytes(response_body, usize::MAX).await.unwrap().to_vec();
    body_bytes.shrink_to_fit();
    let response: FullResponse = Response::from_parts(response_parts.clone(), body_bytes.clone());

    cache
        .cache
        .insert(Arc::new(cache_key), response.clone())
        .await;

    let response = Response::from_parts(response_parts, Body::from(body_bytes));
    Ok(CacheStatus::Miss.with_response(response))
}

fn check_cache_bypass(parts: &request::Parts) -> Option<CacheBypassReason> {
    if parts.method != Method::GET {
        return Some(CacheBypassReason::MethodNotCacheable);
    }

    [parts.headers.get(CACHE_CONTROL), parts.headers.get(PRAGMA)]
        .iter()
        .filter_map(|value| value.cloned())
        .any(|value| {
            value
                .to_str()
                .is_ok_and(|value| SKIP_CACHE_DIRECTIVES.iter().any(|&x| value.contains(x)))
        })
        .then_some(CacheBypassReason::CacheControl)
}

// Try to get & parse content-length header
fn extract_content_length(resp: &Response) -> Result<Option<u64>, Error> {
    let size = match resp.headers().get(CONTENT_LENGTH) {
        Some(v) => v.to_str()?.parse::<u64>()?,
        None => return Ok(None),
    };

    Ok(Some(size))
}
