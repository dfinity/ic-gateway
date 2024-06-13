use std::{sync::Arc, time::Duration};

use anyhow::{anyhow, Error};
use axum::{
    body::{to_bytes, Body},
    extract::{Request, State},
    middleware::Next,
    response::{IntoResponse, Response},
};
use http::{
    header::{CACHE_CONTROL, CONTENT_LENGTH, PRAGMA, RANGE},
    HeaderValue, Method,
};
use http::{request, response, Uri};
use moka::future::{Cache as MokaCache, CacheBuilder as MokaCacheBuilder};
use std::hash::Hash;

use crate::routing::error_cause::ErrorCause;

type FullResponse = response::Response<Vec<u8>>;
type FullRequest = request::Request<Vec<u8>>;
pub type CacheType = Arc<Cache<Arc<CacheKey>, Arc<RequestCacheKeyExtractor>>>;

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

pub struct Cache<K, M> {
    store: MokaCache<K, FullResponse>,
    max_item_size: u64,
    key_extractor: M,
}

// Estimate rough amount of bytes that cache entry takes in memory
fn weigh_entry<K, V>(_k: &K, _v: &V) -> u32 {
    (std::mem::size_of::<K>() + std::mem::size_of::<V>()) as u32
}

// TODO: add an error
pub trait KeyExtractor {
    type Key;
    fn extract(&self, req: &FullRequest) -> Self::Key;
}

impl<K, M> Cache<K, M>
where
    K: Eq + Hash + Send + Sync + 'static,
    M: KeyExtractor<Key = K>,
{
    pub fn new(
        cache_size: u64,
        max_item_size: u64,
        ttl: Duration,
        key_extractor: M,
    ) -> anyhow::Result<Self> {
        if max_item_size >= cache_size {
            return Err(anyhow!(
                "Cache item size should be less than whole cache size"
            ));
        }

        Ok(Self {
            max_item_size,
            key_extractor,
            store: MokaCacheBuilder::new(cache_size)
                .time_to_live(ttl)
                .weigher(weigh_entry)
                .build(),
        })
    }

    pub async fn get(&self, req: &FullRequest) -> Option<FullResponse> {
        let key = self.key_extractor.extract(req);
        self.store.get(&key).await
    }

    pub async fn insert(&self, req: &FullRequest, resp: FullResponse) {
        let key = self.key_extractor.extract(req);
        self.store.insert(key, resp).await
    }
}

pub async fn middleware(
    State(cache): State<CacheType>,
    request: Request,
    next: Next,
) -> Result<impl IntoResponse, ErrorCause> {
    // Inspect request for reasons of bypassing cache lookup.
    let cache_bypass_reason = check_cache_bypass(&request);

    if let Some(reason) = cache_bypass_reason {
        return Ok(CacheStatus::Bypass(reason).with_response(next.run(request).await));
    }

    // Use cached response if found.
    let full_request = into_full_request(request).await;
    if let Some(full_response) = cache.get(&full_request).await {
        return Ok(CacheStatus::Hit.with_response(from_full_response(full_response)));
    }

    // If response is not cached, we propagate request as is further.
    let response = next.run(from_full_request(full_request.clone())).await;

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

    let full_response = into_full_response(response).await;

    cache.insert(&full_request, full_response.clone()).await;

    Ok(CacheStatus::Miss.with_response(from_full_response(full_response)))
}

fn check_cache_bypass(request: &request::Request<Body>) -> Option<CacheBypassReason> {
    if request.method() != Method::GET {
        return Some(CacheBypassReason::MethodNotCacheable);
    }

    let headers = request.headers();
    [headers.get(CACHE_CONTROL), headers.get(PRAGMA)]
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

pub struct RequestCacheKeyExtractor;

impl KeyExtractor for Arc<RequestCacheKeyExtractor> {
    type Key = Arc<CacheKey>;

    fn extract(&self, req: &FullRequest) -> Self::Key {
        let (request_parts, _) = req.clone().into_parts();
        let cache_key = CacheKey {
            uri: request_parts.uri,
            range: request_parts.headers.get(RANGE).cloned(),
        };
        Arc::new(cache_key)
    }
}

// Helpers to convert Request/Response from axum Body type to Vec<u8> type.
async fn into_full_request(request: Request<Body>) -> FullRequest {
    let (parts, body) = request.into_parts();
    let mut body_bytes = to_bytes(body, usize::MAX).await.unwrap().to_vec();
    body_bytes.shrink_to_fit();
    Request::from_parts(parts.clone(), body_bytes)
}

fn from_full_request(request: FullRequest) -> Request<Body> {
    let (parts, body) = request.into_parts();
    Request::from_parts(parts, Body::from(body))
}

async fn into_full_response(response: Response<Body>) -> FullResponse {
    let (parts, body) = response.into_parts();
    let mut body_bytes = to_bytes(body, usize::MAX).await.unwrap().to_vec();
    body_bytes.shrink_to_fit();
    Response::from_parts(parts, body_bytes)
}

fn from_full_response(response: FullResponse) -> Response<Body> {
    let (parts, body) = response.into_parts();
    Response::from_parts(parts, Body::from(body))
}
