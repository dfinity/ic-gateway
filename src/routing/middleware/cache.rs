use std::{mem::size_of, sync::Arc, time::Duration};

use anyhow::{anyhow, Error};
use axum::{
    body::{to_bytes, Body},
    extract::{Request, State},
    middleware::Next,
    response::{IntoResponse, Response},
};
use futures::TryFutureExt;
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

pub trait SizeInBytes {
    fn size_in_bytes(&self) -> usize;
}

impl SizeInBytes for Arc<CacheKey> {
    fn size_in_bytes(&self) -> usize {
        let mut size = size_of::<Arc<CacheKey>>();
        if let Some(ref range) = self.range {
            size += range.as_bytes().len()
        }
        if let Some(path_and_query) = self.uri.path_and_query() {
            size += path_and_query.as_str().as_bytes().len();
        }
        size as usize
    }
}

impl SizeInBytes for FullResponse {
    fn size_in_bytes(&self) -> usize {
        let mut size = size_of::<FullResponse>();
        size += self.body().len();
        for (k, v) in self.headers().iter() {
            size += k.as_str().as_bytes().len();
            size += v.as_bytes().len();
        }
        size
    }
}

fn weigh_entry<K: SizeInBytes>(k: &K, v: &FullResponse) -> u32 {
    (k.size_in_bytes() + v.size_in_bytes()) as u32
}

pub trait KeyExtractor {
    type Key;
    fn extract(&self, req: &FullRequest) -> anyhow::Result<Self::Key>;
}

impl<K, M> Cache<K, M>
where
    K: SizeInBytes + Eq + Hash + Send + Sync + 'static,
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

    pub fn extract_key(&self, req: &FullRequest) -> anyhow::Result<K> {
        self.key_extractor.extract(req)
    }

    pub async fn get(&self, key: &K) -> Option<FullResponse> {
        self.store.get(&key).await
    }

    pub async fn insert(&self, key: K, resp: FullResponse) {
        self.store.insert(key, resp).await;
    }

    pub fn size(&self) -> u64 {
        self.store.weighted_size()
    }

    pub fn len(&self) -> u64 {
        self.store.entry_count()
    }

    pub async fn housekeep(&self) {
        self.store.run_pending_tasks().await;
    }

    // For now stuff below is used only in tests, but belongs here
    #[allow(dead_code)]
    async fn clear(&self) {
        self.store.invalidate_all();
        self.housekeep().await;
    }
}

pub async fn middleware(
    State(cache): State<CacheType>,
    request: Request,
    next: Next,
) -> Result<impl IntoResponse, ErrorCause> {
    // Check if request should bypass cache lookup.
    let cache_bypass_reason = check_cache_bypass(&request);
    if let Some(reason) = cache_bypass_reason {
        return Ok(CacheStatus::Bypass(reason).with_response(next.run(request).await));
    }
    // Use cached response if found.
    let full_request = into_full_request(request).await;
    let cache_key = cache.extract_key(&full_request).map_err(|err| {
        ErrorCause::Other(format!("Unable to extract cache key from request: {err}"))
    })?;
    if let Some(full_response) = cache.get(&cache_key).await {
        return Ok(CacheStatus::Hit.with_response(from_full_response(full_response)));
    }
    // If response is not cached, we propagate request as is further.
    let response = next.run(from_full_request(full_request.clone())).await;
    // Do not cache non-2xx responses
    if !response.status().is_success() {
        return Ok(CacheStatus::Bypass(CacheBypassReason::HTTPError).with_response(response));
    }
    // Extract content length from the response header
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
    // We convert axum Response<Body> into Response<Vec<u8>> for caching.
    let full_response = into_full_response(response).await;
    cache.insert(cache_key, full_response.clone()).await;
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

    fn extract(&self, req: &FullRequest) -> anyhow::Result<Self::Key> {
        let (request_parts, _) = req.clone().into_parts();
        let cache_key = CacheKey {
            uri: request_parts.uri,
            range: request_parts.headers.get(RANGE).cloned(),
        };
        Ok(Arc::new(cache_key))
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

#[cfg(test)]
mod tests {
    use std::{sync::Arc, time::Duration};

    use axum::{
        body::{to_bytes, Body},
        extract::Request,
        middleware,
        response::{IntoResponse, Response},
        routing::{get, post},
        Router,
    };
    use http::{
        header::{CACHE_CONTROL, CONTENT_LENGTH, PRAGMA},
        HeaderValue, StatusCode,
    };
    use tokio::time::sleep;
    use tower::Service;

    use crate::routing::{
        error_cause::ErrorCause,
        middleware::cache::{
            self, Cache, CacheBypassReason, CacheStatus, RequestCacheKeyExtractor,
            SKIP_CACHE_DIRECTIVES,
        },
    };

    const MAX_ITEM_SIZE: u64 = 1024;
    const MAX_CACHE_SIZE: u64 = 32768;

    async fn dispatch_get_request(router: &mut Router, uri: String) -> Option<CacheStatus> {
        let req = Request::get(uri).body(Body::from("")).unwrap();
        let result = router.call(req).await.unwrap();
        assert_eq!(result.status(), StatusCode::OK);
        result.extensions().get::<CacheStatus>().cloned()
    }

    async fn handler_bypassing_cache(
        _request: Request<Body>,
    ) -> Result<impl IntoResponse, ErrorCause> {
        // Without content-length header, caching middleware should issue CacheStatus::Bypass
        Ok("test_call".into_response())
    }

    async fn handler_cache_hit(_request: Request<Body>) -> Result<impl IntoResponse, ErrorCause> {
        let mut response = Response::new(Body::from(b"test_body".to_vec()));
        response
            .headers_mut()
            .insert(CONTENT_LENGTH, HeaderValue::from_str("10").unwrap());
        Ok(response)
    }

    async fn handler_malformed_content_length_header(
        _request: Request<Body>,
    ) -> Result<impl IntoResponse, ErrorCause> {
        let mut response = Response::new(Body::from(b"foo".to_vec()));
        response
            .headers_mut()
            .insert(CONTENT_LENGTH, HeaderValue::from_str("not an int").unwrap());
        Ok(response)
    }

    async fn handler_content_length_header_too_big(
        _request: Request<Body>,
    ) -> Result<impl IntoResponse, ErrorCause> {
        let mut response = Response::new(Body::from(b"foo".to_vec()));
        let body_size = MAX_ITEM_SIZE + 1;
        response.headers_mut().insert(
            CONTENT_LENGTH,
            HeaderValue::from_str(body_size.to_string().as_str()).unwrap(),
        );
        Ok(response)
    }

    #[tokio::test]
    #[should_panic(expected = "Cache item size should be less than whole cache size")]
    async fn test_cache_creation_errors() {
        let cache = Cache::new(
            1024,
            1024,
            Duration::from_secs(60),
            Arc::new(RequestCacheKeyExtractor),
        );
        cache.unwrap();
    }

    #[tokio::test]
    async fn test_cache_bypass() {
        let cache = Cache::new(
            MAX_CACHE_SIZE,
            MAX_ITEM_SIZE,
            Duration::from_secs(3600),
            Arc::new(RequestCacheKeyExtractor),
        )
        .unwrap();
        let cache = Arc::new(cache);
        let mut app = Router::new()
            .route("/", post(handler_bypassing_cache))
            .route("/", get(handler_bypassing_cache))
            .route(
                "/malformed_content_length_header",
                get(handler_malformed_content_length_header),
            )
            .route(
                "/content_length_header_too_big",
                get(handler_content_length_header_too_big),
            )
            .layer(middleware::from_fn_with_state(
                Arc::clone(&cache),
                cache::middleware,
            ));

        // Test only GET requests are cached.
        let req = Request::post("/").body(Body::from("")).unwrap();

        let result = app.call(req).await.unwrap();

        assert_eq!(result.status(), StatusCode::OK);
        let cache_status = result.extensions().get::<CacheStatus>().cloned().unwrap();
        assert_eq!(cache.len(), 0);
        assert_eq!(
            cache_status,
            CacheStatus::Bypass(cache::CacheBypassReason::MethodNotCacheable)
        );

        // Test requests with Cache-Control are not cached
        for header in [CACHE_CONTROL, PRAGMA].iter() {
            for &v in SKIP_CACHE_DIRECTIVES.iter() {
                let mut req = Request::get("/").body(Body::from("")).unwrap();
                req.headers_mut()
                    .insert(header, HeaderValue::from_str(v).unwrap());
                let result = app.call(req).await.unwrap();
                let cache_status = result.extensions().get::<CacheStatus>().cloned().unwrap();
                assert_eq!(cache.len(), 0);
                assert_eq!(result.status(), StatusCode::OK);
                assert_eq!(
                    cache_status,
                    CacheStatus::Bypass(CacheBypassReason::CacheControl)
                );
            }
        }

        // Test non-2xx response are not cached
        let req = Request::get("/non_existing_path")
            .body(Body::from("foobar"))
            .unwrap();
        let result = app.call(req).await.unwrap();
        let cache_status = result.extensions().get::<CacheStatus>().cloned().unwrap();
        assert_eq!(result.status(), StatusCode::NOT_FOUND);
        assert_eq!(
            cache_status,
            CacheStatus::Bypass(CacheBypassReason::HTTPError)
        );
        assert_eq!(cache.len(), 0);

        // Test malformed Content-Length
        let req = Request::get("/malformed_content_length_header")
            .body(Body::from("foobar"))
            .unwrap();
        let result = app.call(req).await.unwrap();
        assert!(result.extensions().get::<CacheStatus>().is_none());
        assert_eq!(result.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(cache.len(), 0);

        // Test Content-Length too big
        let req = Request::get("/content_length_header_too_big")
            .body(Body::from("foobar"))
            .unwrap();
        let result = app.call(req).await.unwrap();
        let cache_status = result.extensions().get::<CacheStatus>().cloned().unwrap();
        assert_eq!(
            cache_status,
            CacheStatus::Bypass(CacheBypassReason::BodyTooBig)
        );
        assert_eq!(result.status(), StatusCode::OK);
        assert_eq!(cache.len(), 0);
    }

    #[tokio::test]
    async fn test_cache_hit() {
        let cache_ttl = Duration::from_secs(3);
        let cache = Cache::new(
            MAX_CACHE_SIZE,
            MAX_ITEM_SIZE,
            Duration::from_secs(2),
            Arc::new(RequestCacheKeyExtractor),
        )
        .unwrap();
        let cache = Arc::new(cache);
        let mut app = Router::new().route("/:key", get(handler_cache_hit)).layer(
            middleware::from_fn_with_state(Arc::clone(&cache), cache::middleware),
        );

        // First request is not stored in cache
        let req = Request::get("/1").body(Body::from("")).unwrap();
        let result = app.call(req).await.unwrap();
        let cache_status = result.extensions().get::<CacheStatus>().cloned().unwrap();
        assert_eq!(result.status(), StatusCode::OK);
        assert_eq!(cache_status, CacheStatus::Miss);
        cache.housekeep().await;
        assert_eq!(cache.len(), 1);

        // Second request hits the cache
        let req = Request::get("/1").body(Body::from("")).unwrap();
        let result = app.call(req).await.unwrap();
        let cache_status = result.extensions().get::<CacheStatus>().cloned().unwrap();
        assert_eq!(result.status(), StatusCode::OK);
        assert_eq!(cache_status, CacheStatus::Hit);
        let (_, body) = result.into_parts();
        let body = to_bytes(body, usize::MAX).await.unwrap().to_vec();
        let body = String::from_utf8_lossy(&body);
        assert_eq!("test_body", body);
        cache.housekeep().await;
        assert_eq!(cache.len(), 1);

        // Third request hits the cache too
        let req = Request::get("/1").body(Body::from("")).unwrap();
        let result = app.call(req).await.unwrap();
        let cache_status = result.extensions().get::<CacheStatus>().cloned().unwrap();
        assert_eq!(result.status(), StatusCode::OK);
        assert_eq!(cache_status, CacheStatus::Hit);
        cache.housekeep().await;
        assert_eq!(cache.len(), 1);

        // After ttl, request doesn't hit the cache anymore
        sleep(cache_ttl + Duration::from_secs(1)).await;
        let req = Request::get("/1").body(Body::from("")).unwrap();
        let result = app.call(req).await.unwrap();
        let cache_status = result.extensions().get::<CacheStatus>().cloned().unwrap();
        assert_eq!(result.status(), StatusCode::OK);
        assert_eq!(cache_status, CacheStatus::Miss);

        // Before cache_size is reached all requests should be stored in cache.
        cache.clear().await;
        let req_count = 50;
        // First dispatch round
        for idx in 0..req_count {
            let status = dispatch_get_request(&mut app, format!("/{idx}")).await;
            assert_eq!(status.unwrap(), CacheStatus::Miss);
        }
        // Second dispatch round
        for idx in 0..req_count {
            let status = dispatch_get_request(&mut app, format!("/{idx}")).await;
            assert_eq!(status.unwrap(), CacheStatus::Hit);
        }

        // Once cache_size is reached some requests should be evicted.
        cache.clear().await;
        let req_count = 800;
        // First dispatch round
        for idx in 0..req_count {
            let status = dispatch_get_request(&mut app, format!("/{idx}")).await;
            assert_eq!(status.unwrap(), CacheStatus::Miss);
        }
        // Second dispatch round
        let mut count_misses = 0;
        let mut count_hits = 0;
        for idx in 0..req_count {
            let status = dispatch_get_request(&mut app, format!("/{idx}")).await;
            if let Some(CacheStatus::Miss) = status {
                count_misses += 1;
            } else if let Some(CacheStatus::Hit) = status {
                count_hits += 1;
            }
        }
        assert!(count_misses > 0);
        assert!(count_hits > 0);
    }
}
