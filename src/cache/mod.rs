use std::{
    fmt::Debug,
    hash::Hash,
    mem::size_of,
    sync::Arc,
    time::{Duration, Instant},
};

use ahash::RandomState;
use axum::{
    body::{to_bytes, Body},
    extract::Request,
    middleware::Next,
    response::Response,
};
use bytes::Bytes;
use http::{header::CONTENT_LENGTH, Method};
use moka::sync::{Cache as MokaCache, CacheBuilder as MokaCacheBuilder};
use prometheus::{register_histogram_with_registry, Histogram, Registry};
use strum_macros::{Display, IntoStaticStr};
use tokio::{select, sync::Mutex, time::sleep};

#[derive(Debug, Clone, Display, PartialEq, Eq, IntoStaticStr)]
#[strum(serialize_all = "snake_case")]
pub enum CacheBypassReason {
    MethodNotCacheable,
    SizeUnknown,
    BodyTooBig,
    HTTPError,
}

#[derive(Debug, Clone, Display, PartialEq, Eq, Default, IntoStaticStr)]
#[strum(serialize_all = "SCREAMING_SNAKE_CASE")]
pub enum CacheStatus {
    #[default]
    Disabled,
    Bypass(CacheBypassReason),
    Hit,
    Miss,
}

// Injects itself into a given response to be accessible by middleware
impl CacheStatus {
    pub fn with_response<T>(self, mut resp: Response<T>) -> Response<T> {
        resp.extensions_mut().insert(self);
        resp
    }
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("unable to extract key from request: {0}")]
    ExtractKey(String),
    #[error("unable to fetch request body: {0}")]
    FetchBody(String),
    #[error("unable to parse content-length header")]
    ParseContentLength,
    #[error("{0}")]
    Other(String),
}

#[derive(Clone)]
pub struct Entry {
    response: Response<Bytes>,
    /// Time it took to generate the response for given entry.
    /// Used for x-fetch algorithm.
    delta: f64,
    expires: Instant,
}

impl Entry {
    /// Probabilistically decide if we need to refresh the given cache entry early.
    /// This is an implementation of x-fetch algorigthm, see:
    /// https://en.wikipedia.org/wiki/Cache_stampede#Probabilistic_early_expiration
    fn need_to_refresh(&self, now: Instant, beta: f64) -> bool {
        let rnd = rand::random::<f64>();
        let xfetch = self.delta * beta * rnd.ln();
        let ttl_left = (self.expires - now).as_secs_f64();
        xfetch <= ttl_left
    }
}

pub trait KeyExtractor: Clone + Send + Sync + 'static {
    /// The type of the key.
    type Key: Send + Sync + Clone + Hash + Eq + Debug + 'static;

    /// Extraction method, will return [`Error`] response when the extraction failed
    fn extract<T>(&self, req: &Request<T>) -> Result<Self::Key, Error>;
}

#[derive(Clone)]
pub struct Metrics {
    lock_await: Histogram,
}

impl Metrics {
    pub fn new(registry: &Registry) -> Self {
        Self {
            lock_await: register_histogram_with_registry!(
                "cache_proxy_lock_await",
                "Time spent waiting for the proxy cache lock",
                registry,
            )
            .unwrap(),
        }
    }
}

pub struct Cache<K: KeyExtractor> {
    store: MokaCache<K::Key, Arc<Entry>, RandomState>,
    locks: MokaCache<K::Key, Arc<Mutex<()>>, RandomState>,
    max_item_size: usize,
    lock_timeout: Duration,
    key_extractor: K,
    ttl: Duration,
    xfetch_beta: f64,
    metrics: Metrics,
}

fn weigh_entry<K: KeyExtractor>(_k: &K::Key, v: &Arc<Entry>) -> u32 {
    let mut size = size_of::<K::Key>() + size_of::<Arc<Entry>>();
    size += v.response.body().len();

    for (k, v) in v.response.headers() {
        size += k.as_str().as_bytes().len();
        size += v.as_bytes().len();
    }

    size as u32
}

impl<K: KeyExtractor + 'static> Cache<K> {
    pub fn new(
        cache_size: u64,
        max_item_size: usize,
        ttl: Duration,
        key_extractor: K,
        xfetch_beta: f64,
        lock_timeout: Duration,
        registry: &Registry,
    ) -> Result<Self, Error> {
        if max_item_size as u64 >= cache_size {
            return Err(Error::Other(
                "Cache item size should be less than whole cache size".into(),
            ));
        }

        Ok(Self {
            ttl,
            max_item_size,
            key_extractor,
            xfetch_beta,
            lock_timeout,
            store: MokaCacheBuilder::new(cache_size)
                .time_to_live(ttl)
                .weigher(weigh_entry::<K>)
                .build_with_hasher(RandomState::default()),
            locks: MokaCacheBuilder::new(32768)
                .time_to_idle(Duration::from_secs(60))
                .build_with_hasher(RandomState::default()),
            metrics: Metrics::new(registry),
        })
    }

    pub fn get_lock(&self, key: &K::Key) -> Arc<Mutex<()>> {
        self.locks
            .get_with(key.clone(), || Arc::new(Mutex::new(())))
    }

    pub fn get(&self, key: &K::Key) -> Option<Response> {
        let val = self.store.get(key)?;

        // Run x-fetch if configured and simulate the cache miss if we need to refresh the entry
        if self.xfetch_beta > 0.0 && val.need_to_refresh(Instant::now(), self.xfetch_beta) {
            return None;
        }

        let (parts, body) = val.response.clone().into_parts();
        Some(Response::from_parts(parts, Body::from(body)))
    }

    pub fn insert(&self, key: K::Key, delta: Duration, response: Response<Bytes>) {
        let expires = Instant::now() + self.ttl;

        self.store.insert(
            key,
            Arc::new(Entry {
                response,
                delta: delta.as_secs_f64(),
                expires,
            }),
        );
    }

    pub async fn process_request(&self, request: Request, next: Next) -> Result<Response, Error> {
        // Check if request should bypass cache lookup.
        if request.method() != Method::GET {
            return Ok(CacheStatus::Bypass(CacheBypassReason::MethodNotCacheable)
                .with_response(next.run(request).await));
        }

        // Use cached response if found
        let key = self.key_extractor.extract(&request)?;

        if let Some(v) = self.get(&key) {
            return Ok(CacheStatus::Hit.with_response(v));
        }

        // Get synchronization lock to handle parallel requests.
        let lock = self.get_lock(&key);

        // Record the time spent waiting for the lock.
        let start = Instant::now();

        let mut lock_obtained = false;
        select! {
            // Only one parallel request should execute the response and populate the cache.
            // Other requests will wait for the lock to be released and get results from the cache.
            _ = lock.lock() => {
                lock_obtained = true;
            }

            // We proceed with the request as is if takes too long to get the lock.
            _ = sleep(self.lock_timeout) => {}
        }

        // Record prometheus metrics for the time spent waiting for the lock.
        self.metrics
            .lock_await
            .observe(start.elapsed().as_secs_f64());

        // Check again the cache in case some other request filled it
        // while we were waiting for the lock
        if let Some(v) = self.get(&key) {
            return Ok(CacheStatus::Hit.with_response(v));
        }

        // Otherwise execute the request
        self.proxy_request(request, next, key).await
    }

    async fn proxy_request(
        &self,
        request: Request,
        next: Next,
        key: K::Key,
    ) -> Result<Response, Error> {
        let now = Instant::now();
        // Execute the response & get the headers
        let response = next.run(request).await;

        // Do not cache non-2xx responses
        if !response.status().is_success() {
            return Ok(CacheStatus::Bypass(CacheBypassReason::HTTPError).with_response(response));
        }

        // Extract content length from the response header if there's one
        let content_length = extract_content_length(&response)?;

        // Do not cache responses that have no known size (probably streaming etc)
        let Some(body_size) = content_length else {
            return Ok(CacheStatus::Bypass(CacheBypassReason::SizeUnknown).with_response(response));
        };

        // Do not cache items larger than configured
        if body_size > self.max_item_size {
            return Ok(CacheStatus::Bypass(CacheBypassReason::BodyTooBig).with_response(response));
        }

        // Read the response body into a buffer
        let response = fetch_body(response, body_size).await?;
        let delta = now.elapsed();
        self.insert(key, delta, response.clone());

        let (parts, body) = response.into_parts();
        let response = Response::from_parts(parts, Body::from(body));

        Ok(CacheStatus::Miss.with_response(response))
    }

    #[cfg(test)]
    pub fn housekeep(&self) {
        self.store.run_pending_tasks();
        self.locks.run_pending_tasks();
    }

    #[cfg(test)]
    pub fn size(&self) -> u64 {
        self.store.weighted_size()
    }

    #[cfg(test)]
    pub fn len(&self) -> u64 {
        self.store.entry_count()
    }

    #[cfg(test)]
    pub fn clear(&self) {
        self.store.invalidate_all();
        self.locks.invalidate_all();
        self.housekeep();
    }
}

/// Try to get & parse content-length header
fn extract_content_length(resp: &Response) -> Result<Option<usize>, Error> {
    match resp.headers().get(CONTENT_LENGTH) {
        Some(v) => Ok(Some(
            v.to_str()
                .map_err(|_| Error::ParseContentLength)?
                .parse::<usize>()
                .map_err(|_| Error::ParseContentLength)?,
        )),
        None => Ok(None),
    }
}

/// Read the full response body into memory while applying a limit on the length
async fn fetch_body(response: Response, length: usize) -> Result<Response<Bytes>, Error> {
    let (parts, body) = response.into_parts();
    let body = to_bytes(body, length)
        .await
        .map_err(|x| Error::FetchBody(x.to_string()))?;
    Ok(Response::from_parts(parts, body))
}

#[cfg(test)]
mod tests {
    use super::*;

    use axum::{
        extract::State,
        middleware::from_fn_with_state,
        response::IntoResponse,
        routing::{get, post},
        Router,
    };
    use http::{HeaderValue, StatusCode};
    use sha1::Digest;
    use tower::{Service, ServiceExt};

    #[derive(Clone, Debug)]
    pub struct KeyExtractorTest;

    impl KeyExtractor for KeyExtractorTest {
        type Key = [u8; 20];

        fn extract<T>(&self, request: &Request<T>) -> Result<Self::Key, Error> {
            let paq = request
                .uri()
                .path_and_query()
                .ok_or_else(|| Error::ExtractKey("no path_and_query found".into()))?
                .as_str()
                .as_bytes();

            let hash: [u8; 20] = sha1::Sha1::new().chain_update(paq).finalize().into();
            Ok(hash)
        }
    }

    const MAX_ITEM_SIZE: usize = 1024;
    const MAX_CACHE_SIZE: u64 = 32768;
    const PROXY_LOCK_TIMEOUT: Duration = Duration::from_secs(1);

    async fn dispatch_get_request(router: &mut Router, uri: String) -> Option<CacheStatus> {
        let req = Request::get(uri).body(Body::from("")).unwrap();
        let result = router.call(req).await.unwrap();
        assert_eq!(result.status(), StatusCode::OK);
        result.extensions().get::<CacheStatus>().cloned()
    }

    async fn handler_bypassing_cache(_request: Request<Body>) -> impl IntoResponse {
        // Without content-length header, caching middleware should issue CacheStatus::Bypass
        "test_call".into_response()
    }

    async fn handler_cache_hit(_request: Request<Body>) -> impl IntoResponse {
        let mut response = Response::new(Body::from(b"test_body".to_vec()));
        response
            .headers_mut()
            .insert(CONTENT_LENGTH, HeaderValue::from_str("10").unwrap());
        response
    }

    async fn handler_proxy_cache_lock(request: Request<Body>) -> impl IntoResponse {
        if request.uri().path().contains("slow_response") {
            sleep(2 * PROXY_LOCK_TIMEOUT).await;
        }
        let mut response = Response::new(Body::from(b"test_body".to_vec()));
        response
            .headers_mut()
            .insert(CONTENT_LENGTH, HeaderValue::from_str("10").unwrap());
        response
    }

    async fn handler_malformed_content_length_header(_request: Request<Body>) -> impl IntoResponse {
        let mut response = Response::new(Body::from(b"foo".to_vec()));
        response
            .headers_mut()
            .insert(CONTENT_LENGTH, HeaderValue::from_str("not an int").unwrap());
        response
    }

    async fn handler_content_length_header_too_big(_request: Request<Body>) -> impl IntoResponse {
        let mut response = Response::new(Body::from(b"foo".to_vec()));
        let body_size = MAX_ITEM_SIZE + 1;
        response.headers_mut().insert(
            CONTENT_LENGTH,
            HeaderValue::from_str(body_size.to_string().as_str()).unwrap(),
        );
        response
    }

    async fn middleware(
        State(cache): State<Arc<Cache<KeyExtractorTest>>>,
        request: Request,
        next: Next,
    ) -> impl IntoResponse {
        cache
            .process_request(request, next)
            .await
            .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR.into_response())
    }

    #[test]
    fn test_cache_creation_errors() {
        let cache = Cache::new(
            1024,
            1024,
            Duration::from_secs(60),
            KeyExtractorTest,
            0.0,
            PROXY_LOCK_TIMEOUT,
            &Registry::default(),
        );
        assert!(cache.is_err());
    }

    #[tokio::test]
    async fn test_cache_bypass() {
        let cache = Arc::new(
            Cache::new(
                MAX_CACHE_SIZE,
                MAX_ITEM_SIZE,
                Duration::from_secs(3600),
                KeyExtractorTest,
                0.0,
                PROXY_LOCK_TIMEOUT,
                &Registry::default(),
            )
            .unwrap(),
        );

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
            .layer(from_fn_with_state(Arc::clone(&cache), middleware));

        // Test only GET requests are cached.
        let req = Request::post("/").body(Body::from("")).unwrap();
        let result = app.call(req).await.unwrap();
        assert_eq!(result.status(), StatusCode::OK);
        let cache_status = result.extensions().get::<CacheStatus>().cloned().unwrap();
        assert_eq!(cache.len(), 0);
        assert_eq!(
            cache_status,
            CacheStatus::Bypass(CacheBypassReason::MethodNotCacheable)
        );

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
        let cache_ttl = Duration::from_millis(500);

        let cache = Arc::new(
            Cache::new(
                MAX_CACHE_SIZE,
                MAX_ITEM_SIZE,
                cache_ttl,
                KeyExtractorTest,
                0.0,
                PROXY_LOCK_TIMEOUT,
                &Registry::default(),
            )
            .unwrap(),
        );

        let mut app = Router::new()
            .route("/:key", get(handler_cache_hit))
            .layer(from_fn_with_state(Arc::clone(&cache), middleware));

        // First request doesn't hit the cache, but is stored in the cache
        let req = Request::get("/1").body(Body::from("")).unwrap();
        let result = app.call(req).await.unwrap();
        let cache_status = result.extensions().get::<CacheStatus>().cloned().unwrap();
        assert_eq!(result.status(), StatusCode::OK);
        assert_eq!(cache_status, CacheStatus::Miss);
        cache.housekeep();
        assert_eq!(cache.len(), 1);

        // Next request doesn't hit the cache, but is stored in the cache
        let req = Request::get("/2").body(Body::from("")).unwrap();
        let result = app.call(req).await.unwrap();
        let cache_status = result.extensions().get::<CacheStatus>().cloned().unwrap();
        assert_eq!(result.status(), StatusCode::OK);
        assert_eq!(cache_status, CacheStatus::Miss);
        cache.housekeep();
        assert_eq!(cache.len(), 2);

        // Next request hits the cache
        let req = Request::get("/1").body(Body::from("")).unwrap();
        let result = app.call(req).await.unwrap();
        let cache_status = result.extensions().get::<CacheStatus>().cloned().unwrap();
        assert_eq!(result.status(), StatusCode::OK);
        assert_eq!(cache_status, CacheStatus::Hit);
        let (_, body) = result.into_parts();
        let body = to_bytes(body, usize::MAX).await.unwrap().to_vec();
        let body = String::from_utf8_lossy(&body);
        assert_eq!("test_body", body);
        cache.housekeep();
        assert_eq!(cache.len(), 2);

        // Next request hits again
        let req = Request::get("/2").body(Body::from("")).unwrap();
        let result = app.call(req).await.unwrap();
        let cache_status = result.extensions().get::<CacheStatus>().cloned().unwrap();
        assert_eq!(result.status(), StatusCode::OK);
        assert_eq!(cache_status, CacheStatus::Hit);
        let (_, body) = result.into_parts();
        let body = to_bytes(body, usize::MAX).await.unwrap().to_vec();
        let body = String::from_utf8_lossy(&body);
        assert_eq!("test_body", body);
        cache.housekeep();
        assert_eq!(cache.len(), 2);

        // After ttl, request doesn't hit the cache anymore
        sleep(cache_ttl + Duration::from_millis(100)).await;
        let req = Request::get("/1").body(Body::from("")).unwrap();
        let result = app.call(req).await.unwrap();
        let cache_status = result.extensions().get::<CacheStatus>().cloned().unwrap();
        assert_eq!(result.status(), StatusCode::OK);
        assert_eq!(cache_status, CacheStatus::Miss);

        // Before cache_size limit is reached all requests should be stored in cache.
        cache.clear();
        let req_count = 50;
        // First dispatch round, all requests miss cache.
        for idx in 0..req_count {
            let status = dispatch_get_request(&mut app, format!("/{idx}")).await;
            assert_eq!(status.unwrap(), CacheStatus::Miss);
        }
        // Second dispatch round, all requests hit the cache.
        for idx in 0..req_count {
            let status = dispatch_get_request(&mut app, format!("/{idx}")).await;
            assert_eq!(status.unwrap(), CacheStatus::Hit);
        }

        // Once cache_size limit is reached some requests should be evicted.
        cache.clear();
        let req_count = 800;
        // First dispatch round, all cache misses.
        for idx in 0..req_count {
            let status = dispatch_get_request(&mut app, format!("/{idx}")).await;
            assert_eq!(status.unwrap(), CacheStatus::Miss);
        }
        // Second dispatch round, some requests hit the cache, some don't
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
        cache.housekeep();
        let entry_size = cache.size() / cache.len();
        // Make sure cache size limit was reached.
        // Check that adding one more entry to the cache would overflow its max capacity.
        assert!(MAX_CACHE_SIZE > cache.size());
        assert!(MAX_CACHE_SIZE < cache.size() + entry_size);
    }

    #[tokio::test]
    async fn test_proxy_cache_lock() {
        let cache_ttl = Duration::from_millis(500);
        let cache = Arc::new(
            Cache::new(
                MAX_CACHE_SIZE,
                MAX_ITEM_SIZE,
                cache_ttl,
                KeyExtractorTest,
                0.0,
                PROXY_LOCK_TIMEOUT,
                &Registry::default(),
            )
            .unwrap(),
        );

        let app = Router::new()
            .route("/:key", get(handler_proxy_cache_lock))
            .layer(from_fn_with_state(Arc::clone(&cache), middleware));

        let req_count = 50;
        // Expected cache misses/hits for fast/slow responses, respectively.
        let expected_misses = [1, req_count];
        let expected_hits = [req_count - 1, 0];
        for (idx, uri) in ["/fast_response", "/slow_response"].iter().enumerate() {
            let mut tasks = vec![];
            // Dispatch requests simultaneously.
            for _ in 0..req_count {
                let app = app.clone();
                tasks.push(tokio::spawn(async move {
                    let req = Request::get(*uri).body(Body::from("")).unwrap();
                    let result = app.oneshot(req).await.unwrap();
                    assert_eq!(result.status(), StatusCode::OK);
                    result.extensions().get::<CacheStatus>().cloned()
                }));
            }
            let mut count_hits = 0;
            let mut count_misses = 0;
            for task in tasks {
                task.await
                    .map(|res| match res {
                        Some(CacheStatus::Hit) => count_hits += 1,
                        Some(CacheStatus::Miss) => count_misses += 1,
                        _ => panic!("Unexpected cache status"),
                    })
                    .expect("failed to complete task");
            }
            assert_eq!(count_hits, expected_hits[idx]);
            assert_eq!(count_misses, expected_misses[idx]);
            cache.housekeep();
            cache.clear();
        }
    }
}
