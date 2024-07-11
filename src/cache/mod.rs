use std::{
    mem::size_of,
    sync::Arc,
    time::{Duration, Instant},
};

use ahash::RandomState;
use anyhow::anyhow;
use axum::{body::Body, extract::Request, response::Response};
use bytes::Bytes;
use http::header::RANGE;
use moka::sync::{Cache as MokaCache, CacheBuilder as MokaCacheBuilder};
use prometheus::{register_histogram_with_registry, Error, Histogram, Registry};
use sha1::{Digest, Sha1};
use strum_macros::{Display, IntoStaticStr};
use tokio::sync::Mutex;

// Storing sha1 hash of the key (20 bytes) is enough, no need to store the whole key.
pub const KEY_HASH_BYTES: usize = 20;

#[derive(Debug, Clone, Display, PartialEq, Eq, Default, IntoStaticStr)]
#[strum(serialize_all = "SCREAMING_SNAKE_CASE")]
pub enum CacheStatus {
    #[default]
    Disabled,
    Bypass(CacheBypassReason),
    Hit,
    Miss,
}

#[derive(Debug, Clone, Display, PartialEq, Eq, IntoStaticStr)]
#[strum(serialize_all = "snake_case")]
pub enum CacheBypassReason {
    MethodNotCacheable,
    SizeUnknown,
    BodyTooBig,
    HTTPError,
}

// Injects itself into a given response to be accessible by middleware
impl CacheStatus {
    pub fn with_response<T>(self, mut resp: Response<T>) -> Response<T> {
        resp.extensions_mut().insert(self);
        resp
    }
}

#[derive(Clone, Hash, PartialEq, Eq)]
pub struct CacheKey([u8; KEY_HASH_BYTES]);

#[derive(Clone)]
pub struct CacheValue {
    response: Response<Bytes>,
    /// Time it took to generate the response for given entry.
    /// Used for x-fetch algorithm.
    delta: f64,
    expires: Instant,
}

impl CacheValue {
    /// Probabilistically decide if we need to refresh the given cache entry early.
    /// This is an implementation of X-Fetch algorigthm, see:
    /// https://en.wikipedia.org/wiki/Cache_stampede#Probabilistic_early_expiration
    fn need_to_refresh(&self, now: Instant, beta: f64) -> bool {
        let rnd = rand::random::<f64>();
        let xfetch = self.delta * beta * rnd.ln();
        let ttl_left = (self.expires - now).as_secs_f64();
        xfetch <= ttl_left
    }
}

pub struct Cache {
    store: MokaCache<CacheKey, Arc<CacheValue>, RandomState>,
    locks: MokaCache<CacheKey, Arc<Mutex<()>>, RandomState>,
    pub max_item_size: usize,
    pub lock_timeout: Duration,
    ttl: Duration,
    xfetch_beta: f64,
    metrics: CacheMetrics,
}

#[derive(Clone)]
pub struct CacheMetrics {
    lock_await: Histogram,
}

impl CacheMetrics {
    pub fn new(registry: &Registry) -> Result<Self, Error> {
        Ok(Self {
            lock_await: register_histogram_with_registry!(
                "cache_proxy_lock_await",
                "Time spent waiting for the proxy cache lock",
                registry,
            )?,
        })
    }

    pub fn observe(&self, duration: Duration) {
        self.lock_await.observe(duration.as_secs_f64());
    }
}

fn weigh_entry(_k: &CacheKey, v: &Arc<CacheValue>) -> u32 {
    let mut size = size_of::<CacheKey>() + size_of::<Arc<CacheValue>>();
    size += v.response.body().len();

    for (k, v) in v.response.headers() {
        size += k.as_str().as_bytes().len();
        size += v.as_bytes().len();
    }

    size as u32
}

impl Cache {
    pub fn new(
        cache_size: u64,
        max_item_size: usize,
        ttl: Duration,
        xfetch_beta: f64,
        lock_timeout: Duration,
        registry: &Registry,
    ) -> anyhow::Result<Self> {
        if max_item_size as u64 >= cache_size {
            return Err(anyhow!(
                "Cache item size should be less than whole cache size"
            ));
        }

        Ok(Self {
            ttl,
            max_item_size,
            xfetch_beta,
            lock_timeout,
            store: MokaCacheBuilder::new(cache_size)
                .time_to_live(ttl)
                .weigher(weigh_entry)
                .build_with_hasher(RandomState::default()),
            locks: MokaCacheBuilder::new(32768)
                .time_to_idle(Duration::from_secs(60))
                .build_with_hasher(RandomState::default()),
            metrics: CacheMetrics::new(registry)?,
        })
    }

    pub fn metrics(&self) -> CacheMetrics {
        self.metrics.clone()
    }

    pub fn get_lock(&self, key: &CacheKey) -> Arc<Mutex<()>> {
        self.locks
            .get_with(key.clone(), || Arc::new(Mutex::new(())))
    }

    pub fn get(&self, key: &CacheKey) -> Option<Response> {
        let val = self.store.get(key)?;

        // Run x-fetch if configured and simulate the cache miss if we need to refresh the entry
        if self.xfetch_beta > 0.0 && val.need_to_refresh(Instant::now(), self.xfetch_beta) {
            return None;
        }

        let (parts, body) = val.response.clone().into_parts();
        Some(Response::from_parts(parts, Body::from(body)))
    }

    pub fn insert(&self, key: CacheKey, delta: Duration, response: Response<Bytes>) {
        let expires = Instant::now() + self.ttl;

        self.store.insert(
            key,
            Arc::new(CacheValue {
                response,
                delta: delta.as_secs_f64(),
                expires,
            }),
        );
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

pub fn extract_key(request: &Request) -> CacheKey {
    // in our case it's always Some()
    let authority = request.uri().authority().unwrap().host().as_bytes();
    let paq = request.uri().path_and_query().unwrap().as_str().as_bytes();

    // Compute a composite hash of two variables: uri and header.
    let mut hash = Sha1::new().chain_update(authority).chain_update(paq);
    if let Some(v) = request.headers().get(RANGE) {
        hash = hash.chain_update(v.as_bytes());
    }

    // Sha1 is a 20 byte hash value.
    let hash: [u8; KEY_HASH_BYTES] = hash.finalize().into();
    CacheKey(hash)
}
