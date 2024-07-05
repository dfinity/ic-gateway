use std::{mem::size_of, sync::Arc, time::Duration};

use ahash::RandomState;
use anyhow::anyhow;
use axum::{
    extract::Request,
    response::{self, Response},
};
use http::header::RANGE;
use moka::sync::{Cache as MokaCache, CacheBuilder as MokaCacheBuilder};
use sha1::{Digest, Sha1};
use strum_macros::{Display, IntoStaticStr};
use tokio::sync::Mutex;

pub type FullResponse = response::Response<Vec<u8>>;

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
    CacheControl,
    SizeUnknown,
    BodyTooBig,
    HTTPError,
}

// Injects itself into a given response to be accessible by middleware
impl CacheStatus {
    pub fn with_response(self, mut resp: Response) -> Response {
        resp.extensions_mut().insert(self);
        resp
    }
}

#[derive(Clone, Hash, PartialEq, Eq)]
pub struct CacheKey([u8; KEY_HASH_BYTES]);

pub struct Cache {
    store: MokaCache<CacheKey, FullResponse, RandomState>,
    lock_map: MokaCache<CacheKey, Arc<Mutex<()>>>,
    max_item_size: u64,
}

fn weigh_entry(_k: &CacheKey, v: &FullResponse) -> u32 {
    let mut size = KEY_HASH_BYTES + size_of::<FullResponse>();
    size += v.body().len();
    for (k, v) in v.headers() {
        size += k.as_str().as_bytes().len();
        size += v.as_bytes().len();
    }
    size as u32
}

impl Cache {
    pub fn new(cache_size: u64, max_item_size: u64, ttl: Duration) -> anyhow::Result<Self> {
        if max_item_size >= cache_size {
            return Err(anyhow!(
                "Cache item size should be less than whole cache size"
            ));
        }

        Ok(Self {
            max_item_size,
            store: MokaCacheBuilder::new(cache_size)
                .time_to_live(ttl)
                .weigher(weigh_entry)
                .build_with_hasher(RandomState::default()),
            lock_map: MokaCacheBuilder::new(cache_size).time_to_live(ttl).build(),
        })
    }

    pub fn max_item_size(&self) -> u64 {
        self.max_item_size
    }

    pub async fn get_lock(&self, key: &CacheKey) -> Arc<Mutex<()>> {
        self.lock_map
            .get_with(key.clone(), || Arc::new(Mutex::new(())))
    }

    pub async fn get(&self, key: &CacheKey) -> Option<FullResponse> {
        self.store.get(key)
    }

    pub async fn insert(&self, key: CacheKey, resp: FullResponse) {
        self.store.insert(key, resp)
    }

    #[cfg(test)]
    pub async fn housekeep(&self) {
        self.store.run_pending_tasks();
        self.lock_map.run_pending_tasks();
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
    pub async fn clear(&self) {
        self.store.invalidate_all();
        self.lock_map.invalidate_all();
        self.housekeep().await;
    }
}

pub fn extract_key(request: &Request) -> CacheKey {
    let uri_str = request.uri().to_string();
    let uri_bytes = uri_str.as_bytes();

    let slice_range_bytes = request
        .headers()
        .get(RANGE)
        .map_or_else(Vec::new, |value| value.as_bytes().to_vec());

    // Compute a composite hash of two variables: uri and header.
    let hash = Sha1::new()
        .chain_update(uri_bytes)
        .chain_update(slice_range_bytes)
        .finalize();

    // Sha1 is a 20 byte hash value.
    let hash: [u8; KEY_HASH_BYTES] = hash.into();
    CacheKey(hash)
}
