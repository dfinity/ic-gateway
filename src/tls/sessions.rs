use std::time::Duration;

use ahash::RandomState;
use moka::sync::Cache;
use rustls::server::StoresServerSessions;

type Key = Vec<u8>;
type Val = Vec<u8>;

fn weigher(k: &Key, v: &Val) -> u32 {
    (k.len() + v.len()) as u32
}

pub struct Stats {
    pub entries: u64,
    pub size: u64,
}

/// Stores TLS sessions for TLSv1.2 only.
/// SipHash is replaced with ~10x faster aHash.
/// see https://github.com/tkaitchuck/aHash/blob/master/compare/readme.md
#[derive(Debug)]
pub struct Storage {
    cache: Cache<Key, Val, RandomState>,
}

impl Storage {
    pub fn new(capacity: u64, tti: Duration) -> Self {
        let cache = Cache::builder()
            .max_capacity(capacity)
            .time_to_idle(tti)
            .weigher(weigher)
            .build_with_hasher(RandomState::default());

        Self { cache }
    }

    pub fn stats(&self) -> Stats {
        self.cache.run_pending_tasks();
        Stats {
            entries: self.cache.entry_count(),
            size: self.cache.weighted_size(),
        }
    }
}

impl StoresServerSessions for Storage {
    fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.cache.get(key)
    }

    fn put(&self, key: Vec<u8>, value: Vec<u8>) -> bool {
        self.cache.insert(key, value);
        true
    }

    fn take(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.cache.remove(key)
    }

    fn can_cache(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_storage() {
        let c = Storage::new(10000, Duration::from_secs(3600));

        let key1 = "a".repeat(2500).as_bytes().to_vec();
        let key2 = "b".repeat(2500).as_bytes().to_vec();
        let key3 = "b".as_bytes().to_vec();

        // Check that two entries fit
        c.put(key1.clone(), key1.clone());
        c.cache.run_pending_tasks();
        assert_eq!(c.cache.entry_count(), 1);
        assert_eq!(c.cache.weighted_size(), 5000);
        c.put(key2.clone(), key2.clone());
        c.cache.run_pending_tasks();
        assert_eq!(c.cache.entry_count(), 2);
        assert_eq!(c.cache.weighted_size(), 10000);

        // Check that 3rd entry won't fit
        c.put(key3.clone(), key3.clone());
        c.cache.run_pending_tasks();
        assert_eq!(c.cache.entry_count(), 2);
        assert_eq!(c.cache.weighted_size(), 10000);
        assert!(c.get(&key3).is_none());

        // Check that keys are taken and not left
        assert!(c.take(&key1).is_some());
        assert!(c.get(&key1).is_none());
        assert!(c.take(&key2).is_some());
        assert!(c.get(&key2).is_none());

        // Check that nothing left
        c.cache.run_pending_tasks();
        assert_eq!(c.cache.entry_count(), 0);
        assert_eq!(c.cache.weighted_size(), 0);
    }
}
