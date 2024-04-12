use std::{collections::HashMap, str::FromStr, sync::Arc};

use arc_swap::ArcSwapOption;
use fqdn::FQDN;
use rustls::{
    server::{ClientHello, ResolvesServerCert},
    sign::CertifiedKey,
};

pub type CertStorage<T> = Arc<ArcSwapOption<HashMap<String, T>>>;

// Generic certificate resolver that supports wildcards.
// It provides Rustls with a certificate corresponding to the SNI hostname, if there's one.
#[derive(Debug)]
pub struct CertResolver<T: Clone> {
    storage: CertStorage<T>,
}

impl<T: Clone> CertResolver<T> {
    pub fn new(storage: CertStorage<T>) -> Self {
        Self { storage }
    }

    fn find_cert(&self, sni: &str) -> Option<T> {
        let storage = self.storage.load_full()?;

        // Try to parse SNI as FQDN
        let fqdn = FQDN::from_str(sni).ok()?;

        // First try to find full FQDN
        if let Some(v) = storage.get(sni) {
            return Some(v.clone());
        }

        // Next try to find a wildcard certificate for the parent FQDN
        let parent = fqdn.parent()?.to_string();
        let wildcard = format!("*.{parent}");
        storage.get(&wildcard).cloned()
    }
}

impl ResolvesServerCert for CertResolver<Arc<CertifiedKey>> {
    fn resolve(&self, ch: ClientHello) -> Option<Arc<CertifiedKey>> {
        // See if client provided us with an SNI
        let sni = ch.server_name()?;
        self.find_cert(sni)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use anyhow::Error;

    #[test]
    fn test() -> Result<(), Error> {
        let mut hm = HashMap::new();
        hm.insert("foo.bar".to_string(), "foo.bar".to_string());
        hm.insert("*.foo.bar".to_string(), "*.foo.bar".to_string());
        hm.insert("foo.baz".to_string(), "foo.baz".to_string());
        hm.insert("bad:hostname".to_string(), "bad".to_string());

        let storage: CertStorage<String> = Arc::new(ArcSwapOption::new(Some(Arc::new(hm))));
        let resolver = CertResolver::new(storage);

        assert_eq!(resolver.find_cert("foo.bar"), Some("foo.bar".into()));
        assert_eq!(resolver.find_cert("blah.foo.bar"), Some("*.foo.bar".into()));
        assert_eq!(
            resolver.find_cert("blahblah.foo.bar"),
            Some("*.foo.bar".into())
        );
        assert_eq!(resolver.find_cert("blah.blah.foo.bar"), None);
        assert_eq!(resolver.find_cert("foo.baz"), Some("foo.baz".into()));
        assert_eq!(resolver.find_cert("blah.foo.baz"), None);
        assert_eq!(resolver.find_cert("foo.foo"), None);
        assert_eq!(resolver.find_cert("bad:hostname"), None);

        Ok(())
    }
}
