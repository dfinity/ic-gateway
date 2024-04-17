use std::{collections::HashMap, str::FromStr, sync::Arc};

use anyhow::{anyhow, Error};
use arc_swap::ArcSwapOption;
use fqdn::FQDN;
use rustls::{
    server::{ClientHello, ResolvesServerCert},
    sign::CertifiedKey,
};

use super::Cert;

// Shared certificate storage
#[derive(Clone, Debug)]
pub struct Storage<T: Clone> {
    inner: Arc<ArcSwapOption<HashMap<String, T>>>,
}

impl<T: Clone> Storage<T> {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(ArcSwapOption::empty()),
        }
    }

    fn lookup(&self, hostname: &str) -> Option<T> {
        // Try to parse SNI as FQDN
        let fqdn = FQDN::from_str(hostname).ok()?;

        // Get current snapshot if there's one
        let storage = self.inner.load_full()?;

        // First try to find full FQDN
        if let Some(v) = storage.get(hostname) {
            return Some(v.clone());
        }

        // Next try to find a wildcard certificate for the parent FQDN
        let parent = fqdn.parent()?.to_string();
        let wildcard = format!("*.{parent}");
        storage.get(&wildcard).cloned()
    }

    pub fn store(&self, certs: Vec<Cert<T>>) -> Result<(), Error> {
        let mut h = HashMap::new();

        for v in certs {
            for san in v.san {
                if h.insert(san.clone(), v.cert.clone()).is_some() {
                    return Err(anyhow!("Duplicate SAN detected: {san}"));
                };
            }
        }

        self.inner.store(Some(Arc::new(h)));
        Ok(())
    }
}

// Implement certificate resolving for Rustls
impl ResolvesServerCert for Storage<Arc<CertifiedKey>> {
    fn resolve(&self, ch: ClientHello) -> Option<Arc<CertifiedKey>> {
        // See if client provided us with an SNI
        let sni = ch.server_name()?;
        self.lookup(sni)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_storage() -> Result<(), Error> {
        let storage: Storage<String> = Storage::new();

        // Check common lookups
        let certs = vec![
            Cert {
                san: vec!["foo.bar".into(), "*.foo.bar".into()],
                cert: "foo.bar.cert".into(),
            },
            Cert {
                san: vec!["foo.baz".into(), "*.foo.baz".into()],
                cert: "foo.baz.cert".into(),
            },
        ];

        storage.store(certs)?;

        assert_eq!(storage.lookup("foo.bar"), Some("foo.bar.cert".into()));
        assert_eq!(storage.lookup("blah.foo.bar"), Some("foo.bar.cert".into()));
        assert_eq!(
            storage.lookup("blahblah.foo.bar"),
            Some("foo.bar.cert".into())
        );
        assert_eq!(storage.lookup("blah.blah.foo.bar"), None);
        assert_eq!(storage.lookup("foo.baz"), Some("foo.baz.cert".into()));
        assert_eq!(storage.lookup("bar.foo.baz"), Some("foo.baz.cert".into()));
        assert_eq!(storage.lookup("blah.foo.baz"), Some("foo.baz.cert".into()));
        assert_eq!(storage.lookup("foo.foo"), None);
        assert_eq!(storage.lookup("bad:hostname"), None);

        // Ensure that duplicate SAN fails
        let certs = vec![Cert {
            san: vec!["foo.bar".into(), "foo.bar".into()],
            cert: "foo.bar.cert".into(),
        }];

        assert!(matches!(storage.store(certs), Err(_)));

        Ok(())
    }
}
