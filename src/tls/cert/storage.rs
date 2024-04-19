use std::{collections::HashMap, str::FromStr, sync::Arc};

use anyhow::{anyhow, Error};
use arc_swap::ArcSwapOption;
use candid::Principal;
use fqdn::FQDN;
use rustls::{server::ClientHello, sign::CertifiedKey};

use super::{Cert, LookupCanister};
use crate::tls::{self, resolver};

#[derive(Debug)]
struct StorageInner<T: Clone> {
    certs: HashMap<String, T>,
    canisters: HashMap<String, Principal>,
}

// Generic shared certificate storage
#[derive(Debug)]
pub struct Storage<T: Clone> {
    inner: ArcSwapOption<StorageInner<T>>,
}

pub type StorageKey = Storage<Arc<CertifiedKey>>;

impl<T: Clone> Storage<T> {
    pub fn new() -> Self {
        Self {
            inner: ArcSwapOption::empty(),
        }
    }

    // Looks up cert by hostname in SubjectAlternativeName table
    fn lookup_cert(&self, hostname: &str) -> Option<T> {
        // Try to parse hostname as FQDN
        let fqdn = FQDN::from_str(hostname).ok()?;

        // Get current snapshot if there's one
        let inner = self.inner.load_full()?;

        // First try to find full FQDN
        if let Some(v) = inner.certs.get(hostname) {
            return Some(v.clone());
        }

        // Next try to find a wildcard certificate for the parent FQDN
        let parent = fqdn.parent()?.to_string();
        let wildcard = format!("*.{parent}");
        inner.certs.get(&wildcard).cloned()
    }

    // Update storage contents with a new list of Certs
    pub fn store(&self, cert_list: Vec<Cert<T>>) -> Result<(), Error> {
        let mut certs = HashMap::new();
        let mut canisters = HashMap::new();

        for c in cert_list {
            // Take note of the canister ID
            if let Some(v) = c.custom {
                if canisters.insert(v.name.clone(), v.canister_id).is_some() {
                    return Err(anyhow!("Duplicate name detected: {}", v.name));
                }
            }

            for san in &c.san {
                if certs.insert(san.clone(), c.cert.clone()).is_some() {
                    return Err(anyhow!("Duplicate SAN detected: {san}"));
                };
            }
        }

        let inner = StorageInner { certs, canisters };
        self.inner.store(Some(Arc::new(inner)));

        Ok(())
    }
}

// Implement certificate resolving for Rustls
impl resolver::ResolvesServerCert for StorageKey {
    fn resolve(&self, ch: &ClientHello) -> Option<Arc<CertifiedKey>> {
        // Make sure we've got an ALPN list and they're all HTTP, otherwise refuse resolving.
        // This is to make sure we don't answer to e.g. ACME challenges here
        if !ch.alpn()?.all(tls::is_http_alpn) {
            return None;
        }

        // See if client provided us with an SNI
        let sni = ch.server_name()?;
        self.lookup_cert(sni)
    }
}

// Implement looking up custom domain canister id by hostname
impl<T: Clone + Sync + Send> LookupCanister for Storage<T> {
    fn lookup_canister(&self, hostname: &str) -> Option<Principal> {
        self.inner.load_full()?.canisters.get(hostname).copied()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::tls::cert::CustomDomain;

    #[test]
    fn test_storage() -> Result<(), Error> {
        let storage: Storage<String> = Storage::new();
        let canister_id = Principal::from_text("s6hwe-laaaa-aaaab-qaeba-cai").unwrap();

        // Check common lookups
        let certs = vec![
            Cert {
                san: vec!["foo.bar".into(), "*.foo.bar".into()],
                cert: "foo.bar.cert".into(),
                custom: None,
            },
            Cert {
                san: vec!["foo.baz".into(), "*.foo.baz".into()],
                cert: "foo.baz.cert".into(),
                custom: Some(CustomDomain {
                    name: "foo.baz".into(),
                    canister_id,
                }),
            },
        ];

        storage.store(certs)?;

        // Check SAN
        assert_eq!(storage.lookup_cert("foo.bar"), Some("foo.bar.cert".into()));
        assert_eq!(
            storage.lookup_cert("blah.foo.bar"),
            Some("foo.bar.cert".into())
        );
        assert_eq!(
            storage.lookup_cert("blahblah.foo.bar"),
            Some("foo.bar.cert".into())
        );
        assert_eq!(storage.lookup_cert("blah.blah.foo.bar"), None);
        assert_eq!(storage.lookup_cert("foo.baz"), Some("foo.baz.cert".into()));
        assert_eq!(
            storage.lookup_cert("bar.foo.baz"),
            Some("foo.baz.cert".into())
        );
        assert_eq!(
            storage.lookup_cert("blah.foo.baz"),
            Some("foo.baz.cert".into())
        );
        assert_eq!(storage.lookup_cert("foo.foo"), None);
        assert_eq!(storage.lookup_cert("bad:hostname"), None);

        // Ensure that duplicate SAN fails
        let certs = vec![Cert {
            san: vec!["foo.bar".into(), "foo.bar".into()],
            cert: "foo.bar.cert".into(),
            custom: None,
        }];

        assert!(matches!(storage.store(certs), Err(_)));

        // Ensure that duplicate custom domain name fails
        let certs = vec![
            Cert {
                san: vec!["foo.bar".into()],
                cert: "foo.bar.cert".into(),
                custom: Some(CustomDomain {
                    name: "foo.bar".into(),
                    canister_id,
                }),
            },
            Cert {
                san: vec!["foo.baz".into()],
                cert: "foo.baz.cert".into(),
                custom: Some(CustomDomain {
                    name: "foo.bar".into(),
                    canister_id,
                }),
            },
        ];

        assert!(matches!(storage.store(certs), Err(_)));

        // Check custom domain lookup
        assert_eq!(storage.lookup_canister("foo.baz"), Some(canister_id));
        assert_eq!(storage.lookup_canister("foo.bar"), None);

        Ok(())
    }
}
