use core::fmt;
use std::{collections::BTreeMap, str::FromStr, sync::Arc};

use anyhow::{anyhow, Error};
use arc_swap::ArcSwapOption;
use candid::Principal;
use derive_new::new;
use fqdn::{Fqdn, FQDN};
use fqdn_trie::FqdnTrieMap;
use rustls::{server::ClientHello, sign::CertifiedKey};

use super::Cert;
use crate::{http::ACME_TLS_ALPN_NAME, routing::domain::LooksupCustomDomain, tls::resolver};

pub trait StoresCertificates<T: Clone + Send + Sync>: Send + Sync {
    fn store(&self, cert_list: Vec<Cert<T>>) -> Result<(), Error>;
}

struct StorageInner<T: Clone + Send + Sync> {
    // BTreeMap seems to be faster than HashMap
    // for smaller datasets due to cache locality
    certs: BTreeMap<String, Arc<Cert<T>>>,
    canisters: FqdnTrieMap<FQDN, Principal>,
}

// Generic shared certificate storage
#[derive(new)]
pub struct Storage<T: Clone + Send + Sync> {
    #[new(default)]
    inner: ArcSwapOption<StorageInner<T>>,
}

impl<T: Clone + Send + Sync> fmt::Debug for Storage<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Storage")
    }
}

pub type StorageKey = Storage<Arc<CertifiedKey>>;

impl<T: Clone + Send + Sync> Storage<T> {
    // Looks up cert by hostname in SubjectAlternativeName table
    fn lookup_cert(&self, hostname: &str) -> Option<Arc<Cert<T>>> {
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
}

impl<T: Clone + Send + Sync> StoresCertificates<T> for Storage<T> {
    // Update storage contents with a new list of Certs
    fn store(&self, certs_in: Vec<Cert<T>>) -> Result<(), Error> {
        let mut certs = BTreeMap::new();
        // Root value does not matter here, just a placeholder
        let mut canisters = FqdnTrieMap::new(Principal::management_canister());

        for cert in certs_in {
            // Take note of the canister ID
            if let Some(v) = &cert.custom {
                if canisters
                    .insert(FQDN::from_str(&v.name)?, v.canister_id)
                    .is_some()
                {
                    return Err(anyhow!("Duplicate name detected: {}", v.name));
                }
            }

            let cert = Arc::new(cert.clone());
            for san in &cert.san {
                if certs.insert(san.clone(), cert.clone()).is_some() {
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
        // If the ALPN is ACME - don't return anything to make sure
        // we don't break ACME challenge
        if ch
            .alpn()
            .map(|mut x| x.all(|x| x == ACME_TLS_ALPN_NAME))
            .unwrap_or(false)
        {
            return None;
        }

        // See if client provided us with an SNI
        let sni = ch.server_name()?;
        self.lookup_cert(sni).map(|x| x.cert.clone())
    }
}

// Implement looking up custom domain canister id by hostname
impl<T: Clone + Sync + Send> LooksupCustomDomain for Storage<T> {
    fn lookup_custom_domain(&self, hostname: &Fqdn) -> Option<Principal> {
        self.inner.load_full()?.canisters.get(hostname).copied()
    }
}

#[cfg(test)]
pub mod test {
    use fqdn::fqdn;

    use super::*;
    use crate::tls::cert::CustomDomain;

    pub const TEST_CANISTER_ID: &str = "s6hwe-laaaa-aaaab-qaeba-cai";

    pub fn create_test_storage() -> Storage<String> {
        let canister_id = Principal::from_text(TEST_CANISTER_ID).unwrap();
        let storage: Storage<String> = Storage::new();

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

        storage.store(certs).unwrap();
        storage
    }

    #[test]
    fn test_storage() -> Result<(), Error> {
        let canister_id = Principal::from_text(TEST_CANISTER_ID).unwrap();
        let storage = create_test_storage();

        // Check SAN
        assert_eq!(storage.lookup_cert("foo.bar").unwrap().cert, "foo.bar.cert");
        assert_eq!(
            storage.lookup_cert("blah.foo.bar").unwrap().cert,
            "foo.bar.cert",
        );
        assert_eq!(
            storage.lookup_cert("blahblah.foo.bar").unwrap().cert,
            "foo.bar.cert"
        );
        assert!(storage.lookup_cert("blah.blah.foo.bar").is_none());
        assert_eq!(storage.lookup_cert("foo.baz").unwrap().cert, "foo.baz.cert");
        assert_eq!(
            storage.lookup_cert("bar.foo.baz").unwrap().cert,
            "foo.baz.cert"
        );
        assert_eq!(
            storage.lookup_cert("blah.foo.baz").unwrap().cert,
            "foo.baz.cert"
        );
        assert!(storage.lookup_cert("foo.foo").is_none());
        assert!(storage.lookup_cert("bad:hostname").is_none());

        // Ensure that duplicate SAN fails
        let certs = vec![Cert {
            san: vec!["foo.bar".into(), "foo.bar".into()],
            cert: "foo.bar.cert".into(),
            custom: None,
        }];
        assert!(storage.store(certs).is_err());

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
        assert!(storage.store(certs).is_err());

        // Check custom domain lookup
        assert_eq!(
            storage.lookup_custom_domain(&fqdn!("foo.baz")),
            Some(canister_id)
        );
        assert!(storage.lookup_custom_domain(&fqdn!("foo.bar")).is_none());

        Ok(())
    }
}
