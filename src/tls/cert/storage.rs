use core::fmt;
use std::{collections::BTreeMap, str::FromStr, sync::Arc};

use anyhow::{anyhow, Context, Error};
use arc_swap::ArcSwapOption;
use derive_new::new;
use fqdn::{Fqdn, FQDN};
use ic_bn_lib::http::ALPN_ACME;
use rustls::{server::ClientHello, sign::CertifiedKey};

use super::Cert;
use crate::tls::resolver::ResolvesServerCert;

pub trait StoresCertificates<T: Clone + Send + Sync>: Send + Sync {
    fn store(&self, cert_list: Vec<Cert<T>>) -> Result<(), Error>;
}

struct StorageInner<T: Clone + Send + Sync> {
    certs: BTreeMap<FQDN, Arc<Cert<T>>>,
    certs_wildcard: BTreeMap<FQDN, Arc<Cert<T>>>,
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
    // Looks up cert by hostname
    fn lookup_cert(&self, hostname: &Fqdn) -> Option<Arc<Cert<T>>> {
        // Get current snapshot if there's one
        let inner = self.inner.load_full()?;

        // First try to find full FQDN
        if let Some(v) = inner.certs.get(hostname) {
            return Some(v.clone());
        }

        // Next try to find a wildcard certificate for the parent FQDN
        inner.certs_wildcard.get(hostname.parent()?).cloned()
    }

    fn any(&self) -> Option<Arc<Cert<T>>> {
        let inner = self.inner.load_full()?;

        // Try to find some certificate
        inner
            .certs
            .first_key_value()
            .or_else(|| inner.certs_wildcard.first_key_value())
            .map(|x| x.1)
            .cloned()
    }
}

impl<T: Clone + Send + Sync> StoresCertificates<T> for Storage<T> {
    // Update storage contents with a new list of Certs
    fn store(&self, certs_in: Vec<Cert<T>>) -> Result<(), Error> {
        let mut certs = BTreeMap::new();
        let mut certs_wildcard = BTreeMap::new();

        for cert in certs_in {
            let cert = Arc::new(cert.clone());

            for san in &cert.san {
                // Insert wildcards into a separate tree while stripping the prefix
                // It makes lookups faster
                let (key, tree) = if san.starts_with("*.") {
                    (san.strip_prefix("*.").unwrap(), &mut certs_wildcard)
                } else {
                    (san.as_str(), &mut certs)
                };

                let key =
                    FQDN::from_str(key).context(format!("unable to parse '{san}' as FQDN"))?;

                if tree.insert(key, cert.clone()).is_some() {
                    return Err(anyhow!("Duplicate SAN detected: {san}"));
                };
            }
        }

        let inner = StorageInner {
            certs,
            certs_wildcard,
        };
        self.inner.store(Some(Arc::new(inner)));

        Ok(())
    }
}

// Implement certificate resolving for Rustls
impl ResolvesServerCert for StorageKey {
    fn resolve(&self, ch: &ClientHello) -> Option<Arc<CertifiedKey>> {
        // If the ALPN is ACME - don't return anything to make sure
        // we don't break ACME challenge
        if ch.alpn().is_some_and(|mut x| x.all(|x| x == ALPN_ACME)) {
            return None;
        }

        // See if client provided us with an SNI
        let sni = ch.server_name()?;
        // Try to parse SNI as FQDN
        let sni = FQDN::from_str(sni).ok()?;
        self.lookup_cert(&sni).map(|x| x.cert.clone())
    }

    fn resolve_any(&self) -> Option<Arc<CertifiedKey>> {
        self.any().map(|x| x.cert.clone())
    }
}

#[cfg(test)]
pub mod test {
    use fqdn::fqdn;

    use super::*;

    pub fn create_test_storage() -> Storage<String> {
        let storage: Storage<String> = Storage::new();

        let certs = vec![
            Cert {
                san: vec!["foo.bar".into(), "*.foo.bar".into()],
                cert: "foo.bar.cert".into(),
            },
            Cert {
                san: vec!["foo.baz".into()],
                cert: "foo.baz.cert".into(),
            },
        ];

        storage.store(certs).unwrap();
        storage
    }

    #[test]
    fn test_btreemap() {
        fn get(h: &Fqdn, t: &BTreeMap<FQDN, i32>) -> Option<i32> {
            t.get(h).copied()
        }

        let mut t = BTreeMap::new();
        t.insert(fqdn!("3foo.xyz"), 1);
        t.insert(fqdn!("rbar.baz"), 2);

        let fqdn1 = &fqdn::fqdn!("rbar.baz");
        let fqdn2 = FQDN::from_str("rbar.baz").unwrap();

        assert!(t.contains_key(fqdn1));
        assert!(get(fqdn1, &t).is_some());
        assert!(get(&fqdn2, &t).is_some());
    }

    #[test]
    fn test_storage() -> Result<(), Error> {
        let storage = create_test_storage();

        // Direct
        assert_eq!(
            storage.lookup_cert(&fqdn!("foo.bar")).unwrap().cert,
            "foo.bar.cert"
        );
        assert_eq!(
            storage.lookup_cert(&fqdn!("foo.baz")).unwrap().cert,
            "foo.baz.cert"
        );

        // Wildcard
        assert_eq!(
            storage.lookup_cert(&fqdn!("blah.foo.bar")).unwrap().cert,
            "foo.bar.cert",
        );
        assert_eq!(
            storage
                .lookup_cert(&fqdn!("blahblah.foo.bar"))
                .unwrap()
                .cert,
            "foo.bar.cert"
        );

        // Too deeply nested wildcard should fail
        assert!(storage.lookup_cert(&fqdn!("blah.blah.foo.bar")).is_none());

        // No wildcard available
        assert!(storage.lookup_cert(&fqdn!("bar.foo.baz")).is_none());

        // Non-existant
        assert!(storage.lookup_cert(&fqdn!("foo.foo")).is_none());

        // Ensure that duplicate SAN fails
        let certs = vec![Cert {
            san: vec!["foo.bar".into(), "foo.bar".into()],
            cert: "foo.bar.cert".into(),
        }];
        assert!(storage.store(certs).is_err());

        // Make sure the old info is there
        assert_eq!(
            storage.lookup_cert(&fqdn!("foo.bar")).unwrap().cert,
            "foo.bar.cert"
        );

        // Check any
        assert_eq!(storage.any().unwrap().cert, "foo.bar.cert");

        Ok(())
    }
}
