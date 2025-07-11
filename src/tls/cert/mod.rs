pub mod providers;
pub mod storage;

use std::sync::{Arc, Mutex};

use anyhow::{Context, Error, anyhow};
use async_trait::async_trait;
use ic_bn_lib::{
    tasks::Run,
    tls::{extract_sans_der, pem_convert_to_rustls_single},
};
use rustls::sign::CertifiedKey;
use tokio_util::sync::CancellationToken;
use tracing::{debug, warn};

use providers::{Pem, ProvidesCertificates};
use storage::StoresCertificates;

// Generic certificate and a list of its SANs
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Cert<T: Clone + Send + Sync> {
    pub san: Vec<String>,
    pub cert: T,
}

// Commonly used concrete type of the above for Rustls
pub type CertKey = Cert<Arc<CertifiedKey>>;

pub fn pem_convert_to_certkey(pem: &[u8]) -> Result<CertKey, Error> {
    let cert_key = pem_convert_to_rustls_single(pem)
        .context("unable to convert certificate chain and/or private key from PEM")?;

    let san = extract_sans_der(cert_key.cert[0].as_ref()).context("unable to extract SANs")?;
    if san.is_empty() {
        return Err(anyhow!(
            "no supported names found in SubjectAlternativeName extension"
        ));
    }

    Ok(CertKey {
        san,
        cert: Arc::new(cert_key),
    })
}

fn parse_pem(pem: &[Pem]) -> Result<Vec<CertKey>, Error> {
    pem.iter()
        .map(|x| pem_convert_to_certkey(&x.0))
        .collect::<Result<Vec<_>, _>>()
}

#[derive(Clone, Debug)]
struct AggregatorSnapshot {
    pem: Vec<Option<Vec<Pem>>>,
    parsed: Vec<Option<Vec<CertKey>>>,
}

impl AggregatorSnapshot {
    fn flatten(&self) -> Vec<CertKey> {
        self.parsed
            .clone()
            .into_iter()
            .flatten()
            .flatten()
            .collect()
    }
}

impl PartialEq for AggregatorSnapshot {
    fn eq(&self, other: &Self) -> bool {
        self.pem == other.pem
    }
}
impl Eq for AggregatorSnapshot {}

// Collects certificates from providers and stores them in a given storage
pub struct Aggregator {
    providers: Vec<Arc<dyn ProvidesCertificates>>,
    storage: Arc<dyn StoresCertificates<Arc<CertifiedKey>>>,
    snapshot: Mutex<AggregatorSnapshot>,
}

impl std::fmt::Debug for Aggregator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "CertificateAggregator")
    }
}

impl Aggregator {
    pub fn new(
        providers: Vec<Arc<dyn ProvidesCertificates>>,
        storage: Arc<dyn StoresCertificates<Arc<CertifiedKey>>>,
    ) -> Self {
        let snapshot = AggregatorSnapshot {
            pem: vec![None; providers.len()],
            parsed: vec![None; providers.len()],
        };

        Self {
            providers,
            storage,
            snapshot: Mutex::new(snapshot),
        }
    }
}

impl Aggregator {
    /// Fetches certificates concurrently from all providers.
    /// It returns both raw & parsed since parsed can't be compared.
    async fn fetch(&self, mut snapshot: AggregatorSnapshot) -> AggregatorSnapshot {
        // Go over the providers and try to fetch the certificates
        for (i, p) in self.providers.iter().enumerate() {
            // Update the certificates on successful fetch & parse, otherwise old version will be used if any
            match p.get_certificates().await {
                Ok(pem) => {
                    // Try to parse them first to make sure they're valid
                    match parse_pem(&pem) {
                        Ok(mut parsed) => {
                            parsed.sort_by(|a, b| a.san.cmp(&b.san));

                            // Update the entries in the snapshot
                            snapshot.pem[i] = Some(pem);
                            snapshot.parsed[i] = Some(parsed);
                        }

                        Err(e) => warn!(
                            "{self:?}: failed to parse certificates from provider {p:?}: {e:#}"
                        ),
                    }
                }

                Err(e) => warn!("{self:?}: failed to fetch from provider {p:?}: {e:#}"),
            }
        }

        snapshot
    }

    #[allow(clippy::cognitive_complexity)]
    #[allow(clippy::significant_drop_tightening)]
    async fn refresh(&self) {
        // Get a snapshot of current data to update
        let snapshot_old = self.snapshot.lock().unwrap().clone();

        // Fetch new certificates on top of the old snapshot
        let snapshot = self.fetch(snapshot_old.clone()).await;

        // Check if the new set is different
        if snapshot == snapshot_old {
            debug!("{self:?}: certs haven't changed, not updating");
            return;
        }

        let certs = snapshot.flatten();
        warn!(
            "{self:?}: publishing new snapshot with {} certs",
            certs.len()
        );

        debug!("{self:?}: {} certs fetched:", certs.len());
        for v in &certs {
            debug!("{self:?}: {:?}", v.san);
        }

        // Store the new snapshot
        *self.snapshot.lock().unwrap() = snapshot;

        // Publish to storage
        if let Err(e) = self.storage.store(certs) {
            warn!("{self:?}: error storing certificates: {e:#}");
        }
    }
}

#[async_trait]
impl Run for Aggregator {
    async fn run(&self, _: CancellationToken) -> Result<(), Error> {
        self.refresh().await;
        Ok(())
    }
}

#[cfg(test)]
pub mod test {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use prometheus::Registry;
    use providers::Pem;

    use super::*;

    // Some snakeoil certs

    pub const CERT_1: &[u8] = b"-----BEGIN CERTIFICATE-----\n\
    MIIC6TCCAdGgAwIBAgIUK60AjMl8YTJ5nWViMweY043y6/EwDQYJKoZIhvcNAQEL\n\
    BQAwDzENMAsGA1UEAwwEbm92ZzAeFw0yMzAxMDkyMTM5NTZaFw0zMzAxMDYyMTM5\n\
    NTZaMA8xDTALBgNVBAMMBG5vdmcwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK\n\
    AoIBAQCd/7NXWeENaITmYU+eWMJEJMZa6v74g70RpZlprQzx148U0QOKEw/r6mmd\n\
    SlbN4wsbb9lUu3zmXXpvYDAHYuOTYsDWcuNJXP/gCnPrD2wU8lJt3C5blmeU/9+0\n\
    U6/ppRmu6kf/jmm7CMBnowI0+kdvTF7sbpiUBXTDujXNsqtX0FaksILc9ZAqpUCC\n\
    2gqRcOXahzT2vnvJ2N+2bhveG+eB0/5oZcKgx0D4QgjR9k1+thWOQZUCJMg32OYS\n\
    k4e57WhOQxu9Kh5N2MU1Ff3fhCYXzg7/GhJtWyDmjt1vNBwGW9Zn0BicySdcVFPC\n\
    mRW3/rZrSpnwvsEnpIuyKGq+NMSXAgMBAAGjPTA7MAkGA1UdEwQCMAAwDwYDVR0R\n\
    BAgwBoIEbm92ZzAdBgNVHQ4EFgQUYHN6l0ihbfbLQXqnKPltmv9DWDkwDQYJKoZI\n\
    hvcNAQELBQADggEBAFBvyns/lJZ+zB4/Tmx3YUryji20XUNwhtlBC6V7rdWCXneY\n\
    kqKVgbyDZ+XAYX2eL3o1gcv+XJxQgHfL+OqHJCVbK2kkYVSCW38WNVZb+oeTp/w3\n\
    pgtmg91JcCjFEw2doqImLZLQDX6KK1gDGdTQ2dtisFcxGEkMUyjzqmZmZNzl+u7d\n\
    JeDygLfGrMleO7ij2hP2vEfgkGbbvM+JCTav0B91Rj8/CbJHBwr8/CW4BJTjsqZC\n\
    mglNb9+hY8N6XAxntoqZsFzuDyDx7ZSxeAW0yVRemrIPSgcPwpLDBFm4dCSwUHJN\n\
    ujBjp7DRCQgg8uUq+0FMQ63ioZoR5mXQ5hzmTqk=\n\
    -----END CERTIFICATE-----\n\
    ";

    pub const KEY_1: &[u8] = b"-----BEGIN PRIVATE KEY-----\n\
    MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCd/7NXWeENaITm\n\
    YU+eWMJEJMZa6v74g70RpZlprQzx148U0QOKEw/r6mmdSlbN4wsbb9lUu3zmXXpv\n\
    YDAHYuOTYsDWcuNJXP/gCnPrD2wU8lJt3C5blmeU/9+0U6/ppRmu6kf/jmm7CMBn\n\
    owI0+kdvTF7sbpiUBXTDujXNsqtX0FaksILc9ZAqpUCC2gqRcOXahzT2vnvJ2N+2\n\
    bhveG+eB0/5oZcKgx0D4QgjR9k1+thWOQZUCJMg32OYSk4e57WhOQxu9Kh5N2MU1\n\
    Ff3fhCYXzg7/GhJtWyDmjt1vNBwGW9Zn0BicySdcVFPCmRW3/rZrSpnwvsEnpIuy\n\
    KGq+NMSXAgMBAAECggEAKYtxTFAxWZW4kF1ZEqFzH3juAT0WYyE8x1WcY8mhhDvy\n\
    fv5AqH8/qgBe2gGQlp2TL5k2881C184PohaQOnj5rykB3MGj2wgNrgsBlPberBlV\n\
    rFZ/iAyh2u93EpMIx+5mNPScjumTCp+P/BBERcrjmrPhp9ii3RUcMVUWzaoj3Lhc\n\
    wa5trC1r7UqbUZeO7NaVA7cGETZLVm8U7NaL8ccb1dKASUzrC9QCy9VVekJbb2S7\n\
    h38MELR9wvTGS7s4hXQGejb8vEDuXcZzWIFg3YMkJPIyGLAEaRynfeAHm/ji48U0\n\
    zh1ba3CWE/6z6nayDPqWqrwic4Hff6Mz+SIWAz2LyQKBgQDcdeWweNRVXhVkcFUP\n\
    JNpUiLOF5j3f4nqZwk7j5hQBxcXilYO/lmrcimvhvJ3ox97GfqCkvEQM8thTnPmi\n\
    JBagynOfIaUK2qdVwS1BbZ2JpYe3k/rO+iSKtRO4mF94cHgFIafPb5qt0fFz9bDS\n\
    7D2lnWSbveMvb+mZsp/+FZx2DwKBgQC3eBhAbOSrSGuh7KOuWsav8pROMdcsESpz\n\
    j8el1iEklRsklYiNrVsztlZtNUXE2zSHeNPsGENDGlvKG8qD/vbcdTFsYa1H8Hk5\n\
    NydTLAb0/Bm256Xee1Dm5Wt2yG2aLfc9eG0trJz8VgBDhDlulnjo2kavhWIpTBNm\n\
    0WmkMQsQ+QKBgQDYXd1PlUbPgcb9DEJu2nxs+r02bQHM+TnaLhm/EdAQ7UmJV7Q2\n\
    FCpMyI2YvsU78O1zYlPHWf5vtucZKLbXqxOKOye+xgZ04KPaRf1keXBj51GLmnBN\n\
    MrMqbw0r3l/UlI02fBF2RNJKRgHzDO6+E51tLUvQjkyqAewCLI1ZkVw9gQKBgD0F\n\
    J2O+E+vX4VxwnRvvOyfn0WWUdBFHAEyBJJDGgC1vniBzz3/3iV7QpTwbPMI1eeoY\n\
    yLs8cpqN2LuGtLtkAGzgWXjHn99OXrMl4eFqwkGW22KW9vbhIs44vZ47GSDvasy6\n\
    Ee3f/DJ81AegoY1jZIFln57fCP/dOpK20aD3YsvZAoGBAKgaWVYbROCRJ6C8CQGd\n\
    yetoZ8n25E7O5JtyKSNGwiQyD0IURgLuotiBpQvCCz9HGS53E6HLzBCc4jZc3GDq\n\
    qVDS5cIgcfWAOBalBQ+JxoHsnLRGXeBBKwvaJB+EzlrV8st1dCmM4gukElBJm/PZ\n\
    TvEPeiHG81OgB1RPgUt3DVIf\n\
    -----END PRIVATE KEY-----\n\
    ";

    pub const CERT_2: &[u8] = b"-----BEGIN CERTIFICATE-----\n\
    MIIC4jCCAcqgAwIBAgIUDAdBS7aRT7YfKgt/H2VQ1b8u80kwDQYJKoZIhvcNAQEL\n\
    BQAwFzEVMBMGA1UEAwwMMzY1ODE1M2YyN2UwMB4XDTI0MDMwNzIyNTMwOVoXDTM0\n\
    MDMwNTIyNTMwOVowFzEVMBMGA1UEAwwMMzY1ODE1M2YyN2UwMIIBIjANBgkqhkiG\n\
    9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyITGTjnOLGCiW51EuDl5Us7YJk6gkLWeQ+A5\n\
    FQtUaVqjaLKHVZlNnuqFsQ7Y58GKOPzlO1nECfTgv6xUr0i8bhQhoB8GjWdKvhA6\n\
    zxPXOMCDIIW8JuYKCbG67ygVxBx5ER5fNq2GMmyMfmLoLfejPVqWyoV9e9RIY7Vi\n\
    wmiToXXI6vFETom3w7rMhKjJGXR+3/om7i531zmzOFY0jDS0lPMsaNwNQhL3GFfA\n\
    bXjNyBJLYakHsga8VDZcsM5uoS7Zf4ogpFiLczk5DlYvnSdCDhO2KVUe4XwY5oqJ\n\
    IPLL97/uL1tpB9v7D6EX6gGWBMjJpExnggeKDDjXSc16DOUT9wIDAQABoyYwJDAJ\n\
    BgNVHRMEAjAAMBcGA1UdEQQQMA6CDDM2NTgxNTNmMjdlMDANBgkqhkiG9w0BAQsF\n\
    AAOCAQEAPzgUej2SaXnR+0tCFygFALkU33DJMBFU/8JF8HYrm3pgaa4y+okVt6zq\n\
    y1wUCeFejlLB2/AlajPshLJzsmHy6HRH/VKpkL5WkcGSqiFiKr3K+FEpsXtgemiF\n\
    sJP7g0zi8qHPDDUHyHA5idDJzBt0E7UvFO9Dtx4IPkLm1rF7xSQiRl/SzNI9U4py\n\
    7DnY8dtqYhUa2gaYMkZ1Y2BTzzBy6hjl3PnDfCPzTlzMT63Jxj3jFgqO3TGtkj0F\n\
    mrym8qHmCWHHsBdqr0LuD1kzmHoW13PtLzKixzDfyaPsx53ChxJmw7w3K5paFpVU\n\
    PNTlQReyX3nOvb85CynvGgZ3/FQxnw==\n\
    -----END CERTIFICATE-----\n\
    ";

    pub const KEY_2: &[u8] = b"-----BEGIN PRIVATE KEY-----\n\
    MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDIhMZOOc4sYKJb\n\
    nUS4OXlSztgmTqCQtZ5D4DkVC1RpWqNosodVmU2e6oWxDtjnwYo4/OU7WcQJ9OC/\n\
    rFSvSLxuFCGgHwaNZ0q+EDrPE9c4wIMghbwm5goJsbrvKBXEHHkRHl82rYYybIx+\n\
    Yugt96M9WpbKhX171EhjtWLCaJOhdcjq8UROibfDusyEqMkZdH7f+ibuLnfXObM4\n\
    VjSMNLSU8yxo3A1CEvcYV8BteM3IEkthqQeyBrxUNlywzm6hLtl/iiCkWItzOTkO\n\
    Vi+dJ0IOE7YpVR7hfBjmiokg8sv3v+4vW2kH2/sPoRfqAZYEyMmkTGeCB4oMONdJ\n\
    zXoM5RP3AgMBAAECggEADB25vdBQXO4Z4V9HX7pZUl+dP/NQUG4o+gD6cgMVPqhz\n\
    Z0giVVHGFuwk1+YFxTs0luzxDP0Hk3JwgiRvmYfTmvMsdPhq9PBg28svQoP4ZT18\n\
    ruJl1BPiV2Od4AWUCx2NUzN6nVsu2K0mcByZ2u0zt+lZYzNdubXCCgRTy1t2UDMq\n\
    QYhpJAm+yE3TwaAucxV+7T3aD4S23RVcz4N1hnLu90EmPQ6TBHGFC4eproSd8TJ0\n\
    rj2caRPlSast/j1oBwyCfwX6VC/jQU7zv9RaVHK3Y0LN9rlfBCCjWzH1cCjvUpkH\n\
    q7fklHM+BzEB3pZzUAjB7aamDe3eR3xCrbO7QHUiwQKBgQD7W429aXLUQ60pXOpg\n\
    k/56lkW7K9g/SFZJs0lXpyVLNImRcu4NQOl/upm1ADaaI15PPO165UjMjm7N6Tfc\n\
    IZe6tXaGlRIyzURjz4T5f7oko75hJWCW4jCV/6N6e00Y8bldnWkoNdVUSWVOF79c\n\
    ouT4rMn5td9ZAELfqA1c8WhNywKBgQDMONlE7S12Ppd1rfQwdKgNa4d428Hlschl\n\
    lZUSCkRUjF1a8oP5mnf66ySf+QFEVYzRLFeQgTcPej4DDS/EYERF3bLNowroWDzo\n\
    +gbbjuC2oQMFyhMwwcYdSdsfD0FmxVs79tKvu0gsDB005uzEmXs4gQo0nNc9oUJe\n\
    bBE/fLDNBQKBgHXiKkd6/O+wDbYobYN95Qt5DpsJpRGIy28lNnB1Y3gx25LrY9mz\n\
    Z88PpKbOwsznaYOf/4BzqADHjA/mINyMpKxcDopvv2kz+68T1DlvPc2RPegxr2sU\n\
    CdVPX0xCJ5ZbR6Qv/vFszfAJvAkz+ftoKhq2bsM+GNGU3cgm+J1uWoyhAoGAP06w\n\
    K6nKmgk1MonGVO8U2XQn/tNA/E9sa/E+0OTV4c/RcMwVFV9JKkOSivTJ68EJch5o\n\
    1qb3xpiCeLexwxKEl5PuRcjxLK2N1DsNvSpBhtvK8BSAdnDbVWD7yFkWUSGE8sXE\n\
    8i0AZocq1qdvZlKd3BpEa6LjJnvC8zpU7nVc6XECgYEAner1t7zPWvu3L3YiddCZ\n\
    RZw1UnyRTs+OVmmDfWVkkWHpdEQWMHmtJvESp0l7mvOQKtWrco/FT4fOYHrDp0mz\n\
    /xbEEBoYlUOLQPLMqcdP056Qh5BLq8dw/yv9v2KdfVd/yfu97ekQULHQcMetlIed\n\
    v1tiHPlW4461iUonC6zsOVI=\n\
    -----END PRIVATE KEY-----\n\
    ";

    #[derive(Debug)]
    struct TestProvider(Pem, AtomicUsize);

    #[async_trait]
    impl ProvidesCertificates for TestProvider {
        async fn get_certificates(&self) -> Result<Vec<Pem>, Error> {
            if self.1.load(Ordering::SeqCst) == 0 {
                self.1.fetch_add(1, Ordering::SeqCst);
                Ok(vec![self.0.clone()])
            } else {
                Err(anyhow!("foo"))
            }
        }
    }

    #[derive(Debug)]
    struct TestProviderBroken;

    #[async_trait]
    impl ProvidesCertificates for TestProviderBroken {
        async fn get_certificates(&self) -> Result<Vec<Pem>, Error> {
            Err(anyhow!("I'm dead"))
        }
    }

    #[test]
    fn test_pem_convert_to_certkey() -> Result<(), Error> {
        let cert = pem_convert_to_certkey(&[KEY_1, CERT_1].concat())?;
        assert_eq!(cert.san, vec!["novg"]);
        let cert = pem_convert_to_certkey(&[KEY_2, CERT_2].concat())?;
        assert_eq!(cert.san, vec!["3658153f27e0"]);
        Ok(())
    }

    #[tokio::test]
    async fn test_aggregator() -> Result<(), Error> {
        let prov1 = TestProvider(Pem([KEY_1, CERT_1].concat().to_vec()), AtomicUsize::new(0));
        let prov2 = TestProvider(Pem([KEY_2, CERT_2].concat().to_vec()), AtomicUsize::new(0));

        let storage = Arc::new(storage::StorageKey::new(
            None,
            storage::Metrics::new(&Registry::new()),
        ));
        let aggregator = Aggregator::new(
            vec![
                Arc::new(prov1),
                Arc::new(prov2),
                Arc::new(TestProviderBroken),
            ],
            storage,
        );
        aggregator.refresh().await;

        let certs = aggregator.snapshot.lock().unwrap().clone().flatten();
        assert_eq!(certs.len(), 2);
        assert_eq!(certs[0].san, vec!["novg"]);
        assert_eq!(certs[1].san, vec!["3658153f27e0"]);

        // The providers will fail on the 2nd request, make sure the snapshot stays the same
        aggregator.refresh().await;

        let certs = aggregator.snapshot.lock().unwrap().clone().flatten();
        assert_eq!(certs.len(), 2);
        assert_eq!(certs[0].san, vec!["novg"]);
        assert_eq!(certs[1].san, vec!["3658153f27e0"]);

        Ok(())
    }
}
