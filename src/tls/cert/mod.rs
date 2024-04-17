pub mod providers;
pub mod storage;

use std::{
    net::{Ipv4Addr, Ipv6Addr},
    sync::Arc,
    time::Duration,
};

use anyhow::{anyhow, Context, Error};
use async_trait::async_trait;
use futures::future::join_all;
use rustls::{crypto::aws_lc_rs, sign::CertifiedKey};
use tokio::select;
use tokio_util::sync::CancellationToken;
use tracing::warn;
use x509_parser::prelude::*;

use crate::{core::Run, tls::cert::storage::Storage};

// Generic certificate and a list of its SANs
pub struct Cert<T> {
    san: Vec<String>,
    cert: T,
}

// Commonly used concrete type of the above for Rustls
pub type CertKey = Cert<Arc<CertifiedKey>>;

// Trait that the certificate providers should implement
// It should return a vector of Rustls-compatible keys
#[async_trait]
pub trait ProvidesCertificates: Sync + Send {
    async fn get_certificates(&self) -> Result<Vec<CertKey>, Error>;
}

// Extracts a list of SubjectAlternativeName from a single certificate, formatted as strings.
// Skips everything except DNSName and IPAddress
fn extract_san_from_der(cert: &[u8]) -> Result<Vec<String>, Error> {
    let cert = X509Certificate::from_der(cert)
        .context("Unable to parse DER-encoded certificate")?
        .1;

    for ext in cert.extensions() {
        if let ParsedExtension::SubjectAlternativeName(san) = ext.parsed_extension() {
            let mut names = vec![];
            for name in &san.general_names {
                let name = match name {
                    GeneralName::DNSName(v) => (*v).to_string(),
                    GeneralName::IPAddress(v) => match v.len() {
                        4 => {
                            let b: [u8; 4] = (*v).try_into().unwrap(); // We already checked that it's 4
                            let ip = Ipv4Addr::from(b);
                            ip.to_string()
                        }

                        16 => {
                            let b: [u8; 16] = (*v).try_into().unwrap(); // We already checked that it's 16
                            let ip = Ipv6Addr::from(b);
                            ip.to_string()
                        }

                        _ => return Err(anyhow!("Invalid IP address length {}", v.len())),
                    },

                    _ => continue,
                };

                names.push(name);
            }

            if names.is_empty() {
                return Err(anyhow!(
                    "No supported names found in SubjectAlternativeName extension"
                ));
            }

            return Ok(names);
        }
    }

    Err(anyhow!("SubjectAlternativeName extension not found"))
}

// Converts raw PEM certificate chain & private key to a CertifiedKey ready to be consumed by Rustls
pub fn pem_convert_to_rustls(key: &[u8], certs: &[u8]) -> Result<Cert<Arc<CertifiedKey>>, Error> {
    let (key, certs) = (key.to_vec(), certs.to_vec());

    let key = rustls_pemfile::private_key(&mut key.as_ref())?
        .ok_or_else(|| anyhow!("No private key found"))?;

    let certs = rustls_pemfile::certs(&mut certs.as_ref()).collect::<Result<Vec<_>, _>>()?;
    if certs.is_empty() {
        return Err(anyhow!("No certificates found"));
    }

    // Extract a list of SANs from the 1st certificate in the chain
    let san = extract_san_from_der(certs[0].as_ref())?;

    // Parse key
    let key = aws_lc_rs::sign::any_supported_type(&key)?;

    Ok(Cert {
        san,
        cert: Arc::new(CertifiedKey::new(certs, key)),
    })
}

// Collects certificates from providers and stores them in a given storage
pub struct Aggregator {
    providers: Vec<Arc<dyn ProvidesCertificates>>,
    storage: Arc<Storage<Arc<CertifiedKey>>>,
}

impl Aggregator {
    pub fn new(
        providers: Vec<Arc<dyn ProvidesCertificates>>,
        storage: Arc<Storage<Arc<CertifiedKey>>>,
    ) -> Self {
        Self { providers, storage }
    }

    // Fetches certificates concurrently from all providers
    async fn fetch(&self) -> Result<Vec<CertKey>, Error> {
        let certs = join_all(
            self.providers
                .iter()
                .map(|x| async { x.get_certificates().await }),
        )
        .await;

        // Flatten them into a single vector
        let certs = certs
            .into_iter()
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .flatten()
            .collect::<Vec<_>>();

        Ok(certs)
    }
}

#[async_trait]
impl Run for Aggregator {
    async fn run(&self, token: CancellationToken) -> Result<(), Error> {
        let mut interval = tokio::time::interval(Duration::from_secs(10));

        loop {
            select! {
                () = token.cancelled() => {
                    warn!("Aggregator exiting");
                    return Ok(());
                },

                _ = interval.tick() => {
                    let certs = match self.fetch().await {
                        Err(e) => {
                            warn!("Unable to fetch certificates: {e}");
                            continue;
                        }

                        Ok(v) => v,
                    };

                    if let Err(e) = self.storage.store(certs) {
                        warn!("Error storing certificates: {e}");
                    }
                }
            }
        }
    }
}

#[cfg(test)]
pub mod test {
    use super::*;

    // Some snakeoil cert+key from one of the hosts

    pub const CERT: &[u8] = b"-----BEGIN CERTIFICATE-----\n\
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

    pub const KEY: &[u8] = b"-----BEGIN PRIVATE KEY-----\n\
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

    #[test]
    fn test_pem_convert_to_rustls() -> Result<(), Error> {
        let cert = pem_convert_to_rustls(KEY, CERT)?;
        assert_eq!(cert.san, vec!["novg"]);
        Ok(())
    }

    #[test]
    fn test_aggregator() -> Result<(), Error> {
        let dir = tempfile::tempdir()?;

        let keyfile = dir.path().join("foobar.key");
        std::fs::write(keyfile, KEY)?;

        let certfile = dir.path().join("foobar.pem");
        std::fs::write(certfile, CERT)?;

        Ok(())
    }
}
