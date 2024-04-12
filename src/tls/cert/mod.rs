mod syncer;
mod test;

use std::sync::Arc;

use anyhow::{anyhow, Error};
use async_trait::async_trait;
use futures::future::join_all;
use rustls::{crypto::aws_lc_rs, sign::CertifiedKey};

// Converts raw PEM certificate chain & private key to a CertifiedKey ready to be consumed by Rustls
pub fn pem_convert_to_rustls(key: &[u8], certs: &[u8]) -> Result<Arc<CertifiedKey>, Error> {
    let (key, certs) = (key.to_vec(), certs.to_vec());

    let key = rustls_pemfile::private_key(&mut key.as_ref())?
        .ok_or_else(|| anyhow!("No private key found"))?;

    let certs = rustls_pemfile::certs(&mut certs.as_ref()).collect::<Result<Vec<_>, _>>()?;
    if certs.is_empty() {
        return Err(anyhow!("No certificates found"));
    }

    let key = aws_lc_rs::sign::any_supported_type(&key)?;
    Ok(Arc::new(CertifiedKey::new(certs, key)))
}

// Trait that the certificate sources should implement
// It should return a vector of Rustls-compatible CertifiedKeys
#[async_trait]
pub trait ProvidesCertificates: Sync + Send {
    async fn get_certificates(&self) -> Result<Vec<Arc<CertifiedKey>>, Error>;
}

// Provider that aggregates other providers' output
pub struct AggregatingProvider {
    providers: Vec<Arc<dyn ProvidesCertificates>>,
}

impl AggregatingProvider {
    pub fn new(providers: Vec<Arc<dyn ProvidesCertificates>>) -> Self {
        Self { providers }
    }
}

#[async_trait]
impl ProvidesCertificates for AggregatingProvider {
    async fn get_certificates(&self) -> Result<Vec<Arc<CertifiedKey>>, Error> {
        let certs = join_all(
            self.providers
                .iter()
                .map(|x| async { x.get_certificates().await }),
        )
        .await;

        let certs = certs
            .into_iter()
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .flatten()
            .collect::<Vec<_>>();

        Ok(certs)
    }
}
