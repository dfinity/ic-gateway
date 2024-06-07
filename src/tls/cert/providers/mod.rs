pub mod dir;
pub mod issuer;

pub use dir::Provider as Dir;
pub use issuer::CertificatesImporter as Issuer;

use async_trait::async_trait;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Pem {
    pub cert: Vec<u8>,
    pub key: Vec<u8>,
}

// Trait that the certificate providers should implement
// It should return a vector of PEM-encoded cert-keys pairs
#[async_trait]
pub trait ProvidesCertificates: Sync + Send + std::fmt::Debug {
    async fn get_certificates(&self) -> Result<Vec<Pem>, anyhow::Error>;
}
