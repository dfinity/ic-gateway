pub mod dir;
pub mod issuer;

pub use dir::Provider as Dir;
pub use issuer::CertificatesImporter as Issuer;

use async_trait::async_trait;

use super::CertKey;

// Trait that the certificate providers should implement
// It should return a vector of Rustls-compatible keys
#[async_trait]
pub trait ProvidesCertificates: Sync + Send + std::fmt::Debug {
    async fn get_certificates(&self) -> Result<Vec<CertKey>, anyhow::Error>;
}
