pub mod dir;
pub mod syncer;

pub use dir::Provider as Dir;
pub use syncer::CertificatesImporter as Syncer;

use async_trait::async_trait;

use super::CertKey;

// Trait that the certificate providers should implement
// It should return a vector of Rustls-compatible keys
#[async_trait]
pub trait ProvidesCertificates: Sync + Send {
    async fn get_certificates(&self) -> Result<Vec<CertKey>, anyhow::Error>;
}
