pub mod dir;
pub mod issuer;

pub use dir::Provider as Dir;
pub use issuer::CertificatesImporter as Issuer;

use async_trait::async_trait;
use ic_bn_lib::{http::Client, tasks::TaskManager};
use prometheus::Registry;
use std::sync::Arc;

use crate::{cli::Cli, routing::domain::ProvidesCustomDomains};

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

#[allow(clippy::type_complexity)]
pub fn setup_issuer_providers(
    cli: &Cli,
    tasks: &mut TaskManager,
    http_client: Arc<dyn Client>,
    registry: &Registry,
) -> (
    Vec<Arc<dyn ProvidesCertificates>>,
    Vec<Arc<dyn ProvidesCustomDomains>>,
) {
    let mut cert_providers: Vec<Arc<dyn ProvidesCertificates>> = vec![];
    let mut custom_domain_providers: Vec<Arc<dyn ProvidesCustomDomains>> = vec![];

    let issuer_metrics = issuer::Metrics::new(registry);
    for v in &cli.cert.cert_provider_issuer_url {
        let issuer = Arc::new(Issuer::new(
            http_client.clone(),
            v.clone(),
            issuer_metrics.clone(),
        ));

        cert_providers.push(issuer.clone());
        custom_domain_providers.push(issuer.clone());
        tasks.add_interval(
            &format!("{issuer:?}"),
            issuer,
            cli.cert.cert_provider_issuer_poll_interval,
        );
    }

    (cert_providers, custom_domain_providers)
}
