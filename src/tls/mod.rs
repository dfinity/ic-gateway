pub mod acme;
pub mod cert;
pub mod resolver;
mod test;

use std::sync::Arc;

use anyhow::{anyhow, Error};
use rustls::{
    client::{ClientConfig, ClientSessionMemoryCache, Resumption},
    server::{ServerConfig, ServerSessionMemoryCache},
    sign::CertifiedKey,
    version::{TLS12, TLS13},
    RootCertStore,
};
use rustls_acme::acme::ACME_TLS_ALPN_NAME;

use crate::{
    cli::Cli,
    core::Run,
    http,
    tls::{
        cert::{providers, Aggregator},
        resolver::{AggregatingResolver, ResolvesServerCert},
    },
};

use cert::{providers::ProvidesCertificates, storage::StoresCertificates};

const ALPN_H1: &[u8] = b"http/1.1";
const ALPN_H2: &[u8] = b"h2";
const ALPN_HTTP: &[&[u8]] = &[ALPN_H1, ALPN_H2];

pub fn is_http_alpn(alpn: &[u8]) -> bool {
    ALPN_HTTP.contains(&alpn)
}

pub fn prepare_server_config(
    resolver: Arc<dyn rustls::server::ResolvesServerCert>,
) -> ServerConfig {
    let mut cfg = ServerConfig::builder_with_protocol_versions(&[&TLS13, &TLS12])
        .with_no_client_auth()
        .with_cert_resolver(resolver);

    // Create custom session storage with higher limit to allow effective TLS session resumption
    cfg.session_storage = ServerSessionMemoryCache::new(131_072);
    cfg.alpn_protocols = vec![
        ALPN_H2.to_vec(),
        ALPN_H1.to_vec(),
        // Support ACME challenge ALPN too
        ACME_TLS_ALPN_NAME.to_vec(),
    ];

    cfg
}

pub fn prepare_client_config() -> ClientConfig {
    let root_store = RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.into(),
    };

    // TODO no revocation checking currently
    let mut cfg = ClientConfig::builder_with_protocol_versions(&[&TLS13, &TLS12])
        .with_root_certificates(root_store)
        .with_no_client_auth();

    // Session resumption
    let store = ClientSessionMemoryCache::new(2048);
    cfg.resumption = Resumption::store(Arc::new(store));
    cfg.alpn_protocols = vec![ALPN_H2.to_vec(), ALPN_H1.to_vec()];

    cfg
}

// Prepares the stuff needed for serving TLS
pub fn setup(
    cli: &Cli,
    http_client: Arc<dyn http::Client>,
    storage: Arc<dyn StoresCertificates<Arc<CertifiedKey>>>,
    cert_resolver: Arc<dyn ResolvesServerCert>,
) -> Result<(Arc<dyn Run>, ServerConfig), Error> {
    let mut providers = vec![];

    for v in &cli.cert.dir {
        providers.push(Arc::new(providers::Dir::new(v.clone())) as Arc<dyn ProvidesCertificates>);
    }

    for v in &cli.cert.issuer_urls {
        providers.push(
            Arc::new(providers::Syncer::new(http_client.clone(), v.clone()))
                as Arc<dyn ProvidesCertificates>,
        );
    }

    if providers.is_empty() {
        return Err(anyhow!(
            "No certificate providers specified - HTTPS cannot be used"
        ));
    }

    let cert_aggregator = Arc::new(Aggregator::new(providers, storage, cli.cert.poll_interval));
    let resolve_aggregator = Arc::new(AggregatingResolver::new(None, vec![cert_resolver]));
    let config = prepare_server_config(resolve_aggregator);

    Ok((cert_aggregator, config))
}
