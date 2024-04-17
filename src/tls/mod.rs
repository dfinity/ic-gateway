mod cert;
mod test;

use std::sync::Arc;

use rustls::{
    client::{ClientConfig, ClientSessionMemoryCache, Resumption},
    server::{ResolvesServerCert, ServerConfig, ServerSessionMemoryCache},
    version::{TLS12, TLS13},
    RootCertStore,
};

use crate::{
    cli::Cli,
    core::Run,
    http,
    tls::cert::{
        providers::{dir, syncer},
        storage::Storage,
        Aggregator,
    },
};

use self::cert::ProvidesCertificates;

const ALPN_H1: &[u8] = b"http/1.1";
const ALPN_H2: &[u8] = b"h2";

pub fn prepare_rustls_server_config(resolver: Arc<dyn ResolvesServerCert>) -> ServerConfig {
    let mut cfg = ServerConfig::builder_with_protocol_versions(&[&TLS13, &TLS12])
        .with_no_client_auth()
        .with_cert_resolver(resolver);

    // Create custom session storage with higher limit to allow effective TLS session resumption
    cfg.session_storage = ServerSessionMemoryCache::new(131_072);
    cfg.alpn_protocols = vec![ALPN_H2.to_vec(), ALPN_H1.to_vec()];

    cfg
}

pub fn prepare_rustls_client_config() -> ClientConfig {
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
    http_client: Arc<dyn http::client::Client>,
) -> (Arc<dyn Run>, ServerConfig) {
    let storage = Arc::new(Storage::new());

    let mut providers = vec![];

    for v in &cli.cert.dir {
        providers.push(Arc::new(dir::Provider::new(v.clone())) as Arc<dyn ProvidesCertificates>);
    }

    for v in &cli.cert.syncer_urls {
        providers.push(Arc::new(syncer::CertificatesImporter::new(
            http_client.clone(),
            v.clone(),
        )) as Arc<dyn ProvidesCertificates>);
    }

    let aggregator = Arc::new(Aggregator::new(providers, storage.clone()));
    let config = prepare_rustls_server_config(storage);

    (aggregator, config)
}
