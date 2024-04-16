mod cert;
mod resolver;
mod test;

use std::sync::Arc;

use rustls::{
    client::{ClientConfig, ClientSessionMemoryCache, Resumption},
    server::{ResolvesServerCert, ServerConfig, ServerSessionMemoryCache},
    version::{TLS12, TLS13},
    RootCertStore,
};

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
