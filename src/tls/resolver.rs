use std::{fmt::Debug, sync::Arc};

use rustls::{
    server::{ClientHello, ResolvesServerCert as ResolvesServerCertRustls},
    sign::CertifiedKey,
};
use tracing::debug;

/// Custom `ResolvesServerCert` trait that borrows `ClientHello`.
/// It's needed because Rustls' `ResolvesServerCert` consumes `ClientHello`
/// <https://github.com/rustls/rustls/issues/1908>
pub trait ResolvesServerCert: Debug + Send + Sync {
    fn resolve(&self, client_hello: &ClientHello) -> Option<Arc<CertifiedKey>>;

    /// Return first available certificate, if any.
    /// Can be used as a fallback option.
    fn resolve_any(&self) -> Option<Arc<CertifiedKey>> {
        None
    }
}

// Combines several certificate resolvers into one.
// Only one Rustls-compatible resolver can be used since it consumes ClientHello.
#[derive(Debug, derive_new::new)]
pub struct AggregatingResolver {
    rustls: Option<Arc<dyn ResolvesServerCertRustls>>,
    resolvers: Vec<Arc<dyn ResolvesServerCert>>,
}

// Implement certificate resolving for Rustls
impl ResolvesServerCertRustls for AggregatingResolver {
    fn resolve(&self, ch: ClientHello) -> Option<Arc<CertifiedKey>> {
        // Accept missing SNI e.g. for testing cases when we're accessed over IP directly
        let sni = ch.server_name().unwrap_or("").to_string();

        let alpn = ch
            .alpn()
            .map(|x| x.map(String::from_utf8_lossy).collect::<Vec<_>>());

        // Iterate over our resolvers to find matching cert if any.
        let cert = self
            .resolvers
            .iter()
            .find_map(|x| x.resolve(&ch))
            // Otherwise try the Rustls-compatible resolver that consumes ClientHello.
            .or_else(|| self.rustls.as_ref().and_then(|x| x.resolve(ch)));

        if cert.is_some() {
            return cert;
        }

        debug!(
            "AggregatingResolver: No certificate found for SNI '{}' (ALPN {:?}), trying fallback",
            sni, alpn
        );

        // Check if any of the resolvers provide us with a fallback
        self.resolvers.iter().find_map(|x| x.resolve_any())
    }
}
