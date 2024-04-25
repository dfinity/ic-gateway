use std::{fmt::Debug, sync::Arc};

use rustls::{
    server::{ClientHello, ResolvesServerCert as ResolvesServerCertRustls},
    sign::CertifiedKey,
};

// Custom ResolvesServerCert trait that takes ClientHello by reference.
// It's needed because Rustls' ResolvesServerCert consumes ClientHello
pub trait ResolvesServerCert: Debug + Send + Sync {
    fn resolve(&self, client_hello: &ClientHello) -> Option<Arc<CertifiedKey>>;
}

// Combines several certificate resolvers into one
// Only one Rustls-compatible resolver can be used (acme) since it takes ClientHello by value
#[derive(Debug, derive_new::new)]
pub struct AggregatingResolver {
    acme: Option<Arc<dyn ResolvesServerCertRustls>>,
    resolvers: Vec<Arc<dyn ResolvesServerCert>>,
}

// Implement certificate resolving for Rustls
impl ResolvesServerCertRustls for AggregatingResolver {
    fn resolve(&self, ch: ClientHello) -> Option<Arc<CertifiedKey>> {
        // Iterate over our resolvers to find matching cert if any
        let cert = self.resolvers.iter().find_map(|x| x.resolve(&ch));
        if let Some(v) = cert {
            return Some(v);
        }

        // Otherwise try the ACME resolver with Rustls trait that consumes ClientHello
        self.acme.as_ref().and_then(|x| x.resolve(ch))
    }
}