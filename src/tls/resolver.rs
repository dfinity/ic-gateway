use std::{fmt::Debug, sync::Arc};

use rustls::{
    server::{ClientHello, ResolvesServerCert as ResolvesServerCertRustls},
    sign::CertifiedKey,
};

// Custom ResolvesServerCert trait that borrows ClientHello.
// It's needed because Rustls' ResolvesServerCert consumes ClientHello
// https://github.com/rustls/rustls/issues/1908
pub trait ResolvesServerCert: Debug + Send + Sync {
    fn resolve(&self, client_hello: &ClientHello) -> Option<Arc<CertifiedKey>>;
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
        println!("{:?}", ch.server_name());

        // Iterate over our resolvers to find matching cert if any.
        self.resolvers
            .iter()
            .find_map(|x| x.resolve(&ch))
            // Otherwise try the Rustls-compatible resolver that consumes ClientHello.
            .or_else(|| self.rustls.as_ref().and_then(|x| x.resolve(ch)))
    }
}
