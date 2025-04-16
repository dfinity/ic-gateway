use std::{fmt::Debug, sync::Arc, time::Instant};

use prometheus::{
    HistogramVec, IntCounterVec, Registry, register_histogram_vec_with_registry,
    register_int_counter_vec_with_registry,
};
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

#[derive(Debug, Clone)]
pub struct Metrics {
    resolve_count: IntCounterVec,
    supported_scheme: IntCounterVec,
    supported_cipher: IntCounterVec,
    resolve_duration: HistogramVec,
}

impl Metrics {
    pub fn new(registry: &Registry) -> Self {
        Self {
            resolve_count: register_int_counter_vec_with_registry!(
                format!("tls_resolver_total"),
                format!("Counts the number of resolves"),
                &["found"],
                registry
            )
            .unwrap(),

            supported_scheme: register_int_counter_vec_with_registry!(
                format!("tls_resolver_supported_scheme"),
                format!("Counts the number clients that support given scheme"),
                &["scheme"],
                registry
            )
            .unwrap(),

            supported_cipher: register_int_counter_vec_with_registry!(
                format!("tls_resolver_supported_cipher"),
                format!("Counts the number clients that support given ciphersuite"),
                &["cipher"],
                registry
            )
            .unwrap(),

            resolve_duration: register_histogram_vec_with_registry!(
                format!("tls_resolver_duration_sec"),
                format!("Records the duration of resolves in seconds"),
                &["found"],
                [0.0001, 0.0005, 0.001, 0.002, 0.004, 0.008, 0.016, 0.032].to_vec(),
                registry
            )
            .unwrap(),
        }
    }
}

// Combines several certificate resolvers into one.
// Only one Rustls-compatible resolver can be used since it consumes ClientHello.
#[derive(Debug, derive_new::new)]
pub struct AggregatingResolver {
    rustls: Option<Arc<dyn ResolvesServerCertRustls>>,
    resolvers: Vec<Arc<dyn ResolvesServerCert>>,
    metrics: Metrics,
}

impl AggregatingResolver {
    fn resolve_inner(&self, ch: ClientHello) -> Option<Arc<CertifiedKey>> {
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

// Implement certificate resolving for Rustls
impl ResolvesServerCertRustls for AggregatingResolver {
    fn resolve(&self, ch: ClientHello) -> Option<Arc<CertifiedKey>> {
        for v in ch.signature_schemes() {
            self.metrics
                .supported_scheme
                .with_label_values(&[v.as_str().unwrap_or("unknown")])
                .inc();
        }

        for v in ch.cipher_suites() {
            self.metrics
                .supported_cipher
                .with_label_values(&[v.as_str().unwrap_or("unknown")])
                .inc();
        }

        let start = Instant::now();
        let r = self.resolve_inner(ch);
        let found = if r.is_some() { "yes" } else { "no" };

        self.metrics
            .resolve_duration
            .with_label_values(&[found])
            .observe(start.elapsed().as_secs_f64());

        self.metrics.resolve_count.with_label_values(&[found]).inc();

        r
    }
}
