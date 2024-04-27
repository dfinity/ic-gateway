use rustls_acme::{caches::DirCache, AcmeConfig, AcmeState};
use std::io::Error;

pub struct AcmeTls {
    state: AcmeState<Error, Error>,
}

impl AcmeTls {
    pub fn new(domains: &[&str]) -> Self {
        let state = AcmeConfig::new(domains)
            .contact_push("mailto:boundary-nodes@dfinity.org")
            .directory_lets_encrypt(false)
            .cache(DirCache::new("./acme"))
            .state();

        Self { state }
    }
}
