use std::{io, sync::Arc};

use anyhow::Error;
use async_trait::async_trait;
use futures::StreamExt;
use rustls::server::ResolvesServerCert;
use rustls_acme::{caches::DirCache, AcmeConfig, AcmeState};
use tokio::{select, sync::Mutex};
use tokio_util::sync::CancellationToken;
use tracing::warn;

use crate::tasks::{Run, TaskManager};

use super::AcmeOptions;

// Mutex here is only to make it Sync
pub struct AcmeAlpn(Mutex<AcmeState<io::Error, io::Error>>);

impl AcmeAlpn {
    #[allow(clippy::new_ret_no_self)]
    pub fn new(
        opts: AcmeOptions,
        tasks: &mut TaskManager,
    ) -> Result<Arc<dyn ResolvesServerCert>, Error> {
        let state = AcmeConfig::new(opts.domains)
            .contact_push(opts.contact)
            .directory_lets_encrypt(!opts.staging);

        let state = state.cache(DirCache::new(opts.cache_path)).state();
        let resolver = state.resolver();
        tasks.add("acme_alpn_runner", Arc::new(Self(Mutex::new(state))));

        Ok(resolver)
    }
}

#[async_trait]
impl Run for AcmeAlpn {
    async fn run(&self, token: CancellationToken) -> Result<(), Error> {
        #[allow(clippy::significant_drop_tightening)]
        let mut state = self.0.lock().await;

        warn!("ACME-ALPN: started");
        loop {
            select! {
                biased; // Poll top-down

                () = token.cancelled() => {
                    warn!("ACME-ALPN: exiting");
                    return Ok(());
                },

                // Kick the ACME process forward
                res = state.next() => {
                    match res {
                        Some(Ok(v)) => warn!("ACME-ALPN: success: {v:?}"),
                        Some(Err(e)) => warn!("ACME-ALPN: error: {e}"),
                        _ => warn!("ACME-ALPN: unexpected None"),
                    }
                }
            }
        }
    }
}
