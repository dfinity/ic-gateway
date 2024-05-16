use std::{io::Error as IoError, sync::Arc};

use anyhow::Error;
use async_trait::async_trait;
use futures::StreamExt;
use rustls::server::ResolvesServerCert;
use rustls_acme::{caches::DirCache, AcmeConfig, AcmeState};
use tokio::{select, sync::Mutex};
use tokio_util::sync::CancellationToken;
use tracing::warn;

use crate::tasks::Run;

use super::AcmeOptions;

pub struct AcmeAlpn {
    // Mutex here is only to make AcmeTlsAlpn Sync
    state: Mutex<AcmeState<IoError, IoError>>,
}

impl AcmeAlpn {
    #[allow(clippy::all)]
    pub fn new(opts: AcmeOptions) -> Result<(Arc<dyn Run>, Arc<dyn ResolvesServerCert>), Error> {
        let state = AcmeConfig::new(opts.domains)
            .contact_push(opts.contact)
            .directory_lets_encrypt(!opts.staging);

        let state = state.cache(DirCache::new(opts.cache_path)).state();
        let resolver = state.resolver();

        Ok((
            Arc::new(Self {
                state: Mutex::new(state),
            }),
            resolver,
        ))
    }
}

#[async_trait]
impl Run for AcmeAlpn {
    async fn run(&self, token: CancellationToken) -> Result<(), Error> {
        let mut state = self.state.lock().await;

        warn!("ACMEALPN: started");
        loop {
            select! {
                biased; // Poll top-down

                () = token.cancelled() => {
                    warn!("ACMEALPN: shutting down");
                    return Ok(());
                },

                // Kick the ACME process forward
                res = state.next() => {
                    match res {
                        Some(Ok(v)) => warn!("ACMEALPN: success: {v:?}"),
                        Some(Err(e)) => warn!("ACMEALPN: error: {e}"),
                        _ => warn!("ACMEALPN: unexpected None"),
                    }
                }
            }
        }
    }
}
