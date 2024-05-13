use std::{io::Error as IoError, path::PathBuf, sync::Arc};

use anyhow::Error;
use async_trait::async_trait;
use futures::StreamExt;
use rustls::server::ResolvesServerCert;
use rustls_acme::{caches::DirCache, AcmeConfig, AcmeState};
use strum_macros::{Display, EnumString};
use tokio::{select, sync::Mutex};
use tokio_util::sync::CancellationToken;
use tracing::warn;

use crate::core::Run;

#[derive(Clone, Display, EnumString)]
#[strum(serialize_all = "snake_case")]
pub enum Challenge {
    Alpn,
}

pub struct AcmeTlsAlpn {
    // Mutex here is only to make AcmeTlsAlpn Sync
    state: Mutex<AcmeState<IoError, IoError>>,
}

impl AcmeTlsAlpn {
    #[allow(clippy::all)]
    pub fn new(
        domains: Vec<String>,
        staging: bool,
        cache_path: PathBuf,
    ) -> Result<(Arc<dyn Run>, Arc<dyn ResolvesServerCert>), Error> {
        let state = AcmeConfig::new(domains)
            .contact_push("mailto:boundary-nodes@dfinity.org")
            .directory_lets_encrypt(!staging);

        let state = state.cache(DirCache::new(cache_path)).state();
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
impl Run for AcmeTlsAlpn {
    async fn run(&self, token: CancellationToken) -> Result<(), Error> {
        let mut state = self.state.lock().await;

        warn!("AcmeTlsAlpn: started");
        loop {
            select! {
                biased; // Poll top-down

                () = token.cancelled() => {
                    warn!("AcmeTlsAlpn: shutting down");
                    return Ok(());
                },

                // Kick the ACME process forward
                res = state.next() => {
                    match res.unwrap() {
                        Ok(v) => warn!("AcmeTlsAlpn: success: {v:?}"),
                        Err(e) => warn!("AcmeTlsAlpn: error: {e}"),
                    }
                }
            }
        }
    }
}
