pub mod cloudflare;

use anyhow::Error;
use arc_swap::ArcSwapOption;
use async_trait::async_trait;
use backoff::ExponentialBackoffBuilder;
use core::fmt;
use derive_new::new;
use fqdn::FQDN;
use rustls::{
    server::{ClientHello, ResolvesServerCert},
    sign::CertifiedKey,
};
use std::{str::FromStr, sync::Arc, time::Duration};
use strum_macros::{Display, EnumString};
use tokio_util::sync::CancellationToken;
use tracing::{error, warn};

use super::{Acme, TokenManager, Validity};
use crate::{
    http::dns::Resolves,
    tasks::Run,
    tls::{cert::pem_convert_to_rustls, sni_matches},
};

const ACME_RECORD: &str = "_acme-challenge";
// 60s is the lowest possible Cloudflare TTL
const TTL: u32 = 60;

#[derive(Clone, Display, EnumString)]
#[strum(serialize_all = "snake_case")]
pub enum DnsBackend {
    Cloudflare,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Record {
    Txt(String),
}

#[async_trait]
pub trait DnsManager: Sync + Send {
    async fn create(&self, zone: &str, name: &str, record: Record, ttl: u32) -> Result<(), Error>;
    async fn delete(&self, zone: &str, name: &str) -> Result<(), Error>;
}

// Manages ACME tokens using DNS
#[derive(new)]
pub struct TokenManagerDns {
    resolver: Arc<dyn Resolves>,
    manager: Arc<dyn DnsManager>,
}

#[async_trait]
impl TokenManager for TokenManagerDns {
    async fn verify(&self, zone: &str, token: &str) -> Result<(), Error> {
        // Try to resolve with expo backoff the hostname and verify that the record is there and correct.
        // Retry for up to double the DNS TTL.
        let boff = ExponentialBackoffBuilder::new()
            .with_max_elapsed_time(Some(Duration::from_secs(2 * TTL as u64)))
            .build();

        let host = format!("{ACME_RECORD}.{zone}");
        backoff::future::retry(boff, || async {
            self.resolver.flush_cache();

            let records = self
                .resolver
                .resolve(&host, "TXT")
                .await
                .map_err(|x| backoff::Error::transient(x.to_string()))?;

            records
                .iter()
                .find(|&x| x.0 == "TXT" && x.1 == token)
                .ok_or_else(|| backoff::Error::transient("requested record not found".into()))?;

            Ok::<_, backoff::Error<String>>(())
        });

        Ok(())
    }

    async fn set(&self, zone: &str, token: &str) -> Result<(), Error> {
        self.manager
            .create(zone, ACME_RECORD, Record::Txt(token.into()), TTL)
            .await
    }

    async fn unset(&self, zone: &str) -> Result<(), Error> {
        self.manager.delete(zone, ACME_RECORD).await
    }
}

#[derive(new)]
pub struct AcmeDns {
    acme: Acme,
    domains: Vec<FQDN>,
    wildcard: bool,
    #[new(default)]
    cert: ArcSwapOption<CertifiedKey>,
}

impl AcmeDns {
    async fn reload(&self) -> Result<(), Error> {
        let cert = self.acme.load().await?;
        let ckey = pem_convert_to_rustls(&cert.key, &cert.cert)?;
        self.cert.store(Some(ckey.cert));
        Ok(())
    }

    // Checks if certificate is still valid & reissues if needed
    async fn refresh(&self) {
        match self.acme.is_valid().await {
            Err(e) => warn!("ACMEDNS: Unable to check validity: {e}"),

            Ok(Validity::Valid) => {
                warn!("ACMEDNS: Certificate is still valid");

                if self.cert.load_full().is_none() {
                    warn!("ACMEDNS: No certificate loaded, loading");

                    if let Err(e) = self.reload().await {
                        error!("ACMEDNS: Unable to load certificate: {e}");
                    }
                }
            }

            Ok(v) => {
                warn!("ACMEDNS: Certificate needs to be renewed ({v})");
                if let Err(e) = self.acme.issue().await {
                    error!("ACMEDNS: Unable to issue a certificate: {e}");
                }

                if let Err(e) = self.reload().await {
                    error!("ACMEDNS: Unable to load certificate: {e}");
                }
            }
        }
    }
}

impl fmt::Debug for AcmeDns {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "AcmeDns")
    }
}

// Implement certificate resolving for Rustls
impl ResolvesServerCert for AcmeDns {
    fn resolve(&self, ch: ClientHello) -> Option<Arc<CertifiedKey>> {
        let sni = FQDN::from_str(ch.server_name()?).ok()?;
        // Make sure SNI matches our domains
        sni_matches(&sni, &self.domains, self.wildcard).then_some(self.cert.load_full())?
    }
}

#[async_trait]
impl Run for AcmeDns {
    async fn run(&self, token: CancellationToken) -> Result<(), Error> {
        let mut interval = tokio::time::interval(Duration::from_secs(600));

        loop {
            tokio::select! {
                biased;

                () = token.cancelled() => {
                    warn!("ACMEDNS: Runner exiting");
                    return Ok(());
                }

                _ = interval.tick() => self.refresh().await,
            }
        }
    }
}
