mod verify;

use std::{
    str::FromStr,
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{anyhow, Context as AnyhowContext};
use arc_swap::ArcSwapOption;
use async_trait::async_trait;
use candid::Principal;
use fqdn::FQDN;
use ic_bn_lib::{http, tasks::Run};
use mockall::automock;
use reqwest::{Method, Request, StatusCode, Url};
use serde::Deserialize;
use tokio::select;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use crate::routing::domain::{CustomDomain, ProvidesCustomDomains};
use verify::{Verify, VerifyError, WithVerify};

use super::{Pem, ProvidesCertificates};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    UnexpectedError(#[from] anyhow::Error),

    #[error(transparent)]
    VerificationError(#[from] VerifyError),
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Pair(
    pub Vec<u8>, // Private Key
    pub Vec<u8>, // Certificate Chain
);

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Package {
    pub name: String,
    pub canister: Principal,
    pub pair: Pair,
}

#[automock]
#[async_trait]
pub trait Import: Sync + Send {
    async fn import(&self) -> Result<Vec<Package>, Error>;
}

pub struct CertificatesImporter {
    http_client: Arc<dyn http::Client>,
    exporter_url: Url,
    poll_interval: Duration,
    snapshot: ArcSwapOption<Vec<Package>>,
}

impl std::fmt::Debug for CertificatesImporter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "CertificatesImporter({})", self.exporter_url)
    }
}

impl CertificatesImporter {
    pub fn new(
        http_client: Arc<dyn http::Client>,
        mut exporter_url: Url,
        poll_interval: Duration,
    ) -> Self {
        exporter_url.set_path("");
        let exporter_url = exporter_url.join("/certificates").unwrap();

        Self {
            http_client,
            exporter_url,
            poll_interval,
            snapshot: ArcSwapOption::empty(),
        }
    }

    async fn refresh(&self) -> Result<(), Error> {
        let start = Instant::now();
        let packages = self.import().await.context("unable to fetch packages")?;
        info!(
            "{self:?}: {} certs loaded in {}s",
            packages.len(),
            start.elapsed().as_secs_f64()
        );

        self.snapshot.store(Some(Arc::new(packages)));
        Ok(())
    }
}

#[async_trait]
impl ProvidesCustomDomains for CertificatesImporter {
    async fn get_custom_domains(&self) -> Result<Vec<CustomDomain>, anyhow::Error> {
        let packages = self
            .snapshot
            .load_full()
            .ok_or_else(|| anyhow!("no packages fetched yet"))?;

        let domains = packages
            .iter()
            .map(|x| -> Result<_, anyhow::Error> {
                Ok(CustomDomain {
                    name: FQDN::from_str(&x.name)?,
                    canister_id: x.canister,
                })
            })
            .collect::<Result<Vec<_>, _>>()?;

        Ok(domains)
    }
}

#[async_trait]
impl ProvidesCertificates for CertificatesImporter {
    async fn get_certificates(&self) -> Result<Vec<Pem>, anyhow::Error> {
        let packages = self
            .snapshot
            .load_full()
            .ok_or_else(|| anyhow!("no packages fetched yet"))?;

        let certs = packages
            .as_ref()
            .clone()
            .into_iter()
            .map(|x| Pem {
                cert: x.pair.1,
                key: x.pair.0,
            })
            .collect::<Vec<_>>();

        Ok(certs)
    }
}

#[async_trait]
impl Import for CertificatesImporter {
    async fn import(&self) -> Result<Vec<Package>, Error> {
        let mut req = Request::new(Method::GET, self.exporter_url.clone());
        *req.timeout_mut() = Some(Duration::from_secs(30));

        let response = self
            .http_client
            .execute(req)
            .await
            .context("failed to make http request")?;

        if response.status() != StatusCode::OK {
            return Err(anyhow!("incorrect response code: {}", response.status()).into());
        }

        let bs = response
            .bytes()
            .await
            .context("failed to fetch response body")?
            .to_vec();

        let pkgs: Vec<Package> =
            serde_json::from_slice(&bs).context("failed to parse json body")?;

        Ok(pkgs)
    }
}

#[async_trait]
impl Run for CertificatesImporter {
    async fn run(&self, token: CancellationToken) -> Result<(), anyhow::Error> {
        let mut interval = tokio::time::interval(self.poll_interval);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            select! {
                biased;

                () = token.cancelled() => {
                    warn!("{self:?}: exiting");
                    return Ok(());
                },

                _ = interval.tick() => {
                    if let Err(e) = self.refresh().await {
                        warn!("{self:?}: unable to refresh certificates: {e:#}");
                    };
                }
            }
        }
    }
}

// Wraps an importer with a verifier
// The importer imports a set of packages as usual, but then passes the packages to the verifier.
// The verifier parses out the public certificate and compares the common name to the name in the package to make sure they match.
// This should help eliminate risk of the replica returning a malicious package.
#[async_trait]
impl<T: Import, V: Verify> Import for WithVerify<T, V> {
    async fn import(&self) -> Result<Vec<Package>, Error> {
        let pkgs = self.0.import().await?;

        for pkg in &pkgs {
            self.1.verify(pkg)?;
        }

        Ok(pkgs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use anyhow::Error as AnyhowError;
    use axum::http::Response;
    use ic_bn_lib::http::client::MockClient;
    use mockall::predicate;
    use reqwest::Body;
    use std::{str::FromStr, sync::Arc};

    use crate::tls::cert::providers::issuer::verify::MockVerify;

    #[tokio::test]
    async fn import_ok() -> Result<(), AnyhowError> {
        let mut http_client = MockClient::new();
        http_client
            .expect_execute()
            .times(1)
            .with(predicate::function(|req: &Request| {
                req.method().as_str().eq("GET")
                    && req.url().to_string().eq("http://foo/certificates")
            }))
            .returning(|_| {
                Ok(Response::builder()
                    .body(Body::from(
                        r#"[
                {
                    "name": "name",
                    "canister": "aaaaa-aa",
                    "pair": [
                        [1, 2, 3],
                        [4, 5, 6]
                    ]
                }
            ]"#,
                    ))
                    .unwrap()
                    .into())
            });

        let importer = CertificatesImporter::new(
            Arc::new(http_client),
            Url::from_str("http://foo")?,
            Duration::ZERO,
        );

        let out = importer.import().await?;

        assert_eq!(
            out,
            vec![Package {
                name: "name".into(),
                canister: Principal::from_text("aaaaa-aa")?,
                pair: Pair(vec![1, 2, 3], vec![4, 5, 6]),
            }],
        );

        Ok(())
    }

    #[tokio::test]
    async fn import_verify_multiple() {
        let mut verifier = MockVerify::new();
        verifier
            .expect_verify()
            .times(3)
            .with(predicate::in_iter(vec![
                Package {
                    name: "name-1".into(),
                    canister: Principal::from_text("aaaaa-aa").unwrap(),
                    pair: Pair(vec![], vec![]),
                },
                Package {
                    name: "name-2".into(),
                    canister: Principal::from_text("aaaaa-aa").unwrap(),
                    pair: Pair(vec![], vec![]),
                },
                Package {
                    name: "name-3".into(),
                    canister: Principal::from_text("aaaaa-aa").unwrap(),
                    pair: Pair(vec![], vec![]),
                },
            ]))
            .returning(|_| Ok(()));

        let mut importer = MockImport::new();
        importer.expect_import().times(1).returning(|| {
            Ok(vec![
                Package {
                    name: "name-1".into(),
                    canister: Principal::from_text("aaaaa-aa").unwrap(),
                    pair: Pair(vec![], vec![]),
                },
                Package {
                    name: "name-2".into(),
                    canister: Principal::from_text("aaaaa-aa").unwrap(),
                    pair: Pair(vec![], vec![]),
                },
                Package {
                    name: "name-3".into(),
                    canister: Principal::from_text("aaaaa-aa").unwrap(),
                    pair: Pair(vec![], vec![]),
                },
            ])
        });

        let importer = WithVerify(importer, verifier);

        match importer.import().await {
            Ok(_) => {}
            other => panic!("expected Ok but got {other:?}"),
        }
    }

    #[tokio::test]
    async fn import_verify_mismatch() {
        let mut verifier = MockVerify::new();
        verifier
            .expect_verify()
            .times(1)
            .with(predicate::eq(Package {
                name: "name-1".into(),
                canister: Principal::from_text("aaaaa-aa").unwrap(),
                pair: Pair(vec![], vec![]),
            }))
            .returning(|_| {
                // Mock an error
                Err(VerifyError::CommonNameMismatch(
                    "name-1".into(),
                    "name-2".into(),
                ))
            });

        let mut importer = MockImport::new();
        importer.expect_import().times(1).returning(|| {
            Ok(vec![Package {
                name: "name-1".into(),
                canister: Principal::from_text("aaaaa-aa").unwrap(),
                pair: Pair(vec![], vec![]),
            }])
        });

        let importer = WithVerify(importer, verifier);

        match importer.import().await {
            Err(Error::VerificationError(_)) => {}
            other => panic!("expected VerificationError but got {other:?}"),
        }
    }
}
