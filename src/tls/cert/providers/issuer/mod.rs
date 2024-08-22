mod verify;

use std::{
    str::FromStr,
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{anyhow, Context as AnyhowContext};
use async_trait::async_trait;
use candid::Principal;
use fqdn::FQDN;
use ic_bn_lib::http;
use mockall::automock;
use reqwest::{Method, Request, StatusCode, Url};
use serde::Deserialize;
use tokio::sync::Mutex;
use tracing::info;

use crate::routing::domain::{CustomDomain, ProvidesCustomDomains};
use verify::{Verify, VerifyError, WithVerify};

use super::{Pem, ProvidesCertificates};

const CACHE_TTL: Duration = Duration::from_secs(9);

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

struct Cache {
    updated_at: Instant,
    packages: Vec<Package>,
}

pub struct CertificatesImporter {
    http_client: Arc<dyn http::Client>,
    exporter_url: Url,
    cache: Mutex<Cache>,
}

impl std::fmt::Debug for CertificatesImporter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "CertificatesImporter({})", self.exporter_url)
    }
}

impl CertificatesImporter {
    pub fn new(http_client: Arc<dyn http::Client>, mut exporter_url: Url) -> Self {
        exporter_url.set_path("");
        let exporter_url = exporter_url.join("/certificates").unwrap();

        Self {
            http_client,
            exporter_url,
            cache: Mutex::new(Cache {
                updated_at: Instant::now().checked_sub(CACHE_TTL * 2).unwrap(),
                packages: vec![],
            }),
        }
    }
}

#[async_trait]
impl ProvidesCustomDomains for CertificatesImporter {
    async fn get_custom_domains(&self) -> Result<Vec<CustomDomain>, anyhow::Error> {
        let domains = self
            .import()
            .await?
            .into_iter()
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
        let certs = self
            .import()
            .await?
            .into_iter()
            .map(|x| Pem {
                cert: x.pair.1,
                key: x.pair.0,
            })
            .collect::<Vec<_>>();

        info!(
            "IssuerProvider ({}): {} certs loaded",
            self.exporter_url,
            certs.len()
        );

        Ok(certs)
    }
}

#[allow(clippy::significant_drop_tightening)]
#[async_trait]
impl Import for CertificatesImporter {
    async fn import(&self) -> Result<Vec<Package>, Error> {
        // Return result from cache if available
        let now = Instant::now();
        let mut cache = self.cache.lock().await;
        if cache.updated_at >= now.checked_sub(CACHE_TTL).unwrap() {
            return Ok(cache.packages.clone());
        }

        let req = Request::new(Method::GET, self.exporter_url.clone());
        let response = self
            .http_client
            .execute(req)
            .await
            .context("failed to make http request")?;

        if response.status() != StatusCode::OK {
            return Err(anyhow!(format!("request failed: {}", response.status())).into());
        }

        let bs = response
            .bytes()
            .await
            .context("failed to consume response")?
            .to_vec();

        let pkgs: Vec<Package> =
            serde_json::from_slice(&bs).context("failed to parse json body")?;

        cache.packages.clone_from(&pkgs);
        cache.updated_at = now;
        Ok(pkgs)
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

        let importer =
            CertificatesImporter::new(Arc::new(http_client), Url::from_str("http://foo")?);

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
