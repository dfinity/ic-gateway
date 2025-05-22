mod verify;

use std::{
    str::FromStr,
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{Context as AnyhowContext, anyhow};
use arc_swap::ArcSwapOption;
use async_trait::async_trait;
use candid::Principal;
use fqdn::FQDN;
use ic_bn_lib::{http, tasks::Run};
use prometheus::{
    HistogramVec, IntGaugeVec, Registry, register_histogram_vec_with_registry,
    register_int_gauge_vec_with_registry,
};
use reqwest::{Method, Request, StatusCode, Url};
use serde::Deserialize;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use crate::routing::domain::{CustomDomain, ProvidesCustomDomains};
use verify::{Parser, Verifier, Verify, VerifyError};

#[cfg(test)]
use mockall::automock;

use super::{Pem, ProvidesCertificates};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    UnexpectedError(#[from] anyhow::Error),

    #[error(transparent)]
    VerificationError(#[from] VerifyError),
}

#[derive(Debug, Clone)]
pub struct Metrics {
    packages: IntGaugeVec,
    errors: IntGaugeVec,
    duration: HistogramVec,
}

impl Metrics {
    pub fn new(registry: &Registry) -> Self {
        Self {
            packages: register_int_gauge_vec_with_registry!(
                format!("issuer_packages_loaded"),
                format!("Number of packages in the current snapshot"),
                &["issuer"],
                registry
            )
            .unwrap(),

            errors: register_int_gauge_vec_with_registry!(
                format!("issuer_packages_errors"),
                format!("Number of packages with errors"),
                &["issuer"],
                registry
            )
            .unwrap(),

            duration: register_histogram_vec_with_registry!(
                format!("issuer_fetch_duration_sec"),
                format!("Time it takes to fetch a package in seconds"),
                &["issuer"],
                vec![0.2, 0.4, 0.8, 1.6, 3.2, 6.4, 12.8, 25.6],
                registry
            )
            .unwrap(),
        }
    }
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

impl std::fmt::Display for Package {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} ({})", self.name, self.canister)
    }
}

#[cfg_attr(test, automock)]
#[async_trait]
pub trait Import: Sync + Send {
    async fn import(&self) -> Result<Vec<Package>, Error>;
}

pub struct CertificatesImporter {
    http_client: Arc<dyn http::Client>,
    exporter_url: Url,
    snapshot: ArcSwapOption<Vec<Package>>,
    verifier: Verifier<Parser>,
    metrics: Metrics,
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
        metrics: Metrics,
    ) -> Self {
        exporter_url.set_path("");
        let exporter_url = exporter_url.join("/certificates").unwrap();

        Self {
            http_client,
            exporter_url,
            snapshot: ArcSwapOption::empty(),
            verifier: Verifier(Parser),
            metrics,
        }
    }

    async fn refresh(&self) -> Result<(), Error> {
        let start = Instant::now();
        let packages = self.import().await.context("unable to fetch packages")?;
        let len_full = packages.len();

        let packages = packages
            .into_iter()
            .filter(|x| match self.verifier.verify(x) {
                Ok(_) => true,
                Err(e) => {
                    warn!("{self:?}: package '{x}' verification failed, skipping: {e:#}");
                    false
                }
            })
            .collect::<Vec<_>>();

        info!(
            "{self:?}: {} certs loaded ({} skipped due to errors) in {}s",
            packages.len(),
            len_full - packages.len(),
            start.elapsed().as_secs_f64()
        );

        let id = format!("{self:?}");
        let labels = &[id.as_str()];
        self.metrics
            .packages
            .with_label_values(labels)
            .set(packages.len() as i64);
        self.metrics
            .errors
            .with_label_values(labels)
            .set((len_full - packages.len()) as i64);
        self.metrics
            .duration
            .with_label_values(labels)
            .observe(start.elapsed().as_secs_f64());

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
            .map(|x| Pem([x.pair.0, x.pair.1].concat()))
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
    async fn run(&self, _: CancellationToken) -> Result<(), anyhow::Error> {
        self.refresh()
            .await
            .context("unable to refresh certificates")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use anyhow::Error as AnyhowError;
    use axum::http::Response;
    use ic_bn_lib::http::client::Client;
    use mockall::{mock, predicate};
    use reqwest::Body;
    use std::{fmt, str::FromStr, sync::Arc};

    mock! {
        pub HttpClient {}

        impl Client for HttpClient {
            fn execute<'life0,'async_trait>(&'life0 self,req:reqwest::Request) -> ::core::pin::Pin<Box<dyn ::core::future::Future<Output = Result<reqwest::Response,reqwest::Error> > + ::core::marker::Send+'async_trait> >where 'life0:'async_trait,Self:'async_trait;
        }

        impl fmt::Debug for HttpClient {
            fn fmt<'a>(&self, f: &mut fmt::Formatter<'a>) -> fmt::Result {
                write!(f, "MockHttpClient")
            }
        }
    }

    #[tokio::test]
    async fn import_ok() -> Result<(), AnyhowError> {
        let mut http_client = MockHttpClient::new();

        http_client
            .expect_execute()
            .times(1)
            .with(predicate::function(|req: &Request| {
                req.method().as_str().eq("GET")
                    && req.url().to_string().eq("http://foo/certificates")
            }))
            .returning(|_| {
                Box::pin(async {
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
                })
            });

        let importer = CertificatesImporter::new(
            Arc::new(http_client),
            Url::from_str("http://foo")?,
            Metrics::new(&Registry::new()),
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
    async fn import_multiple() {
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

        match importer.import().await {
            Ok(_) => {}
            other => panic!("expected Ok but got {other:?}"),
        }
    }
}
