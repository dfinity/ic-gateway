use std::str::FromStr as _;
use std::sync::atomic::{AtomicU64, Ordering};
use std::{sync::Arc, time::Duration};

use ahash::HashMap;
use anyhow::Error;
use anyhow::{Context as AnyhowContext, anyhow};
use arc_swap::ArcSwapOption;
use async_trait::async_trait;
use bytes::Bytes;
use candid::Principal;
use derive_new::new;
use fqdn::FQDN;
use ic_bn_lib::http;
use reqwest::{Method, Request, Url};
use serde::Deserialize;

use crate::routing::domain::{CustomDomain, ProvidesCustomDomains};

// Gets the body of the given URL
async fn get_url_body(
    cli: &Arc<dyn http::Client>,
    url: &Url,
    timeout: Duration,
) -> Result<Bytes, Error> {
    let mut req = Request::new(Method::GET, url.clone());
    *req.timeout_mut() = Some(timeout);

    let response = cli
        .execute(req)
        .await
        .context("failed to make HTTP request")?;

    if !response.status().is_success() {
        return Err(anyhow!("unsuccessful response code: {}", response.status()));
    }

    response
        .bytes()
        .await
        .context("failed to fetch response body")
}

// Fetches a list of custom domains from the given URL in JSON format
async fn get_custom_domains_from_url(
    cli: &Arc<dyn http::Client>,
    url: &Url,
    timeout: Duration,
) -> Result<Vec<CustomDomain>, Error> {
    let body = get_url_body(cli, url, timeout)
        .await
        .context("unable to fetch custom domains list JSON")?;

    // TODO use fqdn's crate serde when it's fixed
    let domains: HashMap<String, Principal> =
        serde_json::from_slice(&body).context("failed to parse JSON body")?;

    domains
        .into_iter()
        .map(|(k, v)| -> Result<CustomDomain, Error> {
            Ok(CustomDomain {
                name: FQDN::from_str(&k)?,
                canister_id: v,
            })
        })
        .collect::<Result<Vec<_>, _>>()
}

#[derive(new)]
pub struct GenericProvider {
    http_client: Arc<dyn http::Client>,
    url: Url,
    timeout: Duration,
}

#[async_trait]
impl ProvidesCustomDomains for GenericProvider {
    async fn get_custom_domains(&self) -> Result<Vec<CustomDomain>, Error> {
        get_custom_domains_from_url(&self.http_client, &self.url, self.timeout).await
    }
}

#[derive(Deserialize)]
struct TimestampedResponse {
    timestamp: u64,
    url: String,
}

#[derive(new)]
pub struct GenericProviderTimestamped {
    http_client: Arc<dyn http::Client>,
    url: Url,
    timeout: Duration,
    #[new(default)]
    timestamp: AtomicU64,
    #[new(default)]
    cache: ArcSwapOption<Vec<CustomDomain>>,
}

#[async_trait]
impl ProvidesCustomDomains for GenericProviderTimestamped {
    async fn get_custom_domains(&self) -> Result<Vec<CustomDomain>, Error> {
        let body = get_url_body(&self.http_client, &self.url, self.timeout)
            .await
            .context("failed to get timestamp JSON")?;

        let resp: TimestampedResponse = serde_json::from_slice(&body)
            .context("unable to parse response as TimestampedResponse")?;

        let ts = self.timestamp.swap(resp.timestamp, Ordering::SeqCst);
        let cache = self.cache.load_full();

        // Return the cached value if we have one & the timestamps are the same
        if ts == resp.timestamp && cache.is_some() {
            return Ok(cache.unwrap().as_ref().clone());
        }

        // Otherwise fetch a fresh version from the provided URL
        let url = Url::parse(&resp.url).context("unable to parse source URL")?;
        let domains = get_custom_domains_from_url(&self.http_client, &url, self.timeout).await?;
        self.cache.store(Some(Arc::new(domains.clone())));

        Ok(domains)
    }
}

#[cfg(test)]
mod test {
    use ::http::Response as HttpResponse;
    use async_trait::async_trait;
    use fqdn::fqdn;
    use itertools::Itertools;
    use serde_json::json;

    use super::*;
    use crate::principal;

    #[derive(Debug)]
    struct MockClient;

    #[async_trait]
    impl http::Client for MockClient {
        async fn execute(&self, _: reqwest::Request) -> Result<reqwest::Response, reqwest::Error> {
            Ok(HttpResponse::new(
                json!({"foo.bar": "aaaaa-aa", "bar.foo": "qoctq-giaaa-aaaaa-aaaea-cai"})
                    .to_string(),
            )
            .into())
        }
    }

    #[derive(Debug)]
    struct MockClientBadDomain;

    #[async_trait]
    impl http::Client for MockClientBadDomain {
        async fn execute(&self, _: reqwest::Request) -> Result<reqwest::Response, reqwest::Error> {
            Ok(HttpResponse::new(json!({"foo.bar!!!!": "aaaaa-aa"}).to_string()).into())
        }
    }

    #[derive(Debug)]
    struct MockClientBadCanister;

    #[async_trait]
    impl http::Client for MockClientBadCanister {
        async fn execute(&self, _: reqwest::Request) -> Result<reqwest::Response, reqwest::Error> {
            Ok(HttpResponse::new(json!({"foo.bar": "aaaaa-aa!!!"}).to_string()).into())
        }
    }

    #[derive(Debug)]
    struct MockClientTimestamped(AtomicU64);

    #[async_trait]
    impl http::Client for MockClientTimestamped {
        async fn execute(
            &self,
            req: reqwest::Request,
        ) -> Result<reqwest::Response, reqwest::Error> {
            if req.url().as_str().contains("subdomains") {
                return Ok(HttpResponse::new(
                    if req.url().as_str().ends_with("/subdomains1") {
                        json!({"foo.bar": "aaaaa-aa", "bar.foo": "qoctq-giaaa-aaaaa-aaaea-cai"})
                    } else {
                        json!({"foo.barr": "aaaaa-aa", "bar.foos": "qoctq-giaaa-aaaaa-aaaea-cai"})
                    }
                    .to_string(),
                )
                .into());
            }

            let i = self.0.fetch_add(1, Ordering::SeqCst);
            return Ok(HttpResponse::new(
                if i <= 1 {
                    json!({"timestamp": 1743756162, "url": "https://boundary.caffeine.ai/subdomains1"})
                } else {
                    json!({"timestamp": 1743756163, "url": "https://boundary.caffeine.ai/subdomains2"})
                }
                .to_string(),
            )
            .into());
        }
    }

    #[tokio::test]
    async fn test_generic_provider_timestamped() {
        let cli = Arc::new(MockClientTimestamped(AtomicU64::new(0)));
        let prov =
            GenericProviderTimestamped::new(cli, "http://foo".try_into().unwrap(), Duration::ZERO);

        // Check that 1st call provides the 1st set of domains
        let domains: Vec<CustomDomain> = prov
            .get_custom_domains()
            .await
            .unwrap()
            .into_iter()
            .sorted_by_key(|x| x.name.clone())
            .collect();

        assert_eq!(
            domains,
            vec![
                CustomDomain {
                    name: fqdn!("bar.foo"),
                    canister_id: principal!("qoctq-giaaa-aaaaa-aaaea-cai")
                },
                CustomDomain {
                    name: fqdn!("foo.bar"),
                    canister_id: principal!("aaaaa-aa")
                },
            ]
        );

        // Check that 2nd call provides the same set (timestamp not changed)
        let domains: Vec<CustomDomain> = prov
            .get_custom_domains()
            .await
            .unwrap()
            .into_iter()
            .sorted_by_key(|x| x.name.clone())
            .collect();

        assert_eq!(
            domains,
            vec![
                CustomDomain {
                    name: fqdn!("bar.foo"),
                    canister_id: principal!("qoctq-giaaa-aaaaa-aaaea-cai")
                },
                CustomDomain {
                    name: fqdn!("foo.bar"),
                    canister_id: principal!("aaaaa-aa")
                },
            ]
        );

        // Check that 3rd call provides different set
        let domains: Vec<CustomDomain> = prov
            .get_custom_domains()
            .await
            .unwrap()
            .into_iter()
            .sorted_by_key(|x| x.name.clone())
            .collect();

        assert_eq!(
            domains,
            vec![
                CustomDomain {
                    name: fqdn!("bar.foos"),
                    canister_id: principal!("qoctq-giaaa-aaaaa-aaaea-cai")
                },
                CustomDomain {
                    name: fqdn!("foo.barr"),
                    canister_id: principal!("aaaaa-aa")
                },
            ]
        );
    }

    #[tokio::test]
    async fn test_generic_provider() {
        let cli = Arc::new(MockClient);
        let prov = GenericProvider::new(cli, "http://foo".try_into().unwrap(), Duration::ZERO);

        let domains: Vec<CustomDomain> = prov
            .get_custom_domains()
            .await
            .unwrap()
            .into_iter()
            .sorted_by_key(|x| x.name.clone())
            .collect();

        assert_eq!(
            domains,
            vec![
                CustomDomain {
                    name: fqdn!("bar.foo"),
                    canister_id: principal!("qoctq-giaaa-aaaaa-aaaea-cai")
                },
                CustomDomain {
                    name: fqdn!("foo.bar"),
                    canister_id: principal!("aaaaa-aa")
                },
            ]
        );

        let cli = Arc::new(MockClientBadDomain);
        let prov = GenericProvider::new(cli, "http://foo".try_into().unwrap(), Duration::ZERO);
        assert!(prov.get_custom_domains().await.is_err());

        let cli = Arc::new(MockClientBadCanister);
        let prov = GenericProvider::new(cli, "http://foo".try_into().unwrap(), Duration::ZERO);
        assert!(prov.get_custom_domains().await.is_err());
    }
}
