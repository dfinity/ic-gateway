use std::str::FromStr as _;
use std::{sync::Arc, time::Duration};

use ahash::HashMap;
use anyhow::Error;
use anyhow::{Context as AnyhowContext, anyhow};
use async_trait::async_trait;
use candid::Principal;
use derive_new::new;
use fqdn::FQDN;
use ic_bn_lib::http;
use reqwest::{Method, Request, StatusCode, Url};

use crate::routing::domain::{CustomDomain, ProvidesCustomDomains};

#[derive(new, Debug)]
pub struct GenericProvider {
    http_client: Arc<dyn http::Client>,
    url: Url,
    timeout: Duration,
}

#[async_trait]
impl ProvidesCustomDomains for GenericProvider {
    async fn get_custom_domains(&self) -> Result<Vec<CustomDomain>, Error> {
        let mut req = Request::new(Method::GET, self.url.clone());
        *req.timeout_mut() = Some(self.timeout);

        let response = self
            .http_client
            .execute(req)
            .await
            .context("failed to make http request")?;

        if response.status() != StatusCode::OK {
            return Err(anyhow!("incorrect response code: {}", response.status()));
        }

        let bs = response
            .bytes()
            .await
            .context("failed to fetch response body")?
            .to_vec();

        // TODO use fqdn's crate serde when it's fixed
        let domains: HashMap<String, Principal> =
            serde_json::from_slice(&bs).context("failed to parse json body")?;

        Ok(domains
            .into_iter()
            .map(|(k, v)| -> Result<CustomDomain, Error> {
                Ok(CustomDomain {
                    name: FQDN::from_str(&k)?,
                    canister_id: v,
                })
            })
            .collect::<Result<Vec<_>, _>>()?)
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

    #[tokio::test]
    async fn test_provider() {
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
