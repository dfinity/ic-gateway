use std::{fs, path::PathBuf, sync::Arc};

use ahash::{AHashMap, AHashSet};
use anyhow::{Context, Error, anyhow};
use arc_swap::ArcSwapOption;
use candid::Principal;
use ic_bn_lib_common::traits::http::Client;
use serde::Deserialize;
use serde_json as json;
use tracing::warn;
use url::Url;

use super::load_principal_list;
use crate::routing::middleware::geoip::CountryCode;

pub struct Denylist {
    url: Option<Url>,
    http_client: Arc<dyn Client>,
    inner: ArcSwapOption<AHashMap<Principal, Vec<String>>>,
    allowlist: AHashSet<Principal>,
}

impl Denylist {
    pub fn new(
        url: Option<Url>,
        allowlist: AHashSet<Principal>,
        http_client: Arc<dyn Client>,
    ) -> Self {
        Self {
            url,
            http_client,
            inner: ArcSwapOption::empty(),
            allowlist,
        }
    }

    pub fn init(
        url: Option<Url>,
        allowlist: Option<PathBuf>,
        seed: Option<PathBuf>,
        http_client: Arc<dyn Client>,
    ) -> Result<Self, Error> {
        let allowlist = if let Some(v) = allowlist {
            let r = load_principal_list(&v).context("unable to read allowlist")?;
            warn!("Denylist: allowlist loaded: {} canisters", r.len());
            r
        } else {
            AHashSet::new()
        };

        let denylist = Self::new(url, allowlist, http_client);

        if let Some(v) = seed {
            let seed = fs::read(v).context("unable to read seed")?;
            let r = denylist.load_json(&seed).context("unable to parse seed")?;
            warn!("Denylist: seed loaded: {r} canisters");
        }

        Ok(denylist)
    }

    pub fn is_blocked(&self, canister_id: Principal, country_code: Option<CountryCode>) -> bool {
        if self.allowlist.contains(&canister_id) {
            return false;
        }

        // Load the list
        let list = match self.inner.load_full() {
            None => return false,
            Some(v) => v,
        };

        // See if there's an entry
        let Some(entry) = list.get(&canister_id) else {
            return false;
        };

        // if there are no codes - then all regions are blocked
        if entry.is_empty() {
            return true;
        }

        // If there's no country code info -> then we don't block by default
        // TODO discuss
        country_code.is_some_and(|code| entry.contains(&code.0))
    }

    pub async fn update(&self) -> Result<usize, Error> {
        let url = match &self.url {
            Some(v) => v.clone(),
            None => return Err(anyhow!("no URL provided")),
        };

        let request = reqwest::Request::new(reqwest::Method::GET, url);

        let response = self
            .http_client
            .execute(request)
            .await
            .context("request failed")?;

        if response.status() != reqwest::StatusCode::OK {
            return Err(anyhow!("request failed with status {}", response.status()));
        }

        let data = response
            .bytes()
            .await
            .context("failed to get response bytes")?;

        self.load_json(&data)
    }

    pub fn load_json(&self, data: &[u8]) -> Result<usize, Error> {
        #[derive(Deserialize)]
        struct Canister {
            localities: Option<Vec<String>>,
        }

        #[derive(Deserialize)]
        struct Response {
            canisters: std::collections::HashMap<String, Canister>,
        }

        let entries =
            json::from_slice::<Response>(data).context("failed to deserialize JSON response")?;

        let denylist = entries
            .canisters
            .into_iter()
            .map(|x| {
                let canister_id = Principal::from_text(x.0)?;
                let country_codes = x.1.localities.unwrap_or_default();
                Ok((canister_id, country_codes))
            })
            .collect::<Result<AHashMap<_, _>, Error>>()?;

        let count = denylist.len();
        self.inner.store(Some(Arc::new(denylist)));

        Ok(count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;

    #[derive(Debug)]
    struct TestClient(reqwest::Client);

    #[async_trait]
    impl Client for TestClient {
        async fn execute(
            &self,
            req: reqwest::Request,
        ) -> Result<reqwest::Response, reqwest::Error> {
            self.0.execute(req).await
        }
    }

    #[tokio::test]
    async fn test_update() -> Result<(), Error> {
        use httptest::{Expectation, Server, matchers::*, responders::*};
        use serde_json::json;

        let denylist_json = json!({
          "$schema": "./schema.json",
          "version": "1",
          "canisters": {
            "qoctq-giaaa-aaaaa-aaaea-cai": {"localities": ["CH", "US"]},
            "s6hwe-laaaa-aaaab-qaeba-cai": {"localities": []},
            "2dcn6-oqaaa-aaaai-abvoq-cai": {},
            "g3wsl-eqaaa-aaaan-aaaaa-cai": {},
          }
        });

        let server = Server::run();
        server.expect(
            Expectation::matching(request::method_path("GET", "/denylist.json"))
                .respond_with(json_encoded(denylist_json)),
        );

        let client =
            Arc::new(TestClient(reqwest::ClientBuilder::new().build()?)) as Arc<dyn Client>;

        let denylist = Denylist::new(
            Some(Url::parse(&server.url_str("/denylist.json")).unwrap()),
            AHashSet::from([Principal::from_text("g3wsl-eqaaa-aaaan-aaaaa-cai").unwrap()]),
            client,
        );
        denylist.update().await?;

        // blocked in given regions
        assert!(denylist.is_blocked(
            Principal::from_text("qoctq-giaaa-aaaaa-aaaea-cai").unwrap(),
            Some(CountryCode("CH".into()))
        ));

        assert!(denylist.is_blocked(
            Principal::from_text("qoctq-giaaa-aaaaa-aaaea-cai").unwrap(),
            Some(CountryCode("US".into()))
        ));

        // unblocked in other
        assert!(!denylist.is_blocked(
            Principal::from_text("qoctq-giaaa-aaaaa-aaaea-cai").unwrap(),
            Some(CountryCode("RU".into()))
        ));

        // no country code
        assert!(!denylist.is_blocked(
            Principal::from_text("qoctq-giaaa-aaaaa-aaaea-cai").unwrap(),
            None
        ));

        // blocked regardless of region
        assert!(denylist.is_blocked(
            Principal::from_text("s6hwe-laaaa-aaaab-qaeba-cai").unwrap(),
            Some(CountryCode("foobar".into()))
        ));

        assert!(denylist.is_blocked(
            Principal::from_text("2dcn6-oqaaa-aaaai-abvoq-cai").unwrap(),
            Some(CountryCode("foobar".into()))
        ));

        // allowlisted allowed regardless
        assert!(!denylist.is_blocked(
            Principal::from_text("g3wsl-eqaaa-aaaan-aaaaa-cai").unwrap(),
            Some(CountryCode("foo".into()))
        ));

        Ok(())
    }

    #[tokio::test]
    async fn test_corrupted() -> Result<(), Error> {
        use httptest::{Expectation, Server, matchers::*, responders::*};
        use serde_json::json;

        let denylist_json = json!({
          "$schema": "./schema.json",
          "version": "1",
          "canisters": {
            "qoctq-giaaa-aaaaa-aaaea-cai": {"localities": ["CH", "US"]},
            "s6hwe-laaaa-aaaab-qaeba-cai": {"localities": []},
            "foobar": {},
          }
        });

        let server = Server::run();
        server.expect(
            Expectation::matching(request::method_path("GET", "/denylist.json"))
                .respond_with(json_encoded(denylist_json)),
        );

        let client =
            Arc::new(TestClient(reqwest::ClientBuilder::new().build()?)) as Arc<dyn Client>;
        let denylist = Denylist::new(
            Some(Url::parse(&server.url_str("/denylist.json")).unwrap()),
            AHashSet::new(),
            client,
        );
        assert!(denylist.update().await.is_err());

        Ok(())
    }
}
