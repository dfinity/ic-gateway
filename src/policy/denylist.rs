use std::{
    collections::{HashMap, HashSet},
    fs,
    path::PathBuf,
    sync::Arc,
    time::Duration,
};

use anyhow::{anyhow, Context, Error};
use arc_swap::ArcSwapOption;
use candid::Principal;
use prometheus::{register_int_counter_vec_with_registry, IntCounterVec, Registry};
use serde::Deserialize;
use serde_json as json;
use tracing::{info, warn};
use url::Url;

use super::load_canister_list;
use crate::http::Client;

pub struct Denylist {
    url: Option<Url>,
    http_client: Arc<dyn Client>,
    denylist: ArcSwapOption<HashMap<Principal, Vec<String>>>,
    allowlist: HashSet<Principal>,
}

impl Denylist {
    pub fn new(
        url: Option<Url>,
        allowlist: HashSet<Principal>,
        http_client: Arc<dyn Client>,
    ) -> Self {
        Self {
            url,
            http_client,
            denylist: ArcSwapOption::empty(),
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
            load_canister_list(v)?
        } else {
            HashSet::new()
        };

        let denylist = Self::new(url, allowlist, http_client);

        if let Some(v) = seed {
            let seed = fs::read(v)?;
            denylist.load_json(&seed)?;
        }

        Ok(denylist)
    }

    pub fn is_blocked(&self, canister_id: Principal, country_code: &str) -> bool {
        if self.allowlist.contains(&canister_id) {
            return false;
        }

        if let Some(list) = self.denylist.load_full() {
            let entry = match list.get(&canister_id) {
                Some(v) => v,
                None => return false,
            };

            // if there are no codes - then all regions are blocked
            if entry.is_empty() {
                return true;
            }

            return entry.iter().any(|x| x == country_code);
        }

        false
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
            canisters: HashMap<String, Canister>,
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
            .collect::<Result<HashMap<_, _>, Error>>()?;

        let count = denylist.len();
        self.denylist.store(Some(Arc::new(denylist)));

        Ok(count)
    }

    pub async fn run(&self, interval: Duration, registry: &Registry) -> Result<(), Error> {
        // Do not run if no URL was given
        if self.url.is_none() {
            return Ok(());
        }

        let metric_params = MetricParams::new(registry);

        loop {
            let res = self.update().await;

            let lbl = match res {
                Err(e) => {
                    warn!("Denylist update failed: {e}");
                    "fail"
                }
                Ok(v) => {
                    info!("Denylist updated: {} canisters", v);
                    "ok"
                }
            };

            metric_params.updates.with_label_values(&[lbl]).inc();

            tokio::time::sleep(interval).await;
        }
    }
}

#[derive(Clone)]
pub struct MetricParams {
    pub updates: IntCounterVec,
}

impl MetricParams {
    pub fn new(registry: &Registry) -> Self {
        Self {
            updates: register_int_counter_vec_with_registry!(
                format!("denylist_updates"),
                format!("Counts denylist updates and results"),
                &["result"],
                registry
            )
            .unwrap(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;

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
        use httptest::{matchers::*, responders::*, Expectation, Server};
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
            HashSet::from([Principal::from_text("g3wsl-eqaaa-aaaan-aaaaa-cai").unwrap()]),
            client,
        );
        denylist.update().await?;

        // blocked in given regions
        assert!(denylist.is_blocked(
            Principal::from_text("qoctq-giaaa-aaaaa-aaaea-cai").unwrap(),
            "CH"
        ));

        assert!(denylist.is_blocked(
            Principal::from_text("qoctq-giaaa-aaaaa-aaaea-cai").unwrap(),
            "US"
        ));

        // unblocked in other
        assert!(!denylist.is_blocked(
            Principal::from_text("qoctq-giaaa-aaaaa-aaaea-cai").unwrap(),
            "RU"
        ));

        // blocked regardless of region
        assert!(denylist.is_blocked(
            Principal::from_text("s6hwe-laaaa-aaaab-qaeba-cai").unwrap(),
            "foobar"
        ));

        assert!(denylist.is_blocked(
            Principal::from_text("2dcn6-oqaaa-aaaai-abvoq-cai").unwrap(),
            "foobar"
        ));

        // allowlisted allowed regardless
        assert!(!denylist.is_blocked(
            Principal::from_text("g3wsl-eqaaa-aaaan-aaaaa-cai").unwrap(),
            "foo"
        ));

        Ok(())
    }

    #[tokio::test]
    async fn test_corrupted() -> Result<(), Error> {
        use httptest::{matchers::*, responders::*, Expectation, Server};
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
            HashSet::new(),
            client,
        );
        assert!(denylist.update().await.is_err());

        Ok(())
    }
}
