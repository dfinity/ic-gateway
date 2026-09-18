use std::{fs, path::PathBuf, sync::Arc};

use ahash::{AHashMap, AHashSet};
use anyhow::{Context, Error, anyhow};
use arc_swap::ArcSwapOption;
use candid::Principal;
use ic_bn_lib::{geoip::CountryCode, http::Client};
use serde::Deserialize;
use serde_json as json;
use tracing::warn;
use url::Url;

use super::load_principal_list;

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
        let Some(list) = self.inner.load_full() else {
            return false;
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
        country_code.is_some_and(|code| entry.iter().any(|x| x == code.0.as_str()))
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
    use async_trait::async_trait;
    use ic_bn_lib::principal;

    use super::*;

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
            AHashSet::from([principal!("g3wsl-eqaaa-aaaan-aaaaa-cai")]),
            client,
        );
        denylist.update().await?;

        // blocked in given regions
        assert!(denylist.is_blocked(
            principal!("qoctq-giaaa-aaaaa-aaaea-cai"),
            Some(CountryCode("CH".try_into().unwrap()))
        ));

        assert!(denylist.is_blocked(
            principal!("qoctq-giaaa-aaaaa-aaaea-cai"),
            Some(CountryCode("US".try_into().unwrap()))
        ));

        // unblocked in other
        assert!(!denylist.is_blocked(
            principal!("qoctq-giaaa-aaaaa-aaaea-cai"),
            Some(CountryCode("RU".try_into().unwrap()))
        ));

        // no country code
        assert!(!denylist.is_blocked(principal!("qoctq-giaaa-aaaaa-aaaea-cai"), None));

        // blocked regardless of region
        assert!(denylist.is_blocked(
            principal!("s6hwe-laaaa-aaaab-qaeba-cai"),
            Some(CountryCode("ZZ".try_into().unwrap()))
        ));

        assert!(denylist.is_blocked(
            principal!("2dcn6-oqaaa-aaaai-abvoq-cai"),
            Some(CountryCode("ZZ".try_into().unwrap()))
        ));

        // allowlisted allowed regardless
        assert!(!denylist.is_blocked(
            principal!("g3wsl-eqaaa-aaaan-aaaaa-cai"),
            Some(CountryCode("ZZ".try_into().unwrap()))
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

    /// A denylist that was never loaded must not block anything
    #[test]
    fn test_not_loaded_blocks_nothing() {
        let client = Arc::new(TestClient(reqwest::Client::new())) as Arc<dyn Client>;
        let denylist = Denylist::new(None, AHashSet::new(), client);

        assert!(!denylist.is_blocked(principal!("aaaaa-aa"), None));
        assert!(!denylist.is_blocked(
            principal!("aaaaa-aa"),
            Some(CountryCode("CH".try_into().unwrap()))
        ));
    }

    #[tokio::test]
    async fn test_update_without_url() {
        let client = Arc::new(TestClient(reqwest::Client::new())) as Arc<dyn Client>;
        let denylist = Denylist::new(None, AHashSet::new(), client);

        assert!(denylist.update().await.is_err());
    }

    #[tokio::test]
    async fn test_update_non_200() {
        use httptest::{Expectation, Server, matchers::*, responders::*};

        let server = Server::run();
        server.expect(
            Expectation::matching(request::method_path("GET", "/denylist.json"))
                .respond_with(status_code(500)),
        );

        let client = Arc::new(TestClient(reqwest::Client::new())) as Arc<dyn Client>;
        let denylist = Denylist::new(
            Some(Url::parse(&server.url_str("/denylist.json")).unwrap()),
            AHashSet::new(),
            client,
        );

        let err = denylist.update().await.unwrap_err();
        assert!(err.to_string().contains("500"), "{err:#}");
    }

    /// A failed update must leave the previously loaded list in place rather than
    /// clearing it - otherwise a transient fetch error unblocks everything.
    #[tokio::test]
    async fn test_failed_update_keeps_old_list() {
        use httptest::{Expectation, Server, matchers::*, responders::*};

        let server = Server::run();
        server.expect(
            Expectation::matching(request::method_path("GET", "/denylist.json"))
                .times(1..)
                .respond_with(status_code(500)),
        );

        let client = Arc::new(TestClient(reqwest::Client::new())) as Arc<dyn Client>;
        let denylist = Denylist::new(
            Some(Url::parse(&server.url_str("/denylist.json")).unwrap()),
            AHashSet::new(),
            client,
        );

        denylist
            .load_json(br#"{"canisters": {"aaaaa-aa": {"localities": []}}}"#)
            .unwrap();
        assert!(denylist.is_blocked(principal!("aaaaa-aa"), None));

        assert!(denylist.update().await.is_err());
        assert!(denylist.is_blocked(principal!("aaaaa-aa"), None));
    }

    #[test]
    fn test_load_json() {
        let client = Arc::new(TestClient(reqwest::Client::new())) as Arc<dyn Client>;
        let denylist = Denylist::new(None, AHashSet::new(), client);

        // `localities` is optional and an absent one means "everywhere"
        assert_eq!(
            denylist
                .load_json(br#"{"canisters": {"aaaaa-aa": {}, "s6hwe-laaaa-aaaab-qaeba-cai": {"localities": ["CH"]}}}"#)
                .unwrap(),
            2
        );
        assert!(denylist.is_blocked(principal!("aaaaa-aa"), None));

        // Unknown top-level fields are tolerated (the real list has $schema/version)
        assert_eq!(
            denylist
                .load_json(br#"{"$schema": "x", "version": "1", "canisters": {}}"#)
                .unwrap(),
            0
        );
        // ...and reloading replaces the list rather than merging into it
        assert!(!denylist.is_blocked(principal!("aaaaa-aa"), None));

        // Broken input is rejected
        for data in [
            &b"not json"[..],
            // Missing the required `canisters` key
            br#"{"version": "1"}"#,
            // Bad principal
            br#"{"canisters": {"nope": {}}}"#,
            // Wrong shape
            br#"{"canisters": {"aaaaa-aa": {"localities": "CH"}}}"#,
        ] {
            assert!(denylist.load_json(data).is_err(), "data {data:?}");
        }
    }

    #[test]
    fn test_init_with_seed_and_allowlist() {
        use std::io::Write;

        let client = Arc::new(TestClient(reqwest::Client::new())) as Arc<dyn Client>;

        let mut seed = tempfile::NamedTempFile::new().unwrap();
        seed.write_all(
            br#"{"canisters": {"aaaaa-aa": {"localities": []}, "s6hwe-laaaa-aaaab-qaeba-cai": {"localities": []}}}"#,
        )
        .unwrap();
        seed.flush().unwrap();

        let mut allow = tempfile::NamedTempFile::new().unwrap();
        allow.write_all(b"s6hwe-laaaa-aaaab-qaeba-cai\n").unwrap();
        allow.flush().unwrap();

        let denylist = Denylist::init(
            None,
            Some(allow.path().to_path_buf()),
            Some(seed.path().to_path_buf()),
            client.clone(),
        )
        .unwrap();

        assert!(denylist.is_blocked(principal!("aaaaa-aa"), None));
        // The allowlist wins over the seed
        assert!(!denylist.is_blocked(principal!("s6hwe-laaaa-aaaab-qaeba-cai"), None));

        // A broken seed or allowlist is a hard startup failure, not a silent
        // "block nothing".
        let mut bad = tempfile::NamedTempFile::new().unwrap();
        bad.write_all(b"not json").unwrap();
        bad.flush().unwrap();

        assert!(
            Denylist::init(None, None, Some(bad.path().to_path_buf()), client.clone()).is_err()
        );
        assert!(
            Denylist::init(None, Some(bad.path().to_path_buf()), None, client.clone()).is_err()
        );
        assert!(
            Denylist::init(
                None,
                None,
                Some(PathBuf::from("/nonexistent/seed.json")),
                client
            )
            .is_err()
        );
    }
}
