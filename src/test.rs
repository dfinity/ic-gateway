use std::sync::Arc;

use anyhow::Error;
use async_trait::async_trait;
use axum::{Router, response::Response};
use candid::Encode;
use clap::Parser;
use fqdn::fqdn;
use http::{
    StatusCode,
    header::{CONTENT_LENGTH, CONTENT_TYPE},
};
use ic_agent::agent::route_provider::RoundRobinRouteProvider;
use ic_bn_lib::{principal, tasks::TaskManager};
use ic_http_certification::HttpResponse;
use ic_transport_types::{QueryResponse, ReplyResponse};
use prometheus::Registry;
use rand::{Rng, thread_rng};
use serde_cbor::to_vec;

use crate::{
    Cli,
    routing::{
        domain::{CustomDomain, ProvidesCustomDomains},
        setup_router,
    },
};

#[derive(Debug)]
pub struct FakeDomainProvider(pub Vec<CustomDomain>);

#[async_trait]
impl ProvidesCustomDomains for FakeDomainProvider {
    async fn get_custom_domains(&self) -> Result<Vec<CustomDomain>, Error> {
        Ok(self.0.clone())
    }
}

pub fn generate_response(response_size: usize) -> reqwest::Response {
    let response = HttpResponse::builder()
        .with_headers(vec![(CONTENT_TYPE.to_string(), "text/plain".into())])
        .with_body(b"X".repeat(response_size))
        .build();

    let response_body = Encode!(&response).unwrap();
    let response_data = QueryResponse::Replied {
        reply: ReplyResponse { arg: response_body },
        signatures: vec![],
    };

    let cbor_data = to_vec(&response_data).unwrap();
    let content_length = cbor_data.len();

    Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/cbor")
        .header(CONTENT_LENGTH, content_length)
        .body(cbor_data)
        .expect("Failed to build response")
        .try_into()
        .unwrap()
}

#[derive(Debug)]
struct TestClient(pub usize);

#[async_trait]
impl ic_bn_lib::http::Client for TestClient {
    async fn execute(&self, _req: reqwest::Request) -> Result<reqwest::Response, reqwest::Error> {
        Ok(generate_response(self.0))
    }
}

/// Creates a test router with some defaults and returns it along with a list of random custom domains that it serves
pub async fn setup_test_router(tasks: &mut TaskManager) -> (Router, Vec<String>) {
    let mut rng = thread_rng();

    // Generate 1k custom domains
    let rgx_domains =
        rand_regex::Regex::compile(r"[a-z]{1,20}\.[a-z]{1,20}\.[a-z]{1,3}", 20).unwrap();
    let domains = (&mut rng)
        .sample_iter(&rgx_domains)
        .take(1000)
        .collect::<Vec<String>>();

    let args = vec![
        "",
        "--ic-unsafe-disable-response-verification",
        "--cache-size",
        "2gb",
        "--domain",
        "ic0.app",
        "--policy-pre-isolation-canisters",
        "test_data/pre_isolation_canisters.txt",
        "--policy-denylist-seed",
        "test_data/denylist.json",
        "--policy-denylist-allowlist",
        "test_data/allowlist.txt",
        "--log-vector-url",
        "http://127.0.0.1/vector",
    ];
    let cli = Cli::parse_from(args);

    let custom_domains = domains
        .clone()
        .into_iter()
        .map(|x| CustomDomain {
            name: fqdn!(&x),
            canister_id: principal!("aaaaa-aa"),
        })
        .collect::<Vec<_>>();

    let http_client = Arc::new(TestClient(512));
    let route_provider = RoundRobinRouteProvider::new(vec!["http://foo"]).unwrap();

    let router = setup_router(
        &cli,
        vec![Arc::new(FakeDomainProvider(custom_domains))],
        tasks,
        http_client,
        Arc::new(route_provider),
        &Registry::new(),
        #[cfg(feature = "clickhouse")]
        None,
        None,
    )
    .await
    .unwrap();

    (router, domains)
}
