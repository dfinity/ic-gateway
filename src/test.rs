#![allow(clippy::missing_panics_doc)]

use std::sync::Arc;

use anyhow::Error;
use async_trait::async_trait;
use axum::{Router, body::Body as AxumBody, response::Response};
use bytes::Bytes;
use candid::{Encode, Principal};
use clap::Parser;
use fqdn::fqdn;
use http::{
    Request, StatusCode,
    header::{CONTENT_LENGTH, CONTENT_TYPE},
};
use http_body_util::{BodyExt, Full};
use ic_bn_lib::{
    custom_domains::{CustomDomain, ProvidesCustomDomains},
    health::HealthManager,
    http::{Client, ClientHttp, Error as HttpError},
    ic_agent::agent::{ReplyResponse, route_provider::RoundRobinRouteProvider},
    principal,
    tasks::TaskManager,
};
use ic_http_certification::HttpResponse;
use ic_transport_types::QueryResponse;
use prometheus::Registry;
use rand::{Rng, SeedableRng};
use serde_cbor::to_vec;
use tokio_util::sync::CancellationToken;
use tracing_subscriber::{EnvFilter, reload};

use crate::{
    Cli, log,
    routing::{
        domain::CustomDomainStorage,
        ic::routing_table_manager::{LooksUpSubnetType, SubnetType},
        setup_router,
    },
};

/// The NNS (root) subnet ID for the test fixtures in src/routing/ic/testdata/.
/// Captured from a testnet (system subnet) where subnet type info is populated.
pub const TEST_ROOT_SUBNET_ID: &str =
    "x4o6u-54cx4-m6ajt-n3rvt-ztxgq-22nxu-gmzgo-dp6d7-wea57-fvmrf-wqe";

#[derive(Debug)]
pub struct FakeDomainProvider(pub Vec<CustomDomain>);

#[async_trait]
impl ProvidesCustomDomains for FakeDomainProvider {
    async fn get_custom_domains(&self) -> Result<Vec<CustomDomain>, Error> {
        Ok(self.0.clone())
    }
}

pub fn generate_response(response_size: usize) -> Response<AxumBody> {
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
        .body(AxumBody::new(
            Full::new(Bytes::from(cbor_data)).map_err(|_| HttpError::BodyTimedOut),
        ))
        .expect("Failed to build response")
}

#[derive(Debug, Clone)]
pub struct TestClient(pub usize);

#[async_trait]
impl Client for TestClient {
    async fn execute(&self, _req: reqwest::Request) -> Result<reqwest::Response, reqwest::Error> {
        Ok(Response::builder().body("").unwrap().into())
    }
}

#[async_trait]
impl ClientHttp<Full<Bytes>> for TestClient {
    async fn execute(&self, _req: Request<Full<Bytes>>) -> Result<Response<AxumBody>, HttpError> {
        Ok(generate_response(self.0))
    }
}

#[async_trait]
impl ClientHttp<AxumBody> for TestClient {
    async fn execute(&self, _req: Request<AxumBody>) -> Result<Response<AxumBody>, HttpError> {
        Ok(generate_response(self.0))
    }
}

pub(crate) struct TestSubnetTypeLookuperEmpty;
impl LooksUpSubnetType for TestSubnetTypeLookuperEmpty {
    fn lookup_subnet_type(&self, _canister_id: &Principal) -> Option<SubnetType> {
        None
    }
}

/// Creates a test router with some defaults and returns it along with a list of random custom domains that it serves
pub async fn setup_test_router(tasks: &mut TaskManager) -> (Router, Vec<String>) {
    // SmallRng is Send which we require
    let mut rng = rand::rngs::SmallRng::from_entropy();

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
        "--network-trust-x-request-id",
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
        "--geoip-db",
        "test_data/GeoLite2-Country.mmdb",
        "--log-vector-url",
        "http://127.0.0.1/vector",
    ];
    let cli = Cli::parse_from(args);

    let custom_domains = domains
        .clone()
        .into_iter()
        .map(|x| CustomDomain::new(fqdn!(&x), principal!("aaaaa-aa")))
        .collect::<Vec<_>>();

    let http_client = Arc::new(TestClient(512));
    let route_provider = RoundRobinRouteProvider::new(vec!["http://foo"]).unwrap();

    let health_manager = Arc::new(HealthManager::default());
    let (_, reload_handle) =
        reload::Layer::new(EnvFilter::new(format!("warn,{}", log::LOG_LEVEL_OVERRIDES)));

    let custom_domain_storage = CustomDomainStorage::new(
        vec![Arc::new(FakeDomainProvider(custom_domains))],
        &Registry::new(),
    );
    custom_domain_storage.refresh().await;

    let router = setup_router(
        &cli,
        Arc::new(custom_domain_storage),
        reload_handle,
        tasks,
        health_manager,
        http_client.clone(),
        http_client,
        Arc::new(route_provider),
        &Registry::new(),
        CancellationToken::new(),
        None,
        None,
        None,
        Arc::new(TestSubnetTypeLookuperEmpty),
    )
    .await
    .unwrap();

    (router, domains)
}
