#![allow(clippy::declare_interior_mutable_const)]

pub mod health_check;
pub mod route_provider;
pub mod transport;

use std::{fs, sync::Arc};

use anyhow::{Context, Error};
use axum::extract::Request;
use http::header::HeaderName;
use http_body_util::Either;
use ic_agent::agent::http_transport::route_provider::RouteProvider;
use ic_http_gateway::{HttpGatewayClient, HttpGatewayResponse, HttpGatewayResponseMetadata};

use crate::{http::Client as HttpClient, Cli};

const HEADER_IC_CACHE: HeaderName = HeaderName::from_static("x-ic-cache-status");
const HEADER_IC_CACHE_BYPASS_REASON: HeaderName =
    HeaderName::from_static("x-ic-cache-bypass-reason");
const HEADER_IC_SUBNET_ID: HeaderName = HeaderName::from_static("x-ic-subnet-id");
const HEADER_IC_NODE_ID: HeaderName = HeaderName::from_static("x-ic-node-id");
const HEADER_IC_CANISTER_ID_CBOR: HeaderName = HeaderName::from_static("x-ic-canister-id-cbor");
const HEADER_IC_METHOD_NAME: HeaderName = HeaderName::from_static("x-ic-method-name");
const HEADER_IC_SENDER: HeaderName = HeaderName::from_static("x-ic-sender");
const HEADER_IC_RETRIES: HeaderName = HeaderName::from_static("x-ic-retries");
const HEADER_IC_ERROR_CAUSE: HeaderName = HeaderName::from_static("x-ic-error-cause");

#[derive(Clone)]
pub struct BNResponseMetadata {
    pub node_id: String,
    pub subnet_id: String,
    pub canister_id_cbor: String,
    pub method_name: String,
    pub error_cause: String,
    pub retries: u8,
    pub cache_status: String,
    pub cache_bypass_reason: String,
}

impl TryFrom<&Request> for BNResponseMetadata {
    type Error = Error;

    fn try_from(value: &Request) -> Result<Self, Self::Error> {}
}

#[derive(Clone)]
pub struct IcResponseStatus {
    pub streaming: bool,
    pub metadata: HttpGatewayResponseMetadata,
}

impl From<&HttpGatewayResponse> for IcResponseStatus {
    fn from(value: &HttpGatewayResponse) -> Self {
        Self {
            streaming: matches!(value.canister_response.body(), Either::Left(_)),
            metadata: value.metadata.clone(),
        }
    }
}

pub fn setup(
    cli: &Cli,
    http_client: Arc<dyn HttpClient>,
    route_provider: Arc<dyn RouteProvider>,
) -> Result<HttpGatewayClient, Error> {
    let transport =
        transport::ReqwestTransport::create_with_client_route(route_provider, http_client)?;
    let agent = ic_agent::Agent::builder()
        .with_transport(transport)
        .build()?;

    if let Some(v) = &cli.ic.ic_root_key {
        let key = fs::read(v).context("unable to read IC root key")?;
        agent.set_root_key(key);
    }

    let client = ic_http_gateway::HttpGatewayClientBuilder::new()
        .with_agent(agent)
        .build()?;

    Ok(client)
}
