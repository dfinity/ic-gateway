#![allow(clippy::declare_interior_mutable_const)]
#![allow(clippy::borrow_interior_mutable_const)]

pub mod handler;
pub mod health_check;
pub mod route_provider;
pub mod transport;

use std::{fs, sync::Arc};

use anyhow::{Context, Error};
use http::{header::HeaderName, HeaderMap};
use http_body_util::Either;
use ic_agent::agent::http_transport::route_provider::RouteProvider;
use ic_http_gateway::{HttpGatewayClient, HttpGatewayResponse, HttpGatewayResponseMetadata};

use crate::{http::Client as HttpClient, Cli};

pub const HEADER_IC_CACHE_STATUS: HeaderName = HeaderName::from_static("x-ic-cache-status");
pub const HEADER_IC_CACHE_BYPASS_REASON: HeaderName =
    HeaderName::from_static("x-ic-cache-bypass-reason");
pub const HEADER_IC_SUBNET_ID: HeaderName = HeaderName::from_static("x-ic-subnet-id");
pub const HEADER_IC_NODE_ID: HeaderName = HeaderName::from_static("x-ic-node-id");
pub const HEADER_IC_SUBNET_TYPE: HeaderName = HeaderName::from_static("x-ic-subnet-type");
pub const HEADER_IC_CANISTER_ID_CBOR: HeaderName = HeaderName::from_static("x-ic-canister-id-cbor");
pub const HEADER_IC_METHOD_NAME: HeaderName = HeaderName::from_static("x-ic-method-name");
pub const HEADER_IC_SENDER: HeaderName = HeaderName::from_static("x-ic-sender");
pub const HEADER_IC_RETRIES: HeaderName = HeaderName::from_static("x-ic-retries");
pub const HEADER_IC_ERROR_CAUSE: HeaderName = HeaderName::from_static("x-ic-error-cause");
pub const HEADER_IC_REQUEST_TYPE: HeaderName = HeaderName::from_static("x-ic-request-type");
pub const HEADER_IC_CANISTER_ID: HeaderName = HeaderName::from_static("x-ic-canister-id");
pub const HEADER_IC_COUNTRY_CODE: http::HeaderName =
    http::HeaderName::from_static("x-ic-country-code");

/// Metadata about the request by a Boundary Node (ic-boundary)
#[derive(Clone)]
pub struct BNResponseMetadata {
    pub node_id: String,
    pub subnet_id: String,
    pub subnet_type: String,
    pub canister_id_cbor: String,
    pub sender: String,
    pub method_name: String,
    pub error_cause: String,
    pub retries: String,
    pub cache_status: String,
    pub cache_bypass_reason: String,
}

// This defaults to all fields as ""
impl Default for BNResponseMetadata {
    fn default() -> Self {
        let mut map = HeaderMap::new();
        Self::from(&mut map)
    }
}

impl From<&mut HeaderMap> for BNResponseMetadata {
    fn from(v: &mut HeaderMap) -> Self {
        let mut extract = |h: &HeaderName| -> String {
            v.remove(h)
                // It seems there's no way to get the inner Bytes from HeaderValue,
                // so we'll have to accept the allocation
                .and_then(|x| x.to_str().ok().map(|x| x.to_string()))
                .unwrap_or_else(|| "".into())
        };

        Self {
            node_id: extract(&HEADER_IC_NODE_ID),
            subnet_id: extract(&HEADER_IC_SUBNET_ID),
            subnet_type: extract(&HEADER_IC_SUBNET_TYPE),
            canister_id_cbor: extract(&HEADER_IC_CANISTER_ID_CBOR),
            sender: extract(&HEADER_IC_SENDER),
            method_name: extract(&HEADER_IC_METHOD_NAME),
            error_cause: extract(&HEADER_IC_ERROR_CAUSE),
            retries: extract(&HEADER_IC_RETRIES),
            cache_status: extract(&HEADER_IC_CACHE_STATUS),
            cache_bypass_reason: extract(&HEADER_IC_CACHE_BYPASS_REASON),
        }
    }
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
