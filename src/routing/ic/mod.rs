#![allow(clippy::declare_interior_mutable_const)]
#![allow(clippy::borrow_interior_mutable_const)]

pub mod handler;
pub mod health_check;
pub mod nodes_fetcher;
pub mod route_provider;
pub mod transport;

use std::{fs, sync::Arc};

use anyhow::{Context, Error};
use http::{header::HeaderName, HeaderMap};
use http_body_util::Either;
use ic_agent::agent::http_transport::route_provider::RouteProvider;
use ic_bn_lib::http::{
    headers::{
        X_IC_CACHE_BYPASS_REASON, X_IC_CACHE_STATUS, X_IC_CANISTER_ID_CBOR, X_IC_ERROR_CAUSE,
        X_IC_METHOD_NAME, X_IC_NODE_ID, X_IC_RETRIES, X_IC_SENDER, X_IC_SUBNET_ID,
        X_IC_SUBNET_TYPE,
    },
    Client as HttpClient,
};
use ic_http_gateway::{HttpGatewayClient, HttpGatewayResponse, HttpGatewayResponseMetadata};

use crate::Cli;

/// Metadata about the request to a Boundary Node (ic-boundary)
#[derive(Clone, Default)]
pub struct BNRequestMetadata {
    pub backend: Option<String>,
}

/// Metadata about the response from a Boundary Node (ic-boundary)
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
                .unwrap_or_default()
        };

        Self {
            node_id: extract(&X_IC_NODE_ID),
            subnet_id: extract(&X_IC_SUBNET_ID),
            subnet_type: extract(&X_IC_SUBNET_TYPE),
            canister_id_cbor: extract(&X_IC_CANISTER_ID_CBOR),
            sender: extract(&X_IC_SENDER),
            method_name: extract(&X_IC_METHOD_NAME),
            error_cause: extract(&X_IC_ERROR_CAUSE),
            retries: extract(&X_IC_RETRIES),
            cache_status: extract(&X_IC_CACHE_STATUS),
            cache_bypass_reason: extract(&X_IC_CACHE_BYPASS_REASON),
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
    let transport = transport::ReqwestTransport::create_with_client_route(
        route_provider,
        http_client,
        cli.ic.ic_max_request_retries,
    );

    let agent = ic_agent::Agent::builder()
        .with_transport(transport)
        .with_verify_query_signatures(cli.ic.ic_enable_replica_signed_queries)
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
