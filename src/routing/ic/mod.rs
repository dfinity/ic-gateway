pub mod health_check;
pub mod route_provider;
pub mod transport;
use std::{fs, sync::Arc};

use anyhow::{Context, Error};
use http_body_util::Either;
use ic_agent::agent::http_transport::route_provider::RouteProvider;
use ic_http_gateway::{HttpGatewayClient, HttpGatewayResponse, HttpGatewayResponseMetadata};

use crate::{http::Client as HttpClient, Cli};

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
