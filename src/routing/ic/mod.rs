pub mod health_check;
pub mod route_provider;
pub mod transport;
use std::{fs, sync::Arc};

use anyhow::{Context, Error};
use axum::{
    body::Body,
    response::{IntoResponse, Response},
};
use bytes::Bytes;
use futures::StreamExt;
use http_body::Frame;
use http_body_util::{Full, StreamBody};
use ic_agent::agent::http_transport::route_provider::RouteProvider;
use ic_http_gateway::{
    HttpGatewayClient, HttpGatewayResponse, HttpGatewayResponseBody, HttpGatewayResponseMetadata,
};

use crate::{http::Client as HttpClient, Cli};

#[derive(Clone)]
pub struct IcResponseStatus {
    pub streaming: bool,
    pub metadata: HttpGatewayResponseMetadata,
}

impl From<&HttpGatewayResponse> for IcResponseStatus {
    fn from(value: &HttpGatewayResponse) -> Self {
        Self {
            streaming: matches!(
                value.canister_response.body(),
                HttpGatewayResponseBody::Stream(_)
            ),
            metadata: value.metadata.clone(),
        }
    }
}

pub fn convert_response(resp: Response<HttpGatewayResponseBody>) -> Response {
    let (parts, body) = resp.into_parts();

    match body {
        HttpGatewayResponseBody::Bytes(v) => {
            Response::from_parts(parts, Body::new(Full::new(v.into()))).into_response()
        }

        HttpGatewayResponseBody::Stream(v) => {
            let v = v.map(|x| x.map(|y| Frame::data(Bytes::from(y))));
            let body = StreamBody::new(v);
            let body = Body::new(body);

            Response::from_parts(parts, body).into_response()
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
