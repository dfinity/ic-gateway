pub mod canister;
pub mod middleware;

use std::{fmt, sync::Arc};

use anyhow::Error;
use axum::{
    middleware::{from_fn, from_fn_with_state, FromFnLayer},
    response::{IntoResponse, Response},
    Router,
};
use axum_extra::middleware::option_layer;
use fqdn::FQDN;
use http::StatusCode;
use prometheus::Registry;
use strum_macros::Display;
use tower::ServiceBuilder;
use tracing::warn;

use crate::{
    cli::Cli,
    core::Run,
    http::{Client, ConnInfo},
    metrics,
    routing::middleware::{geoip, policy, request_id, validate},
};

use self::canister::{Canister, ResolvesCanister};

pub struct RequestCtx {
    // HTTP2 authority or HTTP1 Host header
    authority: FQDN,
    canister: Canister,
}

#[derive(Debug, Clone, Display)]
#[strum(serialize_all = "snake_case")]
pub enum RateLimitCause {
    Normal,
    LedgerTransfer,
}

// Categorized possible causes for request processing failures
// Not using Error as inner type since it's not cloneable
#[derive(Debug, Clone)]
pub enum ErrorCause {
    UnableToReadBody(String),
    PayloadTooLarge(usize),
    UnableToParseCBOR(String),
    UnableToParseHTTPArg(String),
    LoadShed,
    MalformedRequest(String),
    MalformedResponse(String),
    NoAuthority,
    CanisterIdNotFound,
    SNIMismatch,
    DomainCanisterMismatch,
    Denylisted,
    NoRoutingTable,
    SubnetNotFound,
    NoHealthyNodes,
    ReplicaErrorDNS(String),
    ReplicaErrorConnect,
    ReplicaTimeout,
    ReplicaTLSErrorOther(String),
    ReplicaTLSErrorCert(String),
    ReplicaErrorOther(String),
    RateLimited(RateLimitCause),
    Other(String),
}

impl ErrorCause {
    pub fn status_code(&self) -> StatusCode {
        match self {
            Self::Other(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Self::PayloadTooLarge(_) => StatusCode::PAYLOAD_TOO_LARGE,
            Self::UnableToReadBody(_) => StatusCode::REQUEST_TIMEOUT,
            Self::UnableToParseCBOR(_) => StatusCode::BAD_REQUEST,
            Self::UnableToParseHTTPArg(_) => StatusCode::BAD_REQUEST,
            Self::LoadShed => StatusCode::TOO_MANY_REQUESTS,
            Self::MalformedRequest(_) => StatusCode::BAD_REQUEST,
            Self::MalformedResponse(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Self::NoAuthority => StatusCode::BAD_REQUEST,
            Self::CanisterIdNotFound => StatusCode::BAD_REQUEST,
            Self::SNIMismatch => StatusCode::BAD_REQUEST,
            Self::DomainCanisterMismatch => StatusCode::FORBIDDEN,
            Self::Denylisted => StatusCode::UNAVAILABLE_FOR_LEGAL_REASONS,
            Self::NoRoutingTable => StatusCode::SERVICE_UNAVAILABLE,
            Self::SubnetNotFound => StatusCode::BAD_REQUEST, // TODO change to 404?
            Self::NoHealthyNodes => StatusCode::SERVICE_UNAVAILABLE,
            Self::ReplicaErrorDNS(_) => StatusCode::SERVICE_UNAVAILABLE,
            Self::ReplicaErrorConnect => StatusCode::SERVICE_UNAVAILABLE,
            Self::ReplicaTimeout => StatusCode::INTERNAL_SERVER_ERROR,
            Self::ReplicaTLSErrorOther(_) => StatusCode::SERVICE_UNAVAILABLE,
            Self::ReplicaTLSErrorCert(_) => StatusCode::SERVICE_UNAVAILABLE,
            Self::ReplicaErrorOther(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Self::RateLimited(_) => StatusCode::TOO_MANY_REQUESTS,
        }
    }

    pub fn details(&self) -> Option<String> {
        match self {
            Self::Other(x) => Some(x.clone()),
            Self::PayloadTooLarge(x) => Some(format!("maximum body size is {x} bytes")),
            Self::UnableToReadBody(x) => Some(x.clone()),
            Self::UnableToParseCBOR(x) => Some(x.clone()),
            Self::UnableToParseHTTPArg(x) => Some(x.clone()),
            Self::LoadShed => Some("Overloaded".into()),
            Self::MalformedRequest(x) => Some(x.clone()),
            Self::MalformedResponse(x) => Some(x.clone()),
            Self::ReplicaErrorDNS(x) => Some(x.clone()),
            Self::ReplicaTLSErrorOther(x) => Some(x.clone()),
            Self::ReplicaTLSErrorCert(x) => Some(x.clone()),
            Self::ReplicaErrorOther(x) => Some(x.clone()),
            _ => None,
        }
    }

    pub const fn retriable(&self) -> bool {
        matches!(
            self,
            Self::ReplicaErrorDNS(_)
                | Self::ReplicaErrorConnect
                | Self::ReplicaTLSErrorOther(_)
                | Self::ReplicaTLSErrorCert(_)
        )
    }
}

impl fmt::Display for ErrorCause {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Other(_) => write!(f, "general_error"),
            Self::UnableToReadBody(_) => write!(f, "unable_to_read_body"),
            Self::PayloadTooLarge(_) => write!(f, "payload_too_large"),
            Self::UnableToParseCBOR(_) => write!(f, "unable_to_parse_cbor"),
            Self::UnableToParseHTTPArg(_) => write!(f, "unable_to_parse_http_arg"),
            Self::LoadShed => write!(f, "load_shed"),
            Self::MalformedRequest(_) => write!(f, "malformed_request"),
            Self::MalformedResponse(_) => write!(f, "malformed_response"),
            Self::CanisterIdNotFound => write!(f, "canister_id_not_found"),
            Self::SNIMismatch => write!(f, "sni_mismatch"),
            Self::DomainCanisterMismatch => write!(f, "domain_canister_mismatch"),
            Self::Denylisted => write!(f, "denylisted"),
            Self::NoAuthority => write!(f, "no_authority"),
            Self::NoRoutingTable => write!(f, "no_routing_table"),
            Self::SubnetNotFound => write!(f, "subnet_not_found"),
            Self::NoHealthyNodes => write!(f, "no_healthy_nodes"),
            Self::ReplicaErrorDNS(_) => write!(f, "replica_error_dns"),
            Self::ReplicaErrorConnect => write!(f, "replica_error_connect"),
            Self::ReplicaTimeout => write!(f, "replica_timeout"),
            Self::ReplicaTLSErrorOther(_) => write!(f, "replica_tls_error"),
            Self::ReplicaTLSErrorCert(_) => write!(f, "replica_tls_error_cert"),
            Self::ReplicaErrorOther(_) => write!(f, "replica_error_other"),
            Self::RateLimited(x) => write!(f, "rate_limited_{x}"),
        }
    }
}

// Creates the response from ErrorCause and injects itself into extensions to be visible by middleware
impl IntoResponse for ErrorCause {
    fn into_response(self) -> Response {
        let mut body = self.to_string();

        if let Some(v) = self.details() {
            body = format!("{body}: {v}");
        }

        let mut resp = (self.status_code(), format!("{body}\n")).into_response();
        resp.extensions_mut().insert(self);
        resp
    }
}

async fn handler(request: axum::extract::Request) -> impl IntoResponse {
    warn!("{:?}", request.extensions().get::<Arc<ConnInfo>>());
    warn!("{:?}", request.extensions().get::<geoip::CountryCode>());
    "Hello"
}

pub fn setup_router(
    cli: &Cli,
    http_client: Arc<dyn Client>,
    registry: &Registry,
    canister_resolver: Arc<dyn ResolvesCanister>,
) -> Result<(Router, Option<Arc<dyn Run>>), Error> {
    // GeoIP
    let geoip_mw = cli
        .misc
        .geoip_db
        .as_ref()
        .map(|x| -> Result<FromFnLayer<_, _, _>, Error> {
            let geoip_db = geoip::GeoIp::new(x)?;
            Ok(from_fn_with_state(Arc::new(geoip_db), geoip::middleware))
        })
        .transpose()?;

    // Policy
    let (policy_state, denylist_runner) = policy::PolicyState::new(cli, http_client, registry)?;

    // Metrics
    let metrics_mw = from_fn_with_state(
        metrics::HttpMetricParams::new(registry),
        metrics::middleware,
    );

    // Common layers
    let common_layers = ServiceBuilder::new()
        .layer(from_fn(request_id::middleware))
        .layer(metrics_mw)
        .layer(option_layer(geoip_mw))
        .layer(from_fn_with_state(canister_resolver, validate::middleware))
        .layer(from_fn_with_state(
            Arc::new(policy_state),
            policy::middleware,
        ));

    let router = axum::Router::new()
        .route("/", axum::routing::get(handler))
        .layer(common_layers);

    Ok((router, denylist_runner))
}
