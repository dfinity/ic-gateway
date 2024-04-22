pub mod middleware;

use std::{fmt, sync::Arc};

use axum::{
    middleware::from_fn,
    response::{IntoResponse, Response},
    Router,
};
use http::StatusCode;
use strum_macros::Display;
use tower::ServiceBuilder;
use tracing::warn;

use crate::{http::ConnInfo, routing::middleware::validate_request};

pub struct RequestCtx {
    authority: String,
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
    "Hello"
}

pub fn setup_router() -> Router {
    let common_layers = ServiceBuilder::new().layer(from_fn(validate_request));

    let router = axum::Router::new()
        .route("/", axum::routing::get(handler))
        .layer(common_layers);

    router
}
