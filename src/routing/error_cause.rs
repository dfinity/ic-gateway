use std::error::Error as StdError;

use crate::routing::RequestType;
use axum::response::{IntoResponse, Response};
use hickory_resolver::ResolveError;
use http::{StatusCode, header::CONTENT_TYPE};
use ic_agent::AgentError;
use ic_bn_lib::http::{Error as IcBnError, headers::CONTENT_TYPE_HTML};
use ic_http_gateway::HttpGatewayError;
use ic_transport_types::RejectCode;
use strum::{Display, IntoStaticStr};
use tokio::task_local;

use super::ic::BNResponseMetadata;

task_local! {
    pub static ERROR_CONTEXT: RequestType;
}

const ERROR_PAGE_TEMPLATE: &str = include_str!("error_pages/template.html");

// Process error chain trying to find given error type
pub fn error_infer<E: StdError + Send + Sync + 'static>(error: &anyhow::Error) -> Option<&E> {
    for cause in error.chain() {
        if let Some(e) = cause.downcast_ref() {
            return Some(e);
        }
    }
    None
}

#[derive(Debug, Clone, Display, IntoStaticStr, Eq, PartialEq)]
#[strum(serialize_all = "snake_case")]
pub enum RateLimitCause {
    Normal,
    BoundaryNode,
}

// Categorized possible causes for request processing failures
// Not using Error as inner type since it's not cloneable
#[derive(Debug, Clone, Display, IntoStaticStr, Eq, PartialEq)]
#[strum(serialize_all = "snake_case")]
pub enum ErrorCause {
    ClientBodyTooLarge,
    ClientBodyTimeout,
    ClientBodyError(String),
    LoadShed,
    IncorrectPrincipal,
    MalformedRequest(String),
    NoAuthority,
    UnknownDomain,
    CanisterNotFound,
    CanisterReject,
    CanisterError,
    CanisterFrozen,
    CanisterIdIncorrect(String),
    CanisterIdNotResolved,
    CanisterRouteNotFound,
    SubnetNotFound,
    SubnetUnavailable,
    NoRoutingTable,
    ResponseVerificationError,
    HttpGatewayError(String),
    DomainCanisterMismatch,
    Denylisted,
    Forbidden,
    BackendError(String),
    BackendErrorDNS(String),
    BackendErrorConnect,
    BackendTimeout,
    BackendBodyTimeout,
    BackendBodyError(String),
    BackendTLSErrorOther(String),
    BackendTLSErrorCert(String),
    #[strum(serialize = "rate_limited_{0}")]
    RateLimited(RateLimitCause),
    #[strum(serialize = "internal_server_error")]
    Other(String),
}

impl ErrorCause {
    pub fn details(&self) -> Option<String> {
        match self {
            Self::ClientBodyError(x) => Some(x.clone()),
            Self::MalformedRequest(x) => Some(x.clone()),
            Self::CanisterIdIncorrect(x) => Some(x.clone()),
            Self::BackendError(x) => Some(x.clone()),
            Self::BackendErrorDNS(x) => Some(x.clone()),
            Self::BackendBodyError(x) => Some(x.clone()),
            Self::BackendTLSErrorOther(x) => Some(x.clone()),
            Self::BackendTLSErrorCert(x) => Some(x.clone()),
            Self::RateLimited(x) => Some(x.to_string()),
            Self::HttpGatewayError(x) => Some(x.to_string()),
            Self::Other(x) => Some(x.clone()),
            _ => None,
        }
    }

    // Methods below are not implemented as From<> due to ambiguity

    // Convert from client-side error
    pub fn from_client_error(e: IcBnError) -> Self {
        match e {
            IcBnError::BodyReadingFailed(v) => Self::ClientBodyError(v),
            IcBnError::BodyTimedOut => Self::ClientBodyTimeout,
            IcBnError::BodyTooBig => Self::ClientBodyTooLarge,
            _ => Self::Other(e.to_string()),
        }
    }

    // Convert from backend error
    pub fn from_backend_error(e: IcBnError) -> Self {
        match e {
            IcBnError::RequestFailed(v) => Self::from(&v),
            IcBnError::BodyReadingFailed(v) => Self::BackendBodyError(v),
            IcBnError::BodyTimedOut => Self::BackendBodyTimeout,
            _ => Self::BackendError(e.to_string()),
        }
    }
}

// Creates the response from ErrorCause and injects itself into extensions to be visible by middleware
impl IntoResponse for ErrorCause {
    fn into_response(self) -> Response {
        let client_facing_error: ErrorClientFacing = (&self).into();
        let mut resp = client_facing_error.into_response();
        resp.extensions_mut().insert(self);
        resp
    }
}

// Creates the response from RateLimitCause and injects itself into extensions to be visible by middleware
impl IntoResponse for RateLimitCause {
    fn into_response(self) -> Response {
        ErrorCause::RateLimited(self).into_response()
    }
}

impl From<&reqwest::Error> for ErrorCause {
    fn from(e: &reqwest::Error) -> Self {
        if e.is_connect() {
            return Self::BackendErrorConnect;
        }

        if e.is_timeout() {
            return Self::BackendTimeout;
        }

        Self::BackendError(e.to_string())
    }
}

// TODO update in `ic-boundary` to "canister_route_not_found" and then remove CANISTER_NOT_FOUND
const CANISTER_NOT_FOUND: &str = "canister_not_found";
const CANISTER_ROUTE_NOT_FOUND: &str = "canister_route_not_found";
const SUBNET_NOT_FOUND: &str = "subnet_not_found";
const NO_HEALTHY_NODES: &str = "no_healthy_nodes";
const NO_ROUTING_TABLE: &str = "no_routing_table";
const FORBIDDEN: &str = "forbidden";
const LOAD_SHED: &str = "load_shed";

impl From<&BNResponseMetadata> for Option<ErrorCause> {
    fn from(v: &BNResponseMetadata) -> Self {
        if v.error_cause.is_empty() {
            return None;
        };

        if v.error_cause.starts_with("rate_limited") {
            return Some(ErrorCause::RateLimited(RateLimitCause::BoundaryNode));
        }

        Some(match v.error_cause.as_ref() {
            NO_HEALTHY_NODES => ErrorCause::SubnetUnavailable,
            CANISTER_NOT_FOUND | CANISTER_ROUTE_NOT_FOUND => ErrorCause::CanisterRouteNotFound,
            SUBNET_NOT_FOUND => ErrorCause::SubnetNotFound,
            FORBIDDEN => ErrorCause::Forbidden,
            LOAD_SHED => ErrorCause::LoadShed,
            NO_ROUTING_TABLE => ErrorCause::NoRoutingTable,
            _ => ErrorCause::Other(v.error_cause.clone()),
        })
    }
}

impl From<HttpGatewayError> for ErrorCause {
    fn from(v: HttpGatewayError) -> Self {
        match v {
            HttpGatewayError::ResponseVerificationError(_) => Self::ResponseVerificationError,
            HttpGatewayError::AgentError(ae) => match ae.as_ref() {
                AgentError::CertifiedReject { reject, .. }
                | AgentError::UncertifiedReject { reject, .. } => match reject.reject_code {
                    RejectCode::CanisterError => Self::CanisterError,
                    RejectCode::SysTransient if reject.reject_message.contains("frozen") => {
                        Self::CanisterFrozen
                    }
                    RejectCode::CanisterReject => Self::CanisterReject,
                    RejectCode::DestinationInvalid => Self::CanisterNotFound,
                    _ => Self::BackendError(ae.to_string()),
                },
                _ => Self::HttpGatewayError(ae.to_string()),
            },
            _ => Self::HttpGatewayError(v.to_string()),
        }
    }
}

impl From<anyhow::Error> for ErrorCause {
    fn from(e: anyhow::Error) -> Self {
        // Check if it's a DNS error
        if let Some(e) = error_infer::<ResolveError>(&e) {
            return Self::BackendErrorDNS(e.to_string());
        }

        // Check if it's a Rustls error
        if let Some(e) = error_infer::<rustls::Error>(&e) {
            return match e {
                rustls::Error::InvalidCertificate(v) => Self::BackendTLSErrorCert(format!("{v:?}")),
                rustls::Error::NoCertificatesPresented => {
                    Self::BackendTLSErrorCert("no certificate presented".into())
                }
                _ => Self::BackendTLSErrorOther(e.to_string()),
            };
        }

        // Check if it's a known Reqwest error
        if let Some(e) = error_infer::<reqwest::Error>(&e) {
            return Self::from(e);
        }

        if error_infer::<http_body_util::LengthLimitError>(&e).is_some() {
            return Self::ClientBodyTooLarge;
        }

        Self::Other(e.to_string())
    }
}

#[derive(Debug, Clone, Display, IntoStaticStr)]
#[strum(serialize_all = "snake_case")]
pub enum ErrorClientFacing {
    BodyTimedOut,
    CanisterNotFound,
    CanisterReject,
    CanisterError,
    CanisterFrozen,
    CanisterRouteNotFound,
    CanisterIdNotResolved,
    CanisterIdIncorrect(String),
    SubnetNotFound,
    SubnetUnavailable,
    ResponseVerificationError,
    Denylisted,
    Forbidden,
    DomainCanisterMismatch,
    IncorrectPrincipal,
    LoadShed,
    MalformedRequest(String),
    NoAuthority,
    #[strum(serialize = "internal_server_error")]
    Other,
    PayloadTooLarge,
    RateLimited,
    UnknownDomain,
    UpstreamError,
}

impl ErrorClientFacing {
    pub const fn status_code(&self) -> StatusCode {
        match self {
            Self::BodyTimedOut => StatusCode::REQUEST_TIMEOUT,
            Self::CanisterNotFound => StatusCode::NOT_FOUND,
            Self::CanisterReject => StatusCode::SERVICE_UNAVAILABLE,
            Self::CanisterError => StatusCode::SERVICE_UNAVAILABLE,
            Self::CanisterFrozen => StatusCode::SERVICE_UNAVAILABLE,
            Self::CanisterRouteNotFound => StatusCode::BAD_REQUEST,
            Self::CanisterIdNotResolved => StatusCode::BAD_REQUEST,
            Self::CanisterIdIncorrect(_) => StatusCode::BAD_REQUEST,
            Self::SubnetNotFound => StatusCode::BAD_REQUEST,
            Self::SubnetUnavailable => StatusCode::SERVICE_UNAVAILABLE,
            Self::ResponseVerificationError => StatusCode::SERVICE_UNAVAILABLE,
            Self::Denylisted => StatusCode::UNAVAILABLE_FOR_LEGAL_REASONS,
            Self::Forbidden => StatusCode::FORBIDDEN,
            Self::DomainCanisterMismatch => StatusCode::BAD_REQUEST,
            Self::IncorrectPrincipal => StatusCode::BAD_REQUEST,
            Self::LoadShed => StatusCode::TOO_MANY_REQUESTS,
            Self::MalformedRequest(_) => StatusCode::BAD_REQUEST,
            Self::NoAuthority => StatusCode::BAD_REQUEST,
            Self::Other => StatusCode::INTERNAL_SERVER_ERROR,
            Self::PayloadTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            Self::RateLimited => StatusCode::TOO_MANY_REQUESTS,
            Self::UnknownDomain => StatusCode::BAD_REQUEST,
            Self::UpstreamError => StatusCode::SERVICE_UNAVAILABLE,
        }
    }

    pub fn details(&self) -> String {
        match self {
            Self::BodyTimedOut => "Reading the request body timed out due to data arriving too slowly.".into(),
            Self::CanisterNotFound => "The requested canister does not exist.".into(),
            Self::CanisterReject => "The canister explicitly rejected the request.".into(),
            Self::CanisterError => "The canister encountered an error while processing the request.\nThis issue may be due to resource limitations, configuration problems, or an internal failure.".into(),
            Self::CanisterFrozen => "The canister is temporarily unable to process the request due to insufficient funds.".into(),
            Self::CanisterRouteNotFound => "The requested canister does not seem to belong so any Subnet.".into(),
            Self::CanisterIdNotResolved => "We weren't able to resolve the ID of the canister where to send the request.".into(),
            Self::CanisterIdIncorrect(x) => format!("The canister ID is incorrect: {x}"),
            Self::SubnetNotFound => "The requested subnet was not found.".into(),
            Self::SubnetUnavailable => "The subnet is temporarily unavailable due to maintenance or an ongoing upgrade. Please try again later.".into(),
            Self::ResponseVerificationError => "The response from the canister failed verification and cannot be trusted.\nIf you understand the risks, you can retry using the raw domain to bypass certification.".into(),
            Self::Denylisted => "Access to this resource is denied due to a violation of the code of conduct.".into(),
            Self::Forbidden => "Access to this resource is denied by the current set of application firewall rules.".into(),
            Self::DomainCanisterMismatch => "Access to the canister is forbidden through the current gateway domain. Try accessing it through an allowed gateway domain.".into(),
            Self::IncorrectPrincipal => "The principal in the request is incorrectly formatted.".into(),
            Self::LoadShed => "The HTTP gateway is temporarily unable to handle the request due to high load. Please try again later.".into(),
            Self::MalformedRequest(x) => x.into(),
            Self::NoAuthority => "The request is missing the required authority information (e.g. 'Host' header).".into(),
            Self::Other => "Internal Server Error".into(),
            Self::PayloadTooLarge => "The payload is too large.".into(),
            Self::RateLimited => "Rate limit exceeded. Please slow down requests and try again later.".into(),
            Self::UnknownDomain => "The requested domain is not served by this HTTP gateway.".into(),
            Self::UpstreamError => "The HTTP gateway is temporarily unable to process the request. Please try again later.".into(),
        }
    }

    pub fn html(&self) -> String {
        match self {
            Self::Denylisted => include_str!("error_pages/451.html").to_string(),
            _ => {
                let template = ERROR_PAGE_TEMPLATE;
                let template = template.replace("{status_code}", self.status_code().as_str());
                let template =
                    template.replace("{reason}", self.to_string().replace("_", " ").as_str());

                template.replace("{details}", &self.details().replace("\n", "<br />"))
            }
        }
    }
}

impl From<&ErrorCause> for ErrorClientFacing {
    fn from(v: &ErrorCause) -> Self {
        match v {
            ErrorCause::Other(_) => Self::Other,
            ErrorCause::ClientBodyTooLarge => Self::PayloadTooLarge,
            ErrorCause::ClientBodyTimeout => Self::BodyTimedOut,
            ErrorCause::ClientBodyError(x) => Self::MalformedRequest(x.clone()),
            ErrorCause::LoadShed => Self::LoadShed,
            ErrorCause::IncorrectPrincipal => Self::IncorrectPrincipal,
            ErrorCause::MalformedRequest(x) => Self::MalformedRequest(x.clone()),
            ErrorCause::UnknownDomain => Self::UnknownDomain,
            ErrorCause::CanisterNotFound => Self::CanisterNotFound,
            ErrorCause::CanisterReject => Self::CanisterReject,
            ErrorCause::CanisterError => Self::CanisterError,
            ErrorCause::CanisterFrozen => Self::CanisterFrozen,
            ErrorCause::CanisterRouteNotFound => Self::CanisterRouteNotFound,
            ErrorCause::CanisterIdIncorrect(x) => Self::CanisterIdIncorrect(x.clone()),
            ErrorCause::SubnetNotFound => Self::SubnetNotFound,
            ErrorCause::SubnetUnavailable => Self::SubnetUnavailable,
            ErrorCause::ResponseVerificationError => Self::ResponseVerificationError,
            ErrorCause::DomainCanisterMismatch => Self::DomainCanisterMismatch,
            ErrorCause::Denylisted => Self::Denylisted,
            ErrorCause::Forbidden => Self::Forbidden,
            ErrorCause::NoAuthority => Self::NoAuthority,
            ErrorCause::RateLimited(_) => Self::RateLimited,
            _ => Self::UpstreamError,
        }
    }
}

// Creates the response from ErrorClientFacing
impl IntoResponse for ErrorClientFacing {
    fn into_response(self) -> Response {
        let request_type = ERROR_CONTEXT.try_with(|x| *x).unwrap_or_default();

        // Return an HTML error page if it was an HTTP request
        let body = match request_type {
            RequestType::Http => format!("{}\n", self.html()),
            _ => format!("error: {}\ndetails: {}", self, self.details()),
        };

        let mut resp = (self.status_code(), body).into_response();
        if request_type == RequestType::Http {
            resp.headers_mut().insert(CONTENT_TYPE, CONTENT_TYPE_HTML);
        }
        resp
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use http::HeaderMap;
    use ic_agent::AgentError;
    use ic_bn_lib::{http::headers::X_IC_ERROR_CAUSE, hval};
    use ic_transport_types::RejectResponse;
    use std::sync::Arc;

    #[test]
    fn test_error_cause() {
        // Mapping of Rustls errors
        let err = anyhow::Error::new(rustls::Error::NoCertificatesPresented);
        assert!(matches!(
            ErrorCause::from(err),
            ErrorCause::BackendTLSErrorCert(_)
        ));

        let err = anyhow::Error::new(rustls::Error::InvalidCertificate(
            rustls::CertificateError::ApplicationVerificationFailure,
        ));
        assert!(matches!(
            ErrorCause::from(err),
            ErrorCause::BackendTLSErrorCert(_)
        ));

        let err = anyhow::Error::new(rustls::Error::BadMaxFragmentSize);
        assert!(matches!(
            ErrorCause::from(err),
            ErrorCause::BackendTLSErrorOther(_)
        ));

        // Mapping of "error_cause" BN headers
        let cases = [
            (NO_HEALTHY_NODES, ErrorCause::SubnetUnavailable),
            (NO_ROUTING_TABLE, ErrorCause::NoRoutingTable),
            (FORBIDDEN, ErrorCause::Forbidden),
            (LOAD_SHED, ErrorCause::LoadShed),
            (CANISTER_NOT_FOUND, ErrorCause::CanisterRouteNotFound),
            (CANISTER_ROUTE_NOT_FOUND, ErrorCause::CanisterRouteNotFound),
            (SUBNET_NOT_FOUND, ErrorCause::SubnetNotFound),
        ];
        for (hdr, err) in cases {
            let mut hm = HeaderMap::new();
            hm.insert(X_IC_ERROR_CAUSE, hval!(hdr));
            let meta = BNResponseMetadata::from(&mut hm);
            let error_cause = Option::<ErrorCause>::from(&meta);
            assert_eq!(error_cause, Some(err));
        }

        // Mapping of agent errors
        let cases = [
            (
                AgentError::CertifiedReject {
                    reject: RejectResponse {
                        reject_code: RejectCode::CanisterError,
                        reject_message: "".into(),
                        error_code: None,
                    },
                    operation: None,
                },
                ErrorCause::CanisterError,
            ),
            (
                AgentError::CertifiedReject {
                    reject: RejectResponse {
                        reject_code: RejectCode::CanisterReject,
                        reject_message: "".into(),
                        error_code: None,
                    },
                    operation: None,
                },
                ErrorCause::CanisterReject,
            ),
            (
                AgentError::CertifiedReject {
                    reject: RejectResponse {
                        reject_code: RejectCode::DestinationInvalid,
                        reject_message: "".into(),
                        error_code: None,
                    },
                    operation: None,
                },
                ErrorCause::CanisterNotFound,
            ),
            (
                AgentError::CertifiedReject {
                    reject: RejectResponse {
                        reject_code: RejectCode::SysTransient,
                        reject_message: "foo frozen foo".into(),
                        error_code: None,
                    },
                    operation: None,
                },
                ErrorCause::CanisterFrozen,
            ),
        ];
        for (ae, err) in cases {
            let http_gw_error = HttpGatewayError::AgentError(Arc::new(ae));
            assert_eq!(ErrorCause::from(http_gw_error), err);
        }

        let ae = AgentError::CertifiedReject {
            reject: RejectResponse {
                reject_code: RejectCode::SysFatal,
                reject_message: "".into(),
                error_code: None,
            },
            operation: None,
        };
        let http_gw_error = HttpGatewayError::AgentError(Arc::new(ae));
        assert!(matches!(
            ErrorCause::from(http_gw_error),
            ErrorCause::BackendError(_)
        ))
    }
}
