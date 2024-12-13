use std::error::Error as StdError;

use crate::routing::RequestType;
use axum::response::{IntoResponse, Response};
use hickory_resolver::error::ResolveError;
use http::{header::CONTENT_TYPE, StatusCode};
use ic_agent::AgentError;
use ic_bn_lib::http::{headers::CONTENT_TYPE_HTML, Error as IcBnError};
use ic_http_gateway::HttpGatewayError;
use strum::{Display, IntoStaticStr};
use tokio::task_local;

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

#[derive(Debug, Clone, Display, IntoStaticStr)]
#[strum(serialize_all = "snake_case")]
pub enum RateLimitCause {
    Normal,
}

// Categorized possible causes for request processing failures
// Not using Error as inner type since it's not cloneable
#[derive(Debug, Clone, Display, IntoStaticStr)]
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
    CanisterIdNotFound,
    DomainCanisterMismatch,
    Denylisted,
    AgentError(String),
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
    HttpGatewayError(HttpGatewayError),
}

impl ErrorCause {
    pub fn details(&self) -> Option<String> {
        match self {
            Self::Other(x) => Some(x.clone()),
            Self::ClientBodyError(x) => Some(x.clone()),
            Self::LoadShed => Some("Overloaded".into()),
            Self::MalformedRequest(x) => Some(x.clone()),
            Self::BackendError(x) => Some(x.clone()),
            Self::BackendErrorDNS(x) => Some(x.clone()),
            Self::BackendBodyError(x) => Some(x.clone()),
            Self::BackendTLSErrorOther(x) => Some(x.clone()),
            Self::BackendTLSErrorCert(x) => Some(x.clone()),
            Self::AgentError(x) => Some(x.clone()),
            Self::RateLimited(x) => Some(x.to_string()),
            Self::HttpGatewayError(x) => Some(x.to_string()),
            _ => None,
        }
    }

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
            _ => Self::Other(e.to_string()),
        }
    }

    pub fn to_client_facing_error(&self) -> ErrorClientFacing {
        match self {
            Self::Other(_) => ErrorClientFacing::Other,
            Self::ClientBodyTooLarge => ErrorClientFacing::PayloadTooLarge,
            Self::ClientBodyTimeout => ErrorClientFacing::BodyTimedOut,
            Self::ClientBodyError(x) => ErrorClientFacing::MalformedRequest(x.clone()),
            Self::LoadShed => ErrorClientFacing::LoadShed,
            Self::IncorrectPrincipal => ErrorClientFacing::IncorrectPrincipal,
            Self::MalformedRequest(x) => ErrorClientFacing::MalformedRequest(x.clone()),
            Self::UnknownDomain => ErrorClientFacing::UnknownDomain,
            Self::CanisterIdNotFound => ErrorClientFacing::CanisterIdNotFound,
            Self::DomainCanisterMismatch => ErrorClientFacing::DomainCanisterMismatch,
            Self::Denylisted => ErrorClientFacing::Denylisted,
            Self::NoAuthority => ErrorClientFacing::NoAuthority,
            Self::AgentError(_) => ErrorClientFacing::UpstreamError,
            Self::BackendError(_) => ErrorClientFacing::UpstreamError,
            Self::BackendErrorDNS(_) => ErrorClientFacing::UpstreamError,
            Self::BackendErrorConnect => ErrorClientFacing::UpstreamError,
            Self::BackendTimeout => ErrorClientFacing::UpstreamError,
            Self::BackendBodyTimeout => ErrorClientFacing::UpstreamError,
            Self::BackendBodyError(_) => ErrorClientFacing::UpstreamError,
            Self::BackendTLSErrorOther(_) => ErrorClientFacing::UpstreamError,
            Self::BackendTLSErrorCert(_) => ErrorClientFacing::UpstreamError,
            Self::RateLimited(_) => ErrorClientFacing::RateLimited,
            Self::HttpGatewayError(x) => match x {
                HttpGatewayError::AgentError(y) => {
                    let error_string = y.to_string();
                    if error_string.contains("no_healthy_nodes") {
                        return ErrorClientFacing::SubnetUnavailable;
                    } else if error_string.contains("canister_not_found") {
                        return ErrorClientFacing::CanisterIdNotFound;
                    }
                    ErrorClientFacing::UpstreamError
                }
                HttpGatewayError::HttpError(y) => {
                    if y.contains("no_healthy_nodes") {
                        return ErrorClientFacing::SubnetUnavailable;
                    } else if y.contains("canister_not_found") {
                        return ErrorClientFacing::CanisterIdNotFound;
                    }
                    ErrorClientFacing::UpstreamError
                }
                _ => ErrorClientFacing::UpstreamError,
            },
        }
    }
}

// Creates the response from ErrorCause and injects itself into extensions to be visible by middleware
impl IntoResponse for ErrorCause {
    fn into_response(self) -> Response {
        let client_facing_error = self.to_client_facing_error();
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

impl From<anyhow::Error> for ErrorCause {
    fn from(e: anyhow::Error) -> Self {
        if let Some(e) = error_infer::<AgentError>(&e) {
            return Self::AgentError(e.to_string());
        }

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
    CanisterIdNotFound,
    Denylisted,
    DomainCanisterMismatch,
    IncorrectPrincipal,
    LoadShed,
    MalformedRequest(String),
    NoAuthority,
    #[strum(serialize = "internal_server_error")]
    Other,
    PayloadTooLarge,
    RateLimited,
    SubnetUnavailable,
    UnknownDomain,
    UpstreamError,
}

impl ErrorClientFacing {
    pub const fn status_code(&self) -> StatusCode {
        match self {
            Self::BodyTimedOut => StatusCode::REQUEST_TIMEOUT,
            Self::CanisterIdNotFound => StatusCode::BAD_REQUEST,
            Self::Denylisted => StatusCode::UNAVAILABLE_FOR_LEGAL_REASONS,
            Self::DomainCanisterMismatch => StatusCode::BAD_REQUEST,
            Self::IncorrectPrincipal => StatusCode::BAD_REQUEST,
            Self::LoadShed => StatusCode::TOO_MANY_REQUESTS,
            Self::MalformedRequest(_) => StatusCode::BAD_REQUEST,
            Self::NoAuthority => StatusCode::BAD_REQUEST,
            Self::Other => StatusCode::INTERNAL_SERVER_ERROR,
            Self::PayloadTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            Self::RateLimited => StatusCode::TOO_MANY_REQUESTS,
            Self::SubnetUnavailable => StatusCode::SERVICE_UNAVAILABLE,
            Self::UnknownDomain => StatusCode::BAD_REQUEST,
            Self::UpstreamError => StatusCode::SERVICE_UNAVAILABLE,
        }
    }

    pub fn details(&self) -> String {
        match self {
            Self::BodyTimedOut => "Reading the request body timed out due to data arriving too slowly.".to_string(),
            Self::CanisterIdNotFound => "The canister ID could not be resolved from the provided authority.".to_string(),
            Self::Denylisted => "Access to this resource is denied due to a violation of the code of conduct.".to_string(),
            Self::DomainCanisterMismatch => "Access to the canister is forbidden through the current gateway domain. Try accessing it through an allowed gateway domain.".to_string(),
            Self::IncorrectPrincipal => "The principal in the request is incorrectly formatted.".to_string(),
            Self::LoadShed => "The HTTP gateway is temporarily unable to handle the request due to high load. Please try again later.".to_string(),
            Self::MalformedRequest(x) => x.to_string(),
            Self::NoAuthority => "The request is missing the required authority information (e.g., Host header).".to_string(),
            Self::Other => "Internal Server Error".to_string(),
            Self::PayloadTooLarge => "The payload is too large.".to_string(),
            Self::RateLimited => "Rate limit exceeded. Please slow down requests and try again later.".to_string(),
            Self::SubnetUnavailable => "The subnet is temporarily unavailable. This may be due to an ongoing upgrade of the replica software. Please try again later.".to_string(),
            Self::UnknownDomain => "The requested domain is not served by this HTTP gateway.".to_string(),
            Self::UpstreamError => "The HTTP gateway is temporarily unable to process the request. Please try again later.".to_string(),
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
                let template = template.replace("{details}", self.details().as_str());
                template
            }
        }
    }
}

// Creates the response from ErrorClientFacing
impl IntoResponse for ErrorClientFacing {
    fn into_response(self) -> Response {
        let error_context = ERROR_CONTEXT.get();

        // Return an HTML error page if it was an HTTP request
        let body = match error_context {
            RequestType::Http => format!("{}\n", self.html()),
            _ => format!("error: {}\ndetails: {}", self.to_string(), self.details()),
        };

        let mut resp = (self.status_code(), body).into_response();
        if error_context == RequestType::Http {
            resp.headers_mut().insert(CONTENT_TYPE, CONTENT_TYPE_HTML);
        }
        resp
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use ic_agent::{agent_error::HttpErrorPayload, AgentError};
    use std::sync::Arc;

    #[test]
    fn test_error_cause() {
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

        // test that no_healthy_nodes from upstream is mapped to ErrorClientFacing::NoHealthyNodes
        let err_payload = HttpErrorPayload {
            status: 503,
            content_type: Some("text/plain".to_string()),
            content: "error: no_healthy_nodes\ndetails: There are currently no healthy replica nodes available to handle the request. This may be due to an ongoing upgrade of the replica software in the subnet. Please try again later.".as_bytes().to_vec(),
        };
        let err: HttpGatewayError =
            HttpGatewayError::AgentError(Arc::new(AgentError::HttpError(err_payload)));
        let err_cause = ErrorCause::HttpGatewayError(err);
        let err_client_facing = err_cause.to_client_facing_error();
        assert!(matches!(
            err_client_facing,
            ErrorClientFacing::SubnetUnavailable
        ));

        // test that canister_not_found from upstream is mapped to ErrorClientFacing::CanisterIdNotFound
        let err_payload = HttpErrorPayload {
            status: 400,
            content_type: Some("text/plain".to_string()),
            content: "error: canister_not_found\ndetails: The specified canister does not exist."
                .as_bytes()
                .to_vec(),
        };
        let err: HttpGatewayError =
            HttpGatewayError::AgentError(Arc::new(AgentError::HttpError(err_payload)));
        let err_cause = ErrorCause::HttpGatewayError(err);
        let err_client_facing = err_cause.to_client_facing_error();
        assert!(matches!(
            err_client_facing,
            ErrorClientFacing::CanisterIdNotFound
        ));

        // test that canister_not_found from upstream is mapped to ErrorClientFacing::CanisterIdNotFound
        let err: HttpGatewayError = HttpGatewayError::HeaderValueParsingError {
            header_name: "Test".to_string(),
            header_value: "Test".to_string(),
        };
        let err_cause = ErrorCause::HttpGatewayError(err);
        let err_client_facing = err_cause.to_client_facing_error();
        assert!(matches!(
            err_client_facing,
            ErrorClientFacing::UpstreamError
        ));
    }
}
