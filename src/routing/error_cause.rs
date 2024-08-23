use std::{
    error::Error as StdError,
    fmt::{self},
};

use axum::response::{IntoResponse, Response};
use hickory_resolver::error::ResolveError;
use http::{header::CONTENT_TYPE, StatusCode};
use ic_agent::AgentError;
use ic_bn_lib::http::{headers::CONTENT_TYPE_HTML, Error as IcBnError};
use strum_macros::{Display, IntoStaticStr};

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
#[derive(Debug, Clone)]
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
    RateLimited(RateLimitCause),
    Other(String),
}

impl ErrorCause {
    pub const fn status_code(&self) -> StatusCode {
        match self {
            Self::Other(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Self::ClientBodyTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            Self::ClientBodyTimeout => StatusCode::REQUEST_TIMEOUT,
            Self::ClientBodyError(_) => StatusCode::BAD_REQUEST,
            Self::LoadShed => StatusCode::TOO_MANY_REQUESTS,
            Self::IncorrectPrincipal => StatusCode::BAD_REQUEST,
            Self::MalformedRequest(_) => StatusCode::BAD_REQUEST,
            Self::NoAuthority => StatusCode::BAD_REQUEST,
            Self::UnknownDomain => StatusCode::BAD_REQUEST,
            Self::CanisterIdNotFound => StatusCode::BAD_REQUEST,
            Self::AgentError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Self::DomainCanisterMismatch => StatusCode::FORBIDDEN,
            Self::Denylisted => StatusCode::UNAVAILABLE_FOR_LEGAL_REASONS,
            Self::BackendError(_) => StatusCode::SERVICE_UNAVAILABLE,
            Self::BackendErrorDNS(_) => StatusCode::SERVICE_UNAVAILABLE,
            Self::BackendErrorConnect => StatusCode::SERVICE_UNAVAILABLE,
            Self::BackendTimeout => StatusCode::INTERNAL_SERVER_ERROR,
            Self::BackendBodyTimeout => StatusCode::INTERNAL_SERVER_ERROR,
            Self::BackendBodyError(_) => StatusCode::SERVICE_UNAVAILABLE,
            Self::BackendTLSErrorOther(_) => StatusCode::SERVICE_UNAVAILABLE,
            Self::BackendTLSErrorCert(_) => StatusCode::SERVICE_UNAVAILABLE,
            Self::RateLimited(_) => StatusCode::TOO_MANY_REQUESTS,
        }
    }

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
            _ => None,
        }
    }

    pub const fn html(&self) -> Option<&str> {
        match self {
            Self::Denylisted => Some(include_str!("error_pages/451.html")),
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
}

impl fmt::Display for ErrorCause {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Other(_) => write!(f, "general_error"),
            Self::ClientBodyTooLarge => write!(f, "client_body_too_large"),
            Self::ClientBodyTimeout => write!(f, "client_body_timeout"),
            Self::ClientBodyError(_) => write!(f, "client_body_error"),
            Self::LoadShed => write!(f, "load_shed"),
            Self::IncorrectPrincipal => write!(f, "incorrect_principal"),
            Self::MalformedRequest(_) => write!(f, "malformed_request"),
            Self::UnknownDomain => write!(f, "unknown_domain"),
            Self::CanisterIdNotFound => write!(f, "canister_id_not_found"),
            Self::DomainCanisterMismatch => write!(f, "domain_canister_mismatch"),
            Self::Denylisted => write!(f, "denylisted"),
            Self::NoAuthority => write!(f, "no_authority"),
            Self::AgentError(_) => write!(f, "agent_error"),
            Self::BackendError(_) => write!(f, "backend_error"),
            Self::BackendErrorDNS(_) => write!(f, "backend_error_dns"),
            Self::BackendErrorConnect => write!(f, "backend_error_connect"),
            Self::BackendTimeout => write!(f, "backend_timeout"),
            Self::BackendBodyTimeout => write!(f, "backend_body_timeout"),
            Self::BackendBodyError(_) => write!(f, "backend_body_error"),
            Self::BackendTLSErrorOther(_) => write!(f, "backend_tls_error"),
            Self::BackendTLSErrorCert(_) => write!(f, "backend_tls_error_cert"),
            Self::RateLimited(x) => write!(f, "rate_limited_{x}"),
        }
    }
}

// Creates the response from ErrorCause and injects itself into extensions to be visible by middleware
impl IntoResponse for ErrorCause {
    fn into_response(self) -> Response {
        // Return the HTML reply if it exists, otherwise textual
        let body = self.html().map_or_else(
            || {
                self.details()
                    .map_or_else(|| self.to_string(), |x| format!("{self}: {x}\n"))
            },
            |x| format!("{x}\n"),
        );

        let mut resp = (self.status_code(), body).into_response();
        if self.html().is_some() {
            resp.headers_mut().insert(CONTENT_TYPE, CONTENT_TYPE_HTML);
        }

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

#[cfg(test)]
mod test {
    use super::*;

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
    }
}
