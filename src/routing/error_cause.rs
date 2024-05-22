use std::fmt;

use axum::response::{IntoResponse, Response};
use hickory_resolver::error::ResolveError;
use http::StatusCode;
use strum_macros::Display;

// Process error chain trying to find given error type
pub fn error_infer<E: std::error::Error + 'static>(error: &anyhow::Error) -> Option<&E> {
    for cause in error.chain() {
        if let Some(e) = cause.downcast_ref() {
            return Some(e);
        }
    }
    None
}

#[derive(Debug, Clone, Display)]
#[strum(serialize_all = "snake_case")]
pub enum RateLimitCause {
    Normal,
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
    BackendErrorDNS(String),
    BackendErrorConnect,
    BackendTimeout,
    BackendTLSErrorOther(String),
    BackendTLSErrorCert(String),
    BackendErrorOther(String),
    RateLimited(RateLimitCause),
    Other(String),
}

impl ErrorCause {
    pub const fn status_code(&self) -> StatusCode {
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
            Self::BackendErrorDNS(_) => StatusCode::SERVICE_UNAVAILABLE,
            Self::BackendErrorConnect => StatusCode::SERVICE_UNAVAILABLE,
            Self::BackendTimeout => StatusCode::INTERNAL_SERVER_ERROR,
            Self::BackendTLSErrorOther(_) => StatusCode::SERVICE_UNAVAILABLE,
            Self::BackendTLSErrorCert(_) => StatusCode::SERVICE_UNAVAILABLE,
            Self::BackendErrorOther(_) => StatusCode::INTERNAL_SERVER_ERROR,
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
            Self::BackendErrorDNS(x) => Some(x.clone()),
            Self::BackendTLSErrorOther(x) => Some(x.clone()),
            Self::BackendTLSErrorCert(x) => Some(x.clone()),
            Self::BackendErrorOther(x) => Some(x.clone()),
            _ => None,
        }
    }

    pub const fn retriable(&self) -> bool {
        matches!(
            self,
            Self::BackendErrorDNS(_)
                | Self::BackendErrorConnect
                | Self::BackendTLSErrorOther(_)
                | Self::BackendTLSErrorCert(_)
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
            Self::BackendErrorDNS(_) => write!(f, "backend_error_dns"),
            Self::BackendErrorConnect => write!(f, "backend_error_connect"),
            Self::BackendTimeout => write!(f, "backend_timeout"),
            Self::BackendTLSErrorOther(_) => write!(f, "backend_tls_error"),
            Self::BackendTLSErrorCert(_) => write!(f, "backend_tls_error_cert"),
            Self::BackendErrorOther(_) => write!(f, "backend_error_other"),
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

impl From<anyhow::Error> for ErrorCause {
    fn from(e: anyhow::Error) -> Self {
        // Check if it's a DNS error
        if let Some(e) = error_infer::<ResolveError>(&e) {
            return Self::BackendErrorDNS(e.to_string());
        }

        // Check if it's a Rustls error
        if let Some(e) = error_infer::<rustls::Error>(&e) {
            return match e {
                rustls::Error::InvalidCertificate(v) => {
                    Self::BackendTLSErrorCert(format!("{:?}", v))
                }
                rustls::Error::NoCertificatesPresented => {
                    Self::BackendTLSErrorCert("no certificate presented".into())
                }
                _ => Self::BackendTLSErrorOther(e.to_string()),
            };
        }

        // Check if it's a known Reqwest error
        if let Some(e) = error_infer::<reqwest::Error>(&e) {
            if e.is_connect() {
                return Self::BackendErrorConnect;
            }

            if e.is_timeout() {
                return Self::BackendTimeout;
            }
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
