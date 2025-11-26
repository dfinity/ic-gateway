use std::{cell::RefCell, error::Error as StdError};

use crate::routing::RequestType;
use axum::response::{IntoResponse, Response};
use candid::Principal;
use fqdn::FQDN;
use hickory_resolver::ResolveError;
use http::{HeaderValue, StatusCode, header::CONTENT_TYPE};
use ic_bn_lib::{
    http::headers::{CONTENT_TYPE_HTML, X_IC_ERROR_CAUSE},
    ic_agent::AgentError,
};
use ic_bn_lib_common::types::http::Error as HttpError;
use ic_http_gateway::HttpGatewayError;
use ic_transport_types::RejectCode;
use serde_json::{json, to_string_pretty};
use strum::{Display, IntoStaticStr};
use tokio::task_local;

use super::ic::BNResponseMetadata;

#[derive(Default, Clone)]
pub struct ErrorContext {
    pub request_type: RequestType,
    pub is_browser: bool,
    pub authority: Option<FQDN>,
    pub alternate_error_domain: Option<FQDN>,
}

task_local! {
    pub static ERROR_CONTEXT: RefCell<ErrorContext>;
}

const ERROR_PAGE_TEMPLATE: &str = include_str!("error_pages/template.html");
const CANISTER_SECTION_TEMPLATE: &str =
    include_str!("error_pages/components/canister_section.html");
const RETRY_SECTION_TEMPLATE: &str = include_str!("error_pages/components/retry_section.html");
const RETRY_LOGIC: &str = include_str!("error_pages/components/retry_logic.js");
const APPEAL_SECTION: &str = include_str!("error_pages/components/appeal_section.html");

const ALTERNATE_ERROR: &str = include_str!("error_pages/caffeine_error.html");
const ALTERNATE_ERROR_UNKNOWN_DOMAIN: &str =
    include_str!("error_pages/caffeine_error_unknown_domain.html");

const CANISTER_ERROR_SVG: &str = include_str!("error_pages/assets/canister-error.svg");
const CANISTER_WARNING_SVG: &str = include_str!("error_pages/assets/canister-warning.svg");
const GENERAL_ERROR_SVG: &str = include_str!("error_pages/assets/general-error.svg");
const SUBNET_SVG: &str = include_str!("error_pages/assets/subnet.svg");

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

// Creates the response from RateLimitCause and injects itself into extensions to be visible by middleware
impl IntoResponse for RateLimitCause {
    fn into_response(self) -> Response {
        ErrorCause::RateLimited(self).into_response()
    }
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
    UnknownDomain(FQDN),
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
    DomainCanisterMismatch(Principal),
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
    BoundaryNodeError(String),
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
            Self::BoundaryNodeError(x) => Some(x.clone()),
            Self::RateLimited(x) => Some(x.to_string()),
            Self::HttpGatewayError(x) => Some(x.to_string()),
            Self::Other(x) => Some(x.clone()),
            _ => None,
        }
    }

    // Methods below are not implemented as From<> due to ambiguity

    // Convert from client-side error
    pub fn from_client_error(e: HttpError) -> Self {
        match e {
            HttpError::BodyReadingFailed(v) => Self::ClientBodyError(v),
            HttpError::BodyTimedOut => Self::ClientBodyTimeout,
            HttpError::BodyTooBig => Self::ClientBodyTooLarge,
            _ => Self::Other(e.to_string()),
        }
    }

    // Convert from backend error
    pub fn from_backend_error(e: HttpError) -> Self {
        match e {
            HttpError::RequestFailed(v) => Self::from(&v),
            HttpError::BodyReadingFailed(v) => Self::BackendBodyError(v),
            HttpError::BodyTimedOut => Self::BackendBodyTimeout,
            _ => Self::BackendError(e.to_string()),
        }
    }
}

// Creates the response from ErrorCause and injects itself into extensions to be visible by middleware
impl IntoResponse for ErrorCause {
    #[cfg(not(feature = "debug"))]
    fn into_response(self) -> Response {
        let client_facing_error: ErrorClientFacing = (&self).into();
        let mut resp = client_facing_error.into_response();
        resp.extensions_mut().insert(self);
        resp
    }

    #[cfg(feature = "debug")]
    fn into_response(self) -> Response {
        let client_facing_error: ErrorClientFacing = (&self).into();
        let error_data = client_facing_error.data();

        let body = format!("error: {}\ndetails:\n{}", self, error_data.description);

        let mut resp = (error_data.status_code, body).into_response();
        resp.extensions_mut().insert(self);
        resp
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
        if let Some(x) = v.status
            && x.is_success()
        {
            return None;
        }

        if ["", "none"].contains(&v.error_cause.as_str()) {
            return None;
        }

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
            _ => ErrorCause::BoundaryNodeError(v.error_cause.clone()),
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
    CanisterIdNotResolved,
    CanisterIdIncorrect,
    SubnetNotFound,
    #[strum(serialize = "subnet_updating")]
    SubnetUnavailable,
    ResponseVerificationError,
    Denylisted,
    Forbidden,
    DomainCanisterMismatch(Principal),
    IncorrectPrincipal,
    LoadShed,
    MalformedRequest(String),
    NoAuthority,
    #[strum(serialize = "internal_server_error")]
    Other,
    PayloadTooLarge,
    RateLimited,
    UnknownDomain(FQDN),
    UpstreamError,
}

impl ErrorClientFacing {
    fn data(&self) -> ErrorData {
        match self {
            Self::BodyTimedOut => ErrorData {
                status_code: StatusCode::REQUEST_TIMEOUT,
                title: "Request Timed Out".into(),
                description: "The request took too long to complete because data was arriving too slowly. Check your network connection and try again. If you are on a spotty network, switch to a more stable connection.".into(),
                ..Default::default()
            },
            Self::CanisterNotFound => ErrorData {
                status_code: StatusCode::NOT_FOUND,
                title: "Canister Not Found".into(),
                description: "The requested canister does not exist or is no longer available on the Internet Computer.".into(),
                icon: CANISTER_ERROR_SVG.into(),
                ..Default::default()
            },
            Self::CanisterReject => ErrorData {
                status_code: StatusCode::SERVICE_UNAVAILABLE,
                title: "Request Rejected".into(),
                description: "The canister explicitly rejected the request.".into(),
                icon: CANISTER_WARNING_SVG.into(),
                ..Default::default()
            },
            Self::CanisterError => ErrorData {
                status_code: StatusCode::SERVICE_UNAVAILABLE,
                title: "Canister Error".into(),
                description: r#"The canister failed to process your request.
                    This may be due to an issue with the canister's program, the resources it has allocated, or its configuration.
                    This is not an ICP issue, but local to this specific canister. You might want to try again in a moment.
                    If the problem persists, please reach out to the developers or check the ICP developer forum."#.trim().into(),
                icon: CANISTER_ERROR_SVG.into(),
                ..Default::default()
            },
            Self::CanisterFrozen => ErrorData {
                status_code: StatusCode::SERVICE_UNAVAILABLE,
                title: "Canister Temporarily Unavailable".into(),
                description: "The canister has run out of cycles. You or others can top it up to restore functionality.".into(),
                description_html: Some(r#"
                    The canister has run out of "cycles", the computational resource it needs to operate.
                    You or others can top it up to restore functionality:<br>
                    <a href="https://internetcomputer.org/docs/building-apps/canister-management/topping-up"
                        target="_blank" rel="noopener noreferrer" class="external-link">
                        Learn how to top up a canister.
                    </a>
                "#.trim().into()),
                icon: CANISTER_ERROR_SVG.into(),
                ..Default::default()
            },
            Self::CanisterIdNotResolved => ErrorData {
                status_code: StatusCode::BAD_REQUEST,
                title: "Canister ID Not Resolved".into(),
                description: "The gateway couldn't determine the destination canister for this request. Ensure the request includes a valid canister ID or uses a recognized domain.".into(),
                icon: CANISTER_WARNING_SVG.into(),
                ..Default::default()
            },
            Self::CanisterIdIncorrect => ErrorData {
                status_code: StatusCode::BAD_REQUEST,
                title: "Incorrect Canister ID".into(),
                description: "The canister ID you provided is invalid. Please verify the canister ID and try again.".into(),
                icon: CANISTER_ERROR_SVG.into(),
                ..Default::default()
            },
            Self::SubnetNotFound => ErrorData {
                status_code: StatusCode::BAD_REQUEST,
                title: "Subnet Not Found".into(),
                description: "The requested subnet was not found.".into(),
                icon: SUBNET_SVG.into(),

                ..Default::default()
            },
            Self::SubnetUnavailable => ErrorData {
                status_code: StatusCode::SERVICE_UNAVAILABLE,
                title: "Subnet Upgrade".into(),
                description: "The protocol currently upgrades this part of the Internet Computer. It should be back momentarily. No worries—your data is safe!".into(),
                retry_message: Some("Wait a few minutes and refresh this page.".into()),
                icon: SUBNET_SVG.into(),
                ..Default::default()
            },
            Self::ResponseVerificationError => ErrorData {
                status_code: StatusCode::SERVICE_UNAVAILABLE,
                title: "Response Verification Error".into(),
                description: "The response from the canister failed verification and cannot be trusted. If you understand the risks, you can retry using the raw domain to bypass certification.".into(),
                ..Default::default()
            },
            Self::Denylisted => ErrorData {
                status_code: StatusCode::UNAVAILABLE_FOR_LEGAL_REASONS,
                title: "Unavailable Due to Policy Violation".into(),
                description: "Access to this resource is denied due to a violation of the code of conduct.".into(),
                description_html: Some(r#"
                    This gateway denies access to the requested resource due to a violation of the
                    <a href="https://dfinity.org/boundary-nodes/ic0-app/code-of-conduct/" target="_blank" rel="noopener noreferrer" class="external-link">code of conduct.</a>.
                    If you believe this is an error, please file an appeal:"#.trim().into()),
                appeal_section: true,
                ..Default::default()
            },
            Self::Forbidden => ErrorData {
                status_code: StatusCode::FORBIDDEN,
                title: "Access Forbidden".into(),
                description: "Access to this resource is denied by the current set of application firewall rules.".into(),
                icon: SUBNET_SVG.into(),
                ..Default::default()
            },
            Self::DomainCanisterMismatch(canister_id) => ErrorData {
                status_code: StatusCode::BAD_REQUEST,
                title: "Canister Not Available Through This Gateway".into(),
                description: "This canister is not served through this gateway. Use a gateway that matches the canister's configuration.".into(),
                description_html: Some(format!(
                    r#"
                        This canister is not served through this gateway. Use a gateway that matches the canister's configuration:<br>
                        <a href="https://{canister_id}.icp0.io" target="_blank" rel="noopener noreferrer" class="external-link">
                            {canister_id}.icp0.io
                    </a>.
                "#).trim().into()),
                canister_id: Some(*canister_id),
                ..Default::default()
            },
            Self::IncorrectPrincipal => ErrorData {
                status_code: StatusCode::BAD_REQUEST,
                title: "Incorrect Principal".into(),
                description: "The principal in the request is incorrectly formatted.".into(),
                ..Default::default()
            },
            Self::LoadShed => ErrorData {
                status_code: StatusCode::TOO_MANY_REQUESTS,
                title: "Too Many Requests".into(),
                description: "The HTTP gateway is experiencing high load and cannot process your request right now. Please try again later.".into(),
                ..Default::default()
            },
            Self::MalformedRequest(x) => ErrorData {
                status_code: StatusCode::BAD_REQUEST,
                title: "Malformed Request".into(),
                description: x.clone(),
                ..Default::default()
            },
            Self::NoAuthority => ErrorData {
                status_code: StatusCode::BAD_REQUEST,
                title: "Missing Authority".into(),
                description: "The request is missing the required authority information (e.g. 'Host' header).".into(),
                ..Default::default()
            },
            Self::Other => ErrorData {
                status_code: StatusCode::INTERNAL_SERVER_ERROR,
                title: "Internal Gateway Error".into(),
                description: "Something went wrong. Please try again later.".into(),
                ..Default::default()
            },
            Self::PayloadTooLarge => ErrorData {
                status_code: StatusCode::PAYLOAD_TOO_LARGE,
                title: "Payload too Large".into(),
                description: "The data you sent is too large for the Internet Computer to handle. Please reduce your payload and try again.".into(),
                ..Default::default()
            },
            Self::RateLimited => ErrorData {
                status_code: StatusCode::TOO_MANY_REQUESTS,
                title: "Rate Limited".into(),
                description: "Your request has exceeded the rate limit. Please slow down your requests and try again in a moment.".into(),
                ..Default::default()
            },
            Self::UnknownDomain(_) => ErrorData {
                status_code: StatusCode::BAD_REQUEST,
                title: "Unknown Domain".into(),
                description: "The requested domain is not served by this HTTP gateway. Please check that the address is correct.".into(),
                ..Default::default()
            },
            Self::UpstreamError => ErrorData {
                status_code: StatusCode::SERVICE_UNAVAILABLE,
                title: "Upstream Unavailable".into(),
                description: "The HTTP gateway is temporarily unable to process the request. Please try again later. If this persists, check the status page for updates and reach out on the ICP developer forum.".into(),
                icon: SUBNET_SVG.into(),
                ..Default::default()
            },
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
            ErrorCause::UnknownDomain(x) => Self::UnknownDomain(x.clone()),
            ErrorCause::CanisterNotFound => Self::CanisterNotFound,
            ErrorCause::CanisterReject => Self::CanisterReject,
            ErrorCause::CanisterError => Self::CanisterError,
            ErrorCause::CanisterFrozen => Self::CanisterFrozen,
            ErrorCause::CanisterRouteNotFound => Self::CanisterNotFound,
            ErrorCause::CanisterIdNotResolved => Self::CanisterIdNotResolved,
            ErrorCause::CanisterIdIncorrect(_) => Self::CanisterIdIncorrect,
            ErrorCause::SubnetNotFound => Self::SubnetNotFound,
            ErrorCause::SubnetUnavailable => Self::SubnetUnavailable,
            ErrorCause::ResponseVerificationError => Self::ResponseVerificationError,
            ErrorCause::DomainCanisterMismatch(cid) => Self::DomainCanisterMismatch(*cid),
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
        let context = ERROR_CONTEXT
            .try_with(|ctx| ctx.clone())
            .unwrap_or_default();
        let context = context.borrow();

        let error_data = self.data();

        // Return an HTML error page if it was an HTTP request and it was sent from a browser
        let body = if context.request_type == RequestType::Http && context.is_browser {
            // Check if this is an alternate error domain
            // and produce alternate errors then
            if context
                .alternate_error_domain
                .as_ref()
                .zip(context.authority.as_ref())
                .map(|(alternate, authority)| authority.is_subdomain_of(alternate))
                == Some(true)
            {
                match self {
                    Self::UnknownDomain(_) => ALTERNATE_ERROR_UNKNOWN_DOMAIN,
                    _ => ALTERNATE_ERROR,
                }
                .to_string()
            } else {
                error_data.html()
            }
        } else {
            to_string_pretty(&json!({
                "error_type": self.to_string(),
                "details": error_data.description
            }))
            .unwrap() // this never fails
        };

        // Build the final response
        let mut resp = (error_data.status_code, body).into_response();

        // Insert the error cause header
        let error_cause_str: &'static str = self.into();
        resp.headers_mut()
            .insert(X_IC_ERROR_CAUSE, HeaderValue::from_static(error_cause_str));

        if context.request_type == RequestType::Http {
            resp.headers_mut().insert(CONTENT_TYPE, CONTENT_TYPE_HTML);
        }

        resp
    }
}

struct ErrorData {
    status_code: StatusCode,
    title: String,
    description: String,
    description_html: Option<String>,
    retry_message: Option<String>,
    canister_id: Option<Principal>,
    appeal_section: bool,
    icon: String,
}

impl Default for ErrorData {
    fn default() -> Self {
        Self {
            status_code: StatusCode::SERVICE_UNAVAILABLE,
            title: String::new(),
            description: String::new(),
            description_html: None,
            retry_message: None,
            canister_id: None,
            appeal_section: false,
            icon: GENERAL_ERROR_SVG.into(),
        }
    }
}

impl ErrorData {
    pub fn html(&self) -> String {
        let mut tpl = ERROR_PAGE_TEMPLATE
            .replace("{{ERROR_CODE}}", self.status_code.as_str())
            .replace("{{ERROR_TITLE}}", &self.title);
        if let Some(description) = &self.description_html {
            tpl = tpl.replace("{{ERROR_DESCRIPTION}}", description);
        } else {
            tpl = tpl.replace("{{ERROR_DESCRIPTION}}", &self.description);
        }
        tpl = tpl.replace("{{IMAGE_SVG}}", self.icon.as_str());

        if let Some(retry_message) = &self.retry_message {
            tpl = tpl
                .replace("{{RETRY_SECTION}}", RETRY_SECTION_TEMPLATE)
                .replace("{{RETRY_LOGIC}}", RETRY_LOGIC)
                .replace("{{RETRY_MESSAGE}}", retry_message);
        } else {
            tpl = tpl
                .replace("{{RETRY_SECTION}}", "")
                .replace("{{RETRY_LOGIC}}", "");
        }

        if let Some(canister_id) = &self.canister_id {
            tpl = tpl
                .replace("{{CANISTER_SECTION}}", CANISTER_SECTION_TEMPLATE)
                .replace("{{CANISTER_ID}}", canister_id.to_string().as_str());
        } else {
            tpl = tpl.replace("{{CANISTER_SECTION}}", "");
        }

        if self.appeal_section {
            tpl = tpl.replace("{{APPEAL_SECTION}}", APPEAL_SECTION);
        } else {
            tpl = tpl.replace("{{APPEAL_SECTION}}", "");
        }

        tpl
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use fqdn::fqdn;
    use http::HeaderMap;
    use http_body_util::BodyExt;
    use ic_bn_lib::{http::headers::X_IC_ERROR_CAUSE, hval, ic_agent::AgentError};
    use ic_transport_types::RejectResponse;
    use std::{collections::HashMap, sync::Arc};

    #[tokio::test]
    async fn test_error_cause() {
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
            (NO_HEALTHY_NODES, Some(ErrorCause::SubnetUnavailable)),
            (NO_ROUTING_TABLE, Some(ErrorCause::NoRoutingTable)),
            (FORBIDDEN, Some(ErrorCause::Forbidden)),
            (LOAD_SHED, Some(ErrorCause::LoadShed)),
            (CANISTER_NOT_FOUND, Some(ErrorCause::CanisterRouteNotFound)),
            (
                CANISTER_ROUTE_NOT_FOUND,
                Some(ErrorCause::CanisterRouteNotFound),
            ),
            (SUBNET_NOT_FOUND, Some(ErrorCause::SubnetNotFound)),
            ("foo", Some(ErrorCause::BoundaryNodeError("foo".into()))),
            ("", None),
            ("none", None),
        ];
        for (hdr, err) in cases {
            let mut hm = HeaderMap::new();
            hm.insert(X_IC_ERROR_CAUSE, hval!(hdr));
            let meta = BNResponseMetadata::from(&mut hm);
            let error_cause = Option::<ErrorCause>::from(&meta);
            assert_eq!(error_cause, err);
        }

        // Check that successful status code emits no error regardless of headers
        let mut hm = HeaderMap::new();
        hm.insert(X_IC_ERROR_CAUSE, hval!(NO_HEALTHY_NODES));
        let mut meta = BNResponseMetadata::from(&mut hm);
        meta.status = Some(StatusCode::OK);
        let error_cause = Option::<ErrorCause>::from(&meta);
        assert_eq!(error_cause, None);

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
        ));

        // Test alternate errors
        let context = RefCell::new(ErrorContext {
            alternate_error_domain: Some(fqdn!("caffeine.ai")),
            is_browser: true,
            request_type: RequestType::Http,
            authority: Some(fqdn!("foobar.caffeine.ai")),
        });

        let error = ErrorCause::UnknownDomain(fqdn!("foo"));
        let error: ErrorClientFacing = (&error).into();

        ERROR_CONTEXT
            .scope(context.clone(), async move {
                let resp = error.into_response();
                let body = resp.into_body().collect().await.unwrap().to_bytes();
                assert_eq!(body, ALTERNATE_ERROR_UNKNOWN_DOMAIN.as_bytes());
            })
            .await;

        let error = ErrorCause::CanisterError;
        let error: ErrorClientFacing = (&error).into();

        ERROR_CONTEXT
            .scope(context, async move {
                let resp = error.into_response();
                let body = resp.into_body().collect().await.unwrap().to_bytes();
                assert_eq!(body, ALTERNATE_ERROR.as_bytes());
            })
            .await;

        let context = RefCell::new(ErrorContext {
            alternate_error_domain: Some(fqdn!("caffeine.ai")),
            is_browser: true,
            request_type: RequestType::Http,
            authority: Some(fqdn!("foobar.cocaine.ai")),
        });

        let error = ErrorCause::UnknownDomain(fqdn!("foo"));
        let error: ErrorClientFacing = (&error).into();

        ERROR_CONTEXT
            .scope(context.clone(), async move {
                let resp = error.into_response();
                let body = resp.into_body().collect().await.unwrap().to_bytes();
                assert_ne!(body, ALTERNATE_ERROR_UNKNOWN_DOMAIN.as_bytes());
            })
            .await;

        // Test browser
        let context = RefCell::new(ErrorContext {
            alternate_error_domain: None,
            is_browser: true,
            request_type: RequestType::Http,
            authority: Some(fqdn!("foobar")),
        });

        let error = ErrorCause::SubnetUnavailable;
        let error: ErrorClientFacing = (&error).into();

        ERROR_CONTEXT
            .scope(context.clone(), async move {
                let resp = error.into_response();
                assert_eq!(
                    resp.headers().get(CONTENT_TYPE).unwrap().to_str().unwrap(),
                    CONTENT_TYPE_HTML
                );
            })
            .await;

        // Test non-browser
        let context = RefCell::new(ErrorContext {
            alternate_error_domain: None,
            is_browser: false,
            request_type: RequestType::Http,
            authority: Some(fqdn!("foobar")),
        });

        let error = ErrorCause::SubnetUnavailable;
        let error: ErrorClientFacing = (&error).into();

        ERROR_CONTEXT
            .scope(context.clone(), async move {
                let resp = error.into_response();
                let body = resp.into_body().collect().await.unwrap().to_bytes();
                let js: HashMap<String, String> = serde_json::from_slice(&body).unwrap();
                assert_eq!(js.get("error_type").unwrap(), "subnet_updating");
            })
            .await;
    }
}
