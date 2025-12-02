use std::{cell::RefCell, error::Error as StdError};

use crate::routing::{CONTENT_TYPE_JSON, RequestType};
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
use serde::{Deserialize, Serialize};
use serde_json::to_string_pretty;
use strum::{Display, IntoStaticStr};
use tokio::task_local;

use super::ic::BNResponseMetadata;

#[derive(Default, Clone)]
pub struct ErrorContext {
    pub request_type: RequestType,
    pub canister_id: Option<Principal>,
    pub is_browser: bool,
    pub disable_html_error_messages: bool,
    pub authority: Option<FQDN>,
    pub alternate_error_domain: Option<FQDN>,
}

#[derive(Serialize, Deserialize)]
struct ErrorMessage {
    error_type: String,
    description: String,
    details: Option<String>,
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

#[derive(Debug, Clone, Display, IntoStaticStr, Eq, PartialEq)]
#[strum(serialize_all = "snake_case")]
pub enum CanisterError {
    NotFound(Option<Principal>),
    Reject,
    Error(String),
    Frozen,
    IdIncorrect(String),
    IdNotResolved,
    RouteNotFound(Option<Principal>),
}

#[derive(Debug, Clone, Display, IntoStaticStr, Eq, PartialEq)]
#[strum(serialize_all = "snake_case")]
pub enum BackendError {
    Dns(String),
    Connect,
    Timeout,
    BodyTimeout,
    Body(String),
    TLSOther(String),
    TLSCert(String),
    BoundaryNode(String),
    HttpGateway(String),
    Other(String),
    ResponseVerification(String),
}

impl BackendError {
    pub fn details(&self) -> Option<String> {
        match self {
            Self::Dns(x) => Some(x.clone()),
            Self::Body(x) => Some(x.clone()),
            Self::TLSOther(x) => Some(x.clone()),
            Self::TLSCert(x) => Some(x.clone()),
            Self::BoundaryNode(x) => Some(x.clone()),
            Self::HttpGateway(x) => Some(x.clone()),
            Self::Other(x) => Some(x.clone()),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Display, IntoStaticStr, Eq, PartialEq)]
#[strum(serialize_all = "snake_case")]
pub enum ClientError {
    BodyTooLarge,
    BodyTimeout,
    Body(String),
    IncorrectPrincipal,
    MalformedRequest(String),
    NoAuthority,
    UnknownDomain(FQDN),
    DomainCanisterMismatch(Principal),
    SubnetNotFound,
}

impl ClientError {
    pub fn details(&self) -> Option<String> {
        match self {
            Self::Body(x) => Some(x.clone()),
            Self::MalformedRequest(x) => Some(x.clone()),
            Self::UnknownDomain(x) => Some(x.to_string()),
            Self::DomainCanisterMismatch(x) => {
                Some(format!("The canister {x} is not served by this domain"))
            }
            _ => None,
        }
    }
}

/// Categorized possible causes for request processing failures
#[derive(Debug, Clone, Display, Eq, PartialEq)]
#[strum(serialize_all = "snake_case")]
pub enum ErrorCause {
    LoadShed,
    SubnetUnavailable,
    NoRoutingTable,
    Denylisted,
    Forbidden,
    #[strum(to_string = "client_{0}")]
    Client(ClientError),
    #[strum(to_string = "backend_{0}")]
    Backend(BackendError),
    #[strum(to_string = "canister_{0}")]
    Canister(CanisterError),
    #[strum(serialize = "rate_limited_{0}")]
    RateLimited(RateLimitCause),
    #[strum(serialize = "internal_server_error")]
    Other(String),
}

impl ErrorCause {
    pub fn details(&self) -> Option<String> {
        match self {
            Self::Client(x) => x.details(),
            Self::Backend(x) => x.details(),
            Self::Canister(CanisterError::IdIncorrect(x)) => Some(x.clone()),
            Self::RateLimited(x) => Some(x.to_string()),
            Self::Other(x) => Some(x.clone()),
            _ => None,
        }
    }

    // Methods below are not implemented as From<> due to ambiguity

    // Convert from client-side error
    pub fn from_client_error(e: HttpError) -> Self {
        match e {
            HttpError::BodyReadingFailed(v) => Self::Client(ClientError::Body(v)),
            HttpError::BodyTimedOut => Self::Client(ClientError::BodyTimeout),
            HttpError::BodyTooBig => Self::Client(ClientError::BodyTooLarge),
            _ => Self::Other(e.to_string()),
        }
    }

    // Convert from backend error
    pub fn from_backend_error(e: HttpError) -> Self {
        match e {
            HttpError::RequestFailed(v) => Self::from(&v),
            HttpError::BodyReadingFailed(v) => Self::Backend(BackendError::Body(v)),
            HttpError::BodyTimedOut => Self::Backend(BackendError::BodyTimeout),
            _ => Self::Backend(BackendError::Other(e.to_string())),
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

impl From<&reqwest::Error> for ErrorCause {
    fn from(e: &reqwest::Error) -> Self {
        if e.is_connect() {
            return Self::Backend(BackendError::Connect);
        }

        if e.is_timeout() {
            return Self::Backend(BackendError::Timeout);
        }

        Self::Backend(BackendError::Other(e.to_string()))
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

        let canister_id = ERROR_CONTEXT
            .try_with(|x| x.borrow().canister_id)
            .ok()
            .flatten();

        Some(match v.error_cause.as_ref() {
            NO_HEALTHY_NODES => ErrorCause::SubnetUnavailable,
            CANISTER_NOT_FOUND | CANISTER_ROUTE_NOT_FOUND => {
                ErrorCause::Canister(CanisterError::RouteNotFound(canister_id))
            }
            SUBNET_NOT_FOUND => ErrorCause::Client(ClientError::SubnetNotFound),
            FORBIDDEN => ErrorCause::Forbidden,
            LOAD_SHED => ErrorCause::LoadShed,
            NO_ROUTING_TABLE => ErrorCause::NoRoutingTable,
            _ => ErrorCause::Backend(BackendError::BoundaryNode(v.error_cause.clone())),
        })
    }
}

impl From<HttpGatewayError> for ErrorCause {
    fn from(v: HttpGatewayError) -> Self {
        let canister_id = ERROR_CONTEXT
            .try_with(|x| x.borrow().canister_id)
            .ok()
            .flatten();

        match v {
            HttpGatewayError::ResponseVerificationError(e) => {
                Self::Backend(BackendError::ResponseVerification(e.to_string()))
            }
            HttpGatewayError::AgentError(ae) => match ae.as_ref() {
                AgentError::CertifiedReject { reject, .. }
                | AgentError::UncertifiedReject { reject, .. } => match reject.reject_code {
                    RejectCode::CanisterError => {
                        Self::Canister(CanisterError::Error(reject.reject_message.clone()))
                    }
                    RejectCode::SysTransient if reject.reject_message.contains("frozen") => {
                        Self::Canister(CanisterError::Frozen)
                    }
                    RejectCode::CanisterReject => Self::Canister(CanisterError::Reject),
                    RejectCode::DestinationInvalid => {
                        Self::Canister(CanisterError::NotFound(canister_id))
                    }
                    _ => Self::Backend(BackendError::Other(ae.to_string())),
                },
                _ => Self::Backend(BackendError::HttpGateway(ae.to_string())),
            },
            _ => Self::Backend(BackendError::HttpGateway(v.to_string())),
        }
    }
}

impl From<anyhow::Error> for ErrorCause {
    fn from(e: anyhow::Error) -> Self {
        // Check if it's a DNS error
        if let Some(e) = error_infer::<ResolveError>(&e) {
            return Self::Backend(BackendError::Dns(e.to_string()));
        }

        // Check if it's a Rustls error
        if let Some(e) = error_infer::<rustls::Error>(&e) {
            return match e {
                rustls::Error::InvalidCertificate(v) => {
                    Self::Backend(BackendError::TLSCert(format!("{v:?}")))
                }
                rustls::Error::NoCertificatesPresented => {
                    Self::Backend(BackendError::TLSCert("no certificate presented".into()))
                }
                _ => Self::Backend(BackendError::TLSOther(e.to_string())),
            };
        }

        // Check if it's a known Reqwest error
        if let Some(e) = error_infer::<reqwest::Error>(&e) {
            return Self::from(e);
        }

        if error_infer::<http_body_util::LengthLimitError>(&e).is_some() {
            return Self::Client(ClientError::BodyTooLarge);
        }

        Self::Other(e.to_string())
    }
}

#[derive(Debug, Clone, Display)]
#[strum(serialize_all = "snake_case")]
pub enum ErrorClientFacing {
    #[strum(serialize = "subnet_updating")]
    SubnetUnavailable,
    Denylisted,
    Forbidden,
    LoadShed,
    #[strum(serialize = "internal_server_error")]
    Other(String),
    RateLimited,
    #[strum(to_string = "client_{0}")]
    Client(ClientError),
    #[strum(to_string = "backend_{0}")]
    Backend(BackendError),
    #[strum(to_string = "canister_{0}")]
    Canister(CanisterError),
}

impl ErrorClientFacing {
    fn data(&self) -> ErrorData {
        match self {
            // Client errors
            Self::Client(ClientError::SubnetNotFound) => ErrorData {
                status_code: StatusCode::BAD_REQUEST,
                title: "Subnet Not Found".into(),
                description: "The requested subnet was not found.".into(),
                icon: SUBNET_SVG.into(),
                ..Default::default()
            },
            Self::Client(ClientError::UnknownDomain(d)) => ErrorData {
                status_code: StatusCode::BAD_REQUEST,
                title: "Unknown Domain".into(),
                description: "The requested domain is not served by this HTTP gateway. Please check that the address is correct.".into(),
                details: Some(format!("The domain {d} is not served by this gateway")),
                ..Default::default()
            },
            Self::Client(ClientError::DomainCanisterMismatch(canister_id)) => ErrorData {
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
            Self::Client(ClientError::IncorrectPrincipal) => ErrorData {
                status_code: StatusCode::BAD_REQUEST,
                title: "Incorrect Principal".into(),
                description: "The principal in the request is incorrectly formatted.".into(),
                ..Default::default()
            },
            Self::Client(ClientError::MalformedRequest(x)) => ErrorData {
                status_code: StatusCode::BAD_REQUEST,
                title: "Malformed Request".into(),
                description: "Your request was not correctly formed.".into(),
                details: Some(x.clone()),
                ..Default::default()
            },
            Self::Client(ClientError::NoAuthority) => ErrorData {
                status_code: StatusCode::BAD_REQUEST,
                title: "Missing Authority".into(),
                description: "The request is missing the required authority information (e.g. 'Host' header).".into(),
                ..Default::default()
            },
            Self::Client(ClientError::BodyTooLarge) => ErrorData {
                status_code: StatusCode::PAYLOAD_TOO_LARGE,
                title: "Payload too Large".into(),
                description: "The data you sent is too large for the Internet Computer to handle. Please reduce your payload and try again.".into(),
                ..Default::default()
            },
            // The remaining errors are never shown to the clients: if the request never completes we don't send response obviously.
            // So there's no need to provide any details. Code 408 is informational (for logging) - clients never see it.
            Self::Client(_) => ErrorData {
                status_code: StatusCode::REQUEST_TIMEOUT,
                title: "".into(),
                description: "".into(),
                ..Default::default()
            },

            // Backend errors
            Self::Backend(BackendError::ResponseVerification(e)) => ErrorData {
                status_code: StatusCode::SERVICE_UNAVAILABLE,
                title: "Response Verification Error".into(),
                description: "The response from the canister failed verification and cannot be trusted. If you understand the risks, you can retry using the raw domain to bypass certification.".into(),
                details: Some(e.clone()),
                ..Default::default()
            },
            Self::Backend(e) => ErrorData {
                status_code: StatusCode::SERVICE_UNAVAILABLE,
                title: "Upstream Unavailable".into(),
                description: "The HTTP gateway is temporarily unable to process the request. Please try again later. If this persists, check the status page for updates and reach out on the ICP developer forum.".into(),
                details: e.details(),
                icon: SUBNET_SVG.into(),
                ..Default::default()
            },

            // Canister errors
            Self::Canister(CanisterError::NotFound(v)) | Self::Canister(CanisterError::RouteNotFound(v)) => {
                let canister_id = v.map(|x| x.to_string()).unwrap_or_else(|| "unknown".into());

                ErrorData {
                    status_code: StatusCode::NOT_FOUND,
                    title: "Canister Not Found".into(),
                    description: format!("The requested canister ({canister_id}) does not exist or is no longer available on the Internet Computer."),
                    canister_id: *v,
                    icon: CANISTER_ERROR_SVG.into(),
                    ..Default::default()
                }
            },
            Self::Canister(CanisterError::Reject) => ErrorData {
                status_code: StatusCode::SERVICE_UNAVAILABLE,
                title: "Request Rejected".into(),
                description: "The canister explicitly rejected the request.".into(),
                icon: CANISTER_WARNING_SVG.into(),
                ..Default::default()
            },
            Self::Canister(CanisterError::Error(e)) => ErrorData {
                status_code: StatusCode::SERVICE_UNAVAILABLE,
                title: "Canister Error".into(),
                description: r#"The canister failed to process your request.
                    This may be due to an issue with the canister's program, the resources it has allocated, or its configuration.
                    This is not an ICP issue, but local to this specific canister. You might want to try again in a moment.
                    If the problem persists, please reach out to the developers or check the ICP developer forum."#.trim().into(),
                details: Some(e.clone()),
                icon: CANISTER_ERROR_SVG.into(),
                ..Default::default()
            },
            Self::Canister(CanisterError::Frozen) => ErrorData {
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
            Self::Canister(CanisterError::IdNotResolved) => ErrorData {
                status_code: StatusCode::BAD_REQUEST,
                title: "Canister ID Not Resolved".into(),
                description: "The gateway couldn't determine the destination canister for this request. Ensure the request includes a valid canister ID or uses a recognized domain.".into(),
                icon: CANISTER_WARNING_SVG.into(),
                ..Default::default()
            },
            Self::Canister(CanisterError::IdIncorrect(e)) => ErrorData {
                status_code: StatusCode::BAD_REQUEST,
                title: "Incorrect Canister ID".into(),
                description: "The canister ID you provided is invalid. Please verify the canister ID and try again.".into(),
                details: Some(e.clone()),
                icon: CANISTER_ERROR_SVG.into(),
                ..Default::default()
            },

            // Other errors
            Self::SubnetUnavailable => ErrorData {
                status_code: StatusCode::SERVICE_UNAVAILABLE,
                title: "Subnet Upgrade".into(),
                description: "The protocol currently upgrades this part of the Internet Computer. It should be back momentarily. No worries—your data is safe!".into(),
                retry_message: Some("Wait a few minutes and refresh this page.".into()),
                icon: SUBNET_SVG.into(),
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
            Self::LoadShed => ErrorData {
                status_code: StatusCode::TOO_MANY_REQUESTS,
                title: "Too Many Requests".into(),
                description: "The HTTP gateway is experiencing high load and cannot process your request right now. Please try again later.".into(),
                ..Default::default()
            },
            Self::RateLimited => ErrorData {
                status_code: StatusCode::TOO_MANY_REQUESTS,
                title: "Rate Limited".into(),
                description: "Your request has exceeded the rate limit. Please slow down your requests and try again in a moment.".into(),
                ..Default::default()
            },
            Self::Other(e) => ErrorData {
                status_code: StatusCode::INTERNAL_SERVER_ERROR,
                title: "Internal Gateway Error".into(),
                description: "Something went wrong. Please try again later.".into(),
                details: Some(e.clone()),
                ..Default::default()
            },
        }
    }
}

impl From<&ErrorCause> for ErrorClientFacing {
    fn from(v: &ErrorCause) -> Self {
        match v {
            ErrorCause::LoadShed => Self::LoadShed,
            ErrorCause::SubnetUnavailable => Self::SubnetUnavailable,
            ErrorCause::Denylisted => Self::Denylisted,
            ErrorCause::Forbidden => Self::Forbidden,
            ErrorCause::RateLimited(_) => Self::RateLimited,
            ErrorCause::Client(x) => Self::Client(x.clone()),
            ErrorCause::Backend(x) => Self::Backend(x.clone()),
            ErrorCause::Canister(x) => Self::Canister(x.clone()),
            ErrorCause::NoRoutingTable => Self::Other("No routing table available".into()),
            ErrorCause::Other(x) => Self::Other(x.clone()),
        }
    }
}

// Creates the response from ErrorClientFacing
impl IntoResponse for ErrorClientFacing {
    fn into_response(self) -> Response {
        let ctx = ERROR_CONTEXT
            .try_with(|x| x.borrow().clone())
            .unwrap_or_default();

        let error_data = self.data();

        // Return an HTML error page if it was an HTTP request and it was sent from a browser.
        let (body, content_type) = if ctx.request_type == RequestType::Http
            && ctx.is_browser
            && !ctx.disable_html_error_messages
        {
            // Check if this is an alternate error domain
            // and produce alternate errors in this case
            let msg = if ctx
                .alternate_error_domain
                .as_ref()
                .zip(ctx.authority.as_ref())
                .map(|(alternate, authority)| authority.is_subdomain_of(alternate))
                == Some(true)
            {
                match self {
                    Self::Client(ClientError::UnknownDomain(_)) => ALTERNATE_ERROR_UNKNOWN_DOMAIN,
                    _ => ALTERNATE_ERROR,
                }
                .to_string()
            } else {
                error_data.html()
            };

            (msg, CONTENT_TYPE_HTML)
        } else {
            let msg = ErrorMessage {
                error_type: self.to_string(),
                description: error_data.description,
                details: error_data.details,
            };

            // this never fails
            let js = to_string_pretty(&msg).unwrap();

            (js, CONTENT_TYPE_JSON)
        };

        // Build the final response
        let mut resp = (error_data.status_code, body).into_response();

        // Insert the error cause header
        resp.headers_mut().insert(
            X_IC_ERROR_CAUSE,
            HeaderValue::from_str(&self.to_string()).unwrap(), // This should never fail
        );
        resp.headers_mut().insert(CONTENT_TYPE, content_type);

        resp
    }
}

struct ErrorData {
    status_code: StatusCode,
    title: String,
    description: String,
    description_html: Option<String>,
    details: Option<String>,
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
            details: None,
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

    use std::sync::Arc;

    use fqdn::fqdn;
    use http::HeaderMap;
    use http_body_util::BodyExt;
    use ic_bn_lib::{http::headers::X_IC_ERROR_CAUSE, hval, ic_agent::AgentError};
    use ic_transport_types::RejectResponse;

    #[tokio::test]
    async fn test_error_cause() {
        // Basic naming
        assert_eq!(
            ErrorCause::Backend(BackendError::BodyTimeout).to_string(),
            "backend_body_timeout"
        );
        assert_eq!(
            ErrorCause::Backend(BackendError::Dns("foo".into())).to_string(),
            "backend_dns"
        );
        assert_eq!(
            ErrorCause::Canister(CanisterError::Frozen).to_string(),
            "canister_frozen"
        );
        assert_eq!(
            ErrorCause::Canister(CanisterError::IdIncorrect("bar".into())).to_string(),
            "canister_id_incorrect"
        );

        // Mapping of Rustls errors
        let err = anyhow::Error::new(rustls::Error::NoCertificatesPresented);
        assert!(matches!(
            ErrorCause::from(err),
            ErrorCause::Backend(BackendError::TLSCert(_))
        ));

        let err = anyhow::Error::new(rustls::Error::InvalidCertificate(
            rustls::CertificateError::ApplicationVerificationFailure,
        ));
        assert!(matches!(
            ErrorCause::from(err),
            ErrorCause::Backend(BackendError::TLSCert(_))
        ));

        let err = anyhow::Error::new(rustls::Error::BadMaxFragmentSize);
        assert!(matches!(
            ErrorCause::from(err),
            ErrorCause::Backend(BackendError::TLSOther(_))
        ));

        // Mapping of "error_cause" BN headers
        let cases = [
            (NO_HEALTHY_NODES, Some(ErrorCause::SubnetUnavailable)),
            (NO_ROUTING_TABLE, Some(ErrorCause::NoRoutingTable)),
            (FORBIDDEN, Some(ErrorCause::Forbidden)),
            (LOAD_SHED, Some(ErrorCause::LoadShed)),
            (
                CANISTER_NOT_FOUND,
                Some(ErrorCause::Canister(CanisterError::RouteNotFound(None))),
            ),
            (
                CANISTER_ROUTE_NOT_FOUND,
                Some(ErrorCause::Canister(CanisterError::RouteNotFound(None))),
            ),
            (
                SUBNET_NOT_FOUND,
                Some(ErrorCause::Client(ClientError::SubnetNotFound)),
            ),
            (
                "foo",
                Some(ErrorCause::Backend(BackendError::BoundaryNode(
                    "foo".into(),
                ))),
            ),
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
                ErrorCause::Canister(CanisterError::Error("".into())),
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
                ErrorCause::Canister(CanisterError::Reject),
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
                ErrorCause::Canister(CanisterError::NotFound(None)),
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
                ErrorCause::Canister(CanisterError::Frozen),
            ),
        ];
        for (ae, err) in cases {
            let http_gw_error = HttpGatewayError::AgentError(Arc::new(ae));
            assert_eq!(ErrorCause::from(http_gw_error), err);
        }

        let ae = Arc::new(AgentError::CertifiedReject {
            reject: RejectResponse {
                reject_code: RejectCode::SysFatal,
                reject_message: "".into(),
                error_code: None,
            },
            operation: None,
        });
        let http_gw_error = HttpGatewayError::AgentError(ae.clone());
        assert_eq!(
            ErrorCause::from(http_gw_error),
            ErrorCause::Backend(BackendError::Other(ae.to_string()))
        );

        // Test alternate errors
        let context = RefCell::new(ErrorContext {
            alternate_error_domain: Some(fqdn!("caffeine.ai")),
            is_browser: true,
            request_type: RequestType::Http,
            authority: Some(fqdn!("foobar.caffeine.ai")),
            ..Default::default()
        });

        let error = ErrorCause::Client(ClientError::UnknownDomain(fqdn!("foo")));
        let error: ErrorClientFacing = (&error).into();

        ERROR_CONTEXT
            .scope(context.clone(), async move {
                let resp = error.into_response();
                let body = resp.into_body().collect().await.unwrap().to_bytes();
                assert_eq!(body, ALTERNATE_ERROR_UNKNOWN_DOMAIN.as_bytes());
            })
            .await;

        let error = ErrorCause::Canister(CanisterError::Error("".into()));
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
            ..Default::default()
        });

        let error = ErrorCause::Client(ClientError::UnknownDomain(fqdn!("foo")));
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
            is_browser: true,
            request_type: RequestType::Http,
            authority: Some(fqdn!("foobar")),
            ..Default::default()
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
            request_type: RequestType::Http,
            authority: Some(fqdn!("foobar")),
            ..Default::default()
        });

        let error = ErrorCause::SubnetUnavailable;
        let error: ErrorClientFacing = (&error).into();

        ERROR_CONTEXT
            .scope(context.clone(), async move {
                let resp = error.into_response();
                let body = resp.into_body().collect().await.unwrap().to_bytes();
                let msg: ErrorMessage = serde_json::from_slice(&body).unwrap();
                assert_eq!(msg.error_type, "subnet_updating");
            })
            .await;
    }

    #[tokio::test]
    async fn test_no_friendly_messages() {
        // Should produce JSON even if is_browser == true
        let context = RefCell::new(ErrorContext {
            is_browser: true,
            disable_html_error_messages: true,
            request_type: RequestType::Http,
            authority: Some(fqdn!("foobar")),
            ..Default::default()
        });

        let error = ErrorCause::Canister(CanisterError::Error("some scary error".into()));
        let error: ErrorClientFacing = (&error).into();

        ERROR_CONTEXT
            .scope(context, async move {
                let resp = error.into_response();
                assert_eq!(
                    resp.headers().get(CONTENT_TYPE).unwrap().to_str().unwrap(),
                    CONTENT_TYPE_JSON
                );
                let body = resp.into_body().collect().await.unwrap().to_bytes();
                let msg: ErrorMessage = serde_json::from_slice(&body).unwrap();
                assert_eq!(msg.error_type, "canister_error");
                assert_eq!(msg.details, Some("some scary error".into()));
            })
            .await;
    }
}
