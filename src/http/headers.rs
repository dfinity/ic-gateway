// Clippy complains that these are interior-mutable.
// We don't mutate them, so silence it.
// https://rust-lang.github.io/rust-clippy/master/index.html#/declare_interior_mutable_const
#![allow(clippy::declare_interior_mutable_const)]
#![allow(clippy::borrow_interior_mutable_const)]

use http::header::{HeaderName, HeaderValue};

pub const HEADER_IC_CACHE_STATUS: HeaderName = HeaderName::from_static("x-ic-cache-status");
pub const HEADER_IC_CACHE_BYPASS_REASON: HeaderName =
    HeaderName::from_static("x-ic-cache-bypass-reason");
pub const HEADER_IC_SUBNET_ID: HeaderName = HeaderName::from_static("x-ic-subnet-id");
pub const HEADER_IC_NODE_ID: HeaderName = HeaderName::from_static("x-ic-node-id");
pub const HEADER_IC_SUBNET_TYPE: HeaderName = HeaderName::from_static("x-ic-subnet-type");
pub const HEADER_IC_CANISTER_ID_CBOR: HeaderName = HeaderName::from_static("x-ic-canister-id-cbor");
pub const HEADER_IC_METHOD_NAME: HeaderName = HeaderName::from_static("x-ic-method-name");
pub const HEADER_IC_SENDER: HeaderName = HeaderName::from_static("x-ic-sender");
pub const HEADER_IC_RETRIES: HeaderName = HeaderName::from_static("x-ic-retries");
pub const HEADER_IC_ERROR_CAUSE: HeaderName = HeaderName::from_static("x-ic-error-cause");
pub const HEADER_IC_REQUEST_TYPE: HeaderName = HeaderName::from_static("x-ic-request-type");
pub const HEADER_IC_CANISTER_ID: HeaderName = HeaderName::from_static("x-ic-canister-id");
pub const HEADER_IC_COUNTRY_CODE: HeaderName = HeaderName::from_static("x-ic-country-code");
pub const X_REQUEST_ID: HeaderName = HeaderName::from_static("x-request-id");
pub const X_REQUESTED_WITH: HeaderName = HeaderName::from_static("x-requested-with");

pub const CONTENT_TYPE_CBOR: HeaderValue = HeaderValue::from_static("application/cbor");
pub const CONTENT_TYPE_OCTET_STREAM: HeaderValue =
    HeaderValue::from_static("application/octet-stream");
pub const HEADER_HSTS: HeaderValue =
    HeaderValue::from_static("max-age=31536000; includeSubDomains");
pub const X_CONTENT_TYPE_OPTIONS_NO_SNIFF: HeaderValue = HeaderValue::from_static("nosniff");
pub const X_FRAME_OPTIONS_DENY: HeaderValue = HeaderValue::from_static("DENY");
