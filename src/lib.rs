#![deny(clippy::all)]
#![warn(clippy::nursery)]
#![allow(clippy::too_many_lines)]
#![allow(clippy::type_complexity)]
// False positive on `#[derive(new)]` (derive-new) since clippy 1.99
#![allow(clippy::redundant_field_names)]
// Needed for certain macros
#![recursion_limit = "256"]

mod api;
mod cli;
mod core;
pub mod log;
#[cfg(feature = "mcp")]
mod mcp;
pub mod metrics;
mod policy;
pub mod routing;
#[cfg(feature = "smtp")]
mod smtp;
#[cfg(any(test, feature = "bench"))]
pub mod test;
mod tls;

pub use crate::cli::Cli;
pub use ic_bn_lib::custom_domains::ProvidesCustomDomains;

pub use core::main;
pub use routing::setup_router;

pub use ic_bn_lib;
