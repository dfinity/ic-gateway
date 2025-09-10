#![deny(clippy::all)]
#![warn(clippy::nursery)]
#![allow(clippy::too_many_lines)]
#![allow(clippy::type_complexity)]
// Needed for certain macros
#![recursion_limit = "256"]

mod api;
mod cli;
mod core;
pub mod metrics;
mod policy;
pub mod routing;
#[cfg(any(test, feature = "bench"))]
pub mod test;
mod tls;

pub use crate::cli::Cli;
pub use ic_bn_lib::custom_domains::ProvidesCustomDomains;
#[cfg(feature = "clickhouse")]
pub use metrics::Clickhouse;

pub use core::main;
pub use routing::setup_router;

pub use ic_bn_lib;
