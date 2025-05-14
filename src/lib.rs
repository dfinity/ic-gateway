#![deny(clippy::all)]
#![warn(clippy::nursery)]
#![allow(clippy::too_many_lines)]
// Needed for certain macros
#![recursion_limit = "256"]

mod cli;
mod core;
pub mod metrics;
mod policy;
pub mod routing;
#[cfg(any(test, feature = "bench"))]
pub mod test;
mod tls;

pub use crate::cli::Cli;
#[cfg(feature = "clickhouse")]
pub use metrics::Clickhouse;
#[cfg(feature = "vector")]
pub use metrics::Vector;
pub use routing::domain::ProvidesCustomDomains;

pub use core::main;
pub use routing::setup_router;

pub use ic_agent;
pub use ic_bn_lib;
