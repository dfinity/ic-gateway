#![deny(clippy::all)]
#![warn(clippy::nursery)]
#![allow(clippy::too_many_lines)]
// Needed for certain macros
#![recursion_limit = "256"]

mod cli;
mod core;
mod metrics;
mod policy;
mod routing;
mod tls;

pub use crate::cli::Cli;
pub use metrics::{Clickhouse, Vector};
pub use routing::domain::ProvidesCustomDomains;

pub use core::main;
pub use routing::setup_router;
