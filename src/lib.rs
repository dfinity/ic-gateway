#![deny(clippy::all)]
#![warn(clippy::nursery)]
#![allow(clippy::too_many_lines)]
// Needed for certain macros
#![recursion_limit = "256"]

pub mod cli;
mod core;
mod metrics;
mod policy;
mod routing;
mod tls;

use crate::cli::Cli;

pub use core::main;
pub use routing::setup_router;
