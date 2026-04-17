#![deny(clippy::all)]
#![warn(clippy::nursery)]
#![allow(clippy::too_many_lines)]
#![allow(clippy::type_complexity)]
// Needed for certain macros
#![recursion_limit = "256"]

mod api;
pub mod cashier;
mod cli;
mod core;
pub mod log;
pub mod metrics;
mod policy;
pub mod routing;
pub mod s3;
pub mod storage;
#[cfg(any(test, feature = "bench"))]
pub mod test;
mod tls;

pub use crate::cli::Cli;
pub use ic_bn_lib_common::traits::custom_domains::ProvidesCustomDomains;

pub use core::main;
pub use routing::setup_router;

pub use ic_bn_lib;
