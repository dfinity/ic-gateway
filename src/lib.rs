#![deny(clippy::all)]
//#![warn(clippy::pedantic)]
#![warn(clippy::nursery)]

mod cache;
mod cli;
mod core;
mod http;
mod log;
mod metrics;
mod policy;
mod routing;
mod tasks;
mod tls;

pub use cli::Cli;
pub use core::main;
pub use log::setup_logging;
pub use routing::domain::{DomainLookup, DomainResolver, ResolvesDomain};
pub use routing::ic::handler::{handler, HandlerState};
pub use routing::middleware::cors::layer;
pub use routing::middleware::validate::middleware as validate_middleware;
