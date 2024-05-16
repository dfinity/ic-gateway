#![deny(clippy::all)]
//#![warn(clippy::pedantic)]
#![warn(clippy::nursery)]

use anyhow::{Context, Error};
use clap::Parser;
use jemallocator::Jemalloc;

use crate::cli::Cli;

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

#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

#[tokio::main]
async fn main() -> Result<(), Error> {
    let cli = Cli::parse();

    log::setup_logging(&cli.log).context("unable to setup logging")?;
    core::main(&cli).await
}
