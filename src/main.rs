#![deny(clippy::all)]
#![warn(clippy::pedantic)]
#![warn(clippy::nursery)]

use anyhow::Error;
use clap::Parser;
use jemallocator::Jemalloc;

use crate::cli::Cli;

mod cache;
mod cli;
mod core;
mod dns;
mod http;
mod policy;
mod tls;

#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

#[tokio::main]
async fn main() -> Result<(), Error> {
    let cli = Cli::parse();
    core::main(cli).await
}
