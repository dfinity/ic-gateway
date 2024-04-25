#![deny(clippy::all)]
//#![warn(clippy::pedantic)]
#![warn(clippy::nursery)]

use anyhow::Error;
use clap::Parser;
use jemallocator::Jemalloc;

use crate::cli::Cli;

mod cache;
mod cli;
mod core;
mod http;
mod policy;
mod routing;
mod tls;

#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

#[tokio::main]
async fn main() -> Result<(), Error> {
    let cli = Cli::parse();

    let subscriber = tracing_subscriber::FmtSubscriber::builder()
        .with_max_level(tracing::Level::INFO)
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

    core::main(&cli).await
}
