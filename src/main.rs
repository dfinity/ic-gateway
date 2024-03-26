use anyhow::Error;
use clap::Parser;
use jemallocator::Jemalloc;

use crate::cli::Cli;

mod cli;
mod core;

#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

#[tokio::main]
async fn main() -> Result<(), Error> {
    let cli = Cli::parse();

    core::main(cli).await
}
