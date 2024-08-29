#![deny(clippy::all)]
//#![warn(clippy::pedantic)]
#![warn(clippy::nursery)]
#![allow(clippy::too_many_lines)]
// Needed for certain macros
#![recursion_limit = "256"]

use anyhow::{Context, Error};
use clap::Parser;
//#[cfg(not(feature = "dhat-heap"))]
//use tikv_jemallocator::Jemalloc;
use tracing::warn;

use crate::cli::Cli;

mod cli;
mod core;
mod log;
mod metrics;
mod policy;
mod routing;
mod tls;

// #[cfg(not(feature = "dhat-heap"))]
// #[global_allocator]
// static GLOBAL: Jemalloc = Jemalloc;

fn main() -> Result<(), Error> {
    let cli = Cli::parse();
    log::setup_logging(&cli.log).context("unable to setup logging")?;
    warn!("Env: {}, Hostname: {}", cli.misc.env, cli.misc.hostname);

    let threads = if let Some(v) = cli.misc.threads {
        v
    } else {
        std::thread::available_parallelism()
            .context("unable to get the number of CPUs")?
            .get()
    };

    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(threads)
        .build()?
        .block_on(core::main(&cli))
}
