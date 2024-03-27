use clap::Parser;

use crate::core::{AUTHOR_NAME, SERVICE_NAME};

#[derive(Parser)]
#[clap(name = SERVICE_NAME)]
#[clap(author = AUTHOR_NAME)]
pub struct Cli {}
