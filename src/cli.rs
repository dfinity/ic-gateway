use std::{net::SocketAddr, path::PathBuf};

use clap::{Args, Parser};
use url::Url;

use crate::core::{AUTHOR_NAME, SERVICE_NAME};

#[derive(Parser)]
#[clap(name = SERVICE_NAME)]
#[clap(author = AUTHOR_NAME)]
pub struct Cli {}
