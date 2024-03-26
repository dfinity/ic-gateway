use anyhow::Error;

use crate::cli::Cli;

pub const SERVICE_NAME: &str = "ic_gateway";
pub const AUTHOR_NAME: &str = "Boundary Node Team <boundary-nodes@dfinity.org>";

pub async fn main(cli: Cli) -> Result<(), Error> {
    Ok(())
}
