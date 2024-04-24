pub mod denylist;
pub mod domain_canister;
mod test;

use std::{collections::HashSet, fs, path::PathBuf};

use anyhow::{Context, Error};
use candid::Principal;

// Generic function to load a list of canister ids from a text file into a HashSet
pub fn load_canister_list(path: PathBuf) -> Result<HashSet<Principal>, Error> {
    let data = fs::read_to_string(path).context("failed to read canisters file")?;
    let set = data
        .lines()
        .filter(|x| !x.trim().is_empty())
        .map(Principal::from_text)
        .collect::<Result<HashSet<Principal>, _>>()?;
    Ok(set)
}
