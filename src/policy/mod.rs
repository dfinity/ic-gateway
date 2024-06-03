pub mod denylist;
pub mod domain_canister;
mod test;

use std::{collections::HashSet, fs, path::PathBuf};

use anyhow::{Context, Error};
use candid::Principal;

// Generic function to load a list of principals from a text file into a HashSet
pub fn load_principal_list(path: &PathBuf) -> Result<HashSet<Principal>, Error> {
    let data = fs::read_to_string(path).context("failed to read file")?;
    let set = data
        .lines()
        .filter(|x| !x.trim().is_empty())
        .map(Principal::from_text)
        .collect::<Result<HashSet<Principal>, _>>()?;
    Ok(set)
}
