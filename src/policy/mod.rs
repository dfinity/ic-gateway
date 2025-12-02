pub mod denylist;
pub mod domain_canister;

use std::{fs, path::PathBuf};

use ahash::AHashSet;
use anyhow::{Context, Error};
use candid::Principal;

/// Generic function to load a list of principals from a text file into a HashSet
/// Expects a single principal per line.
pub fn load_principal_list(path: &PathBuf) -> Result<AHashSet<Principal>, Error> {
    let data = fs::read_to_string(path).context("failed to read file")?;
    let set = data
        .lines()
        .filter(|x| !x.trim().is_empty())
        .map(Principal::from_text)
        .collect::<Result<AHashSet<Principal>, _>>()?;
    Ok(set)
}
