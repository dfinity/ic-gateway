pub mod denylist;
pub mod domain_canister;

use std::{fs, path::PathBuf};

use ahash::AHashSet;
use anyhow::{Context, Error};
use candid::Principal;

/// Generic function to load a list of principals from a text file into a `AHashSet`
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

#[cfg(test)]
mod test {
    use std::io::Write;

    use ic_bn_lib::principal;

    use super::*;

    fn write_temp(content: &str) -> tempfile::NamedTempFile {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(content.as_bytes()).unwrap();
        f.flush().unwrap();
        f
    }

    #[test]
    fn test_load_principal_list() {
        // Blank & whitespace-only lines are skipped, and a missing trailing
        // newline is fine
        let f = write_temp(
            "qoctq-giaaa-aaaaa-aaaea-cai\n\
             \n\
             \t  \n\
             s6hwe-laaaa-aaaab-qaeba-cai\n\
             \n\
             oydqf-haaaa-aaaao-afpsa-cai",
        );

        let set = load_principal_list(&f.path().to_path_buf()).unwrap();
        assert_eq!(
            set,
            AHashSet::from([
                principal!("qoctq-giaaa-aaaaa-aaaea-cai"),
                principal!("s6hwe-laaaa-aaaab-qaeba-cai"),
                principal!("oydqf-haaaa-aaaao-afpsa-cai"),
            ])
        );

        // Duplicates collapse
        let f = write_temp("aaaaa-aa\naaaaa-aa\n");
        let set = load_principal_list(&f.path().to_path_buf()).unwrap();
        assert_eq!(set.len(), 1);

        // An empty file is valid, just empty
        let f = write_temp("");
        assert!(load_principal_list(&f.path().to_path_buf()).unwrap().is_empty());

        let f = write_temp("\n\n  \n");
        assert!(load_principal_list(&f.path().to_path_buf()).unwrap().is_empty());
    }

    #[test]
    fn test_load_principal_list_errors() {
        // A malformed entry fails the whole load rather than being dropped -
        // silently ignoring it would weaken the policy it's used for.
        let f = write_temp("aaaaa-aa\nnot-a-principal\n");
        assert!(load_principal_list(&f.path().to_path_buf()).is_err());

        // Leading/trailing whitespace isn't trimmed from actual entries
        let f = write_temp("  aaaaa-aa  \n");
        assert!(load_principal_list(&f.path().to_path_buf()).is_err());

        // Missing file
        assert!(load_principal_list(&PathBuf::from("/nonexistent/principals.txt")).is_err());
    }
}
