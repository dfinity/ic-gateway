use std::{str::FromStr, sync::Arc};

use anyhow::{anyhow, Context, Error};
use candid::Principal;
use fqdn::{Fqdn, FQDN};

use crate::tls::cert::LooksupCustomDomain;

const INVALID_ALIAS_FORMAT: &str = "Invalid alias format, must be 'alias:canister_id'";

#[derive(Clone)]
pub struct CanisterAlias(FQDN, Principal);

impl FromStr for CanisterAlias {
    type Err = Error;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.split_once(':') {
            Some((alias, principal)) => {
                if alias.is_empty() {
                    return Err(anyhow!(INVALID_ALIAS_FORMAT));
                }

                Ok(Self(
                    FQDN::from_str(alias)?,
                    Principal::from_str(principal)?,
                ))
            }

            None => Err(anyhow!(INVALID_ALIAS_FORMAT)),
        }
    }
}

// Combination of canister id and whether we need to verify the response
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Canister {
    pub id: Principal,
    pub verify: bool,
}

// Resolves hostname to a canister id
pub trait ResolvesCanister: Send + Sync {
    fn resolve_canister(&self, host: &Fqdn) -> Option<Canister>;
}

pub struct CanisterResolver {
    domains: Vec<FQDN>,
    aliases: Vec<(FQDN, Canister)>,
    custom_domains: Arc<dyn LooksupCustomDomain>,
}

impl CanisterResolver {
    pub fn new(
        domains: Vec<FQDN>,
        aliases_in: Vec<CanisterAlias>,
        custom_domains: Arc<dyn LooksupCustomDomain>,
    ) -> Result<Self, Error> {
        let mut aliases = vec![];
        // Generate a map of all alias+domain combinations
        for a in aliases_in {
            for d in &domains {
                aliases.push((
                    FQDN::from_str(&format!("{}.{d}", a.0))?,
                    Canister {
                        id: a.1,
                        verify: true,
                    },
                ));
            }
        }

        Ok(Self {
            domains,
            aliases,
            custom_domains,
        })
    }

    // Iterate over aliases and see if given host is a subdomain of any.
    // Host is a subdomain of itself also so 'nns.ic0.app' will match the alias 'nns' and domain 'ic0.app'.
    fn lookup_alias(&self, host: &Fqdn) -> Option<Canister> {
        self.aliases
            .iter()
            .find(|x| host.is_subdomain_of(&x.0))
            .map(|x| x.1)
    }

    fn lookup_domain(&self, host: &Fqdn) -> Option<Canister> {
        let mut labels = host.labels();

        // Check if the first part of hostname parses as Principal
        let id = Principal::from_text(labels.next()?).ok()?;

        // Check if the next part is "raw" then we don't need to verify the response
        let mut labels = labels.peekable();
        let verify = if labels.peek() == Some(&"raw") {
            // Consume "raw"
            labels.next();
            false
        } else {
            true
        };

        // Construct the remaining part of domain
        let domain = FQDN::from_str(&labels.collect::<Vec<_>>().join(".")).ok()?;

        // Check if the domain is known
        if !self.domains.iter().any(|x| x == &domain) {
            return None;
        }

        Some(Canister { id, verify })
    }
}

impl ResolvesCanister for CanisterResolver {
    fn resolve_canister(&self, host: &Fqdn) -> Option<Canister> {
        self.lookup_alias(host)
            .or_else(|| self.lookup_domain(host))
            .or_else(|| {
                let id = self.custom_domains.lookup_custom_domain(host)?;
                Some(Canister { id, verify: true })
            })
    }
}

#[cfg(test)]
mod test {
    use fqdn::fqdn;

    use super::*;
    use crate::tls::cert::storage::test::create_test_storage;

    #[test]
    fn test_canister_alias() -> Result<(), Error> {
        // Bad principal
        let a = CanisterAlias::from_str("foo:bar");
        assert!(a.is_err());

        let a = CanisterAlias::from_str("foo:");
        assert!(a.is_err());

        // Bad alias
        let a = CanisterAlias::from_str(":aaaaa-aa");
        assert!(a.is_err());

        // All is empty
        let a = CanisterAlias::from_str(":");
        assert!(a.is_err());

        // No delimiter
        let a = CanisterAlias::from_str("blah");
        assert!(a.is_err());

        // All is good
        let a = CanisterAlias::from_str("foo:aaaaa-aa");
        assert!(a.is_ok());

        Ok(())
    }

    #[test]
    fn test_resolver() -> Result<(), Error> {
        let aliases = [
            "personhood:g3wsl-eqaaa-aaaan-aaaaa-cai",
            "identity:rdmx6-jaaaa-aaaaa-aaadq-cai",
            "nns:qoctq-giaaa-aaaaa-aaaea-cai",
        ]
        .into_iter()
        .map(|x| CanisterAlias::from_str(x).unwrap())
        .collect::<Vec<_>>();

        let domains = vec![fqdn!("ic0.app"), fqdn!("icp0.io")];
        let storage = create_test_storage();

        let resolver = CanisterResolver::new(
            domains.clone(),
            aliases.clone(),
            Arc::new(storage) as Arc<dyn LooksupCustomDomain>,
        )?;

        // Check aliases
        for d in &domains {
            // Ensure all aliases resolve with all domains
            for a in &aliases {
                let canister = resolver.lookup_alias(&FQDN::from_str(&format!("{}.{d}", a.0))?);
                assert_eq!(
                    canister,
                    Some(Canister {
                        id: a.1,
                        verify: true
                    })
                );
            }

            // Ensure that non-existant aliases do not resolve
            assert_eq!(
                resolver.lookup_alias(&FQDN::from_str(&format!("foo.{d}"))?),
                None
            );

            assert_eq!(
                resolver.lookup_alias(&FQDN::from_str(&format!("bar.{d}"))?),
                None
            );
        }

        // Check domains
        let id = Principal::from_text("aaaaa-aa").unwrap();

        // No canister ID
        assert_eq!(resolver.lookup_domain(&fqdn!("ic0.app")), None);
        assert_eq!(resolver.lookup_domain(&fqdn!("raw.ic0.app")), None);

        // Normal & raw
        assert_eq!(
            resolver.lookup_domain(&fqdn!("aaaaa-aa.ic0.app")),
            Some(Canister { id, verify: true })
        );
        assert_eq!(
            resolver.lookup_domain(&fqdn!("aaaaa-aa.icp0.io")),
            Some(Canister { id, verify: true })
        );
        assert_eq!(
            resolver.lookup_domain(&fqdn!("aaaaa-aa.raw.ic0.app")),
            Some(Canister { id, verify: false })
        );
        assert_eq!(
            resolver.lookup_domain(&fqdn!("aaaaa-aa.raw.icp0.io")),
            Some(Canister { id, verify: false })
        );

        // Nested subdomain should not match
        assert_eq!(resolver.lookup_domain(&fqdn!("aaaaa-aa.foo.ic0.app")), None);
        assert_eq!(resolver.lookup_domain(&fqdn!("aaaaa-aa.foo.icp0.io")), None);

        Ok(())
    }
}
