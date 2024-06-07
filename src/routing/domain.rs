use std::{collections::BTreeMap, str::FromStr, sync::Arc, time::Duration};

use anyhow::{anyhow, Context, Error};
use arc_swap::ArcSwapOption;
use async_trait::async_trait;
use candid::Principal;
use fqdn::{Fqdn, FQDN};
use tokio::select;
use tokio_util::sync::CancellationToken;
use tracing::warn;

use crate::tasks::Run;

#[macro_export]
macro_rules! principal {
    ($id:expr) => {{
        #[allow(unused_mut)]
        Principal::from_text($id).unwrap()
    }};
}

// Resolves hostname to a canister id
pub trait ResolvesDomain: Send + Sync {
    fn resolve(&self, host: &Fqdn) -> Option<Domain>;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CustomDomain {
    pub name: FQDN,
    pub canister_id: Principal,
}

// Provides a list of custom domains
#[async_trait]
pub trait ProvidesCustomDomains: Sync + Send {
    async fn get_custom_domains(&self) -> Result<Vec<CustomDomain>, Error>;
}

// Looks up custom domain canister id by hostname
pub trait LooksupCustomDomain: Sync + Send {
    fn lookup_custom_domain(&self, hostname: &Fqdn) -> Option<CustomDomain>;
}

// Alias for a canister under all served domains.
// E.g. an alias 'nns' would resolve under both 'nns.ic0.app' and 'nns.icp0.io'
#[derive(Clone)]
pub struct CanisterAlias(FQDN, Principal);

impl FromStr for CanisterAlias {
    type Err = Error;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        const INVALID_ALIAS_FORMAT: &str = "Invalid alias format, must be '<alias>:<canister_id>'";

        match value.split_once(':') {
            Some((alias, principal)) => {
                if alias.is_empty() {
                    return Err(anyhow!(INVALID_ALIAS_FORMAT));
                }

                Ok(Self(
                    FQDN::from_str(alias).context("unable to parse alias as FQDN")?,
                    Principal::from_str(principal)
                        .context("unable to parse canister id as Principal")?,
                ))
            }

            None => Err(anyhow!(INVALID_ALIAS_FORMAT)),
        }
    }
}

struct CustomDomainStorageInner {
    // BTreeMap seems to be faster than HashMap
    // for smaller datasets due to cache locality
    custom_domains: BTreeMap<FQDN, CustomDomain>,
}

// Custom domain storage
#[derive(derive_new::new)]
pub struct CustomDomainStorage {
    providers: Vec<Arc<dyn ProvidesCustomDomains>>,
    poll_interval: Duration,
    #[new(default)]
    inner: ArcSwapOption<CustomDomainStorageInner>,
}

impl CustomDomainStorage {
    async fn refresh(&self) -> Result<(), Error> {
        let mut buf = vec![];
        for p in &self.providers {
            buf.push(p.get_custom_domains().await?);
        }

        let inner = CustomDomainStorageInner {
            custom_domains: BTreeMap::from_iter(
                buf.into_iter().flatten().map(|x| (x.name.clone(), x)),
            ),
        };
        self.inner.store(Some(Arc::new(inner)));

        Ok(())
    }
}

#[async_trait]
impl Run for CustomDomainStorage {
    async fn run(&self, token: CancellationToken) -> Result<(), Error> {
        let mut interval = tokio::time::interval(self.poll_interval);

        loop {
            select! {
                () = token.cancelled() => {
                    warn!("CustomDomainStorage: exiting");
                    return Ok(());
                },

                _ = interval.tick() => {
                    if let Err(e) = self.refresh().await {
                        warn!("CustomDomainStorage: unable to refresh: {e:#}");
                    }
                }
            }
        }
    }
}

// Implement looking up custom domain canister id by hostname
impl LooksupCustomDomain for CustomDomainStorage {
    fn lookup_custom_domain(&self, hostname: &Fqdn) -> Option<CustomDomain> {
        self.inner
            .load_full()?
            .custom_domains
            .get(hostname)
            .cloned()
    }
}

// Combination of canister id and whether we need to verify the response
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Domain {
    pub name: FQDN,
    pub canister_id: Option<Principal>,
    pub verify: bool,
    // Whether it's custom domain
    pub custom: bool,
}

pub struct DomainResolver {
    domains: Vec<FQDN>,
    aliases: Vec<(FQDN, Domain)>,
    custom_domains: Arc<dyn LooksupCustomDomain>,
}

impl DomainResolver {
    pub fn new(
        domains: Vec<FQDN>,
        aliases_in: Vec<CanisterAlias>,
        custom_domains: Arc<dyn LooksupCustomDomain>,
    ) -> Result<Self, Error> {
        let mut aliases = vec![];
        // Generate a list of all alias+domain combinations
        for a in aliases_in {
            for d in &domains {
                aliases.push((
                    FQDN::from_str(&format!("{}.{d}", a.0))?,
                    Domain {
                        name: d.clone(),
                        canister_id: Some(a.1),
                        verify: true,
                        custom: false,
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
    // This will also match any subdomains of the alias - TODO discuss
    fn resolve_alias(&self, host: &Fqdn) -> Option<Domain> {
        self.aliases
            .iter()
            .find(|x| host.is_subdomain_of(&x.0))
            .map(|x| x.1.clone())
    }

    // Tries to find the base domain that corresponds to the given host and resolve a canister id
    // Expects <canister_id>.<domain> or <canister_id>.raw.<domain> where <canister_id> can have
    // an optional prefix of `<foo>--` which is discarded
    fn resolve_domain(&self, host: &Fqdn) -> Option<Domain> {
        // Check if the host is a subdomain of any of our base domains.
        // The host is also a subdomain of itself, so they can be equal.
        let name = self
            .domains
            .iter()
            .find(|&x| host.is_subdomain_of(x))?
            .to_owned();

        // Host can be 1 or 2 levels below base domain only: <id>.<domain> or <id>.raw.<domain>
        // Fail the lookup if it's deeper.
        let depth = host.labels().count() - name.labels().count();
        if depth > 2 {
            return None;
        }

        // Check if it's a raw domain
        let raw = depth == 2 && host.labels().nth(1) == Some("raw");

        // Attempt to extract canister_id
        let label = host.labels().next()?.split("--").last()?;

        // Do not allow cases like <id>.foo.ic0.app where
        // the base subdomain is not raw or <id>.
        // TODO discuss
        let canister_id = if depth == 1 || (depth == 2 && raw) {
            Principal::from_text(label).ok()
        } else {
            None
        };

        Some(Domain {
            name,
            canister_id,
            verify: !raw,
            custom: false,
        })
    }
}

impl ResolvesDomain for DomainResolver {
    fn resolve(&self, host: &Fqdn) -> Option<Domain> {
        // Try to resolve canister using different sources
        self.resolve_alias(host)
            .or_else(|| self.resolve_domain(host))
            .or_else(|| {
                let custom = self.custom_domains.lookup_custom_domain(host)?;
                Some(Domain {
                    name: host.to_owned(),
                    canister_id: Some(custom.canister_id),
                    verify: true,
                    custom: true,
                })
            })
    }
}

#[cfg(test)]
mod test {
    use fqdn::fqdn;

    use super::*;

    const TEST_CANISTER_ID: &str = "s6hwe-laaaa-aaaab-qaeba-cai";

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

        let a = CanisterAlias::from_str("|||:aaaaa-aa");
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

    struct TestCustomDomainProvider(CustomDomain);

    #[async_trait]
    impl ProvidesCustomDomains for TestCustomDomainProvider {
        async fn get_custom_domains(&self) -> Result<Vec<CustomDomain>, Error> {
            Ok(vec![self.0.clone()])
        }
    }

    #[tokio::test]
    async fn test_resolver() -> Result<(), Error> {
        let aliases = [
            "personhood:g3wsl-eqaaa-aaaan-aaaaa-cai",
            "identity:rdmx6-jaaaa-aaaaa-aaadq-cai",
            "nns:qoctq-giaaa-aaaaa-aaaea-cai",
        ]
        .into_iter()
        .map(|x| CanisterAlias::from_str(x).unwrap())
        .collect::<Vec<_>>();

        let domains = vec![fqdn!("ic0.app"), fqdn!("icp0.io"), fqdn!("foo")];
        let custom_domain_provider = TestCustomDomainProvider(CustomDomain {
            name: fqdn!("foo.baz"),
            canister_id: principal!(TEST_CANISTER_ID),
        });
        let custom_domain_storage =
            CustomDomainStorage::new(vec![Arc::new(custom_domain_provider)], Duration::ZERO);
        custom_domain_storage.refresh().await?;
        let resolver = DomainResolver::new(
            domains.clone(),
            aliases.clone(),
            Arc::new(custom_domain_storage),
        )?;

        // Check aliases
        for d in &domains {
            // Ensure all aliases resolve with all domains
            for a in &aliases {
                assert_eq!(
                    resolver.resolve_alias(&fqdn!(&format!("{}.{d}", a.0))),
                    Some(Domain {
                        name: d.clone(),
                        canister_id: Some(a.1),
                        verify: true,
                        custom: false,
                    })
                );
            }

            // Ensure that non-existant aliases do not resolve
            assert_eq!(
                resolver.resolve_alias(&FQDN::from_str(&format!("foo.{d}"))?),
                None
            );

            assert_eq!(
                resolver.resolve_alias(&FQDN::from_str(&format!("bar.{d}"))?),
                None
            );
        }

        // Check domains
        let id = principal!("aaaaa-aa");

        // No canister ID
        assert_eq!(
            resolver.resolve_domain(&fqdn!("ic0.app")),
            Some(Domain {
                name: fqdn!("ic0.app"),
                canister_id: None,
                verify: true,
                custom: false,
            })
        );

        // Some subdomain
        assert_eq!(
            resolver.resolve_domain(&fqdn!("raw.ic0.app")),
            Some(Domain {
                name: fqdn!("ic0.app"),
                canister_id: None,
                verify: true,
                custom: false,
            })
        );

        // Normal
        assert_eq!(
            resolver.resolve_domain(&fqdn!("aaaaa-aa.ic0.app")),
            Some(Domain {
                name: fqdn!("ic0.app"),
                canister_id: Some(id),
                verify: true,
                custom: false,
            })
        );
        assert_eq!(
            resolver.resolve_domain(&fqdn!("aaaaa-aa.icp0.io")),
            Some(Domain {
                name: fqdn!("icp0.io"),
                canister_id: Some(id),
                verify: true,
                custom: false,
            })
        );

        // Raw
        assert_eq!(
            resolver.resolve_domain(&fqdn!("aaaaa-aa.raw.ic0.app")),
            Some(Domain {
                name: fqdn!("ic0.app"),
                canister_id: Some(id),
                verify: false,
                custom: false,
            })
        );
        assert_eq!(
            resolver.resolve_domain(&fqdn!("aaaaa-aa.raw.icp0.io")),
            Some(Domain {
                name: fqdn!("icp0.io"),
                canister_id: Some(id),
                verify: false,
                custom: false,
            })
        );

        // foo--<canister_id>
        assert_eq!(
            resolver.resolve_domain(&fqdn!("foo--aaaaa-aa.ic0.app")),
            Some(Domain {
                name: fqdn!("ic0.app"),
                canister_id: Some(id),
                verify: true,
                custom: false,
            })
        );

        assert_eq!(
            resolver.resolve_domain(&fqdn!("foo--bar--aaaaa-aa.ic0.app")),
            Some(Domain {
                name: fqdn!("ic0.app"),
                canister_id: Some(id),
                verify: true,
                custom: false,
            })
        );

        // Nested subdomain should not match canister id (?)
        assert_eq!(
            resolver.resolve_domain(&fqdn!("aaaaa-aa.foo.ic0.app")),
            Some(Domain {
                name: fqdn!("ic0.app"),
                canister_id: None,
                verify: true,
                custom: false,
            })
        );
        assert_eq!(
            resolver.resolve_domain(&fqdn!("aaaaa-aa.foo.icp0.io")),
            Some(Domain {
                name: fqdn!("icp0.io"),
                canister_id: None,
                verify: true,
                custom: false,
            })
        );

        // Check the trait
        // Resolve from alias
        assert_eq!(
            resolver.resolve(&fqdn!("nns.ic0.app")),
            Some(Domain {
                canister_id: Some(principal!("qoctq-giaaa-aaaaa-aaaea-cai")),
                name: fqdn!("ic0.app"),
                verify: true,
                custom: false,
            })
        );

        // Resolve from hostname
        assert_eq!(
            resolver.resolve(&fqdn!("aaaaa-aa.ic0.app")),
            Some(Domain {
                name: fqdn!("ic0.app"),
                canister_id: Some(id),
                verify: true,
                custom: false,
            })
        );

        assert_eq!(
            resolver.resolve(&fqdn!("aaaaa-aa.raw.ic0.app")),
            Some(Domain {
                name: fqdn!("ic0.app"),
                canister_id: Some(id),
                verify: false,
                custom: false,
            })
        );

        // Resolve custom domain
        assert_eq!(
            resolver.resolve(&fqdn!("foo.baz")),
            Some(Domain {
                name: fqdn!("foo.baz"),
                canister_id: Some(principal!(TEST_CANISTER_ID)),
                verify: true,
                custom: true,
            })
        );

        // Something that's not there
        assert_eq!(resolver.resolve(&fqdn!("blah.blah")), None);

        Ok(())
    }
}
