use std::{collections::BTreeMap, str::FromStr, sync::Arc, time::Duration};

use anyhow::{anyhow, Context, Error};
use arc_swap::ArcSwapOption;
use async_trait::async_trait;
use candid::Principal;
use derive_new::new;
use fqdn::{fqdn, Fqdn, FQDN};
use ic_bn_lib::tasks::Run;
use tokio::select;
use tokio_util::sync::CancellationToken;
use tracing::warn;

#[macro_export]
macro_rules! principal {
    ($id:expr) => {{
        Principal::from_text($id).unwrap()
    }};
}

/// Domain entity with certain metadata
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Domain {
    pub name: FQDN,
    // Whether it's custom domain
    pub custom: bool,
    // Whether we serve HTTP on this domain
    pub http: bool,
    // Whether we serve IC API on this domain
    pub api: bool,
}

/// Result of a domain lookup
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DomainLookup {
    pub domain: Domain,
    pub canister_id: Option<Principal>,
    pub verify: bool,
}

// Resolves hostname to a canister id
pub trait ResolvesDomain: Send + Sync {
    fn resolve(&self, host: &Fqdn) -> Option<DomainLookup>;
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

struct CustomDomainStorageInner(BTreeMap<FQDN, DomainLookup>);

/// Custom domain storage.
/// Fetches custom domains from several providers and stores them as `DomainLookups`
#[derive(new)]
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

        let domains = buf.into_iter().flatten().map(|x| {
            (
                x.name.clone(),
                DomainLookup {
                    domain: Domain {
                        name: x.name,
                        custom: true,
                        http: true,
                        api: true,
                    },
                    canister_id: Some(x.canister_id),
                    verify: true,
                },
            )
        });

        let inner = CustomDomainStorageInner(domains.collect::<BTreeMap<_, _>>());
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
                biased;

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

/// Implement looking up custom domain by hostname
impl ResolvesDomain for CustomDomainStorage {
    fn resolve(&self, host: &Fqdn) -> Option<DomainLookup> {
        self.inner.load_full()?.0.get(host).cloned()
    }
}

/// Finds the domains by the hostname among base, api domains and aliases.
/// Also checks custom domain storage.
pub struct DomainResolver {
    domains_base: Vec<Domain>,
    domains_all: BTreeMap<FQDN, DomainLookup>,
    custom_domains: Arc<dyn ResolvesDomain>,
}

impl DomainResolver {
    pub fn new(
        domains_base: Vec<FQDN>,
        domains_api: Vec<FQDN>,
        aliases: Vec<CanisterAlias>,
        custom_domains: Arc<dyn ResolvesDomain>,
    ) -> Self {
        fn domain(f: &Fqdn, http: bool) -> Domain {
            Domain {
                name: f.into(),
                custom: false,
                http,
                api: true,
            }
        }

        let domains_base = domains_base
            .into_iter()
            .map(|x| domain(&x, true))
            .collect::<Vec<_>>();

        let domains_api = domains_api
            .into_iter()
            .map(|x| domain(&x, false))
            .collect::<Vec<_>>();

        // Generate all alias+base_domain combinations
        let aliases = aliases.into_iter().flat_map(|alias| {
            domains_base.iter().map(move |domain| {
                (
                    // FQDN.FQDN is a valid FQDN, so macro is safe
                    fqdn!(&format!("{}.{}", alias.0, domain.name)),
                    DomainLookup {
                        domain: domain.clone(),
                        canister_id: Some(alias.1),
                        verify: true,
                    },
                )
            })
        });

        // Combine all domains
        let domains_all = domains_base
            .clone()
            .into_iter()
            .chain(domains_api)
            .map(|x| {
                (
                    x.name.clone(),
                    DomainLookup {
                        domain: x,
                        canister_id: None,
                        verify: true,
                    },
                )
            })
            .chain(aliases);

        Self {
            domains_all: domains_all.collect::<BTreeMap<_, _>>(),
            domains_base,
            custom_domains,
        }
    }

    // Tries to find the base domain that corresponds to the given host and resolve a canister id
    fn resolve_domain(&self, host: &Fqdn) -> Option<DomainLookup> {
        // First try to find an exact match
        // This covers base domains and their aliases, plus API domains
        if let Some(v) = self.domains_all.get(host) {
            return Some(v.clone());
        }

        // Next we try to lookup dynamic subdomains like <canister>.ic0.app or <canister>.raw.ic0.app
        // Check if the host is a subdomain of any of our base domains.
        let domain = self
            .domains_base
            .iter()
            .find(|&x| host.is_subdomain_of(&x.name))?;

        // Host can be 1 or 2 levels below base domain only: <id>.<domain> or <id>.raw.<domain>
        // Fail the lookup if it's deeper.
        let depth = host.labels().count() - domain.name.labels().count();
        if depth > 2 {
            return None;
        }

        // Check if it's a raw domain
        let raw = depth == 2;
        if raw && host.labels().nth(1) != Some("raw") {
            return None;
        }

        // Strip the optional prefix if any
        let label = host.labels().next()?.split("--").last()?;

        // Do not allow cases like <id>.foo.ic0.app where
        // the base subdomain is not raw or <id>.
        // TODO discuss
        let canister_id = if depth == 1 || raw {
            Principal::from_text(label).ok()
        } else {
            None
        };

        Some(DomainLookup {
            domain: domain.clone(),
            canister_id,
            verify: !raw,
        })
    }
}

impl ResolvesDomain for DomainResolver {
    fn resolve(&self, host: &Fqdn) -> Option<DomainLookup> {
        // Try to resolve canister using different sources
        self.resolve_domain(host)
            .or_else(|| self.custom_domains.resolve(host))
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

        let domains_base = vec![fqdn!("ic0.app"), fqdn!("icp0.io")];
        let domains_api = vec![fqdn!("icp-api.io")];
        let custom_domain_provider = TestCustomDomainProvider(CustomDomain {
            name: fqdn!("foo.baz"),
            canister_id: principal!(TEST_CANISTER_ID),
        });

        let custom_domain_storage =
            CustomDomainStorage::new(vec![Arc::new(custom_domain_provider)], Duration::ZERO);
        custom_domain_storage.refresh().await?;

        let resolver = DomainResolver::new(
            domains_base.clone(),
            domains_api,
            aliases.clone(),
            Arc::new(custom_domain_storage),
        );

        // Check aliases
        for d in &domains_base {
            // Ensure all aliases resolve with all domains
            for a in &aliases {
                assert_eq!(
                    resolver.resolve(&fqdn!(&format!("{}.{d}", a.0))),
                    Some(DomainLookup {
                        domain: Domain {
                            name: d.clone(),
                            custom: false,
                            http: true,
                            api: true,
                        },
                        canister_id: Some(a.1),
                        verify: true,
                    })
                );
            }
        }

        // Check resolving
        let canister_id = principal!("aaaaa-aa");
        let domain_ic0_app = Domain {
            name: fqdn!("ic0.app"),
            http: true,
            api: true,
            custom: false,
        };
        let domain_icp0_io = Domain {
            name: fqdn!("icp0.io"),
            http: true,
            api: true,
            custom: false,
        };
        let domain_icp_api_io = Domain {
            name: fqdn!("icp-api.io"),
            http: false,
            api: true,
            custom: false,
        };
        let domain_foo_baz = Domain {
            name: fqdn!("foo.baz"),
            http: true,
            api: true,
            custom: true,
        };

        // Base domain, no canister ID
        assert_eq!(
            resolver.resolve(&fqdn!("ic0.app")),
            Some(DomainLookup {
                domain: domain_ic0_app.clone(),
                canister_id: None,
                verify: true,
            })
        );

        // API domain
        assert_eq!(
            resolver.resolve(&fqdn!("icp-api.io")),
            Some(DomainLookup {
                domain: domain_icp_api_io.clone(),
                canister_id: None,
                verify: true,
            })
        );

        // API domain with canister shouldn't resolve
        assert_eq!(resolver.resolve(&fqdn!("aaaaa-aa.icp-api.io")), None);

        // Raw subdomain but w/o canister
        assert_eq!(
            resolver.resolve(&fqdn!("raw.ic0.app")),
            Some(DomainLookup {
                domain: domain_ic0_app.clone(),
                canister_id: None,
                verify: true,
            })
        );

        // Base domain with canister
        assert_eq!(
            resolver.resolve(&fqdn!("aaaaa-aa.ic0.app")),
            Some(DomainLookup {
                domain: domain_ic0_app.clone(),
                canister_id: Some(canister_id),
                verify: true,
            })
        );

        // Another one
        assert_eq!(
            resolver.resolve(&fqdn!("aaaaa-aa.icp0.io")),
            Some(DomainLookup {
                domain: domain_icp0_io.clone(),
                canister_id: Some(canister_id),
                verify: true,
            })
        );

        // Raw
        assert_eq!(
            resolver.resolve(&fqdn!("aaaaa-aa.raw.ic0.app")),
            Some(DomainLookup {
                domain: domain_ic0_app.clone(),
                canister_id: Some(canister_id),
                verify: false,
            })
        );
        assert_eq!(
            resolver.resolve(&fqdn!("aaaaa-aa.raw.icp0.io")),
            Some(DomainLookup {
                domain: domain_icp0_io.clone(),
                canister_id: Some(canister_id),
                verify: false,
            })
        );

        // Malformed canister shouldn't resolve
        assert_eq!(
            resolver.resolve(&fqdn!("aaaaa-aaa.icp0.io")),
            Some(DomainLookup {
                domain: domain_icp0_io.clone(),
                canister_id: None,
                verify: true,
            })
        );

        // With prefix--
        assert_eq!(
            resolver.resolve(&fqdn!("foo--aaaaa-aa.ic0.app")),
            Some(DomainLookup {
                domain: domain_ic0_app.clone(),
                canister_id: Some(canister_id),
                verify: true,
            })
        );
        assert_eq!(
            resolver.resolve(&fqdn!("foo--bar--baz--aaaaa-aa.ic0.app")),
            Some(DomainLookup {
                domain: domain_ic0_app.clone(),
                canister_id: Some(canister_id),
                verify: true,
            })
        );

        // 2-level non-raw subdomain should not resolve
        assert_eq!(resolver.resolve(&fqdn!("aaaaa-aa.foo.ic0.app")), None);
        assert_eq!(resolver.resolve(&fqdn!("aaaaa-aa.foo.icp0.io")), None,);

        // Resolve custom domain
        assert_eq!(
            resolver.resolve(&fqdn!("foo.baz")),
            Some(DomainLookup {
                domain: domain_foo_baz.clone(),
                canister_id: Some(principal!(TEST_CANISTER_ID)),
                verify: true,
            })
        );

        // Something that's not there
        assert_eq!(resolver.resolve(&fqdn!("blah.blah")), None);

        Ok(())
    }
}
