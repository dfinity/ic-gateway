use std::{
    collections::BTreeMap,
    str::FromStr,
    sync::{Arc, RwLock},
};

use anyhow::{Context, Error, anyhow};
use arc_swap::ArcSwapOption;
use async_trait::async_trait;
use candid::Principal;
use fqdn::{FQDN, Fqdn, fqdn};
use ic_bn_lib_common::{
    traits::{Healthy, Run, custom_domains::ProvidesCustomDomains},
    types::CustomDomain,
};
use prometheus::{IntGauge, Registry, register_int_gauge_with_registry};
use tokio_util::sync::CancellationToken;
use tracing::{debug, warn};

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
    pub timestamp: u64,
    pub verify: bool,
}

/// Resolves hostname to a canister id
pub trait ResolvesDomain: Send + Sync {
    fn resolve(&self, host: &Fqdn) -> Option<DomainLookup>;
}

/// Alias for a canister under all served domains.
/// E.g. an alias 'nns' would resolve under both 'nns.ic0.app' and 'nns.icp0.io'
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
/// Fetches custom domains from several providers and stores them as `DomainLookup`
pub struct CustomDomainStorage {
    providers: Vec<Arc<dyn ProvidesCustomDomains>>,
    inner: ArcSwapOption<CustomDomainStorageInner>,
    snapshot: RwLock<Vec<Option<Vec<CustomDomain>>>>,
    metric_count: IntGauge,
    metric_dupes: IntGauge,
}

impl Healthy for CustomDomainStorage {
    fn healthy(&self) -> bool {
        // We're healthy if all providers delivered custom domains successfully at least once
        self.snapshot.read().unwrap().iter().all(|x| x.is_some())
    }
}

impl std::fmt::Debug for CustomDomainStorage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "CustomDomainStorage")
    }
}

impl CustomDomainStorage {
    pub fn new(providers: Vec<Arc<dyn ProvidesCustomDomains>>, registry: &Registry) -> Self {
        let metric_count = register_int_gauge_with_registry!(
            format!("custom_domains_count"),
            format!("Number of custom domains loaded"),
            registry
        )
        .unwrap();

        let metric_dupes = register_int_gauge_with_registry!(
            format!("custom_domains_dupes"),
            format!("Number of duplicates among custom domains"),
            registry
        )
        .unwrap();

        Self {
            inner: ArcSwapOption::empty(),
            snapshot: RwLock::new(vec![None; providers.len()]),
            providers,
            metric_count,
            metric_dupes,
        }
    }

    /// Fetches the new set of domains from each provider on top of the provided snapshot
    async fn fetch(
        &self,
        mut snapshot: Vec<Option<Vec<CustomDomain>>>,
    ) -> Vec<Option<Vec<CustomDomain>>> {
        for (i, p) in self.providers.iter().enumerate() {
            match p.get_custom_domains().await {
                Ok(mut v) => {
                    v.sort_by(|a, b| a.name.cmp(&b.name));
                    snapshot[i] = Some(v);
                }

                Err(e) => {
                    warn!("{self:?}: unable to fetch domains from provider '{p:?}': {e:#}")
                }
            }
        }

        snapshot
    }

    pub async fn refresh(&self) {
        let snapshot_old = self.snapshot.read().unwrap().clone();
        let snapshot = self.fetch(snapshot_old.clone()).await;

        // Check if the new set is different
        if snapshot == snapshot_old {
            debug!("{self:?}: domains haven't changed, not updating");
            return;
        }

        // Store the new snapshot
        *self.snapshot.write().unwrap() = snapshot.clone();

        let mut tree: BTreeMap<FQDN, DomainLookup> = BTreeMap::new();

        // Convert the snapshot into new lookup structure
        let domains = snapshot.into_iter().flatten().flatten();
        let mut dupes = 0;

        for d in domains {
            // Do not add new domain if the same one exists with newer timestamp
            if let Some(v) = tree.get(&d.name) {
                dupes += 1;

                if v.timestamp > d.timestamp {
                    continue;
                }
            }

            let dl = DomainLookup {
                domain: Domain {
                    name: d.name.clone(),
                    custom: true,
                    http: true,
                    api: true,
                },
                timestamp: d.timestamp,
                canister_id: Some(d.canister_id),
                verify: true,
            };

            tree.insert(d.name, dl);
        }

        warn!(
            "{self:?}: got new set of domains: {} ({dupes} duplicates)",
            tree.len()
        );

        // Set metrics
        self.metric_count.set(tree.len() as i64);
        self.metric_dupes.set(dupes as i64);

        // Store it
        let inner = CustomDomainStorageInner(tree);
        self.inner.store(Some(Arc::new(inner)));
    }
}

#[async_trait]
impl Run for CustomDomainStorage {
    async fn run(&self, _: CancellationToken) -> Result<(), Error> {
        self.refresh().await;
        Ok(())
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
                        timestamp: 0,
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
                        timestamp: 0,
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
            timestamp: 0,
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
    use ic_bn_lib_common::principal;

    use super::*;

    const TEST_CANISTER_ID: &str = "s6hwe-laaaa-aaaab-qaeba-cai";
    const TEST_CANISTER_ID_2: &str = "aaaaa-aa";
    const TEST_CANISTER_ID_3: &str = "oa7fk-maaaa-aaaam-abgka-cai";

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

    #[derive(Debug)]
    struct TestCustomDomainProvider(Vec<CustomDomain>);

    #[async_trait]
    impl ProvidesCustomDomains for TestCustomDomainProvider {
        async fn get_custom_domains(&self) -> Result<Vec<CustomDomain>, Error> {
            Ok(self.0.clone())
        }
    }

    #[derive(Debug)]
    struct TestCustomDomainProviderBroken;

    #[async_trait]
    impl ProvidesCustomDomains for TestCustomDomainProviderBroken {
        async fn get_custom_domains(&self) -> Result<Vec<CustomDomain>, Error> {
            Err(anyhow!("I'm dead"))
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
        let custom_domain_provider = TestCustomDomainProvider(vec![
            CustomDomain {
                name: fqdn!("foo.bar"),
                timestamp: 30,
                canister_id: principal!(TEST_CANISTER_ID),
            },
            CustomDomain {
                name: fqdn!("foo.bar"),
                timestamp: 20,
                canister_id: principal!(TEST_CANISTER_ID_2),
            },
            CustomDomain {
                name: fqdn!("foo.baz"),
                timestamp: 10,
                canister_id: principal!(TEST_CANISTER_ID),
            },
            CustomDomain {
                name: fqdn!("foo.baz"),
                timestamp: 20,
                canister_id: principal!(TEST_CANISTER_ID_3),
            },
        ]);

        // Add one working and one broken provider to make sure that broken one doesn't affect the outcome
        let custom_domain_storage = CustomDomainStorage::new(
            vec![
                Arc::new(custom_domain_provider),
                Arc::new(TestCustomDomainProviderBroken),
            ],
            &Registry::new(),
        );
        custom_domain_storage.refresh().await;

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
                        timestamp: 0,
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

        // Base domain, no canister ID
        assert_eq!(
            resolver.resolve(&fqdn!("ic0.app")),
            Some(DomainLookup {
                domain: domain_ic0_app.clone(),
                canister_id: None,
                timestamp: 0,
                verify: true,
            })
        );

        // API domain
        assert_eq!(
            resolver.resolve(&fqdn!("icp-api.io")),
            Some(DomainLookup {
                domain: domain_icp_api_io,
                canister_id: None,
                timestamp: 0,
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
                timestamp: 0,
                verify: true,
            })
        );

        // Base domain with canister
        assert_eq!(
            resolver.resolve(&fqdn!("aaaaa-aa.ic0.app")),
            Some(DomainLookup {
                domain: domain_ic0_app.clone(),
                canister_id: Some(canister_id),
                timestamp: 0,
                verify: true,
            })
        );

        // Another one
        assert_eq!(
            resolver.resolve(&fqdn!("aaaaa-aa.icp0.io")),
            Some(DomainLookup {
                domain: domain_icp0_io.clone(),
                canister_id: Some(canister_id),
                timestamp: 0,
                verify: true,
            })
        );

        // Raw
        assert_eq!(
            resolver.resolve(&fqdn!("aaaaa-aa.raw.ic0.app")),
            Some(DomainLookup {
                domain: domain_ic0_app.clone(),
                canister_id: Some(canister_id),
                timestamp: 0,
                verify: false,
            })
        );
        assert_eq!(
            resolver.resolve(&fqdn!("aaaaa-aa.raw.icp0.io")),
            Some(DomainLookup {
                domain: domain_icp0_io.clone(),
                canister_id: Some(canister_id),
                timestamp: 0,
                verify: false,
            })
        );

        // Malformed canister shouldn't resolve
        assert_eq!(
            resolver.resolve(&fqdn!("aaaaa-aaa.icp0.io")),
            Some(DomainLookup {
                domain: domain_icp0_io,
                canister_id: None,
                timestamp: 0,
                verify: true,
            })
        );

        // With prefix--
        assert_eq!(
            resolver.resolve(&fqdn!("foo--aaaaa-aa.ic0.app")),
            Some(DomainLookup {
                domain: domain_ic0_app.clone(),
                canister_id: Some(canister_id),
                timestamp: 0,
                verify: true,
            })
        );
        assert_eq!(
            resolver.resolve(&fqdn!("foo--bar--baz--aaaaa-aa.ic0.app")),
            Some(DomainLookup {
                domain: domain_ic0_app,
                canister_id: Some(canister_id),
                timestamp: 0,
                verify: true,
            })
        );

        // 2-level non-raw subdomain should not resolve
        assert_eq!(resolver.resolve(&fqdn!("aaaaa-aa.foo.ic0.app")), None);
        assert_eq!(resolver.resolve(&fqdn!("aaaaa-aa.foo.icp0.io")), None,);

        // Resolve custom domains
        // Make sure that newer custom domains are used (with higher timestamp)
        assert_eq!(
            resolver.resolve(&fqdn!("foo.bar")),
            Some(DomainLookup {
                domain: Domain {
                    name: fqdn!("foo.bar"),
                    http: true,
                    api: true,
                    custom: true,
                },
                canister_id: Some(principal!(TEST_CANISTER_ID)),
                timestamp: 30,
                verify: true,
            })
        );
        assert_eq!(
            resolver.resolve(&fqdn!("foo.baz")),
            Some(DomainLookup {
                domain: Domain {
                    name: fqdn!("foo.baz"),
                    http: true,
                    api: true,
                    custom: true,
                },
                canister_id: Some(principal!(TEST_CANISTER_ID_3)),
                timestamp: 20,
                verify: true,
            })
        );

        // Something that's not there
        assert_eq!(resolver.resolve(&fqdn!("blah.blah")), None);

        Ok(())
    }
}
