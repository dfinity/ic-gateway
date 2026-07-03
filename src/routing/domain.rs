use std::{
    collections::BTreeMap,
    fmt::Display,
    str::FromStr,
    sync::{Arc, LazyLock, RwLock},
    time::Instant,
};

use anyhow::{Context, Error, anyhow};
use arc_swap::ArcSwapOption;
use async_trait::async_trait;
use candid::Principal;
use fqdn::{FQDN, Fqdn, fqdn};
use ic_bn_lib::custom_domains::LooksUpCustomDomain;
use ic_bn_lib_common::{
    traits::{Healthy, Run, custom_domains::ProvidesCustomDomains},
    types::{CustomDomain, DomainFlags},
};
use prometheus::{
    IntCounter, IntGauge, Registry, register_int_counter_with_registry,
    register_int_gauge_with_registry,
};
use regex::Regex;
use tokio_util::sync::CancellationToken;
use tracing::{debug, warn};
use url::Url;

static PROVIDER_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^(?<url>[^|]+?)(?:\|(?<flags>[^<]*))?(?:<(?<prio>\d+)>)?$").unwrap()
});

/// Custom domain provider URL with optional flags and priority.
///
/// It is parsed from the following template by Clap: `https://foo.bar/path/to?foo=a|flag1|flag2<0>`
/// The delimiters chosen here (|<>) are forbidden in the URL by the RFC.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct CustomDomainHttpProvider {
    pub url: Url,
    pub priority: u8,
    pub flags: Option<DomainFlags>,
}

impl Display for CustomDomainHttpProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} (prio {})", self.url, self.priority)?;
        if let Some(v) = self.flags {
            write!(f, " (flags: {v})")?;
        }

        Ok(())
    }
}

impl FromStr for CustomDomainHttpProvider {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let caps = PROVIDER_RE
            .captures(s.trim())
            .ok_or_else(|| anyhow!("invalid provider format: {s}"))?;

        Ok(Self {
            url: Url::parse(&caps["url"]).context("unable to parse URL")?,

            flags: caps
                .name("flags")
                .map(|m| m.as_str().trim())
                .filter(|f| !f.is_empty())
                .map(DomainFlags::from_str)
                .transpose()
                .context("unable to parse flags")?,

            priority: caps
                .name("prio")
                .map(|m| m.as_str().parse())
                .transpose()
                .context("unable to parse priority as integer")?
                .unwrap_or(0),
        })
    }
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
    pub timestamp: u64,
    pub verify: bool,
    pub priority: u8,
    pub flags: Option<DomainFlags>,
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
    metric_dupes_overridden: IntGauge,
    metric_failures: IntCounter,
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

        let metric_dupes_overridden = register_int_gauge_with_registry!(
            format!("custom_domains_dupes_overridden"),
            format!(
                "Number of duplicates among custom domains that were overridden (higher prio/ts)"
            ),
            registry
        )
        .unwrap();

        let metric_failures = register_int_counter_with_registry!(
            format!("custom_domains_failures_total"),
            format!("Total number of fetch failures"),
            registry
        )
        .unwrap();

        Self {
            inner: ArcSwapOption::empty(),
            snapshot: RwLock::new(vec![None; providers.len()]),
            providers,
            metric_count,
            metric_dupes,
            metric_dupes_overridden,
            metric_failures,
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
                    warn!("{self:?}: unable to fetch domains from provider '{p:?}': {e:#}");

                    // Increment counter (total errors)
                    self.metric_failures.inc();
                }
            }
        }

        snapshot
    }

    #[allow(clippy::cast_possible_wrap)]
    pub async fn refresh(&self) {
        let start = Instant::now();

        let snapshot_old = self.snapshot.read().unwrap().clone();
        let snapshot = self.fetch(snapshot_old.clone()).await;

        // Check if the new set is different
        if snapshot == snapshot_old {
            debug!("{self:?}: domains haven't changed, not updating");
            return;
        }

        // Store the new snapshot
        self.snapshot.write().unwrap().clone_from(&snapshot);

        let mut tree: BTreeMap<FQDN, DomainLookup> = BTreeMap::new();

        // Convert the snapshot into new lookup structure
        let domains = snapshot.into_iter().flatten().flatten();
        let mut dupes = 0i64;
        let mut dupes_overridden = 0i64;

        for d in domains {
            // Do not add new domain if the same one exists with newer timestamp or higher prio.
            // Timestamps are only compared if the prio is the same.
            if let Some(exists) = tree.get(&d.name) {
                dupes += 1;

                if (exists.priority, exists.timestamp) > (d.priority, d.timestamp) {
                    continue;
                }

                dupes_overridden += 1;
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
                priority: d.priority,
                flags: d.flags,
            };

            tree.insert(d.name, dl);
        }

        warn!(
            "{self:?}: got new set of domains in {}s: {} ({dupes} dupes, {dupes_overridden} of them overridden)",
            start.elapsed().as_secs(),
            tree.len()
        );

        // Set metrics
        self.metric_count.set(tree.len() as i64);
        self.metric_dupes.set(dupes);
        self.metric_dupes_overridden.set(dupes_overridden);

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

impl LooksUpCustomDomain for CustomDomainStorage {
    fn lookup_custom_domain(&self, host: &Fqdn) -> Option<Principal> {
        self.inner
            .load_full()?
            .0
            .get(host)
            .and_then(|x| x.canister_id)
    }
}

/// Finds the domains by the hostname among base, api domains and aliases.
/// Also checks custom domain storage.
pub struct DomainResolver {
    domains_base: Vec<Domain>,
    domains_all: BTreeMap<FQDN, DomainLookup>,
    custom_domains: Arc<dyn ResolvesDomain>,
    skip_authority_validation: bool,
}

impl DomainResolver {
    pub fn new(
        domains_base: Vec<FQDN>,
        domains_api: Vec<FQDN>,
        aliases: Vec<CanisterAlias>,
        custom_domains: Arc<dyn ResolvesDomain>,
        skip_authority_validation: bool,
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
                        priority: 0,
                        flags: None,
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
                        priority: 0,
                        flags: None,
                    },
                )
            })
            .chain(aliases);

        Self {
            domains_all: domains_all.collect::<BTreeMap<_, _>>(),
            domains_base,
            custom_domains,
            skip_authority_validation,
        }
    }

    // Tries to find the base domain that corresponds to the given host and resolve a canister id
    fn resolve_domain(&self, host: &Fqdn) -> Option<DomainLookup> {
        // First try to find an exact match.
        // This covers base domains and their aliases, plus API domains
        if let Some(v) = self.domains_all.get(host) {
            return Some(v.clone());
        }

        // Next we try to lookup dynamic subdomains like <canister>.ic0.app or <canister>.raw.ic0.app
        // Check if the host is a subdomain of any of our base domains.
        let domain = match self
            .domains_base
            .iter()
            .find(|&x| host.is_subdomain_of(&x.name))
        {
            Some(d) => d,
            None if self.skip_authority_validation => {
                // When skipping authority validation, treat the host itself as the domain
                &Domain {
                    name: host.into(),
                    custom: false,
                    http: true,
                    api: true,
                }
            }
            None => return None,
        };

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
        let canister_id = if depth <= 1 || raw {
            Principal::from_text(label).ok()
        } else {
            None
        };

        Some(DomainLookup {
            domain: domain.clone(),
            canister_id,
            timestamp: 0,
            verify: !raw,
            priority: 0,
            flags: None,
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
    use ic_bn_lib_common::{
        principal,
        types::{FLAG_PRERENDER, FLAG_TEST},
    };

    use super::*;

    const TEST_CANISTER_ID: &str = "s6hwe-laaaa-aaaab-qaeba-cai";
    const TEST_CANISTER_ID_2: &str = "aaaaa-aa";
    const TEST_CANISTER_ID_3: &str = "oa7fk-maaaa-aaaam-abgka-cai";

    #[test]
    fn test_canister_alias() {
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
                name: fqdn!("foo.xyz"),
                canister_id: principal!(TEST_CANISTER_ID),
                timestamp: 10,
                priority: 0,
                flags: Some(DomainFlags::new([FLAG_TEST])),
            },
            CustomDomain {
                name: fqdn!("foo.xyz"),
                canister_id: principal!(TEST_CANISTER_ID),
                timestamp: 0,
                priority: 1,
                flags: Some(DomainFlags::new([FLAG_PRERENDER])),
            },
            CustomDomain {
                name: fqdn!("foo.bar"),
                canister_id: principal!(TEST_CANISTER_ID),
                timestamp: 30,
                priority: 0,
                flags: None,
            },
            CustomDomain {
                name: fqdn!("foo.bar"),
                canister_id: principal!(TEST_CANISTER_ID_2),
                timestamp: 20,
                priority: 0,
                flags: Some(DomainFlags::new([FLAG_PRERENDER])),
            },
            CustomDomain {
                name: fqdn!("foo.baz"),
                canister_id: principal!(TEST_CANISTER_ID),
                timestamp: 10,
                priority: 0,
                flags: None,
            },
            CustomDomain {
                name: fqdn!("foo.baz"),
                canister_id: principal!(TEST_CANISTER_ID_3),
                timestamp: 20,
                priority: 0,
                flags: None,
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

        // Verify metrics are tracked correctly
        assert_eq!(
            custom_domain_storage.metric_count.get(),
            3,
            "should have 3 domains after deduplication"
        );
        assert_eq!(
            custom_domain_storage.metric_dupes.get(),
            3,
            "should have 3 duplicates"
        );
        assert_eq!(
            custom_domain_storage.metric_failures.get(),
            1,
            "broken provider should have 1 failure"
        );

        let resolver = DomainResolver::new(
            domains_base.clone(),
            domains_api,
            aliases.clone(),
            Arc::new(custom_domain_storage),
            false, // skip_authority_validation
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
                        priority: 0,
                        flags: None,
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
                priority: 0,
                flags: None,
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
                priority: 0,
                flags: None,
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
                priority: 0,
                flags: None,
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
                priority: 0,
                flags: None,
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
                priority: 0,
                flags: None,
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
                priority: 0,
                flags: None,
            })
        );
        assert_eq!(
            resolver.resolve(&fqdn!("aaaaa-aa.raw.icp0.io")),
            Some(DomainLookup {
                domain: domain_icp0_io.clone(),
                canister_id: Some(canister_id),
                timestamp: 0,
                verify: false,
                priority: 0,
                flags: None,
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
                priority: 0,
                flags: None,
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
                priority: 0,
                flags: None,
            })
        );
        assert_eq!(
            resolver.resolve(&fqdn!("foo--bar--baz--aaaaa-aa.ic0.app")),
            Some(DomainLookup {
                domain: domain_ic0_app,
                canister_id: Some(canister_id),
                timestamp: 0,
                verify: true,
                priority: 0,
                flags: None,
            })
        );

        // 2-level non-raw subdomain should not resolve
        assert_eq!(resolver.resolve(&fqdn!("aaaaa-aa.foo.ic0.app")), None);
        assert_eq!(resolver.resolve(&fqdn!("aaaaa-aa.foo.icp0.io")), None,);

        // Resolve custom domains
        // Make sure that domain with higher timestamp are used
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
                priority: 0,
                flags: None,
            })
        );
        // Make sure that the domain with higher priority is used even when the timestamp of the other is higher
        assert_eq!(
            resolver.resolve(&fqdn!("foo.xyz")),
            Some(DomainLookup {
                domain: Domain {
                    name: fqdn!("foo.xyz"),
                    http: true,
                    api: true,
                    custom: true,
                },
                canister_id: Some(principal!(TEST_CANISTER_ID)),
                timestamp: 0,
                verify: true,
                priority: 1,
                flags: Some(DomainFlags::new([FLAG_PRERENDER])),
            })
        );
        // Equal priority, higher timestamp
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
                priority: 0,
                flags: None,
            })
        );

        // Something that's not there
        assert_eq!(resolver.resolve(&fqdn!("blah.blah")), None);

        Ok(())
    }

    #[test]
    fn test_skip_authority_validation() {
        let domains_base = vec![fqdn!("ic0.app")];
        let domains_api = vec![];
        let aliases = vec![];

        let registry_1 = Registry::new_custom(Some("test_skip_1".into()), None).unwrap();
        let custom_domain_storage_1 = CustomDomainStorage::new(vec![], &registry_1);

        // Test with skip_authority_validation = false
        let resolver_strict = DomainResolver::new(
            domains_base.clone(),
            domains_api.clone(),
            aliases.clone(),
            Arc::new(custom_domain_storage_1),
            false,
        );

        // Should fail to resolve a standalone canister ID without base domain
        assert_eq!(
            resolver_strict.resolve(&fqdn!("gwp4o-eaaaa-aaaaa-aaaap-2ai")),
            None
        );

        let registry_2 = Registry::new_custom(Some("test_skip_2".into()), None).unwrap();
        let custom_domain_storage_2 = CustomDomainStorage::new(vec![], &registry_2);

        // Test with skip_authority_validation = true
        let resolver_skip = DomainResolver::new(
            domains_base,
            domains_api,
            aliases,
            Arc::new(custom_domain_storage_2),
            true,
        );

        // Should resolve a standalone canister ID
        let result = resolver_skip.resolve(&fqdn!("gwp4o-eaaaa-aaaaa-aaaap-2ai"));
        assert!(result.is_some());
        let lookup = result.unwrap();
        assert_eq!(lookup.domain.name, fqdn!("gwp4o-eaaaa-aaaaa-aaaap-2ai"));
        assert_eq!(
            lookup.canister_id,
            Some(Principal::from_text("gwp4o-eaaaa-aaaaa-aaaap-2ai").unwrap())
        );

        // Should still work with normal subdomain patterns
        let result = resolver_skip.resolve(&fqdn!("aaaaa-aa.ic0.app"));
        assert!(result.is_some());
        let lookup = result.unwrap();
        assert_eq!(lookup.domain.name, fqdn!("ic0.app"));
        assert_eq!(
            lookup.canister_id,
            Some(Principal::from_text("aaaaa-aa").unwrap())
        );
    }

    #[test]
    fn test_custom_domain_provider_flags() {
        // with prio
        assert_eq!(
            CustomDomainHttpProvider::from_str("http://foo/bar|prerender<66>").unwrap(),
            CustomDomainHttpProvider {
                url: "http://foo/bar".parse().unwrap(),
                priority: 66,
                flags: Some(DomainFlags::new([FLAG_PRERENDER])),
            }
        );
        // with prio, empty flags
        assert_eq!(
            CustomDomainHttpProvider::from_str("http://foo/bar|<66>").unwrap(),
            CustomDomainHttpProvider {
                url: "http://foo/bar".parse().unwrap(),
                priority: 66,
                flags: None,
            }
        );
        // with prio, no flags
        assert_eq!(
            CustomDomainHttpProvider::from_str("http://foo/bar<66>").unwrap(),
            CustomDomainHttpProvider {
                url: "http://foo/bar".parse().unwrap(),
                priority: 66,
                flags: None,
            }
        );

        // no prio
        assert_eq!(
            CustomDomainHttpProvider::from_str("http://foo/bar|prerender").unwrap(),
            CustomDomainHttpProvider {
                url: "http://foo/bar".parse().unwrap(),
                priority: 0,
                flags: Some(DomainFlags::new([FLAG_PRERENDER])),
            }
        );

        // just url
        assert_eq!(
            CustomDomainHttpProvider::from_str("http://foo/bar").unwrap(),
            CustomDomainHttpProvider {
                url: "http://foo/bar".parse().unwrap(),
                priority: 0,
                flags: None,
            }
        );

        // error cases
        assert!(CustomDomainHttpProvider::from_str("http://foo/bar|prerender<x66>").is_err());
        assert!(CustomDomainHttpProvider::from_str("http://foo/bar|blah").is_err());
        assert!(CustomDomainHttpProvider::from_str("|||foo/bar|blah").is_err());
    }
}
