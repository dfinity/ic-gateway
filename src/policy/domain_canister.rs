use std::sync::Arc;

use ahash::AHashSet;
use arc_swap::ArcSwapOption;
use candid::Principal;
use fqdn::{FQDN, Fqdn};

use crate::routing::ic::subnets_info::{SubnetType, SubnetsInfo};

/// Things needed to verify domain-canister match
#[derive(derive_new::new)]
pub struct DomainCanisterMatcher {
    pre_isolation_canisters: AHashSet<Principal>,
    domains_app: Vec<FQDN>,
    domains_system: Vec<FQDN>,
    domains_engine: Vec<FQDN>,
    subnets_info: Arc<ArcSwapOption<SubnetsInfo>>,
}

impl DomainCanisterMatcher {
    /// Check if given canister id and host match from policy perspective.
    pub fn check(&self, canister_id: Principal, host: &Fqdn) -> bool {
        let guard = self.subnets_info.load();
        // Compute subnet type once; `None` when no snapshot has been stored yet.
        let subnet_type = guard.as_deref().and_then(|si| si.subnet_type(canister_id));

        // Pre-isolation canisters are exempt from domain checks, unless they are
        // on a CloudEngine subnet, where the normal domain policy still applies.
        if self.pre_isolation_canisters.contains(&canister_id)
            && subnet_type != Some(SubnetType::CloudEngine)
        {
            return true;
        }

        let domains = match subnet_type {
            Some(SubnetType::System) => &self.domains_system,
            Some(SubnetType::CloudEngine) => &self.domains_engine,
            Some(SubnetType::Application)
            | Some(SubnetType::VerifiedApplication)
            | Some(SubnetType::Unknown)
            | None => &self.domains_app,
        };

        domains.iter().any(|x| host.is_subdomain_of(x))
    }
}

#[cfg(test)]
mod tests {
    use ahash::AHashMap;
    use arc_swap::ArcSwapOption;
    use fqdn::fqdn;
    use ic_bn_lib_common::principal;

    use super::*;
    use crate::routing::ic::subnets_info::SubnetType;

    use crate::test::TEST_ROOT_SUBNET_ID;

    // Principals used as subnet IDs in the test snapshot
    const SUBNET_SYSTEM: &str = TEST_ROOT_SUBNET_ID;
    const SUBNET_ENGINE: &str = "nl6hn-ja4yw-wvmpy-3z2jx-ymc34-pisx3-3cp5z-3oj4a-qzzny-jbsv3-4qe";

    // Canisters that fall inside the ranges defined below
    const CANISTER_SYSTEM: &str = "qoctq-giaaa-aaaaa-aaaea-cai"; // NNS
    const CANISTER_ENGINE: &str = "s6hwe-laaaa-aaaab-qaeba-cai";
    const CANISTER_APP: &str = "oydqf-haaaa-aaaao-afpsa-cai";
    const CANISTER_PIC: &str = "2dcn6-oqaaa-aaaai-abvoq-cai"; // pre-isolation

    fn test_snapshot() -> Arc<ArcSwapOption<SubnetsInfo>> {
        let subnet_system = principal!(SUBNET_SYSTEM);
        let subnet_engine = principal!(SUBNET_ENGINE);

        let ranges = vec![
            (
                principal!(CANISTER_SYSTEM),
                principal!(CANISTER_SYSTEM),
                subnet_system,
            ),
            (
                principal!(CANISTER_ENGINE),
                principal!(CANISTER_ENGINE),
                subnet_engine,
            ),
        ];

        let mut types = AHashMap::new();
        types.insert(subnet_system, SubnetType::System);
        types.insert(subnet_engine, SubnetType::CloudEngine);

        Arc::new(ArcSwapOption::new(Some(Arc::new(SubnetsInfo::new(
            ranges, types,
        )))))
    }

    fn matcher() -> DomainCanisterMatcher {
        let mut pic = AHashSet::new();
        pic.insert(principal!(CANISTER_PIC));

        DomainCanisterMatcher::new(
            pic,
            vec![fqdn!("icp0.io")],   // app
            vec![fqdn!("ic0.app")],   // system
            vec![fqdn!("engine.io")], // engine
            test_snapshot(),
        )
    }

    #[test]
    fn system_canister_allowed_on_system_domain() {
        assert!(matcher().check(principal!(CANISTER_SYSTEM), &fqdn!("ic0.app")));
    }

    #[test]
    fn system_canister_rejected_on_app_domain() {
        assert!(!matcher().check(principal!(CANISTER_SYSTEM), &fqdn!("icp0.io")));
    }

    #[test]
    fn engine_canister_allowed_on_engine_domain() {
        assert!(matcher().check(principal!(CANISTER_ENGINE), &fqdn!("engine.io")));
    }

    #[test]
    fn engine_canister_rejected_on_app_domain() {
        assert!(!matcher().check(principal!(CANISTER_ENGINE), &fqdn!("icp0.io")));
    }

    #[test]
    fn app_canister_allowed_on_app_domain() {
        assert!(matcher().check(principal!(CANISTER_APP), &fqdn!("icp0.io")));
    }

    #[test]
    fn app_canister_rejected_on_system_domain() {
        assert!(!matcher().check(principal!(CANISTER_APP), &fqdn!("ic0.app")));
    }

    #[test]
    fn pre_isolation_canister_allowed_on_non_engine_subnet_domains() {
        // CANISTER_PIC is not on a CloudEngine subnet, so it bypasses domain checks
        assert!(matcher().check(principal!(CANISTER_PIC), &fqdn!("ic0.app")));
        assert!(matcher().check(principal!(CANISTER_PIC), &fqdn!("icp0.io")));
        assert!(matcher().check(principal!(CANISTER_PIC), &fqdn!("engine.io")));
    }

    #[test]
    fn pre_isolation_canister_on_engine_subnet_subject_to_domain_policy() {
        // Even if CANISTER_ENGINE is in the pre-isolation set, CloudEngine subnet
        // canisters must still use the engine domain.
        let mut pic = AHashSet::new();
        pic.insert(principal!(CANISTER_ENGINE));
        // Reuse test_snapshot() — CANISTER_ENGINE already maps to CloudEngine there.
        let m = DomainCanisterMatcher::new(
            pic,
            vec![fqdn!("icp0.io")],
            vec![fqdn!("ic0.app")],
            vec![fqdn!("engine.io")],
            test_snapshot(),
        );
        assert!(m.check(principal!(CANISTER_ENGINE), &fqdn!("engine.io")));
        assert!(!m.check(principal!(CANISTER_ENGINE), &fqdn!("icp0.io")));
        assert!(!m.check(principal!(CANISTER_ENGINE), &fqdn!("ic0.app")));
    }

    #[test]
    fn empty_snapshot_falls_through_to_app_domain() {
        let empty = Arc::new(ArcSwapOption::<SubnetsInfo>::empty());
        let mut pic = AHashSet::new();
        pic.insert(principal!(CANISTER_PIC));
        let m = DomainCanisterMatcher::new(
            pic,
            vec![fqdn!("icp0.io")],
            vec![fqdn!("ic0.app")],
            vec![fqdn!("engine.io")],
            empty,
        );
        // With no snapshot, subnet type is unknown → app domain for everything
        assert!(m.check(principal!(CANISTER_APP), &fqdn!("icp0.io")));
        assert!(!m.check(principal!(CANISTER_APP), &fqdn!("ic0.app")));
    }
}
