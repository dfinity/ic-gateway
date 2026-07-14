use std::sync::Arc;

use ahash::AHashSet;
use candid::Principal;
use fqdn::{FQDN, Fqdn};

use crate::routing::ic::routing_table_manager::{LooksUpSubnetType, SubnetType};

/// Things needed to verify domain-canister match
#[derive(derive_new::new)]
pub struct DomainCanisterMatcher {
    pre_isolation_canisters: AHashSet<Principal>,
    domains_app: Vec<FQDN>,
    domains_system: Vec<FQDN>,
    domains_engine: Vec<FQDN>,
    subnet_types: Arc<dyn LooksUpSubnetType>,
}

impl DomainCanisterMatcher {
    /// Check if given canister id and host match from policy perspective.
    pub fn check(&self, canister_id: Principal, host: &Fqdn) -> bool {
        // Lookup subnet type
        let subnet_type = self.subnet_types.lookup_subnet_type(&canister_id);

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
            Some(
                SubnetType::Application | SubnetType::VerifiedApplication | SubnetType::Unknown,
            )
            | None => &self.domains_app,
        };

        domains.iter().any(|x| host.is_subdomain_of(x))
    }
}

#[cfg(test)]
mod tests {
    use fqdn::fqdn;
    use ic_bn_lib::principal;

    use super::*;
    use crate::{
        routing::ic::routing_table_manager::SubnetType, test::TestSubnetTypeLookuperEmpty,
    };

    // Canisters that fall inside the ranges defined below
    const CANISTER_SYSTEM: &str = "qoctq-giaaa-aaaaa-aaaea-cai"; // NNS
    const CANISTER_ENGINE: &str = "s6hwe-laaaa-aaaab-qaeba-cai";
    const CANISTER_APP: &str = "oydqf-haaaa-aaaao-afpsa-cai";
    const CANISTER_PIC: &str = "2dcn6-oqaaa-aaaai-abvoq-cai"; // pre-isolation

    struct TestSubnetTypeLookuper;
    impl LooksUpSubnetType for TestSubnetTypeLookuper {
        fn lookup_subnet_type(&self, canister_id: &Principal) -> Option<SubnetType> {
            if canister_id == &principal!(CANISTER_SYSTEM) {
                Some(SubnetType::System)
            } else if canister_id == &principal!(CANISTER_ENGINE) {
                Some(SubnetType::CloudEngine)
            } else {
                None
            }
        }
    }

    fn matcher() -> DomainCanisterMatcher {
        let mut pic = AHashSet::new();
        pic.insert(principal!(CANISTER_PIC));

        DomainCanisterMatcher::new(
            pic,
            vec![fqdn!("icp0.io")],   // app
            vec![fqdn!("ic0.app")],   // system
            vec![fqdn!("engine.io")], // engine
            Arc::new(TestSubnetTypeLookuper),
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
            Arc::new(TestSubnetTypeLookuper),
        );
        assert!(m.check(principal!(CANISTER_ENGINE), &fqdn!("engine.io")));
        assert!(!m.check(principal!(CANISTER_ENGINE), &fqdn!("icp0.io")));
        assert!(!m.check(principal!(CANISTER_ENGINE), &fqdn!("ic0.app")));
    }

    #[test]
    fn empty_snapshot_falls_through_to_app_domain() {
        let mut pic = AHashSet::new();
        pic.insert(principal!(CANISTER_PIC));
        let m = DomainCanisterMatcher::new(
            pic,
            vec![fqdn!("icp0.io")],
            vec![fqdn!("ic0.app")],
            vec![fqdn!("engine.io")],
            Arc::new(TestSubnetTypeLookuperEmpty),
        );
        // With no snapshot, subnet type is unknown → app domain for everything
        assert!(m.check(principal!(CANISTER_APP), &fqdn!("icp0.io")));
        assert!(!m.check(principal!(CANISTER_APP), &fqdn!("ic0.app")));
    }
}
