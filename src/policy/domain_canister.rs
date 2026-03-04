use ahash::AHashSet;
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
}

impl DomainCanisterMatcher {
    /// Check if given canister id and host match from policy perspective.
    /// `subnets_info` is the current NNS snapshot, loaded by the caller.
    pub fn check(&self, canister_id: Principal, host: &Fqdn, subnets_info: &SubnetsInfo) -> bool {
        // These are always allowed
        if self.pre_isolation_canisters.contains(&canister_id) {
            return true;
        }

        let domains = match subnets_info.subnet_type(canister_id) {
            Some(SubnetType::System) => &self.domains_system,
            Some(SubnetType::CloudEngine) => &self.domains_engine,
            Some(SubnetType::Application) | Some(SubnetType::VerifiedApplication) | None => {
                &self.domains_app
            }
        };

        domains.iter().any(|x| host.is_subdomain_of(x))
    }
}

#[cfg(test)]
mod tests {
    use ahash::AHashMap;
    use fqdn::fqdn;
    use ic_bn_lib_common::principal;

    use super::*;
    use crate::routing::ic::subnets_info::SubnetType;

    use crate::test::NNS_SUBNET_ID;

    // Principals used as subnet IDs in the test snapshot
    const SUBNET_SYSTEM: &str = NNS_SUBNET_ID;
    const SUBNET_ENGINE: &str = "nl6hn-ja4yw-wvmpy-3z2jx-ymc34-pisx3-3cp5z-3oj4a-qzzny-jbsv3-4qe";

    // Canisters that fall inside the ranges defined below
    const CANISTER_SYSTEM: &str = "qoctq-giaaa-aaaaa-aaaea-cai"; // NNS
    const CANISTER_ENGINE: &str = "s6hwe-laaaa-aaaab-qaeba-cai";
    const CANISTER_APP: &str = "oydqf-haaaa-aaaao-afpsa-cai";
    const CANISTER_PIC: &str = "2dcn6-oqaaa-aaaai-abvoq-cai"; // pre-isolation

    fn test_snapshot() -> SubnetsInfo {
        let subnet_system = principal!(SUBNET_SYSTEM);
        let subnet_engine = principal!(SUBNET_ENGINE);

        let system_canister = principal!(CANISTER_SYSTEM);
        let engine_canister = principal!(CANISTER_ENGINE);

        let ranges = vec![
            (system_canister, system_canister, subnet_system),
            (engine_canister, engine_canister, subnet_engine),
        ];

        let mut types = AHashMap::new();
        types.insert(subnet_system, SubnetType::System);
        types.insert(subnet_engine, SubnetType::CloudEngine);

        SubnetsInfo::new(ranges, types)
    }

    fn matcher() -> DomainCanisterMatcher {
        let mut pic = AHashSet::new();
        pic.insert(principal!(CANISTER_PIC));

        DomainCanisterMatcher::new(
            pic,
            vec![fqdn!("icp0.io")],    // app
            vec![fqdn!("ic0.app")],    // system
            vec![fqdn!("engine.io")],  // engine
        )
    }

    #[test]
    fn system_canister_allowed_on_system_domain() {
        let info = test_snapshot();
        assert!(matcher().check(principal!(CANISTER_SYSTEM), &fqdn!("ic0.app"), &info));
    }

    #[test]
    fn system_canister_rejected_on_app_domain() {
        let info = test_snapshot();
        assert!(!matcher().check(principal!(CANISTER_SYSTEM), &fqdn!("icp0.io"), &info));
    }

    #[test]
    fn engine_canister_allowed_on_engine_domain() {
        let info = test_snapshot();
        assert!(matcher().check(principal!(CANISTER_ENGINE), &fqdn!("engine.io"), &info));
    }

    #[test]
    fn engine_canister_rejected_on_app_domain() {
        let info = test_snapshot();
        assert!(!matcher().check(principal!(CANISTER_ENGINE), &fqdn!("icp0.io"), &info));
    }

    #[test]
    fn app_canister_allowed_on_app_domain() {
        let info = test_snapshot();
        assert!(matcher().check(principal!(CANISTER_APP), &fqdn!("icp0.io"), &info));
    }

    #[test]
    fn app_canister_rejected_on_system_domain() {
        let info = test_snapshot();
        assert!(!matcher().check(principal!(CANISTER_APP), &fqdn!("ic0.app"), &info));
    }

    #[test]
    fn pre_isolation_canister_allowed_on_any_domain() {
        let info = test_snapshot();
        assert!(matcher().check(principal!(CANISTER_PIC), &fqdn!("ic0.app"), &info));
        assert!(matcher().check(principal!(CANISTER_PIC), &fqdn!("icp0.io"), &info));
        assert!(matcher().check(principal!(CANISTER_PIC), &fqdn!("engine.io"), &info));
    }

    #[test]
    fn empty_snapshot_falls_through_to_app_domain() {
        let info = SubnetsInfo::default();
        // With no snapshot, subnet type is unknown → app domain for everything
        assert!(matcher().check(principal!(CANISTER_APP), &fqdn!("icp0.io"), &info));
        assert!(!matcher().check(principal!(CANISTER_APP), &fqdn!("ic0.app"), &info));
    }
}
