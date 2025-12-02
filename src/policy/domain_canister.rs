use ahash::AHashSet;
use candid::Principal;
use fqdn::{FQDN, Fqdn};

// System subnets routing table
pub const SYSTEM_SUBNETS: [(Principal, Principal); 5] = [
    (
        Principal::from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01]),
        Principal::from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x01, 0x01]),
    ),
    (
        Principal::from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, 0x01, 0x01]),
        Principal::from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, 0x01, 0x01]),
    ),
    (
        Principal::from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x01, 0x01]),
        Principal::from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x0f, 0xff, 0xff, 0x01, 0x01]),
    ),
    (
        Principal::from_slice(&[0x00, 0x00, 0x00, 0x00, 0x01, 0xa0, 0x00, 0x00, 0x01, 0x01]),
        Principal::from_slice(&[0x00, 0x00, 0x00, 0x00, 0x01, 0xaf, 0xff, 0xff, 0x01, 0x01]),
    ),
    (
        Principal::from_slice(&[0x00, 0x00, 0x00, 0x00, 0x02, 0x10, 0x00, 0x00, 0x01, 0x01]),
        Principal::from_slice(&[0x00, 0x00, 0x00, 0x00, 0x02, 0x1f, 0xff, 0xff, 0x01, 0x01]),
    ),
];

/// Checks if given canister id belongs to a system subnet
pub fn is_system_subnet(canister_id: Principal) -> bool {
    SYSTEM_SUBNETS
        .iter()
        .any(|x| canister_id >= x.0 && canister_id <= x.1)
}

/// Things needed to verify domain-canister match
#[derive(derive_new::new)]
pub struct DomainCanisterMatcher {
    pre_isolation_canisters: AHashSet<Principal>,
    domains_app: Vec<FQDN>,
    domains_system: Vec<FQDN>,
}

impl DomainCanisterMatcher {
    /// Check if given canister id and host match from policy perspective
    pub fn check(&self, canister_id: Principal, host: &Fqdn) -> bool {
        // These are always allowed
        if self.pre_isolation_canisters.contains(&canister_id) {
            return true;
        }

        let domains = if is_system_subnet(canister_id) {
            &self.domains_system
        } else {
            &self.domains_app
        };

        domains.iter().any(|x| host.is_subdomain_of(x))
    }
}

#[cfg(test)]
mod tests {
    use fqdn::fqdn;

    use super::*;

    #[test]
    fn test_is_system_subnet() {
        assert!(is_system_subnet(
            Principal::from_text("qoctq-giaaa-aaaaa-aaaea-cai").unwrap(),
        )); // nns
        assert!(is_system_subnet(
            Principal::from_text("rdmx6-jaaaa-aaaaa-aaadq-cai").unwrap()
        )); // identity
        assert!(!is_system_subnet(
            Principal::from_text("oydqf-haaaa-aaaao-afpsa-cai").unwrap()
        )); // something else
    }

    #[test]
    fn test_domain_canister_match() {
        let mut pic = AHashSet::new();
        pic.insert(Principal::from_text("2dcn6-oqaaa-aaaai-abvoq-cai").unwrap());

        let dcm = DomainCanisterMatcher::new(pic, vec![fqdn!("icp0.io")], vec![fqdn!("ic0.app")]);

        assert!(dcm.check(
            Principal::from_text("qoctq-giaaa-aaaaa-aaaea-cai").unwrap(), // nns on system domain
            &fqdn!("ic0.app"),
        ));

        assert!(!dcm.check(
            Principal::from_text("s6hwe-laaaa-aaaab-qaeba-cai").unwrap(), // something else on system domain
            &fqdn!("ic0.app"),
        ));

        assert!(dcm.check(
            Principal::from_text("s6hwe-laaaa-aaaab-qaeba-cai").unwrap(), // something else on app domain
            &fqdn!("icp0.io"),
        ));

        assert!(dcm.check(
            Principal::from_text("2dcn6-oqaaa-aaaai-abvoq-cai").unwrap(), // pre-isolation canister on system domain
            &fqdn!("ic0.app"),
        ));
    }
}
