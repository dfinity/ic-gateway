mod test;

use hickory_resolver::{
    config::{ResolverConfig, ResolverOpts},
    Resolver,
};

pub fn prepare_dns_resolver() -> std::io::Result<Resolver> {
    Resolver::new(ResolverConfig::cloudflare_tls(), ResolverOpts::default())
}
