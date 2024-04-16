use std::{net::SocketAddr, sync::Arc};

use hickory_resolver::{
    config::{NameServerConfigGroup, ResolverConfig, ResolverOpts},
    lookup_ip::LookupIpIntoIter,
    TokioAsyncResolver,
};
use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use strum_macros::EnumString;

use crate::cli::Dns;

#[derive(Clone, Debug, EnumString)]
#[strum(serialize_all = "snake_case")]
pub enum Protocol {
    Clear,
    Tls,
    Https,
}

#[derive(Debug, Clone)]
pub struct Resolver(Arc<TokioAsyncResolver>);

// new() must be called in Tokio context
impl Resolver {
    pub fn new(cli: &Dns) -> Self {
        let name_servers = match cli.protocol {
            Protocol::Clear => NameServerConfigGroup::from_ips_clear(&cli.servers, 53, true),
            Protocol::Tls => {
                NameServerConfigGroup::from_ips_tls(&cli.servers, 853, cli.tls_name.clone(), true)
            }
            Protocol::Https => {
                NameServerConfigGroup::from_ips_https(&cli.servers, 443, cli.tls_name.clone(), true)
            }
        };

        let cfg = ResolverConfig::from_parts(None, vec![], name_servers);

        let mut opts = ResolverOpts::default();
        opts.rotate = true;
        opts.cache_size = cli.cache_size;
        opts.use_hosts_file = false;
        opts.preserve_intermediates = false;
        opts.try_tcp_on_error = true;

        let resolver = TokioAsyncResolver::tokio(cfg, opts);
        Self(Arc::new(resolver))
    }
}

struct SocketAddrs {
    iter: LookupIpIntoIter,
}

impl Iterator for SocketAddrs {
    type Item = SocketAddr;

    fn next(&mut self) -> Option<Self::Item> {
        self.iter.next().map(|ip_addr| SocketAddr::new(ip_addr, 0))
    }
}

// Implement resolving for Reqwest using Hickory
impl Resolve for Resolver {
    fn resolve(&self, name: Name) -> Resolving {
        let resolver = self.clone();

        Box::pin(async move {
            let lookup = resolver.0.lookup_ip(name.as_str()).await?;
            let addrs: Addrs = Box::new(SocketAddrs {
                iter: lookup.into_iter(),
            });

            Ok(addrs)
        })
    }
}
