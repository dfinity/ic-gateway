use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
};

use hickory_resolver::{
    config::{NameServerConfigGroup, ResolverConfig, ResolverOpts},
    lookup_ip::LookupIpIntoIter,
    TokioAsyncResolver,
};
use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use strum_macros::EnumString;

#[derive(Clone, Copy, Debug, EnumString)]
#[strum(serialize_all = "snake_case")]
pub enum Protocol {
    Clear,
    Tls,
    Https,
}

#[derive(Debug, Clone)]
pub struct Resolver(Arc<TokioAsyncResolver>);

pub struct Options {
    pub protocol: Protocol,
    pub servers: Vec<IpAddr>,
    pub tls_name: String,
    pub cache_size: usize,
}

// new() must be called in Tokio context
impl Resolver {
    pub fn new(o: Options) -> Self {
        let name_servers = match o.protocol {
            Protocol::Clear => NameServerConfigGroup::from_ips_clear(&o.servers, 53, true),
            Protocol::Tls => NameServerConfigGroup::from_ips_tls(&o.servers, 853, o.tls_name, true),
            Protocol::Https => {
                NameServerConfigGroup::from_ips_https(&o.servers, 443, o.tls_name, true)
            }
        };

        let cfg = ResolverConfig::from_parts(None, vec![], name_servers);

        let mut opts = ResolverOpts::default();
        opts.rotate = true;
        opts.cache_size = o.cache_size;
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
