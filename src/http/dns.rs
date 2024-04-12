use std::{net::SocketAddr, str::FromStr, sync::Arc};

use anyhow::{anyhow, Error};
use hickory_resolver::{
    config::{NameServerConfigGroup, ResolverConfig, ResolverOpts},
    lookup_ip::LookupIpIntoIter,
    TokioAsyncResolver,
};
use once_cell::sync::OnceCell;
use reqwest::dns::{Addrs, Name, Resolve, Resolving};

use crate::cli::Dns;

#[derive(Clone, Debug)]
pub enum Protocol {
    Clear,
    Tls,
    Https,
}

impl FromStr for Protocol {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "clear" => Protocol::Clear,
            "tls" => Protocol::Tls,
            "https" => Protocol::Https,
            _ => return Err(anyhow!("Unknown DNS protocol")),
        })
    }
}

pub fn prepare_dns_resolver(cli: Dns) -> TokioAsyncResolver {
    let name_servers = match cli.protocol {
        Protocol::Clear => NameServerConfigGroup::from_ips_clear(&cli.servers, 53, true),
        Protocol::Tls => NameServerConfigGroup::from_ips_tls(&cli.servers, 853, cli.tls_name, true),
        Protocol::Https => {
            NameServerConfigGroup::from_ips_https(&cli.servers, 443, cli.tls_name, true)
        }
    };

    let cfg = ResolverConfig::from_parts(None, vec![], name_servers);

    let mut opts = ResolverOpts::default();
    opts.rotate = true;
    opts.cache_size = 2048;
    opts.use_hosts_file = false;
    opts.preserve_intermediates = false;
    opts.try_tcp_on_error = true;

    TokioAsyncResolver::tokio(cfg, opts)
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

#[derive(Debug, Clone)]
pub struct DnsResolver {
    // Constructor is called most probably not in the Tokio context
    // so we delay creation of the resolver using once_cell
    state: Arc<OnceCell<TokioAsyncResolver>>,
    cli: Dns,
}

impl DnsResolver {
    pub fn new(cli: &Dns) -> Self {
        Self {
            state: Arc::new(OnceCell::new()),
            cli: cli.clone(),
        }
    }
}

// Implement resolving for Reqwest using Hickory
impl Resolve for DnsResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let resolver = self.clone();

        Box::pin(async move {
            let resolver = resolver
                .state
                .get_or_init(|| prepare_dns_resolver(resolver.cli));

            let lookup = resolver.lookup_ip(name.as_str()).await?;
            let addrs: Addrs = Box::new(SocketAddrs {
                iter: lookup.into_iter(),
            });

            Ok(addrs)
        })
    }
}
