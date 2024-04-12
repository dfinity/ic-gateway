use std::{net::IpAddr, time::Duration};

use anyhow::{anyhow, Error};
use clap::{Args, Parser};
use hickory_resolver::config::{Protocol, CLOUDFLARE_IPS};
use humantime::parse_duration;

use crate::{
    core::{AUTHOR_NAME, SERVICE_NAME},
    http::dns,
};

// Clap does not support prefixes due to macro limitations
// so we have to add prefixes manually (long = "...")

#[derive(Parser)]
#[clap(name = SERVICE_NAME)]
#[clap(author = AUTHOR_NAME)]
pub struct Cli {
    #[command(flatten, next_help_heading = "HTTP Client")]
    pub http_client: HttpClient,

    #[command(flatten, next_help_heading = "DNS")]
    pub dns: Dns,
}

#[derive(Args)]
pub struct HttpClient {
    /// Timeout for HTTP connection phase
    #[clap(long = "http-client-timeout-connect", default_value = "5s", value_parser = parse_duration)]
    pub timeout_connect: Duration,

    /// Timeout for whole HTTP call
    #[clap(long = "http-client-timeout", default_value = "60s", value_parser = parse_duration)]
    pub timeout: Duration,

    /// TCP Keepalive interval
    #[clap(long = "http-client-tcp-keepalive", default_value = "15s", value_parser = parse_duration)]
    pub tcp_keepalive: Duration,

    /// HTTP2 Keepalive interval
    #[clap(long = "http-client-http2-keepalive", default_value = "10s", value_parser = parse_duration)]
    pub http2_keepalive: Duration,

    /// HTTP2 Keepalive timeout
    #[clap(long = "http-client-http2-keepalive-timeout", default_value = "5s", value_parser = parse_duration)]
    pub http2_keepalive_timeout: Duration,
}

#[derive(Args, Clone, Debug)]
pub struct Dns {
    /// List of DNS servers to use
    #[clap(long = "dns-servers", default_values_t = CLOUDFLARE_IPS)]
    pub servers: Vec<IpAddr>,

    /// DNS protocol to use (udp/tcp/tls/https)
    #[clap(long = "dns-protocol", default_value = "tls")]
    pub protocol: dns::Protocol,

    /// TLS name for DNS-over-TLS and DNS-over-HTTPS protocols
    #[clap(long = "dns-tls-name", default_value = "cloudflare-dns.com")]
    pub tls_name: String,
}
