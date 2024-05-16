use std::{
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    time::Duration,
};

use clap::{Args, Parser};
use fqdn::FQDN;
use hickory_resolver::config::CLOUDFLARE_IPS;
use humantime::parse_duration;
use reqwest::Url;

use crate::{
    core::{AUTHOR_NAME, SERVICE_NAME},
    http::dns,
    routing::canister::CanisterAlias,
    tls::{self, acme},
};

#[derive(Parser)]
#[clap(name = SERVICE_NAME)]
#[clap(author = AUTHOR_NAME)]
pub struct Cli {
    #[command(flatten, next_help_heading = "HTTP Client")]
    pub http_client: HttpClient,

    #[command(flatten, next_help_heading = "DNS Resolver")]
    pub dns: Dns,

    #[command(flatten, next_help_heading = "HTTP Server")]
    pub http_server: HttpServer,

    #[command(flatten, next_help_heading = "Certificates")]
    pub cert: Cert,

    #[command(flatten, next_help_heading = "Domains")]
    pub domain: Domain,

    #[command(flatten, next_help_heading = "Policy")]
    pub policy: Policy,

    #[command(flatten, next_help_heading = "ACME")]
    pub acme: Acme,

    #[command(flatten, next_help_heading = "Metrics")]
    pub metrics: Metrics,

    #[command(flatten, next_help_heading = "Logging")]
    pub log: Log,

    #[command(flatten, next_help_heading = "Misc")]
    pub misc: Misc,
}

// Clap does not support prefixes due to macro limitations
// so we have to add them manually (long = "...")
//
// Also 'id = ...' in some fields below is needed because clap requires unique field names
// https://github.com/clap-rs/clap/issues/4556

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

#[derive(Args)]
pub struct Dns {
    /// List of DNS servers to use
    #[clap(long = "dns-servers", default_values_t = CLOUDFLARE_IPS)]
    pub servers: Vec<IpAddr>,

    /// DNS protocol to use (clear/tls/https)
    #[clap(long = "dns-protocol", default_value = "tls")]
    pub protocol: dns::Protocol,

    /// TLS name to expect for TLS and HTTPS protocols (e.g. "dns.google" or "cloudflare-dns.com")
    #[clap(long = "dns-tls-name", default_value = "cloudflare-dns.com")]
    pub tls_name: String,

    /// Cache size for the resolver (in number of DNS records)
    #[clap(long = "dns-cache-size", default_value = "2048")]
    pub cache_size: usize,
}

#[derive(Args)]
pub struct HttpServer {
    /// Where to listen for HTTP
    #[clap(long = "http-server-listen-plain", default_value = "[::1]:8080")]
    pub http: SocketAddr,

    /// Where to listen for HTTPS
    #[clap(long = "http-server-listen-tls", default_value = "[::1]:8443")]
    pub https: SocketAddr,

    /// Backlog of incoming connections to set on the listening socket.
    #[clap(long = "http-server-backlog", default_value = "2048")]
    pub backlog: u32,

    /// Maximum number of HTTP2 streams that the client is allowed to create in a single connection
    #[clap(long = "http-server-http2-max-streams", default_value = "128")]
    pub http2_max_streams: u32,

    /// Keepalive interval for HTTP2 connections
    #[clap(long = "http-server-http2-keepalive-interval", id = "HTTP_SERVER_HTTP2_KEEPALIVE_INTERVAL", default_value = "20s", value_parser = parse_duration)]
    pub http2_keepalive_interval: Duration,

    /// Keepalive timeout for HTTP2 connections
    #[clap(long = "http-server-http2-keepalive-timeout", id = "HTTP_SERVER_HTTP2_KEEPALIVE_TIMEOUT", default_value = "10s", value_parser = parse_duration)]
    pub http2_keepalive_timeout: Duration,

    /// How long to wait for the existing connections to finish before shutting down
    #[clap(long = "http-server-grace-period", default_value = "10s", value_parser = parse_duration)]
    pub grace_period: Duration,
}

#[derive(Args)]
pub struct Cert {
    /// Read certificates from given directories, each certificate should be a pair .pem + .key files with the same base name
    #[clap(long = "cert-provider-dir")]
    pub dir: Vec<PathBuf>,

    /// Request certificates from the 'certificate-issuer' instances reachable over given URLs.
    /// Also proxies the `/registrations` path to those issuers.
    #[clap(long = "cert-provider-issuer-url")]
    pub issuer_urls: Vec<Url>,

    /// How frequently to poll providers for certificates
    #[clap(long = "cert-poll-interval", default_value = "10s", value_parser = parse_duration)]
    pub poll_interval: Duration,
}

#[derive(Args)]
pub struct Domain {
    /// Specify domains that will be served. This affects the routing, canister extraction, ACME certificate issuing etc.
    #[clap(long = "domain")]
    pub domains: Vec<FQDN>,

    /// List of domains that we serve system subnets from. This enables domain-canister matching for these domains & adds them to the list of served domains above, do not list them there separately.
    /// Requires --domain-app.
    #[clap(long = "domain-system", requires = "domains_app")]
    pub domains_system: Vec<FQDN>,

    /// List of domains that we serve app subnets from. See --domain-system above for details.
    /// Requires --domain-system.
    #[clap(long = "domain-app", requires = "domains_system")]
    pub domains_app: Vec<FQDN>,

    /// List of canister aliases in format '<alias>:<canister_id>'
    #[clap(long = "domain-alias")]
    pub canister_aliases: Vec<CanisterAlias>,
}

#[derive(Args)]
pub struct Policy {
    /// Path to a list of pre-isolation canisters, one canister per line
    #[clap(long = "policy-pre-isolation-canisters")]
    pub pre_isolation_canisters: Option<PathBuf>,

    /// Denylist URL
    #[clap(long = "policy-denylist-url")]
    pub denylist_url: Option<Url>,

    /// Path to a list of whitelisted canisters
    #[clap(long = "policy-denylist-allowlist")]
    pub denylist_allowlist: Option<PathBuf>,

    /// Path to a local denylist cache for initial seeding
    #[clap(long = "policy-denylist-seed")]
    pub denylist_seed: Option<PathBuf>,

    /// How frequently to poll denlylist for updates
    #[clap(long = "policy-denylist-poll-interval", default_value = "1m", value_parser = parse_duration)]
    pub denylist_poll_interval: Duration,
}

#[derive(Args)]
pub struct Acme {
    /// If specified we'll try to obtain the certificate that is valid for all served domains using given ACME challenge.
    /// Currently supported:
    /// - alpn: all served domains must resolve to the host where this service is running.
    /// - dns: allows to request wildcard certificates, requires DNS backend to be configured.
    #[clap(long = "acme-challenge", requires = "acme_cache_path")]
    pub acme_challenge: Option<acme::Challenge>,

    /// Path to a directory where to store ACME cache (account and certificates).
    /// Directory structure is different when using ALPN and DNS, but it shouldn't collide (I hope).
    /// Must be specified if --acme-challenge is set.
    #[clap(long = "acme-cache-path")]
    pub acme_cache_path: Option<PathBuf>,

    /// DNS backend to use when using DNS challenge. Currently only "cloudflare" is supported.
    #[clap(long = "acme-dns-backend")]
    pub acme_dns_backend: Option<acme::dns::DnsBackend>,

    /// File from which to read API token if DNS backend is Cloudflare
    #[clap(
        long = "acme-dns-cloudflare-url",
        default_value = "https://api.cloudflare.com/client/v4/"
    )]
    pub acme_dns_cloudflare_url: Url,

    /// File from which to read API token if DNS backend is Cloudflare
    #[clap(long = "acme-dns-cloudflare-token")]
    pub acme_dns_cloudflare_token: Option<PathBuf>,

    /// Asks ACME client to request a wildcard certificate for each of the domains configured.
    /// So in addition to `foo.app` the certificate will be also valid for `*.foo.app`.
    /// For obvious reasons this works only with DNS challenge, has no effect with ALPN.
    #[clap(long = "acme-wildcard")]
    pub acme_wildcard: bool,

    /// Attempt to renew the certificates when less than this duration is left until expiration.
    /// This works only with DNS challenge, ALPN currently starts to renew after half of certificate
    /// lifetime has passed.
    #[clap(long = "acme-renew-before", value_parser = parse_duration, default_value = "30d")]
    pub acme_renew_before: Duration,

    /// Whether to use LetsEncrypt staging API for testing to avoid hitting the limits
    #[clap(long = "acme-staging")]
    pub acme_staging: bool,

    /// E-Mail to use when creating ACME accounts, must start with mailto:
    #[clap(
        long = "acme-contact",
        default_value = "mailto:boundary-nodes@dfinity.org"
    )]
    pub acme_contact: String,
}

#[derive(Args)]
pub struct Metrics {
    /// Where to listen for Prometheus metrics scraping
    #[clap(long = "metrics-listen")]
    pub listen: Option<SocketAddr>,
}

#[derive(Args)]
pub struct Log {
    /// Maximum logging level
    #[clap(long = "log-level", default_value = "info")]
    pub log_level: tracing::Level,
    /// Enables logging to stdout
    #[clap(long = "log-stdout")]
    pub log_stdout: bool,
    /// Enables logging to stdout in JSON
    #[clap(long = "log-stdout-json")]
    pub log_stdout_json: bool,
    /// Enables logging to Journald
    #[clap(long = "log-journald")]
    pub log_journald: bool,
    /// Enables logging to /dev/null (to benchmark logging)
    #[clap(long = "log-null")]
    pub log_null: bool,
}

#[derive(Args)]
pub struct Misc {
    /// Path to a GeoIP database
    #[clap(long = "geoip-db")]
    pub geoip_db: Option<PathBuf>,
}

// Some conversions
impl From<&Dns> for crate::http::dns::Options {
    fn from(c: &Dns) -> Self {
        Self {
            protocol: c.protocol,
            servers: c.servers.clone(),
            tls_name: c.tls_name.clone(),
            cache_size: c.cache_size,
        }
    }
}

impl From<&HttpServer> for crate::http::server::Options {
    fn from(c: &HttpServer) -> Self {
        Self {
            backlog: c.backlog,
            http2_keepalive_interval: c.http2_keepalive_interval,
            http2_keepalive_timeout: c.http2_keepalive_timeout,
            http2_max_streams: c.http2_max_streams,
            grace_period: c.grace_period,
        }
    }
}

impl From<&HttpClient> for crate::http::client::Options {
    fn from(c: &HttpClient) -> Self {
        Self {
            timeout_connect: c.timeout_connect,
            timeout: c.timeout,
            tcp_keepalive: Some(c.tcp_keepalive),
            http2_keepalive: Some(c.http2_keepalive),
            http2_keepalive_timeout: c.http2_keepalive_timeout,
            user_agent: crate::core::SERVICE_NAME.into(),
            tls_config: tls::prepare_client_config(),
        }
    }
}
