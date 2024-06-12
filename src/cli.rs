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
    routing::domain::CanisterAlias,
    tls::{self, acme},
};

fn parse_size(s: &str) -> Result<u64, parse_size::Error> {
    parse_size::Config::new().with_binary().parse_size(s)
}

/// Clap does not support prefixes due to macro limitations
/// So the names are a bit redundant (e.g. cli.http_client.http_client_...) to
/// make it consistent with env vars naming etc.

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

    #[command(flatten, next_help_heading = "IC")]
    pub ic: Ic,

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

#[derive(Args)]
pub struct HttpClient {
    /// Timeout for HTTP connection phase
    #[clap(env, long, default_value = "5s", value_parser = parse_duration)]
    pub http_client_timeout_connect: Duration,

    /// Timeout for whole HTTP call
    #[clap(env, long, default_value = "60s", value_parser = parse_duration)]
    pub http_client_timeout: Duration,

    /// TCP Keepalive interval
    #[clap(env, long, default_value = "15s", value_parser = parse_duration)]
    pub http_client_tcp_keepalive: Duration,

    /// HTTP2 Keepalive interval
    #[clap(env, long, default_value = "10s", value_parser = parse_duration)]
    pub http_client_http2_keepalive: Duration,

    /// HTTP2 Keepalive timeout
    #[clap(env, long, default_value = "5s", value_parser = parse_duration)]
    pub http_client_http2_keepalive_timeout: Duration,
}

#[derive(Args)]
pub struct Dns {
    /// List of DNS servers to use
    #[clap(env, long, value_delimiter = ',', default_values_t = CLOUDFLARE_IPS)]
    pub dns_servers: Vec<IpAddr>,

    /// DNS protocol to use (clear/tls/https)
    #[clap(env, long, default_value = "tls")]
    pub dns_protocol: dns::Protocol,

    /// TLS name to expect for TLS and HTTPS protocols (e.g. "dns.google" or "cloudflare-dns.com")
    #[clap(env, long, default_value = "cloudflare-dns.com")]
    pub dns_tls_name: String,

    /// Cache size for the resolver (in number of DNS records)
    #[clap(env, long, default_value = "2048")]
    pub dns_cache_size: usize,
}

#[derive(Args)]
pub struct HttpServer {
    /// Where to listen for HTTP
    #[clap(env, long, default_value = "127.0.0.1:8080")]
    pub http_server_listen_plain: SocketAddr,

    /// Where to listen for HTTPS
    #[clap(env, long, default_value = "127.0.0.1:8443")]
    pub http_server_listen_tls: SocketAddr,

    /// Backlog of incoming connections to set on the listening socket.
    #[clap(env, long, default_value = "2048")]
    pub http_server_backlog: u32,

    /// Maximum number of HTTP2 streams that the client is allowed to create in a single connection
    #[clap(env, long, default_value = "128")]
    pub http_server_http2_max_streams: u32,

    /// Keepalive interval for HTTP2 connections
    #[clap(env, long, default_value = "20s", value_parser = parse_duration)]
    pub http_server_http2_keepalive_interval: Duration,

    /// Keepalive timeout for HTTP2 connections
    #[clap(env, long, default_value = "10s", value_parser = parse_duration)]
    pub http_server_http2_keepalive_timeout: Duration,

    /// How long to wait for the existing connections to finish before shutting down
    #[clap(env, long, default_value = "10s", value_parser = parse_duration)]
    pub http_server_grace_period: Duration,

    /// Maximum size of cache to store TLS sessions in memory
    #[clap(env, long, default_value = "256MB", value_parser = parse_size)]
    pub http_server_tls_session_cache_size: u64,

    /// Maximum time that a TLS session key can stay in cache without being requested (Time-to-Idle)
    #[clap(env, long, default_value = "18h", value_parser = parse_duration)]
    pub http_server_tls_session_cache_tti: Duration,

    /// Lifetime of a TLS1.3 ticket, due to key rotation the actual lifetime will be twice than this.
    #[clap(env, long, default_value = "9h", value_parser = parse_duration)]
    pub http_server_tls_ticket_lifetime: Duration,
}

#[derive(Args)]
pub struct Ic {
    /// URLs to use to connect to the IC network
    #[clap(env, long, value_delimiter = ',')]
    pub ic_url: Vec<Url>,

    /// Whether to use static URLs or dynamically discovered URLs for routing.
    /// For the dynamic routing case, provided argument `ic-url` is used as a seed list of API Nodes.
    #[clap(env, long)]
    pub ic_use_discovery: bool,

    /// Path to an IC root key. Must be DER-encoded. If not specified - hardcoded will be used.
    #[clap(env, long)]
    pub ic_root_key: Option<PathBuf>,
}

#[derive(Args)]
pub struct Cert {
    /// Read certificates from given directories, each certificate should be a pair .pem + .key files with the same base name
    #[clap(env, long, value_delimiter = ',')]
    pub cert_provider_dir: Vec<PathBuf>,

    /// Request certificates from the 'certificate-issuer' instances reachable over given URLs.
    /// Also proxies the `/registrations` path to those issuers.
    #[clap(env, long, value_delimiter = ',')]
    pub cert_provider_issuer_url: Vec<Url>,

    /// How frequently to poll providers for certificates
    #[clap(env, long, default_value = "5s", value_parser = parse_duration)]
    pub cert_provider_poll_interval: Duration,

    /// Disable OCSP stapling
    #[clap(env, long)]
    pub cert_ocsp_stapling_disable: bool,
}

#[derive(Args)]
pub struct Domain {
    /// Specify domains that will be served. This affects the routing, canister extraction, ACME certificate issuing etc.
    #[clap(env, long, value_delimiter = ',')]
    pub domain: Vec<FQDN>,

    /// List of domains that will serve only IC API (no HTTP)
    #[clap(env, long, value_delimiter = ',')]
    pub domain_api: Vec<FQDN>,

    /// List of domains that we serve system subnets from. This enables domain-canister matching for these domains & adds them to the list of served domains above, do not list them there separately.
    /// Requires --domain-app.
    #[clap(env, long, requires = "domain_app", value_delimiter = ',')]
    pub domain_system: Vec<FQDN>,

    /// List of domains that we serve app subnets from. See --domain-system above for details.
    /// Requires --domain-system.
    #[clap(env, long, requires = "domain_system", value_delimiter = ',')]
    pub domain_app: Vec<FQDN>,

    /// List of canister aliases in format '<alias>:<canister_id>'
    #[clap(env, long, value_delimiter = ',')]
    pub domain_canister_alias: Vec<CanisterAlias>,
}

#[derive(Args)]
pub struct Policy {
    /// Path to a list of pre-isolation canisters, one canister per line
    #[clap(env, long)]
    pub policy_pre_isolation_canisters: Option<PathBuf>,

    /// Denylist URL
    #[clap(env, long)]
    pub policy_denylist_url: Option<Url>,

    /// Path to a list of whitelisted canisters
    #[clap(env, long)]
    pub policy_denylist_allowlist: Option<PathBuf>,

    /// Path to a local denylist cache for initial seeding
    #[clap(env, long)]
    pub policy_denylist_seed: Option<PathBuf>,

    /// How frequently to poll denlylist for updates
    #[clap(env, long, default_value = "1m", value_parser = parse_duration)]
    pub policy_denylist_poll_interval: Duration,
}

#[derive(Args)]
pub struct Acme {
    /// If specified we'll try to obtain the certificate that is valid for all served domains using given ACME challenge.
    /// Currently supported:
    /// - alpn: all served domains must resolve to the host where this service is running.
    /// - dns: allows to request wildcard certificates, requires DNS backend to be configured.
    #[clap(env, long, requires = "acme_cache_path")]
    pub acme_challenge: Option<acme::Challenge>,

    /// Path to a directory where to store ACME cache (account and certificates).
    /// Directory structure is different when using ALPN and DNS, but it shouldn't collide (I hope).
    /// Must be specified if --acme-challenge is set.
    #[clap(env, long)]
    pub acme_cache_path: Option<PathBuf>,

    /// DNS backend to use when using DNS challenge. Currently only "cloudflare" is supported.
    #[clap(env, long, default_value = "cloudflare")]
    pub acme_dns_backend: acme::dns::DnsBackend,

    /// Cloudflare API URL
    #[clap(env, long, default_value = "https://api.cloudflare.com/client/v4/")]
    pub acme_dns_cloudflare_url: Url,

    /// File from which to read API token if DNS backend is Cloudflare
    #[clap(env, long)]
    pub acme_dns_cloudflare_token: Option<PathBuf>,

    /// Asks ACME client to request a wildcard certificate for each of the domains configured.
    /// So in addition to `foo.app` the certificate will be also valid for `*.foo.app`.
    /// For obvious reasons this works only with DNS challenge, has no effect with ALPN.
    #[clap(env, long)]
    pub acme_wildcard: bool,

    /// Attempt to renew the certificates when less than this duration is left until expiration.
    /// This works only with DNS challenge, ALPN currently starts to renew after half of certificate
    /// lifetime has passed (45d for LetsEncrypt)
    #[clap(env, long, value_parser = parse_duration, default_value = "30d")]
    pub acme_renew_before: Duration,

    /// Whether to use LetsEncrypt staging API for testing to avoid hitting the limits
    #[clap(env, long)]
    pub acme_staging: bool,

    /// E-Mail to use when creating ACME accounts, must start with mailto:
    #[clap(env, long, default_value = "mailto:boundary-nodes@dfinity.org")]
    pub acme_contact: String,
}

#[derive(Args)]
pub struct Metrics {
    /// Where to listen for Prometheus metrics scraping
    #[clap(env, long)]
    pub metrics_listen: Option<SocketAddr>,
}

#[derive(Args)]
pub struct Log {
    /// Maximum logging level
    #[clap(env, long, default_value = "info")]
    pub log_level: tracing::Level,

    /// Enables logging to stdout
    #[clap(env, long)]
    pub log_stdout: bool,

    /// Enables logging to stdout in JSON
    #[clap(env, long)]
    pub log_stdout_json: bool,

    /// Enables logging to Journald
    #[clap(env, long)]
    pub log_journald: bool,

    /// Enables logging to /dev/null (to benchmark logging)
    #[clap(env, long)]
    pub log_null: bool,

    #[command(flatten, next_help_heading = "Clickhouse")]
    pub clickhouse: Clickhouse,
}

#[derive(Args, Clone)]
pub struct Clickhouse {
    /// Setting this enables logging of HTTP requests to Clickhouse DB
    #[clap(env, long)]
    pub log_clickhouse_url: Option<Url>,

    /// Clickhouse username
    #[clap(env, long)]
    pub log_clickhouse_user: Option<String>,

    /// Clickhouse password
    #[clap(env, long)]
    pub log_clickhouse_pass: Option<String>,

    /// Clickhouse database
    #[clap(env, long)]
    pub log_clickhouse_db: Option<String>,

    /// Clickhouse table
    #[clap(env, long)]
    pub log_clickhouse_table: Option<String>,

    /// Clickhouse batch size
    #[clap(env, long, default_value = "250000")]
    pub log_clickhouse_batch: u64,

    /// Clickhouse batch flush interval
    #[clap(env, long, default_value = "5s", value_parser = parse_duration)]
    pub log_clickhouse_interval: Duration,
}

#[derive(Args)]
pub struct Misc {
    /// Environment we run in to specify in the logs
    #[clap(env, long, default_value = "dev")]
    pub env: String,
    /// Local hostname to identify in e.g. logs.
    /// If not specified - tries to obtain it.
    #[clap(env, long, default_value = hostname::get().unwrap().into_string().unwrap())]
    pub hostname: String,
    /// Path to a GeoIP database
    #[clap(env, long)]
    pub geoip_db: Option<PathBuf>,
}

// Some conversions
impl From<&Dns> for crate::http::dns::Options {
    fn from(c: &Dns) -> Self {
        Self {
            protocol: c.dns_protocol,
            servers: c.dns_servers.clone(),
            tls_name: c.dns_tls_name.clone(),
            cache_size: c.dns_cache_size,
        }
    }
}

impl From<&HttpServer> for crate::http::server::Options {
    fn from(c: &HttpServer) -> Self {
        Self {
            backlog: c.http_server_backlog,
            http2_keepalive_interval: c.http_server_http2_keepalive_interval,
            http2_keepalive_timeout: c.http_server_http2_keepalive_timeout,
            http2_max_streams: c.http_server_http2_max_streams,
            grace_period: c.http_server_grace_period,
        }
    }
}

impl From<&HttpClient> for crate::http::client::Options {
    fn from(c: &HttpClient) -> Self {
        Self {
            timeout_connect: c.http_client_timeout_connect,
            timeout: c.http_client_timeout,
            tcp_keepalive: Some(c.http_client_tcp_keepalive),
            http2_keepalive: Some(c.http_client_http2_keepalive),
            http2_keepalive_timeout: c.http_client_http2_keepalive_timeout,
            user_agent: crate::core::SERVICE_NAME.into(),
            tls_config: tls::prepare_client_config(),
        }
    }
}
