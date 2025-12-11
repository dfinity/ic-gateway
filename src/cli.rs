use std::{net::SocketAddr, path::PathBuf, time::Duration};

use ::http::HeaderValue;
use clap::{Args, Parser};
use fqdn::FQDN;
use humantime::parse_duration;
#[cfg(feature = "acme")]
use ic_bn_lib_common::types::acme::{AcmeUrl, Challenge, DnsBackend};
use ic_bn_lib_common::{
    parse_size, parse_size_decimal, parse_size_usize,
    types::{
        dns::DnsCli,
        http::{HttpClientCli, HttpServerCli, ProxyProtocolMode, WafCli},
        shed::{ShedShardedCli, ShedSystemCli},
        vector::VectorCli,
    },
};
use reqwest::Url;

use crate::{
    core::{AUTHOR_NAME, SERVICE_NAME},
    routing::{RequestType, domain::CanisterAlias},
};

/// Clap does not support prefixes due to macro limitations.
/// So the names are a bit redundant (e.g. cli.http_client.http_client_...) to
/// make it consistent with env vars naming etc.

#[derive(Parser)]
#[clap(name = SERVICE_NAME)]
#[clap(author = AUTHOR_NAME)]
pub struct Cli {
    #[command(flatten, next_help_heading = "DNS Resolver")]
    pub dns: DnsCli,

    #[command(flatten, next_help_heading = "Listening")]
    pub listen: Listen,

    #[command(flatten, next_help_heading = "Network")]
    pub network: Network,

    #[command(flatten, next_help_heading = "HTTP Client")]
    pub http_client: HttpClientCli,

    #[command(flatten, next_help_heading = "HTTP Server")]
    pub http_server: HttpServerCli,

    #[command(flatten, next_help_heading = "IC")]
    pub ic: Ic,

    #[command(flatten, next_help_heading = "Certificates")]
    pub cert: Cert,

    #[command(flatten, next_help_heading = "Domains")]
    pub domain: Domain,

    #[command(flatten, next_help_heading = "Custom Domains")]
    pub custom_domains: Option<ic_custom_domains_base::cli::CustomDomainsCli>,

    #[command(flatten, next_help_heading = "Policy")]
    pub policy: Policy,

    #[command(flatten, next_help_heading = "Load")]
    pub load: Load,

    #[command(flatten, next_help_heading = "API")]
    pub api: Api,

    #[command(flatten, next_help_heading = "WAF")]
    pub waf: WafCli,

    #[cfg(feature = "acme")]
    #[command(flatten, next_help_heading = "ACME")]
    pub acme: Acme,

    #[command(flatten, next_help_heading = "Metrics")]
    pub metrics: Metrics,

    #[command(flatten, next_help_heading = "Logging")]
    pub log: Log,

    #[command(flatten, next_help_heading = "Misc")]
    pub misc: Misc,

    #[command(flatten, next_help_heading = "CORS")]
    pub cors: Cors,

    #[command(flatten, next_help_heading = "Rate limiting")]
    pub rate_limit: RateLimit,

    #[command(flatten, next_help_heading = "Cache")]
    pub cache: CacheConfig,

    #[command(flatten, next_help_heading = "Shedding System")]
    pub shed_system: ShedSystemCli,

    #[command(flatten, next_help_heading = "Shedding Latency")]
    pub shed_latency: ShedShardedCli<RequestType>,

    #[cfg(all(target_os = "linux", feature = "sev-snp"))]
    #[command(flatten, next_help_heading = "SEV-SNP")]
    pub sev_snp: ic_bn_lib_common::types::utils::SevSnpCli,
}

#[derive(Args)]
pub struct Network {
    /// Number of HTTP clients to create to spread the load over
    #[clap(env, long, default_value = "4", value_parser = clap::value_parser!(u16).range(1..))]
    pub network_http_client_count: u16,

    /// Bypass verification of TLS certificates for all outgoing requests.
    /// *** Dangerous *** - use only for testing.
    #[clap(env, long)]
    pub network_http_client_insecure_bypass_tls_verification: bool,

    /// Whether to trust incoming `X-Request-Id` header or override it
    #[clap(env, long)]
    pub network_trust_x_request_id: bool,
}

#[derive(Args)]
pub struct Listen {
    /// Where to listen for HTTP
    #[clap(env, long, default_value = "127.0.0.1:8080")]
    pub listen_plain: SocketAddr,

    /// Where to listen for HTTPS
    #[clap(env, long, default_value = "127.0.0.1:8443")]
    pub listen_tls: SocketAddr,

    /// Option to only serve HTTP instead for testing
    #[clap(env, long)]
    pub listen_insecure_serve_http_only: bool,
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

    /// In dynamic routing mode, limits routing to the top K API nodes with best score (ranked by latency and availability).
    /// If not set, routing uses all healthy API nodes.
    #[clap(env, long)]
    pub ic_use_k_top_api_nodes: Option<usize>,

    /// Path to an IC root key. Must be DER-encoded.
    /// If not specified - hardcoded or fetched (see `--ic-unsafe-root-key-fetch`) will be used.
    #[clap(env, long)]
    pub ic_root_key: Option<PathBuf>,

    /// Fetches the IC root key instead of using hardcoded/provided one.
    /// Unsafe, should be used only in test environments.
    /// If `ic_root_key` is specified then this option is ignored.
    #[clap(env, long)]
    pub ic_unsafe_root_key_fetch: bool,

    /// Maximum number of request retries for connection failures and HTTP code 429.
    /// First attempt is not counted.
    #[clap(env, long, default_value = "4")]
    pub ic_request_retries: usize,

    /// How long to wait between retries.
    /// With each retry this duration will be doubled.
    /// E.g. first delay 25ms, next 50ms and so on.
    #[clap(env, long, default_value = "25ms", value_parser = parse_duration)]
    pub ic_request_retry_interval: Duration,

    /// Max request body size to allow from the client
    #[clap(env, long, default_value = "10MB", value_parser = parse_size_usize)]
    pub ic_request_max_size: usize,

    /// Maximum time to spend waiting for the request body.
    /// Used by the API proxy which buffers the request for later retries.
    #[clap(env, long, default_value = "30s", value_parser = parse_duration)]
    pub ic_request_body_timeout: Duration,

    /// Max response size to allow from the IC
    #[clap(env, long, default_value = "3MB", value_parser = parse_size_usize)]
    pub ic_response_max_size: usize,

    /// Disable response verification for the IC requests.
    #[clap(env, long)]
    pub ic_unsafe_disable_response_verification: bool,

    /// Enable replica-signed queries in the agent.
    /// Since the responses' certificates are anyway validated - it makes the signed queries redundant.
    #[clap(env, long)]
    pub ic_enable_replica_signed_queries: bool,
}

#[derive(Args)]
pub struct Cert {
    /// Read certificates from given files.
    /// Each file should be PEM-encoded concatenated certificate chain with a private key.
    #[clap(env, long, value_delimiter = ',')]
    pub cert_provider_file: Vec<PathBuf>,

    /// Read certificates from given directories
    /// Each certificate should be a pair .pem + .key files with the same base name.
    #[clap(env, long, value_delimiter = ',')]
    pub cert_provider_dir: Vec<PathBuf>,

    /// How frequently to poll providers for certificates
    #[clap(env, long, default_value = "5s", value_parser = parse_duration)]
    pub cert_provider_poll_interval: Duration,

    /// Default certificate to serve when there's no SNI in the request.
    /// Tries to find a certificate that covers given FQDN.
    /// If not found or not specified - picks the first one available.
    #[clap(env, long)]
    pub cert_default: Option<FQDN>,
}

#[derive(Args)]
pub struct Domain {
    /// Specify domains that will be served. This affects the routing, canister extraction, ACME certificate issuing etc.
    #[clap(env, long, value_delimiter = ',')]
    pub domain: Vec<FQDN>,

    /// List of domains that will serve only IC API (no HTTP)
    #[clap(env, long, value_delimiter = ',')]
    pub domain_api: Vec<FQDN>,

    /// List of domains that we serve system subnets from.
    /// This enables domain-canister matching for these domains & adds them to the
    /// list of served domains above, do not list them there separately.
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

    /// List of generic custom domain provider URLs.
    /// Expects a JSON object in form '{"domain.bar": "aaaaa-aa"}' in response to a GET request.
    #[clap(env, long, value_delimiter = ',')]
    pub domain_custom_provider: Vec<Url>,

    /// List of generic timestamped custom domain provider URLs.
    /// Expects a JSON object in form '{"timestamp": 1234, "url": "https://foo/bar"}' in response to a GET request.
    /// When the timestamp changes - the provider gets the list of domains from the URL provided in response.
    /// The JSON format there should be the same as for the normal generic provider (see above).
    #[clap(env, long, value_delimiter = ',')]
    pub domain_custom_provider_timestamped: Vec<Url>,

    /// List of generic differential custom domain provider URLs.
    /// It first downloads the full seed and then only applies incremental updates to it using a timestamp.
    #[clap(env, long, value_delimiter = ',')]
    pub domain_custom_provider_diff: Vec<Url>,

    /// How frequently to poll custom domain providers for updates
    #[clap(env, long, default_value = "30s", value_parser = parse_duration)]
    pub domain_custom_provider_poll_interval: Duration,

    /// Timeout for the outgoing HTTP calls made to fetch custom domains
    #[clap(env, long, default_value = "30s", value_parser = parse_duration)]
    pub domain_custom_provider_timeout: Duration,

    /// Whether to try to resolve canister id from URI's query params.
    /// If canister id is present both in hostname and query params - then the hostname takes precedence.
    #[clap(env, long)]
    pub domain_canister_id_from_query_params: bool,

    /// Whether to try to resolve canister id from the requests referer.
    /// If a canister ID is present in multiple locations (hostname, query params, and referer),
    /// then the resolution precedence is: hostname > query parameters > referer.
    #[clap(env, long)]
    pub domain_canister_id_from_referer: bool,
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

#[cfg(feature = "acme")]
#[derive(Args)]
pub struct Acme {
    /// If specified we'll try to obtain the certificate that is valid for all served domains using given ACME challenge.
    /// Currently supported:
    /// - alpn: all served domains must resolve to the host where this service is running.
    /// - dns: allows to request wildcard certificates, requires DNS backend to be configured.
    #[clap(env, long, requires = "acme_cache_path")]
    pub acme_challenge: Option<Challenge>,

    /// Path to a directory where to store ACME cache (account and certificates).
    /// Directory structure is different when using ALPN and DNS, but it shouldn't collide (I hope).
    /// Must be specified if --acme-challenge is set.
    #[clap(env, long)]
    pub acme_cache_path: Option<PathBuf>,

    /// DNS backend to use when using DNS challenge. Currently only "cloudflare" is supported.
    #[clap(env, long, default_value = "cloudflare")]
    pub acme_dns_backend: DnsBackend,

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

    /// Which ACME provider URL to use. Can be "le_stag", "le_prod" for LetsEncrypt, or a custom URL.
    /// Defaults to "le_stag".
    #[clap(env, long, default_value = "le_stag")]
    pub acme_url: AcmeUrl,

    /// E-Mail to use when creating ACME accounts, must start with mailto:
    #[clap(env, long, default_value = "mailto:boundary-nodes@dfinity.org")]
    pub acme_contact: String,
}

#[derive(Args)]
pub struct Metrics {
    /// Where to listen for Prometheus metrics scraping
    #[clap(env, long)]
    pub metrics_listen: Option<SocketAddr>,

    /// Proxy Protocol mode for the metrics endpoint.
    /// Allows for separate configuration and overrides the value of HTTP server configuration.
    #[clap(env, long, default_value = "off")]
    pub metrics_proxy_protocol_mode: ProxyProtocolMode,
}

#[derive(Args)]
pub struct Log {
    /// Logging level to use
    #[clap(env, long, default_value = "warn")]
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

    /// Enables the Tokio console.
    /// It's listening on 127.0.0.1:6669
    #[cfg(all(tokio_unstable, feature = "tokio_console"))]
    #[clap(env, long)]
    pub log_tokio_console: bool,

    /// Enables logging of HTTP requests to stdout/journald/null.
    /// This does not affect Clickhouse/Vector logging targets -
    /// if they're enabled they'll log the requests in any case.
    #[clap(env, long)]
    pub log_requests: bool,

    #[cfg(feature = "clickhouse")]
    #[command(flatten, next_help_heading = "Clickhouse")]
    pub clickhouse: Clickhouse,

    #[command(flatten, next_help_heading = "Vector")]
    pub vector: VectorCli,
}

#[cfg(feature = "clickhouse")]
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

    /// Clickhouse batch size (in number of rows)
    #[clap(env, long, default_value = "250k", value_parser = parse_size_decimal)]
    pub log_clickhouse_batch: u64,

    /// Clickhouse batch flush interval
    #[clap(env, long, default_value = "5s", value_parser = parse_duration)]
    pub log_clickhouse_interval: Duration,
}

#[derive(Args)]
pub struct Load {
    /// Maximum number of concurrent requests to process.
    /// If more are coming in - they will be throttled.
    #[clap(env, long)]
    pub load_max_concurrency: Option<usize>,
}

#[derive(Args)]
pub struct Api {
    /// Specify a hostname on which to respond to API requests.
    /// If not specified - API isn't enabled.
    #[clap(env, long)]
    pub api_hostname: Option<FQDN>,

    /// Set an API authentication token.
    /// Required for certain API endpoints.
    #[clap(env, long)]
    pub api_token: Option<String>,
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

    /// Number of Tokio threads to use to serve requests.
    /// Defaults to the number of CPUs
    #[clap(env, long)]
    pub threads: Option<usize>,

    /// Domain for which to show alternate error page for unknown domain errors.
    /// If not specified, the default error page will be shown for all domains.
    #[clap(env, long)]
    pub alternate_error_domain: Option<FQDN>,

    /// Whether to consider Custom Domain Providers as critical for health self-assessment.
    /// If enabled - requires all providers to report healthy status for `ic-gateway` to be healthy.
    #[clap(env, long)]
    pub custom_domain_provider_critical: bool,

    /// Disable generation of nice user-friendly HTML error messages.
    /// Instead it produces more detailed JSON-encoded errors.
    #[clap(env, long)]
    pub disable_html_error_messages: bool,
}

#[derive(Args)]
pub struct CacheConfig {
    /// Maximum size of in-memory cache in bytes. Specify a size to enable caching.
    /// Currently the cache key is authority+path+query+range_header.
    #[clap(env, long, value_parser = parse_size)]
    pub cache_size: Option<u64>,

    /// Maximum size of a single cached response item in bytes. Should be less than cache_size.
    #[clap(env, long, default_value = "10MB", value_parser = parse_size_usize)]
    pub cache_max_item_size: usize,

    /// Whether to disregard `Cache-Control` response headers.
    /// The only supported values are `no-cache`/`no-store` to bypass caching
    /// and `max-age=N` to override default TTL.
    #[clap(env, long)]
    pub cache_disregard_cache_control: bool,

    /// Default time-to-live for the cache entries
    #[clap(env, long, default_value = "10s", value_parser = parse_duration)]
    pub cache_ttl: Duration,

    /// Maximum time-to-live for the cache entries.
    /// If `Cache-Control` header sets `max-age` higher than this - it will be capped.
    /// Doesn't do anything when `--cache-disregard-cache-control` is enabled.
    #[clap(env, long, default_value = "1d", value_parser = parse_duration)]
    pub cache_max_ttl: Duration,

    /// For how long to wait for the request to populate the cache if there are concurrent requests for the same resource.
    /// After the timeout the request will continue as-is.
    #[clap(env, long, default_value = "5s", value_parser = parse_duration)]
    pub cache_lock_timeout: Duration,

    /// Timeout for fetching the response body
    #[clap(env, long, default_value = "60s", value_parser = parse_duration)]
    pub cache_body_timeout: Duration,

    /// `beta` parameter of an x-fetch algorithm which influences if earlier or later refreshing of the cache entry is performed.
    /// Values >1 favor earlier refreshes, <1 - later.
    /// Value of 0.0 would effectively disable the x-fetch algorithm.
    #[clap(env, long, default_value = "3.0")]
    pub cache_xfetch_beta: f64,
}

#[derive(Args)]
pub struct Cors {
    /// Default value for Access-Control-Allow-Origin header
    #[clap(env, long, default_value = "*")]
    pub cors_allow_origin: Vec<HeaderValue>,

    /// Default value for Access-Control-Max-Age header. Usually capped to 2h by the browser.
    #[clap(env, long, default_value = "2h", value_parser = parse_duration)]
    pub cors_max_age: Duration,

    /// Whether to forward CORS requests to the canisters.
    /// If the CORS reply from the canister is incorrect then it will be replaced with a default one.
    #[clap(env, long)]
    pub cors_canister_passthrough: bool,

    /// Maximum number of canisters to cache that replied incorrectly to the OPTIONS request
    #[clap(env, long, default_value = "10m", value_parser = parse_size_decimal)]
    pub cors_invalid_canisters_max: u64,

    /// Timeout for expiring invalid canisters from the cache
    #[clap(env, long, default_value = "1d", value_parser = parse_duration)]
    pub cors_invalid_canisters_ttl: Duration,
}

#[derive(Args)]
pub struct RateLimit {
    /// Bypass token for rate-limiter that should be sent in `x-ratelimit-bypass-token` header
    #[clap(env, long)]
    pub rate_limit_bypass_token: Option<String>,
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_cli() {
        let args: Vec<&str> = vec![];
        Cli::parse_from(args);
    }
}
