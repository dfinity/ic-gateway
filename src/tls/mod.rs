pub mod acme;
pub mod cert;
pub mod resolver;
pub mod sessions;
pub mod tickets;

use std::{fs, sync::Arc, time::Duration};

use anyhow::{anyhow, Context, Error};
use cert::Storage;
use fqdn::{Fqdn, FQDN};
use instant_acme::ChallengeType;
use ocsp_stapler::Stapler;
use prometheus::Registry;
use rustls::{
    client::{ClientConfig, ClientSessionMemoryCache, Resumption},
    compress::CompressionCache,
    server::{ResolvesServerCert as ResolvesServerCertRustls, ServerConfig, StoresServerSessions},
    version::{TLS12, TLS13},
    RootCertStore, TicketSwitcher,
};

use crate::{
    cli::Cli,
    http::{dns::Resolves, Client, ACME_TLS_ALPN_NAME, ALPN_H1, ALPN_H2},
    routing::domain::ProvidesCustomDomains,
    tasks::TaskManager,
    tls::{
        cert::{providers, Aggregator},
        resolver::AggregatingResolver,
    },
};

use self::acme::Challenge;

use {
    acme::{
        dns::{AcmeDns, DnsBackend, DnsManager, TokenManagerDns},
        Acme, AcmeOptions,
    },
    cert::providers::ProvidesCertificates,
};

// Checks if given host matches any of domains
// If wildcard is true then also checks if host is a direct child of any of domains
pub fn sni_matches(host: &Fqdn, domains: &[FQDN], wildcard: bool) -> bool {
    domains
        .iter()
        .any(|x| x == host || (wildcard && Some(x.as_ref()) == host.parent()))
}

pub fn prepare_server_config(
    resolver: Arc<dyn ResolvesServerCertRustls>,
    session_storage: Arc<dyn StoresServerSessions + Send + Sync>,
    additional_alpn: Vec<Vec<u8>>,
    ticket_lifetime: Duration,
    registry: &Registry,
) -> ServerConfig {
    let mut cfg = ServerConfig::builder_with_protocol_versions(&[&TLS13, &TLS12])
        .with_no_client_auth()
        .with_cert_resolver(resolver);

    // Set custom session storage with to allow effective TLS session resumption
    let session_storage = sessions::WithMetrics(session_storage, sessions::Metrics::new(registry));
    cfg.session_storage = Arc::new(session_storage);

    // Enable ticketer to encrypt/decrypt TLS tickets
    let ticketer = tickets::WithMetrics(
        TicketSwitcher::new(ticket_lifetime.as_secs() as u32, move || {
            Ok(Box::new(tickets::Ticketer::new()))
        })
        .unwrap(),
        tickets::Metrics::new(registry),
    );
    cfg.ticketer = Arc::new(ticketer);

    // Enable larger certificate compression caching.
    // See https://datatracker.ietf.org/doc/rfc8879/ for details
    cfg.cert_compression_cache = Arc::new(CompressionCache::new(1024));

    // Enable ALPN
    cfg.alpn_protocols = vec![ALPN_H2.to_vec(), ALPN_H1.to_vec()];
    cfg.alpn_protocols.extend_from_slice(&additional_alpn);

    cfg
}

pub fn prepare_client_config() -> ClientConfig {
    let root_store = RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.into(),
    };

    // TODO no revocation checking currently
    let mut cfg = ClientConfig::builder_with_protocol_versions(&[&TLS13, &TLS12])
        .with_root_certificates(root_store)
        .with_no_client_auth();

    // Session resumption
    let store = ClientSessionMemoryCache::new(2048);
    cfg.resumption = Resumption::store(Arc::new(store));
    cfg.alpn_protocols = vec![ALPN_H2.to_vec(), ALPN_H1.to_vec()];

    cfg
}

async fn setup_acme(
    cli: &Cli,
    tasks: &mut TaskManager,
    domains: Vec<FQDN>,
    challenge: &acme::Challenge,
    dns_resolver: Arc<dyn Resolves>,
) -> Result<Arc<dyn ResolvesServerCertRustls>, Error> {
    let opts = AcmeOptions::new(
        domains.iter().map(|x| x.to_string()).collect::<Vec<_>>(),
        cli.acme.acme_cache_path.clone().unwrap(),
        cli.acme.acme_renew_before,
        cli.acme.acme_wildcard,
        cli.acme.acme_staging,
        cli.acme.acme_contact.clone(),
    );

    let resolver = match challenge {
        acme::Challenge::Alpn => acme::alpn::AcmeAlpn::new(opts, tasks)?,

        acme::Challenge::Dns => {
            let dns_backend = match cli.acme.acme_dns_backend {
                DnsBackend::Cloudflare => {
                    let path = cli
                        .acme
                        .acme_dns_cloudflare_token
                        .clone()
                        .ok_or_else(|| anyhow!("Cloudflare token not defined"))?;

                    let token =
                        fs::read_to_string(path).context("unable to read Cloudflare token")?;

                    Arc::new(acme::dns::cloudflare::Cloudflare::new(
                        cli.acme.acme_dns_cloudflare_url.clone(),
                        token,
                    )?) as Arc<dyn DnsManager>
                }
            };

            let token_manager = TokenManagerDns::new(dns_resolver, dns_backend);
            let acme_client = Acme::new(ChallengeType::Dns01, Arc::new(token_manager), opts)
                .await
                .context("unable to create ACME client")?;
            let acme_dns = Arc::new(AcmeDns::new(acme_client, domains, cli.acme.acme_wildcard));
            tasks.add("acme_dns_runner", acme_dns.clone());

            acme_dns
        }
    };

    Ok(resolver)
}

// Prepares the stuff needed for serving TLS
pub async fn setup(
    cli: &Cli,
    tasks: &mut TaskManager,
    domains: Vec<FQDN>,
    http_client: Arc<dyn Client>,
    dns_resolver: Arc<dyn Resolves>,
    tls_session_storage: Arc<dyn StoresServerSessions + Send + Sync>,
    registry: &Registry,
) -> Result<(ServerConfig, Vec<Arc<dyn ProvidesCustomDomains>>), Error> {
    // Prepare certificate storage
    let cert_storage = Arc::new(Storage::new());

    let mut cert_providers: Vec<Arc<dyn ProvidesCertificates>> = vec![];
    let mut custom_domain_providers: Vec<Arc<dyn ProvidesCustomDomains>> = vec![];

    // Create Dir providers
    for v in &cli.cert.cert_provider_dir {
        cert_providers.push(Arc::new(providers::Dir::new(v.clone())));
    }

    // Create CertIssuer providers
    // It's a custom domain & cert provider at the same time.
    for v in &cli.cert.cert_provider_issuer_url {
        let issuer = Arc::new(providers::Issuer::new(http_client.clone(), v.clone()));
        cert_providers.push(issuer.clone());
        custom_domain_providers.push(issuer);
    }

    // Prepare ACME if configured
    let acme_resolver = if let Some(v) = &cli.acme.acme_challenge {
        Some(setup_acme(cli, tasks, domains, v, dns_resolver).await?)
    } else {
        None
    };

    if acme_resolver.is_none() && cert_providers.is_empty() {
        return Err(anyhow!(
            "No ACME or certificate providers specified - HTTPS cannot be used"
        ));
    }

    // Create certificate aggregator that combines all providers
    let cert_aggregator = Arc::new(Aggregator::new(
        cert_providers,
        cert_storage.clone(),
        cli.cert.cert_provider_poll_interval,
    ));
    tasks.add("cert_aggregator", cert_aggregator);

    // Set up certificate resolver
    let certificate_resolver =
        Arc::new(AggregatingResolver::new(acme_resolver, vec![cert_storage]));

    // Optionally wrap resolver with OCSP stapler
    let certificate_resolver: Arc<dyn ResolvesServerCertRustls> =
        if !cli.cert.cert_ocsp_stapling_disable {
            let stapler = Arc::new(Stapler::new_with_registry(certificate_resolver, registry));
            tasks.add("ocsp_stapler", stapler.clone());
            stapler
        } else {
            certificate_resolver
        };

    // Generate Rustls config
    let config = prepare_server_config(
        certificate_resolver,
        tls_session_storage,
        if cli.acme.acme_challenge == Some(Challenge::Alpn) {
            vec![ACME_TLS_ALPN_NAME.to_vec()]
        } else {
            vec![]
        },
        cli.http_server.http_server_tls_ticket_lifetime,
        registry,
    );

    Ok((config, custom_domain_providers))
}

#[cfg(test)]
mod test {
    use fqdn::fqdn;

    use super::*;

    #[test]
    fn test_sni_matches() {
        let domains = vec![fqdn!("foo1.bar"), fqdn!("foo2.bar"), fqdn!("foo3.bar")];

        // Check direct
        assert!(sni_matches(&fqdn!("foo1.bar"), &domains, false));
        assert!(sni_matches(&fqdn!("foo2.bar"), &domains, false));
        assert!(sni_matches(&fqdn!("foo3.bar"), &domains, false));
        assert!(!sni_matches(&fqdn!("foo4.bar"), &domains, false));

        // Check wildcard
        assert!(sni_matches(&fqdn!("foo1.bar"), &domains, true));
        assert!(sni_matches(&fqdn!("baz.foo1.bar"), &domains, true));
        assert!(sni_matches(&fqdn!("bza.foo1.bar"), &domains, true));
        assert!(sni_matches(&fqdn!("baz.foo2.bar"), &domains, true));
        assert!(sni_matches(&fqdn!("bza.foo2.bar"), &domains, true));

        // Make sure deeper subdomains are not matched
        assert!(!sni_matches(&fqdn!("baz.baz.foo1.bar"), &domains, true));
    }
}
