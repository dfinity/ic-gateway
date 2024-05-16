pub mod acme;
pub mod cert;
pub mod resolver;

use std::{fs, sync::Arc};

use anyhow::{anyhow, Context, Error};
use fqdn::{Fqdn, FQDN};
use instant_acme::ChallengeType;
use rustls::{
    client::{ClientConfig, ClientSessionMemoryCache, Resumption},
    server::{
        ResolvesServerCert as ResolvesServerCertRustls, ServerConfig, ServerSessionMemoryCache,
    },
    sign::CertifiedKey,
    version::{TLS12, TLS13},
    RootCertStore,
};
use rustls_acme::acme::ACME_TLS_ALPN_NAME;

use crate::{
    cli::Cli,
    http::{dns::Resolves, is_http_alpn, Client, ALPN_H1, ALPN_H2},
    tasks::TaskManager,
    tls::{
        cert::{providers, Aggregator},
        resolver::{AggregatingResolver, ResolvesServerCert},
    },
};

use cert::{providers::ProvidesCertificates, storage::StoresCertificates};

use self::acme::{
    dns::{AcmeDns, DnsBackend, TokenManagerDns},
    Acme, AcmeOptions,
};

// Checks if given host matches any of domains
// If wildcard is true then also checks if host is a direct child of any of domains
pub fn sni_matches(host: &Fqdn, domains: &[FQDN], wildcard: bool) -> bool {
    domains
        .iter()
        .any(|x| x == host || (wildcard && Some(x.as_ref()) == host.parent()))
}

pub fn prepare_server_config(resolver: Arc<dyn ResolvesServerCertRustls>) -> ServerConfig {
    let mut cfg = ServerConfig::builder_with_protocol_versions(&[&TLS13, &TLS12])
        .with_no_client_auth()
        .with_cert_resolver(resolver);

    // Create custom session storage with higher limit to allow effective TLS session resumption
    cfg.session_storage = ServerSessionMemoryCache::new(131_072);
    cfg.alpn_protocols = vec![
        ALPN_H2.to_vec(),
        ALPN_H1.to_vec(),
        // Support ACME challenge ALPN too
        ACME_TLS_ALPN_NAME.to_vec(),
    ];

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
    resolver: Arc<dyn Resolves>,
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
        acme::Challenge::Alpn => {
            let (run, resolver) = acme::alpn::AcmeAlpn::new(opts)?;
            tasks.add("acme_alpn_runner", run);
            resolver
        }

        acme::Challenge::Dns => {
            let dns_backend = match cli.acme.acme_dns_backend {
                None => return Err(anyhow!("No DNS backend set")),

                Some(DnsBackend::Cloudflare) => {
                    let path = cli
                        .acme
                        .acme_dns_cloudflare_token
                        .clone()
                        .ok_or_else(|| anyhow!("Cloudflare token not defined"))?;

                    let token =
                        fs::read_to_string(path).context("unable to read Cloudflare token")?;

                    acme::dns::cloudflare::Cloudflare::new(
                        cli.acme.acme_dns_cloudflare_url.as_ref(),
                        &token,
                    )?
                }
            };

            let token_manager = TokenManagerDns::new(resolver, Arc::new(dns_backend));
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
    storage: Arc<dyn StoresCertificates<Arc<CertifiedKey>>>,
    cert_resolver: Arc<dyn ResolvesServerCert>,
    dns_resolver: Arc<dyn Resolves>,
) -> Result<ServerConfig, Error> {
    let mut providers = vec![];

    // Create Dir providers
    for v in &cli.cert.dir {
        providers.push(Arc::new(providers::Dir::new(v.clone())) as Arc<dyn ProvidesCertificates>);
    }

    // Create CertIssuer providers
    for v in &cli.cert.issuer_urls {
        providers.push(
            Arc::new(providers::Issuer::new(http_client.clone(), v.clone()))
                as Arc<dyn ProvidesCertificates>,
        );
    }

    // Prepare ACME if configured
    let acme_resolver = if let Some(v) = &cli.acme.acme_challenge {
        Some(setup_acme(cli, tasks, domains, v, dns_resolver).await?)
    } else {
        None
    };

    if acme_resolver.is_none() && providers.is_empty() {
        return Err(anyhow!(
            "No ACME or certificate providers specified - HTTPS cannot be used"
        ));
    }

    let cert_aggregator = Arc::new(Aggregator::new(providers, storage, cli.cert.poll_interval));
    tasks.add("cert_aggregator", cert_aggregator);

    let resolve_aggregator = Arc::new(AggregatingResolver::new(acme_resolver, vec![cert_resolver]));
    let config = prepare_server_config(resolve_aggregator);

    Ok(config)
}

#[cfg(test)]
mod test {
    use fqdn::fqdn;

    use crate::tls::sni_matches;

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
