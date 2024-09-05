pub mod cert;
pub mod resolver;

use std::{fs, sync::Arc};

use anyhow::{anyhow, Context, Error};
use async_trait::async_trait;
use cert::Storage;
use fqdn::FQDN;
use ic_bn_lib::{
    http::{dns::Resolves, Client, ALPN_ACME, ALPN_H1, ALPN_H2},
    tasks::{Run, TaskManager},
    tls::{
        acme::{
            self,
            dns::{AcmeDns, DnsBackend, DnsManager, TokenManagerDns},
            instant_acme::ChallengeType,
            Acme, AcmeOptions, Challenge,
        },
        prepare_server_config,
    },
};
use ocsp_stapler::Stapler;
use prometheus::Registry;
use rustls::{
    client::{ClientConfig, ClientSessionMemoryCache, Resumption},
    server::{ResolvesServerCert as ResolvesServerCertRustls, ServerConfig, StoresServerSessions},
    version::{TLS12, TLS13},
};
use rustls_platform_verifier::Verifier;
use tokio_util::sync::CancellationToken;

use crate::{
    cli::Cli,
    routing::domain::ProvidesCustomDomains,
    tls::{
        cert::{providers, Aggregator},
        resolver::AggregatingResolver,
    },
};

use cert::providers::ProvidesCertificates;

// Wrapper is needed since we can't implement foreign traits
struct OcspStaplerWrapper(Arc<ocsp_stapler::Stapler>);

#[async_trait]
impl Run for OcspStaplerWrapper {
    async fn run(&self, token: CancellationToken) -> Result<(), Error> {
        token.cancelled().await;
        self.0.stop().await;
        Ok(())
    }
}

pub fn prepare_client_config() -> ClientConfig {
    // Use a custom certificate verifier from rustls project that is more secure.
    // It also checks OCSP revocation, though OCSP support for Linux platform for now seems be no-op.
    // https://github.com/rustls/rustls-platform-verifier/issues/99

    // new_with_extra_roots() method isn't available on MacOS, see
    // https://github.com/rustls/rustls-platform-verifier/issues/58
    #[cfg(not(target_os = "macos"))]
    let verifier = Arc::new(Verifier::new_with_extra_roots(
        webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    ));
    #[cfg(target_os = "macos")]
    let verifier = Arc::new(Verifier::new());

    let mut cfg = ClientConfig::builder_with_protocol_versions(&[&TLS13, &TLS12])
        .dangerous() // Nothing really dangerous here
        .with_custom_certificate_verifier(verifier)
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
        acme::Challenge::Alpn => acme::alpn::new(opts, tasks.token()),

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
        if cli.cert.cert_ocsp_stapling_disable {
            certificate_resolver
        } else {
            let stapler = Arc::new(Stapler::new_with_registry(certificate_resolver, registry));
            tasks.add(
                "ocsp_stapler",
                Arc::new(OcspStaplerWrapper(stapler.clone())),
            );
            stapler
        };

    let alpn = if cli.acme.acme_challenge == Some(Challenge::Alpn) {
        vec![ALPN_ACME.to_vec()]
    } else {
        vec![vec![]]
    };

    // Generate Rustls config
    let config = prepare_server_config(
        certificate_resolver,
        tls_session_storage,
        &alpn,
        cli.http_server.http_server_tls_ticket_lifetime,
        &[&rustls::version::TLS13, &rustls::version::TLS12],
        registry,
    );

    Ok((config, custom_domain_providers))
}
