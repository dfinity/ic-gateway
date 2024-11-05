pub mod cert;
pub mod resolver;

use std::{fs, sync::Arc};

use anyhow::{anyhow, bail, Context, Error};
use async_trait::async_trait;
use fqdn::FQDN;
use ic_bn_lib::{
    http::{dns::Resolves, ALPN_ACME},
    tasks::{Run, TaskManager},
    tls::{
        self,
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
use rustls::server::{ResolvesServerCert as ResolvesServerCertRustls, ServerConfig};
use tokio_util::sync::CancellationToken;

use crate::{
    cli::Cli,
    tls::{
        cert::{providers, Aggregator},
        resolver::AggregatingResolver,
    },
};

use cert::{providers::ProvidesCertificates, storage};

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
    dns_resolver: Arc<dyn Resolves>,
    custom_domain_providers: Vec<Arc<dyn ProvidesCertificates>>,
    registry: &Registry,
) -> Result<ServerConfig, Error> {
    // Prepare certificate storage
    let cert_storage = Arc::new(storage::Storage::new(
        cli.cert.cert_default.clone(),
        storage::Metrics::new(registry),
    ));

    let mut cert_providers: Vec<Arc<dyn ProvidesCertificates>> = vec![];

    // Create Dir providers
    for v in &cli.cert.cert_provider_dir {
        cert_providers.push(Arc::new(providers::Dir::new(v.clone())));
    }

    // Add custom domain certificate providers
    cert_providers.extend(custom_domain_providers);

    // Prepare ACME if configured
    let acme_resolver = if let Some(v) = &cli.acme.acme_challenge {
        Some(setup_acme(cli, tasks, domains, v, dns_resolver).await?)
    } else {
        None
    };

    if acme_resolver.is_none() && cert_providers.is_empty() {
        bail!("No ACME or certificate providers specified - HTTPS cannot be used");
    }

    // Create certificate aggregator that combines all providers
    let cert_aggregator = Arc::new(Aggregator::new(
        cert_providers,
        cert_storage.clone(),
        cli.cert.cert_provider_poll_interval,
    ));
    tasks.add("cert_aggregator", cert_aggregator);

    // Set up certificate resolver
    let certificate_resolver = Arc::new(AggregatingResolver::new(
        acme_resolver,
        vec![cert_storage],
        resolver::Metrics::new(registry),
    ));

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

    let mut tls_opts: tls::Options = (&cli.http_server).into();
    tls_opts.tls_versions = vec![&rustls::version::TLS13, &rustls::version::TLS12];
    tls_opts.additional_alpn = if cli.acme.acme_challenge == Some(Challenge::Alpn) {
        vec![ALPN_ACME.to_vec()]
    } else {
        vec![vec![]]
    };

    // Generate Rustls config
    let config = prepare_server_config(tls_opts, certificate_resolver, registry);
    Ok(config)
}
