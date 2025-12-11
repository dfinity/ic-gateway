use std::sync::Arc;

use anyhow::{Error, bail};
use ic_bn_lib::{
    tasks::TaskManager,
    tls::{
        prepare_server_config,
        providers::{self, Aggregator, storage},
        resolver,
    },
    utils::health_manager::HealthManager,
};
#[cfg(feature = "acme")]
use ic_bn_lib_common::{traits::dns::Resolves, types::acme::Challenge};
use ic_bn_lib_common::{traits::tls::ProvidesCertificates, types::tls::TlsOptions};
use prometheus::Registry;
use rustls::server::ServerConfig;

#[cfg(feature = "acme")]
use {
    anyhow::{Context, anyhow},
    fqdn::FQDN,
    ic_bn_lib::tls::acme::{
        self,
        dns::{AcmeDns, TokenManagerDns},
    },
    rustls::server::ResolvesServerCert as ResolvesServerCertRustls,
    std::{fs, time::Duration},
};

use crate::cli::Cli;

#[cfg(feature = "acme")]
async fn setup_acme(
    cli: &Cli,
    tasks: &mut TaskManager,
    domains: Vec<FQDN>,
    challenge: &Challenge,
    dns_resolver: Arc<dyn Resolves>,
) -> Result<Arc<dyn ResolvesServerCertRustls>, Error> {
    let cache_path = cli.acme.acme_cache_path.clone().unwrap();

    let resolver: Arc<dyn ResolvesServerCertRustls> = match challenge {
        Challenge::Alpn => {
            let opts = acme::alpn::Opts::new(
                cli.acme.acme_url.clone(),
                domains.iter().map(|x| x.to_string()).collect::<Vec<_>>(),
                cli.acme.acme_contact.clone(),
                cache_path,
                None,
            );

            let acme_alpn = Arc::new(acme::alpn::AcmeAlpn::new(opts));
            tasks.add("acme_alpn", acme_alpn.clone());

            acme_alpn
        }

        Challenge::Dns => {
            use ic_bn_lib_common::types::acme::DnsBackend;

            let dns_backend = match cli.acme.acme_dns_backend {
                DnsBackend::Cloudflare => {
                    use ic_bn_lib_common::traits::acme::DnsManager;

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

                _ => bail!("unsupported DNS backend: {}", cli.acme.acme_dns_backend),
            };

            let token_manager = Arc::new(TokenManagerDns::new(dns_resolver, dns_backend, None));

            let opts = acme::dns::Opts {
                acme_url: cli.acme.acme_url.clone(),
                domains,
                path: cache_path,
                wildcard: cli.acme.acme_wildcard,
                renew_before: cli.acme.acme_renew_before,
                account_credentials: None,
                token_manager,
                insecure_tls: false,
            };

            let acme_dns = Arc::new(AcmeDns::new(opts).await.context("unable to init AcmeDns")?);
            tasks.add_interval(
                "acme_dns_runner",
                acme_dns.clone(),
                Duration::from_secs(600),
            );

            acme_dns
        }
    };

    Ok(resolver)
}

/// Prepares the stuff needed for serving TLS
pub async fn setup(
    cli: &Cli,
    tasks: &mut TaskManager,
    health_manager: Arc<HealthManager>,
    #[cfg(feature = "acme")] domains: Vec<FQDN>,
    #[cfg(feature = "acme")] dns_resolver: Arc<dyn Resolves>,
    certificate_providers: Vec<Arc<dyn ProvidesCertificates>>,
    registry: &Registry,
) -> Result<ServerConfig, Error> {
    // Prepare certificate storage
    let cert_storage = Arc::new(storage::Storage::new(
        cli.cert.cert_default.clone(),
        storage::Metrics::new(registry),
    ));

    let mut providers: Vec<Arc<dyn ProvidesCertificates>> = vec![];

    // Create File providers
    for v in &cli.cert.cert_provider_file {
        providers.push(Arc::new(providers::File::new(v.clone())));
    }

    // Create Dir providers
    for v in &cli.cert.cert_provider_dir {
        providers.push(Arc::new(providers::Dir::new(v.clone())));
    }

    // Add custom domain certificate providers
    providers.extend(certificate_providers);

    // Prepare ACME if configured
    #[cfg(feature = "acme")]
    let acme_resolver = if let Some(v) = &cli.acme.acme_challenge {
        Some(setup_acme(cli, tasks, domains, v, dns_resolver).await?)
    } else {
        None
    };

    #[cfg(feature = "acme")]
    {
        if acme_resolver.is_none() && providers.is_empty() {
            bail!("No ACME or certificate providers specified - HTTPS cannot be used");
        }
    }
    #[cfg(not(feature = "acme"))]
    {
        if providers.is_empty() {
            bail!("No certificate providers specified - HTTPS cannot be used");
        }
    }

    // Create certificate aggregator that combines all providers
    let cert_aggregator = Arc::new(Aggregator::new(providers, cert_storage.clone()));
    health_manager.add(cert_aggregator.clone());

    tasks.add_interval(
        "cert_aggregator",
        cert_aggregator,
        cli.cert.cert_provider_poll_interval,
    );

    // Set up certificate resolver
    let certificate_resolver = Arc::new(resolver::AggregatingResolver::new(
        #[cfg(feature = "acme")]
        acme_resolver,
        #[cfg(not(feature = "acme"))]
        None,
        vec![cert_storage],
        resolver::Metrics::new(registry),
    ));

    let mut tls_opts: TlsOptions = (&cli.http_server).into();
    tls_opts.tls_versions = vec![&rustls::version::TLS13, &rustls::version::TLS12];

    #[cfg(feature = "acme")]
    {
        tls_opts.additional_alpn = if cli.acme.acme_challenge == Some(Challenge::Alpn) {
            use ic_bn_lib_common::types::http::ALPN_ACME;

            vec![ALPN_ACME.to_vec()]
        } else {
            vec![vec![]]
        };
    }

    // Generate Rustls config
    let config = prepare_server_config(tls_opts, certificate_resolver, registry);
    Ok(config)
}
