use std::sync::Arc;

use anyhow::Context;
use ic_bn_lib::{
    custom_domains::LooksUpCustomDomain,
    ic_agent::Agent,
    mail_auth::{
        MessageAuthenticator,
        hickory_resolver::config::{ResolverConfig, ResolverOpts},
    },
    smtp::{
        ic::delivery_agent::IcSmtpDeliveryAgent,
        inbound::{SessionConfig, SessionTlsMode},
        server::Server,
    },
    tasks::TaskManager,
};
use ic_bn_lib_common::traits::http::Client;
use rustls::ServerConfig;

use crate::Cli;

pub fn setup_smtp_server(
    cli: &Cli,
    tls_config: Option<Arc<ServerConfig>>,
    ic_agent: Agent,
    http_client: Arc<dyn Client>,
    custom_domains: Arc<dyn LooksUpCustomDomain>,
    tasks: &mut TaskManager,
) -> Result<(), anyhow::Error> {
    let mut cfg = SessionConfig::try_from(&cli.smtp_server)?;
    if let Some(v) = tls_config {
        cfg.tls_mode = SessionTlsMode::Allowed(v);
    }

    let authenticator =
        MessageAuthenticator::new(ResolverConfig::from(&cli.dns), ResolverOpts::from(&cli.dns))
            .context("unable to create SMTP Message Authenticator")?;

    let ic_delivery_agent = Arc::new(IcSmtpDeliveryAgent::new_with_agent(
        ic_agent,
        custom_domains,
        http_client,
        &cli.smtp_server.smtp_server_ic_base_domain,
        cli.smtp_server.smtp_server_mx_canister_cache_ttl,
        cli.smtp_server.smtp_server_mx_canister_cache_capacity,
    ));

    cfg.authenticator = Arc::new(authenticator);
    cfg.delivery_agent = ic_delivery_agent.clone();
    cfg.recipient_resolver = ic_delivery_agent;

    let smtp_server = Server::new(cli.smtp_server.smtp_server_listen.unwrap(), cfg)
        .context("unable to create SMTP server")?;
    tasks.add("smtp_server", Arc::new(smtp_server));

    Ok(())
}
