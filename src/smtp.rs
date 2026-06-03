use std::{sync::Arc, time::Duration};

use anyhow::Context;
use async_trait::async_trait;
use ic_bn_lib::{
    SerializeOption,
    custom_domains::LooksUpCustomDomain,
    ic_agent::Agent,
    mail_auth::{
        MessageAuthenticator,
        hickory_resolver::config::{ResolverConfig, ResolverOpts},
    },
    smtp::{
        self, DeliveryError, EmailMessage, MessageError, ProtocolError, ReceivesSmtpNotifications,
        SessionMeta,
        ic::{
            self, DestCanister, ReceivesIcSmtpNotifications, delivery_agent::IcSmtpDeliveryAgent,
        },
        inbound::{SessionConfig, SessionError, SessionTlsMode},
        server::Server,
    },
    tasks::TaskManager,
    vector::{
        VectorOptions,
        client::{Metrics, Vector},
    },
};
use ic_bn_lib_common::traits::http::Client;
use prometheus::Registry;
use rustls::ServerConfig;
use serde_json::json;
use time::OffsetDateTime;

use crate::{
    Cli,
    core::{ENV, HOSTNAME},
};

#[derive(Debug)]
struct SmtpNotificationHandler {
    env: String,
    hostname: String,
    vector: Arc<Vector>,
}

impl SmtpNotificationHandler {
    pub fn new(vector: Arc<Vector>) -> Self {
        let env = ENV.get().unwrap().clone();
        let hostname = HOSTNAME.get().unwrap().clone();

        Self {
            env,
            hostname,
            vector,
        }
    }
}

#[async_trait]
impl ReceivesSmtpNotifications for SmtpNotificationHandler {
    async fn notify_message(
        &self,
        meta: SessionMeta,
        message: Arc<EmailMessage>,
        latency: Duration,
        error: Option<MessageError>,
    ) {
        let timestamp = OffsetDateTime::now_utc().unix_timestamp();
        let error_type: &'static str = error.as_ref().map_or("", |x| x.into());

        let event = json!({
            "type": "message",
            "env": &self.env,
            "hostname": &self.hostname,
            "timestamp": timestamp,
            "message_id": message.id,
            "session_id": meta.id,
            "remote_addr": meta.remote_ip,
            "ehlo_hostname": meta.ehlo_hostname.serialize_or(""),
            "from": message.mail_from,
            "to": message.rcpt_to,
            "size": message.body.len(),
            "latency": latency.as_secs_f64(),
            "error_type": error_type,
            "error_details": error.serialize_or(""),
        });

        self.vector.send(event);
    }

    async fn notify_protocol_error(&self, meta: SessionMeta, error: ProtocolError) {
        let timestamp = OffsetDateTime::now_utc().unix_timestamp();
        let error_type: &'static str = (&error).into();

        let event = json!({
            "type": "error",
            "env": &self.env,
            "hostname": &self.hostname,
            "timestamp": timestamp,
            "session_id": meta.id,
            "remote_addr": meta.remote_ip,
            "ehlo_hostname": &meta.ehlo_hostname.serialize_or(""),
            "error_type": error_type,
            "error_details": error,
        });

        self.vector.send(event);
    }

    async fn notify_session_finish(&self, meta: SessionMeta, error: Option<SessionError>) {
        let timestamp = OffsetDateTime::now_utc().unix_timestamp();
        let (tls_version, tls_cipher, tls_handshake) =
            meta.tls_info
                .as_ref()
                .map_or(("", "", Duration::ZERO), |x| {
                    (
                        x.protocol.as_str().unwrap_or_default(),
                        x.cipher.as_str().unwrap_or_default(),
                        x.handshake_dur,
                    )
                });

        let error_type: &'static str = error.as_ref().map_or("", |x| x.into());

        let event = json!({
            "type": "session",
            "env": &self.env,
            "hostname": &self.hostname,
            "timestamp": timestamp,
            "session_id": meta.id,
            "remote_addr": meta.remote_ip,
            "ehlo_hostname": &meta.ehlo_hostname.serialize_or(""),
            "tls_version": tls_version,
            "tls_cipher": tls_cipher,
            "tls_handshake": tls_handshake.as_secs_f64(),
            "bytes_rx": meta.counters.bytes_rx,
            "bytes_tx": meta.counters.bytes_tx,
            "commands": meta.counters.commands,
            "errors": meta.counters.errors,
            "duration": meta.counters.started.elapsed().as_secs_f64(),
            "error_type": error_type,
            "error_details": error.serialize_or(""),
        });

        self.vector.send(event);
    }
}

#[async_trait]
impl ReceivesIcSmtpNotifications for SmtpNotificationHandler {
    async fn notify_ic_message(
        &self,
        meta: Arc<SessionMeta>,
        message: Arc<EmailMessage>,
        dest: DestCanister,
        latency: Duration,
        error: Option<DeliveryError>,
    ) {
        let timestamp = OffsetDateTime::now_utc().unix_timestamp();
        let error_type: &'static str = error.as_ref().map_or("", |x| x.into());

        let event = json!({
            "type": "ic_message",
            "env": &self.env,
            "hostname": &self.hostname,
            "timestamp": timestamp,
            "message_id": message.id,
            "session_id": meta.id,
            "remote_addr": meta.remote_ip,
            "ehlo_hostname": &meta.ehlo_hostname.serialize_or(""),
            "from": message.mail_from,
            "to": message.rcpt_to,
            "size": message.body.len(),
            "canister_id": dest.orig,
            "canister_id_smtp": dest.smtp,
            "custom_domain": dest.custom_domain,
            "latency": latency.as_secs_f64(),
            "error_type": error_type,
            "error_details": error.serialize_or(""),
        });

        self.vector.send(event);
    }
}

/// Sets up SMTP server
#[allow(clippy::too_many_arguments)]
pub fn setup_smtp_server(
    cli: &Cli,
    tls_config: Option<Arc<ServerConfig>>,
    ic_agent: Agent,
    http_client: Arc<dyn Client>,
    custom_domains: Arc<dyn LooksUpCustomDomain>,
    tasks: &mut TaskManager,
    registry: &Registry,
    vector_metrics: Metrics,
) -> Result<(), anyhow::Error> {
    let mut cfg = SessionConfig::try_from(&cli.smtp_server)?;
    if let Some(v) = tls_config {
        if cli.smtp_server.smtp_server_tls_required {
            cfg.tls_mode = SessionTlsMode::Required(v);
        } else {
            cfg.tls_mode = SessionTlsMode::Allowed(v);
        }
    }

    let notification_handler = if let Some(v) = &cli.smtp_server.smtp_server_vector_url {
        let mut opts =
            VectorOptions::try_from(&cli.log.vector).context("unable to parse Vector options")?;
        opts.url = v.clone();
        opts.user
            .clone_from(&cli.smtp_server.smtp_server_vector_user);
        opts.pass
            .clone_from(&cli.smtp_server.smtp_server_vector_pass);

        let vector = Arc::new(Vector::new_with_metrics(
            opts,
            http_client.clone(),
            "smtp",
            vector_metrics,
        ));

        let notification_handler = Arc::new(SmtpNotificationHandler::new(vector));
        cfg.notifications_handler = Some(notification_handler.clone());

        Some(notification_handler as Arc<dyn ReceivesIcSmtpNotifications>)
    } else {
        None
    };

    let authenticator =
        MessageAuthenticator::new(ResolverConfig::from(&cli.dns), ResolverOpts::from(&cli.dns))
            .context("unable to create SMTP Message Authenticator")?;

    let ic_delivery_agent = Arc::new(IcSmtpDeliveryAgent::new_with_agent(
        ic_agent,
        custom_domains,
        http_client,
        &cli.smtp_server.smtp_server_ic_base_domain,
        cli.smtp_server.smtp_server_canister_cache_ttl,
        cli.smtp_server.smtp_server_canister_cache_capacity,
        ic::Metrics::new(registry),
        notification_handler,
    ));

    cfg.authenticator = Arc::new(authenticator);
    cfg.delivery_agent = ic_delivery_agent.clone();
    cfg.recipient_resolver = ic_delivery_agent;

    let smtp_server = Server::new(
        cli.smtp_server.smtp_server_listen.unwrap(),
        cfg,
        smtp::Metrics::new(registry),
    )
    .context("unable to create SMTP server")?;
    tasks.add("smtp_server", Arc::new(smtp_server));

    Ok(())
}
