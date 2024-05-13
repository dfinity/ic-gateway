use std::{sync::Arc, time::Duration};

use async_trait::async_trait;
use mockall::automock;

use super::dns;

#[automock]
#[async_trait]
pub trait Client: Send + Sync {
    async fn execute(&self, req: reqwest::Request) -> Result<reqwest::Response, reqwest::Error>;
}

pub struct Options {
    pub dns_options: dns::Options,
    pub timeout_connect: Duration,
    pub timeout: Duration,
    pub tcp_keepalive: Option<Duration>,
    pub http2_keepalive: Option<Duration>,
    pub http2_keepalive_timeout: Duration,
    pub user_agent: String,
    pub tls_config: rustls::ClientConfig,
}

#[derive(Clone)]
pub struct ReqwestClient(reqwest::Client);

impl ReqwestClient {
    pub fn new(opts: Options) -> Result<Self, anyhow::Error> {
        let client = reqwest::Client::builder()
            .use_preconfigured_tls(opts.tls_config)
            .dns_resolver(Arc::new(dns::Resolver::new(opts.dns_options)))
            .connect_timeout(opts.timeout_connect)
            .timeout(opts.timeout)
            .tcp_nodelay(true)
            .tcp_keepalive(opts.tcp_keepalive)
            .http2_keep_alive_interval(opts.http2_keepalive)
            .http2_keep_alive_timeout(opts.http2_keepalive_timeout)
            .http2_keep_alive_while_idle(true)
            .http2_adaptive_window(true)
            .user_agent(opts.user_agent)
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .build()?;

        Ok(Self(client))
    }
}

#[async_trait]
impl Client for ReqwestClient {
    async fn execute(&self, req: reqwest::Request) -> Result<reqwest::Response, reqwest::Error> {
        self.0.execute(req).await
    }
}
