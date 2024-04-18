use std::sync::Arc;

use async_trait::async_trait;
use mockall::automock;

use crate::{cli, core::SERVICE_NAME, http::dns::Resolver, tls::prepare_client_config};

#[automock]
#[async_trait]
pub trait Client: Send + Sync {
    async fn execute(&self, req: reqwest::Request) -> Result<reqwest::Response, reqwest::Error>;
}

#[derive(Clone)]
pub struct ReqwestClient(reqwest::Client);

impl ReqwestClient {
    pub fn new(cli: &cli::Cli) -> Result<Self, anyhow::Error> {
        let http = &cli.http_client;

        let client = reqwest::Client::builder()
            .use_preconfigured_tls(prepare_client_config())
            .dns_resolver(Arc::new(Resolver::new(&cli.dns)))
            .connect_timeout(http.timeout_connect)
            .timeout(http.timeout)
            .tcp_nodelay(true)
            .tcp_keepalive(Some(http.tcp_keepalive))
            .http2_keep_alive_interval(Some(http.http2_keepalive))
            .http2_keep_alive_timeout(http.http2_keepalive_timeout)
            .http2_keep_alive_while_idle(true)
            .http2_adaptive_window(true)
            .user_agent(SERVICE_NAME)
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
