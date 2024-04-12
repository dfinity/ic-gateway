pub mod dns;

use std::sync::Arc;

use async_trait::async_trait;
use mockall::automock;
use reqwest::{Client, Error, Request, Response};

use crate::{cli, core::SERVICE_NAME, http::dns::DnsResolver, tls::prepare_rustls_client_config};

#[automock]
#[async_trait]
pub trait HttpClient: Send + Sync {
    async fn execute(&self, req: Request) -> Result<Response, Error>;
}

pub struct ReqwestClient(Client);

impl ReqwestClient {
    pub fn new(cli: &cli::Cli) -> Result<Self, anyhow::Error> {
        let http = &cli.http_client;

        let client = Client::builder()
            .use_preconfigured_tls(prepare_rustls_client_config())
            .dns_resolver(Arc::new(DnsResolver::new(&cli.dns)))
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
impl HttpClient for ReqwestClient {
    async fn execute(&self, req: Request) -> Result<Response, Error> {
        self.0.execute(req).await
    }
}
