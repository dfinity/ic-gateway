use std::{fmt, sync::Arc, time::Duration};

use async_trait::async_trait;
use http::header::HeaderValue;
use mockall::automock;
use reqwest::dns::Resolve;

use ic_agent::agent::http_transport::reqwest_transport::reqwest::Client as AgentClient;

#[automock]
#[async_trait]
pub trait Client: Send + Sync + fmt::Debug {
    async fn execute(&self, req: reqwest::Request) -> Result<reqwest::Response, reqwest::Error>;
}

pub struct Options {
    pub timeout_connect: Duration,
    pub timeout: Duration,
    pub tcp_keepalive: Option<Duration>,
    pub http2_keepalive: Option<Duration>,
    pub http2_keepalive_timeout: Duration,
    pub user_agent: String,
    pub tls_config: rustls::ClientConfig,
}

pub fn new(
    opts: Options,
    dns_resolver: impl Resolve + 'static,
) -> Result<AgentClient, anyhow::Error> {
    let client = AgentClient::builder()
        .use_preconfigured_tls(opts.tls_config)
        .dns_resolver(Arc::new(dns_resolver))
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

    Ok(client)
}

#[derive(Clone, Debug)]
pub struct ReqwestClient(reqwest::Client);

impl ReqwestClient {
    pub const fn new(client: reqwest::Client) -> Self {
        Self(client)
    }
}

#[async_trait]
impl Client for ReqwestClient {
    async fn execute(&self, req: reqwest::Request) -> Result<reqwest::Response, reqwest::Error> {
        self.0.execute(req).await
    }
}

pub fn basic_auth<U, P>(username: U, password: Option<P>) -> HeaderValue
where
    U: std::fmt::Display,
    P: std::fmt::Display,
{
    use base64::prelude::BASE64_STANDARD;
    use base64::write::EncoderWriter;
    use std::io::Write;

    let mut buf = b"Basic ".to_vec();
    {
        let mut encoder = EncoderWriter::new(&mut buf, &BASE64_STANDARD);
        let _ = write!(encoder, "{username}:");
        if let Some(password) = password {
            let _ = write!(encoder, "{password}");
        }
    }
    let mut header = HeaderValue::from_bytes(&buf).expect("base64 is always valid HeaderValue");
    header.set_sensitive(true);
    header
}
