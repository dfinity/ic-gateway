use async_trait::async_trait;
use mockall::automock;
use reqwest::{Client, Error, Request, Response};

#[automock]
#[async_trait]
pub trait HttpClient: Send + Sync {
    async fn execute(&self, req: Request) -> Result<Response, Error>;
}

pub struct ReqwestClient(Client);

impl ReqwestClient {
    pub const fn new(c: Client) -> Self {
        Self(c)
    }
}

#[async_trait]
impl HttpClient for ReqwestClient {
    async fn execute(&self, req: Request) -> Result<Response, Error> {
        self.0.execute(req).await
    }
}
