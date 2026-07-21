use ic_bn_lib::tls::acme::{AcmeUrl, client::ClientBuilder};

#[tokio::main]
async fn main() {
    let (_, creds) = ClientBuilder::default()
        .with_acme_url(AcmeUrl::LetsEncryptStaging)
        .create_account("mailto:boundary-nodes@dfinity.org")
        .await
        .unwrap();

    let js = serde_json::to_vec(&creds).unwrap();
    tokio::fs::write("account.json", js).await.unwrap();
}
