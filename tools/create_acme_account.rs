use ic_bn_lib::tls::acme::client::ClientBuilder;

#[tokio::main]
async fn main() {
    let (_, creds) = ClientBuilder::new(false)
        .with_acme_url(ic_bn_lib::tls::acme::AcmeUrl::LetsEncryptStaging)
        .create_account("mailto:boundary-nodes@dfinity.org")
        .await
        .unwrap();

    let js = serde_json::to_vec(&creds).unwrap();
    tokio::fs::write("account.json", js).await.unwrap();
}
