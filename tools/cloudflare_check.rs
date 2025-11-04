use clap::Parser;
use cloudflare::{
    endpoints::zones::zone::{ListZones, ListZonesParams, Zone},
    framework::{
        Environment,
        auth::Credentials,
        client::{ClientConfig, async_api::Client},
    },
};

#[derive(Parser)]
pub struct Cli {
    #[clap(env, long)]
    pub zone: String,

    #[clap(env, long)]
    pub token: String,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    let credentials = Credentials::UserAuthToken {
        token: cli.token.clone(),
    };

    let client = Client::new(
        credentials,
        ClientConfig::default(),
        Environment::Custom("https://api.cloudflare.com/client/v4/".to_string()),
    )
    .unwrap();

    let resp = client
        .request(&ListZones {
            params: ListZonesParams {
                name: Some(cli.zone.clone()),
                status: None,
                page: None,
                per_page: None,
                order: None,
                direction: None,
                search_match: None,
            },
        })
        .await
        .unwrap();

    let zone_id = match resp.result.first() {
        Some(Zone { id, .. }) => id.clone(),
        None => {
            println!("Zone '{}' not found", cli.zone);
            return;
        }
    };

    println!("Zone '{}' found with id {zone_id}", cli.zone);
}
