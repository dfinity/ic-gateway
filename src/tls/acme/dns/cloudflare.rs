use anyhow::{anyhow, Context, Error};
use async_trait::async_trait;
use cloudflare::{
    endpoints::{
        dns::{
            CreateDnsRecord, CreateDnsRecordParams, DeleteDnsRecord, DnsContent, DnsRecord,
            ListDnsRecords, ListDnsRecordsParams,
        },
        zone::{ListZones, ListZonesParams, Zone},
    },
    framework::{
        async_api::{ApiClient, Client},
        auth::Credentials,
        response::ApiSuccess,
        Environment, HttpApiClientConfig,
    },
};
use tracing::warn;

use super::{DnsManager, Record};

impl TryFrom<DnsContent> for Record {
    type Error = Error;

    fn try_from(value: DnsContent) -> Result<Self, Self::Error> {
        match value {
            DnsContent::TXT { content } => Ok(Self::Txt(content)),
            _ => Err(anyhow!("not supported")),
        }
    }
}

pub struct Cloudflare {
    client: Client,
}

impl Cloudflare {
    pub fn new(url: &str, key: &str) -> Result<Self, Error> {
        let credentials = Credentials::UserAuthToken { token: key.into() };

        let client = Client::new(
            credentials,
            HttpApiClientConfig::default(),
            Environment::Custom(url.try_into().context("invalid api url")?),
        )
        .context("failed to initialize cloudflare api client")?;

        Ok(Self { client })
    }

    async fn find_zone(&self, zone: &str) -> Result<String, Error> {
        let resp = self
            .client
            .request(&ListZones {
                params: ListZonesParams {
                    name: Some(zone.into()),
                    status: None,
                    page: None,
                    per_page: None,
                    order: None,
                    direction: None,
                    search_match: None,
                },
            })
            .await?;

        let zone_id = match resp.result.first() {
            Some(Zone { id, .. }) => id.clone(),
            None => return Err(anyhow!("zone '{zone}' not found")),
        };

        Ok(zone_id)
    }

    async fn find_record(
        &self,
        zone_id: &str,
        name: String,
    ) -> Result<ApiSuccess<Vec<DnsRecord>>, Error> {
        let resp = self
            .client
            .request(&ListDnsRecords {
                zone_identifier: zone_id,
                params: ListDnsRecordsParams {
                    record_type: None,
                    name: Some(name),
                    page: None,
                    per_page: None,
                    order: None,
                    direction: None,
                    search_match: None,
                },
            })
            .await?;

        Ok(resp)
    }
}

#[async_trait]
impl DnsManager for Cloudflare {
    async fn create(&self, zone: &str, name: &str, record: Record, ttl: u32) -> Result<(), Error> {
        // Search zone
        let zone_id = self.find_zone(zone).await?;

        // Create/Update record
        let content = match record {
            Record::Txt(content) => DnsContent::TXT { content },
        };

        warn!("adding {} {:?}", name, content);

        self.client
            .request(&CreateDnsRecord {
                zone_identifier: &zone_id,
                params: CreateDnsRecordParams {
                    ttl: Some(ttl),
                    priority: None,
                    proxied: None,
                    name,
                    content,
                },
            })
            .await?;

        Ok(())
    }

    async fn delete(&self, zone: &str, name: &str) -> Result<(), Error> {
        // Search zone
        let zone_id = self.find_zone(zone).await?;

        // Find records
        let resp = self
            .find_record(&zone_id, format!("{}.{}", name, zone))
            .await?;

        // Delete all matching records
        for record in resp.result {
            warn!("deleting {:?}", record.content);

            self.client
                .request(&DeleteDnsRecord {
                    zone_identifier: &zone_id,
                    identifier: &record.id,
                })
                .await?;
        }

        Ok(())
    }
}
