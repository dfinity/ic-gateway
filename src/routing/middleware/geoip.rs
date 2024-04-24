use std::{net::IpAddr, path::PathBuf, sync::Arc};

use anyhow::Error;
use axum::{
    extract::{Request, State},
    middleware::Next,
    response::Response,
};
use maxminddb::geoip2;

use crate::http::ConnInfo;
use tracing::warn;

#[derive(Clone, Debug)]
pub struct CountryCode(String);

pub struct GeoIp {
    db: maxminddb::Reader<Vec<u8>>,
}

impl GeoIp {
    pub fn new(db_path: &PathBuf) -> Result<Self, Error> {
        let db = maxminddb::Reader::open_readfile(db_path)?;
        warn!("GeoIP loaded with {} entries", db.metadata.node_count);
        Ok(Self { db })
    }

    pub fn lookup(&self, ip: IpAddr) -> CountryCode {
        let country: Option<geoip2::Country> = self.db.lookup(ip).ok();

        CountryCode(
            country
                .and_then(|x| x.country.and_then(|x| x.iso_code))
                .unwrap_or("N/A")
                .into(),
        )
    }
}

pub async fn geoip(State(geoip): State<Arc<GeoIp>>, mut request: Request, next: Next) -> Response {
    // It should always be there, if not - then it's a bug and it's better to die
    let conn_info = request.extensions().get::<Arc<ConnInfo>>().unwrap();

    // Lookup code
    let country_code = geoip.lookup(conn_info.remote_addr.ip());

    request.extensions_mut().insert(country_code);
    next.run(request).await
}
