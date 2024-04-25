use std::{net::IpAddr, path::PathBuf, sync::Arc, time::Instant};

use anyhow::Error;
use axum::{
    extract::{Extension, Request, State},
    middleware::Next,
    response::Response,
};
use maxminddb::geoip2;

use crate::http::ConnInfo;
use tracing::warn;

#[derive(Clone, Debug)]
pub struct CountryCode(pub String);

pub struct GeoIp {
    db: maxminddb::Reader<Vec<u8>>,
}

impl GeoIp {
    pub fn new(db_path: &PathBuf) -> Result<Self, Error> {
        let start = Instant::now();
        let db = maxminddb::Reader::open_readfile(db_path)?;
        warn!(
            "GeoIP loaded with {} entries in {}s",
            db.metadata.node_count,
            start.elapsed().as_secs_f64()
        );
        Ok(Self { db })
    }

    pub fn lookup(&self, ip: IpAddr) -> Option<CountryCode> {
        let country: Option<geoip2::Country> = self.db.lookup(ip).ok();

        country.and_then(|x| {
            x.country
                .and_then(|x| x.iso_code.map(|x| CountryCode(x.into())))
        })
    }
}

pub async fn geoip(
    State(geoip): State<Arc<GeoIp>>,
    Extension(conn_info): Extension<Arc<ConnInfo>>,
    mut request: Request,
    next: Next,
) -> Response {
    // Lookup code
    let country_code = geoip.lookup(conn_info.remote_addr.ip());
    request.extensions_mut().insert(country_code);
    next.run(request).await
}