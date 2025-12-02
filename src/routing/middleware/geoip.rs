use std::{net::IpAddr, path::PathBuf, sync::Arc, time::Instant};

use anyhow::Error;
use axum::{
    extract::{Request, State},
    middleware::Next,
    response::Response,
};
use maxminddb::geoip2;
use tracing::warn;

use crate::routing::RemoteAddr;

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
        let country: Option<geoip2::Country> = self.db.lookup(ip).ok().flatten();

        country.and_then(|x| {
            x.country
                .and_then(|x| x.iso_code.map(|x| CountryCode(x.into())))
        })
    }
}

pub async fn middleware(
    State(geoip): State<Arc<GeoIp>>,
    mut request: Request,
    next: Next,
) -> Response {
    let remote_addr = request.extensions().get::<RemoteAddr>().copied();

    // Lookup code
    let country_code = remote_addr.and_then(|x| geoip.lookup(*x));

    if let Some(v) = &country_code {
        request.extensions_mut().insert(v.clone());
    }

    #[allow(unused_mut)]
    let mut response = next.run(request).await;

    #[cfg(test)]
    if let Some(v) = country_code {
        response.extensions_mut().insert(v);
    }

    response
}
