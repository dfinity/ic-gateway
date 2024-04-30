pub mod client;
pub mod dns;
pub mod server;

use http::{HeaderMap, Version};

pub use client::{Client, ReqwestClient};
pub use server::{ConnInfo, Server};

// Calculate very approximate HTTP request/response headers size in bytes.
// More or less accurate only for http/1.1 since in h2 headers are in HPACK-compressed.
// But it seems there's no better way.
pub fn calc_headers_size(h: &HeaderMap) -> usize {
    h.iter().map(|(k, v)| k.as_str().len() + v.len() + 2).sum()
}

pub const fn http_version(v: Version) -> &'static str {
    match v {
        Version::HTTP_09 => "0.9",
        Version::HTTP_10 => "1.0",
        Version::HTTP_11 => "1.1",
        Version::HTTP_2 => "2.0",
        Version::HTTP_3 => "3.0",
        _ => "-",
    }
}
