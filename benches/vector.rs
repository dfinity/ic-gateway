use bytes::BytesMut;
use criterion::{Criterion, criterion_group, criterion_main};
use serde_json::{Value, json};

use ic_gateway::metrics::vector::EventEncoder;

fn create_event() -> Value {
    json!({
        "env": "prod",
        "hostname": "da11-bnp00",
        "msec": 1000,
        "request_id": "69f9acca-6321-4d03-905b-d2424cba4ba2",
        "request_method": "PUT",
        "server_protocol": "HTTP/2.0",
        "status": 200,
        "status_upstream": 200,
        "http_host": "foobar.com",
        "http_origin": "foobar2.com",
        "http_referer": "foobar3.com/foo/bar",
        "http_user_agent": "Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:47.0) Gecko/20100101 Firefox/47.0",
        "content_type": "text/plain",
        "geo_country_code": "CH",
        "request_uri": "https://foobar.com/foo/bar/baz/dead/beef",
        "query_string": "?foo=1&bar=2&baz=3",
        "ic_node_id": "upg5h-ggk5u-6qxp7-ksz3r-osynn-z2wou-65klx-cuala-sd6y3-3lorr-dae",
        "ic_subnet_id": "yqbqe-whgvn-teyic-zvtln-rcolf-yztin-ecal6-smlwy-6imph-6isdn-qqe",
        "ic_method_name": "http_request",
        "ic_request_type": "query",
        "ic_sender": "4fssn-4vi43-2qufr-hlrfz-hfohd-jgrwc-7l7ok-uatwb-ukau7-lwmoz-tae",
        "ic_canister_id": "canister_id",
        "ic_canister_id_cbor": "4fssn-4vi43-2qufr-hlrfz",
        "ic_error_cause": "foobar",
        "retries": 0,
        "error_cause": "no_error",
        "ssl_protocol": "TLSv1_3",
        "ssl_cipher": "TLS13_AES_256_GCM_SHA384",
        "request_length": 1000,
        "body_bytes_sent": 2000,
        "bytes_sent": 2500,
        "remote_addr": "5fcfafd1a139fc995662feea66e52ae7",
        "request_time": 1.5,
        "request_time_headers": 0,
        "cache_status": "MISS",
        "cache_status_nginx": "MISS",
        "cache_bypass_reason": "unable_to_extract_key",
        "upstream": "or1-dll01.gntlficpnode.com",
    })
}

fn create_batch(size: usize) -> Vec<Value> {
    let mut batch = Vec::with_capacity(size);
    for _ in 0..size {
        batch.push(create_event());
    }

    batch
}

fn criterion_benchmark(c: &mut Criterion) {
    let mut encoder = EventEncoder::new();
    let mut buf = BytesMut::with_capacity(1024 * 1024 * 10);

    c.bench_function("vector_encode_event", |b| {
        b.iter_batched(
            || create_event(),
            |r| encoder.encode_event(r, &mut buf),
            criterion::BatchSize::SmallInput,
        )
    });

    c.bench_function("vector_encode_batch_1000k", |b| {
        b.iter_batched(
            || create_batch(1000),
            |r| encoder.encode_batch(r),
            criterion::BatchSize::SmallInput,
        )
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
