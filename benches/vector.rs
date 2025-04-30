use bytes::BytesMut;
use criterion::{Criterion, criterion_group, criterion_main};
use rand::{Rng, prelude::Distribution, rngs::ThreadRng, seq::SliceRandom, thread_rng};
use serde_json::{Value, json};

use ic_gateway::metrics::vector::EventEncoder;
use uuid::Uuid;

fn create_event(
    rng: &mut ThreadRng,
    rgx_principal: &rand_regex::Regex,
    rgx_canister: &rand_regex::Regex,
) -> Value {
    let p = rgx_principal
        .sample_iter(&mut *rng)
        .take(3)
        .collect::<Vec<String>>();

    let c = rgx_canister
        .sample_iter(&mut *rng)
        .take(2)
        .collect::<Vec<String>>();

    json!({
        "env": "prod",
        "hostname": &["da11-bnp00", "da11-bnp01", "da11-bnp02", "da11-bnp03", "da11-bnp04", "da11-bnp05", "da11-bnp06", "da11-bnp07"].choose(&mut *rng).unwrap(),
        "msec": rng.gen_range(100000000..200000000),
        "request_id": Uuid::now_v7().to_string(),
        "request_method": &["PUT", "GET", "POST", "DELETE", "UPDATE", "OPTIONS"].choose(&mut *rng).unwrap(),
        "server_protocol": &["HTTP/1.0", "HTTP/1.1", "HTTP/2.0"].choose(&mut *rng).unwrap(),
        "status": rng.gen_range(100..599),
        "status_upstream": rng.gen_range(100..599),
        "http_host": "foobar.com",
        "http_origin": "foobar2.com",
        "http_referer": "foobar3.com/foo/bar",
        "http_user_agent": "Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:47.0) Gecko/20100101 Firefox/47.0",
        "content_type": "text/plain",
        "geo_country_code": "CH",
        "request_uri": "https://foobar.com/foo/bar/baz/dead/beef",
        "query_string": "?foo=1&bar=2&baz=3",
        "ic_node_id": p[0],
        "ic_subnet_id": p[1],
        "ic_method_name": "http_request",
        "ic_request_type": &["query", "call", "sync_call", "read_state"].choose(&mut *rng).unwrap(),
        "ic_sender": p[2],
        "ic_canister_id": c[0],
        "ic_canister_id_cbor": c[1],
        "ic_error_cause": "foobar",
        "retries": 0,
        "error_cause": "no_error",
        "ssl_protocol": &["TLSv1_3", "TLSv1_2"].choose(&mut *rng).unwrap(),
        "ssl_cipher": "TLS13_AES_256_GCM_SHA384",
        "request_length": rng.gen_range(100..10000),
        "body_bytes_sent": rng.gen_range(100..10000),
        "bytes_sent": rng.gen_range(100..1000),
        "remote_addr": "5fcfafd1a139fc995662feea66e52ae7",
        "request_time": 1.5,
        "request_time_headers": 0,
        "cache_status": &["MISS", "HIT", "BYPASS", "DISABLED"].choose(&mut *rng).unwrap(),
        "cache_status_nginx": &["MISS", "HIT", "BYPASS", "DISABLED"].choose(&mut *rng).unwrap(),
        "cache_bypass_reason": &["unable_to_extract_key", "no_authoriy"].choose(&mut *rng).unwrap(),
        "upstream": &["or1-dll01.gntlficpnode.com"].choose(&mut *rng).unwrap(),
    })
}

fn create_batch(
    size: usize,
    rng: &mut ThreadRng,
    rgx_principal: &rand_regex::Regex,
    rgx_canister: &rand_regex::Regex,
) -> Vec<Value> {
    let mut batch = Vec::with_capacity(size);
    for _ in 0..size {
        batch.push(create_event(rng, rgx_principal, rgx_canister));
    }

    batch
}

fn criterion_benchmark(c: &mut Criterion) {
    let mut encoder = EventEncoder::new();
    let mut buf = BytesMut::with_capacity(1024 * 1024 * 10);

    let mut rng = thread_rng();
    // upg5h-ggk5u-6qxp7-ksz3r-osynn-z2wou-65klx-cuala-sd6y3-3lorr-dae
    let rgx_principal =
        rand_regex::Regex::compile(r"[a-z]{5}-[a-z]{5}-[a-z]{5}-[a-z]{5}-[a-z]{5}-[a-z]{5}-[a-z]{5}-[a-z]{5}-[a-z]{5}-[a-z]{5}-[a-z]{3}", 5).unwrap();
    let rgx_canister =
        rand_regex::Regex::compile(r"[a-z]{5}-[a-z]{5}-[a-z]{5}-[a-z]{5}", 5).unwrap();

    c.bench_function("vector_encode_event", |b| {
        b.iter_batched(
            || create_event(&mut rng, &rgx_principal, &rgx_canister),
            |r| encoder.encode_event(r, &mut buf),
            criterion::BatchSize::SmallInput,
        )
    });

    c.bench_function("vector_encode_batch_1k", |b| {
        b.iter_batched(
            || create_batch(1000, &mut rng, &rgx_principal, &rgx_canister),
            |r| encoder.encode_batch(r),
            criterion::BatchSize::SmallInput,
        )
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
