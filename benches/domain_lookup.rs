use std::sync::Arc;

use criterion::{Criterion, criterion_group, criterion_main};
use fqdn::fqdn;
use ic_bn_lib_common::{principal, types::CustomDomain};
use prometheus::Registry;
use rand::{Rng, seq::SliceRandom, thread_rng};

use ic_gateway::{
    routing::domain::{CustomDomainStorage, ResolvesDomain},
    test::FakeDomainProvider,
};

fn criterion_benchmark(c: &mut Criterion) {
    let mut rng = thread_rng();
    let rgx_domains =
        rand_regex::Regex::compile(r"[a-z]{1,20}\.[a-z]{1,20}\.[a-z]{1,3}", 20).unwrap();

    let domains = (&mut rng)
        .sample_iter(&rgx_domains)
        .take(10000)
        .collect::<Vec<String>>()
        .into_iter()
        .map(|x| fqdn!(&x))
        .collect::<Vec<_>>();

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    let custom_domains = domains
        .clone()
        .into_iter()
        .map(|x| CustomDomain {
            name: x,
            canister_id: principal!("aaaaa-aa"),
            timestamp: 0,
        })
        .collect::<Vec<_>>();

    let s = CustomDomainStorage::new(
        vec![Arc::new(FakeDomainProvider(custom_domains))],
        &Registry::new(),
    );
    runtime.block_on(async {
        s.refresh().await;
    });

    c.bench_function("domain_lookup", |b| {
        b.iter_batched(
            || domains.choose(&mut rng).unwrap(),
            |r| {
                s.resolve(r);
            },
            criterion::BatchSize::SmallInput,
        )
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
