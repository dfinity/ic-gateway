use std::sync::Arc;

use anyhow::Error;
use async_trait::async_trait;
use criterion::{Criterion, criterion_group, criterion_main};
use fqdn::fqdn;
use rand::{Rng, seq::SliceRandom, thread_rng};

use ic_gateway::{
    ProvidesCustomDomains, principal,
    routing::domain::{CustomDomain, CustomDomainStorage, ResolvesDomain},
};

#[derive(Debug)]
struct FakeDomainProvider(Vec<CustomDomain>);

#[async_trait]
impl ProvidesCustomDomains for FakeDomainProvider {
    async fn get_custom_domains(&self) -> Result<Vec<CustomDomain>, Error> {
        Ok(self.0.clone())
    }
}

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
        })
        .collect::<Vec<_>>();

    let s = CustomDomainStorage::new(vec![Arc::new(FakeDomainProvider(custom_domains))]);
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
