use std::{sync::Arc, time::Duration};

use axum::body::Body;
use criterion::{Criterion, criterion_group, criterion_main};
use http::Uri;
use ic_bn_lib::{http::ConnInfo, tasks::TaskManager};
use rand::{seq::SliceRandom, thread_rng};

use ic_gateway::test::setup_test_router;
use tower::Service;

fn criterion_benchmark(c: &mut Criterion) {
    rustls::crypto::ring::default_provider()
        .install_default()
        .unwrap();

    let mut rng = thread_rng();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();

    // Create the test router
    let mut tasks = TaskManager::new();
    let (router, domains) = setup_test_router(&mut tasks);
    // Start the tasks and give them some time to finish
    runtime.block_on(async {
        tasks.start();
        tokio::time::sleep(Duration::from_secs(5)).await;
    });

    c.bench_function("router", |b| {
        b.to_async(&runtime).iter_batched(
            || {
                // Pick a domain & some other domain as path to make sure that caching doesn't kick in
                let domain = domains.choose(&mut rng).unwrap();
                let path = domains.choose(&mut rng).unwrap();
                let mut req = axum::extract::Request::new(Body::from(""));
                *req.uri_mut() = Uri::try_from(format!("http://{domain}/{path}")).unwrap();
                let conn_info = Arc::new(ConnInfo::default());
                (*req.extensions_mut()).insert(conn_info);

                (req, router.clone())
            },
            |(req, mut router)| async move {
                let _ = router.call(req).await.unwrap();
            },
            criterion::BatchSize::SmallInput,
        )
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
