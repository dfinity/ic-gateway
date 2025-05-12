use std::{sync::Arc, time::Duration};

use async_trait::async_trait;
use axum::{Extension, extract::State};
use bytes::Bytes;
use candid::{CandidType, Encode};
use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use fqdn::fqdn;
use http::{
    HeaderValue,
    header::{
        ACCEPT, ACCEPT_ENCODING, ACCEPT_LANGUAGE, ACCESS_CONTROL_REQUEST_HEADERS,
        ACCESS_CONTROL_REQUEST_METHOD, ORIGIN, USER_AGENT,
    },
};
use ic_agent::{
    AgentError,
    agent::{HttpService, route_provider::RoundRobinRouteProvider},
};
use ic_bn_lib::http::{ConnInfo, body::buffer_body};
use ic_http_certification::HttpRequest;
use ic_http_gateway::{CanisterRequest, HttpGatewayClientBuilder};
use reqwest::{Request, Response};
use uuid::Uuid;

use ic_gateway::{
    principal,
    routing::{
        CanisterId, RequestCtx, RequestType,
        domain::Domain,
        ic::handler::{HandlerState, handler},
        middleware::request_id::RequestId,
    },
    test::generate_response,
};

#[derive(Debug, Clone, CandidType)]
struct HttpRequestCandid<'a, H> {
    /// The HTTP method string.
    pub method: &'a str,
    /// The URL that was visited.
    pub url: &'a str,
    /// The request headers.
    pub headers: H,
    /// The request body.
    pub body: &'a [u8],
    /// The certificate version.
    pub certificate_version: Option<&'a u16>,
}

fn convert_request(request: CanisterRequest) -> HttpRequest<'static> {
    let uri = request.uri();
    let mut url = uri.path().to_string();
    if let Some(query) = uri.query() {
        url.push('?');
        url.push_str(query);
    }

    HttpRequest::builder()
        .with_method(request.method().clone())
        .with_url(url)
        .with_headers(
            request
                .headers()
                .into_iter()
                .map(|(name, value)| (name.to_string(), value.to_str().unwrap().to_string()))
                .collect::<Vec<_>>(),
        )
        .with_body(request.body().to_vec())
        .build()
}

fn encode_request(request: CanisterRequest) {
    let req = convert_request(request);
    let certificate_version = req.certificate_version();

    let req = HttpRequestCandid {
        method: req.method().as_ref(),
        url: req.url(),
        headers: req.headers(),
        body: req.body(),
        certificate_version: certificate_version.as_ref(),
    };

    let _ = Encode!(&req);
}

#[derive(Debug)]
pub struct TestService;

#[async_trait]
impl HttpService for TestService {
    async fn call<'a>(
        &'a self,
        _: &'a (dyn Fn() -> Result<Request, AgentError> + Send + Sync),
        _: usize,
    ) -> Result<Response, AgentError> {
        Ok(generate_response(512))
    }
}

fn add_headers<T>(req: &mut http::Request<T>) {
    req.extensions_mut()
        .insert(CanisterId(principal!("qoctq-giaaa-aaaaa-aaaea-cai")));

    req.headers_mut().insert(USER_AGENT, HeaderValue::from_static("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36"));
    req.headers_mut()
        .insert(ACCEPT, HeaderValue::from_static("*/*"));
    req.headers_mut().insert(
        ACCEPT_LANGUAGE,
        HeaderValue::from_static("en-US,en-GB;q=0.9,en;q=0.8,ru;q=0.7,de;q=0.6"),
    );
    req.headers_mut().insert(
        ACCEPT_ENCODING,
        HeaderValue::from_static("zip, deflate, br, zstd"),
    );
    req.headers_mut().insert(
        ACCESS_CONTROL_REQUEST_HEADERS,
        HeaderValue::from_static("content-type"),
    );
    req.headers_mut().insert(
        ACCESS_CONTROL_REQUEST_METHOD,
        HeaderValue::from_static("POST"),
    );
    req.headers_mut()
        .insert(ORIGIN, HeaderValue::from_static("https://nns.ic0.app"));
}

fn create_request() -> axum::extract::Request {
    let mut req = axum::extract::Request::new(axum::body::Body::from("X".repeat(512)));
    add_headers(&mut req);
    req
}

fn create_request_bytes() -> http::Request<Bytes> {
    let mut req = http::Request::new(Bytes::from("X".repeat(512)));
    add_headers(&mut req);
    req
}

fn criterion_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("http_gateway");
    group.throughput(Throughput::Elements(1));
    group.significance_level(0.1);
    group.sample_size(250);

    rustls::crypto::ring::default_provider()
        .install_default()
        .unwrap();

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    let http_service = Arc::new(TestService);

    let agent = ic_agent::Agent::builder()
        .with_arc_http_middleware(http_service)
        .with_max_concurrent_requests(200000)
        .with_route_provider(RoundRobinRouteProvider::new(vec!["http://foo.bar"]).unwrap())
        .with_verify_query_signatures(false)
        .build()
        .unwrap();

    let client = HttpGatewayClientBuilder::new()
        .with_agent(agent)
        .build()
        .unwrap();
    let state = Arc::new(HandlerState::new(
        client,
        false,
        Duration::from_secs(60),
        10 * 1024 * 1024,
    ));

    let ctx = Arc::new(RequestCtx {
        authority: fqdn!("foo"),
        domain: Domain {
            name: fqdn!("foo"),
            custom: false,
            http: false,
            api: false,
        },
        verify: false,
        request_type: RequestType::Http,
    });
    let request_id = RequestId(Uuid::now_v7());
    let canister_id = CanisterId(principal!("qoctq-giaaa-aaaaa-aaaea-cai"));
    let conn_info = Arc::new(ConnInfo::default());

    let mut req = axum::extract::Request::new(axum::body::Body::from("foobar"));
    req.extensions_mut().insert(canister_id);

    runtime.block_on(async {
        let r = handler(
            State(state.clone()),
            Extension(conn_info.clone()),
            Extension(request_id.clone()),
            Extension(ctx.clone()),
            req,
        )
        .await
        .unwrap();

        // Make sure we get the correct body
        let body = buffer_body(r.into_body(), 100000, Duration::from_secs(10))
            .await
            .unwrap();
        assert_eq!(body, "X".repeat(512));
    });

    group.bench_function("handler", |b| {
        b.to_async(&runtime).iter_batched(
            || create_request(),
            |req| async {
                handler(
                    State(state.clone()),
                    Extension(conn_info.clone()),
                    Extension(request_id.clone()),
                    Extension(ctx.clone()),
                    req,
                )
                .await
                .unwrap();
            },
            criterion::BatchSize::SmallInput,
        )
    });

    group.bench_function("request_encode", |b| {
        b.iter_batched(
            || create_request_bytes(),
            |r| {
                encode_request(r);
            },
            criterion::BatchSize::SmallInput,
        )
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
