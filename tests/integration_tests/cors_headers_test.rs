use std::time::Duration;

use crate::helpers::{
    COUNTER_WAT, TestCase, TestEnv, create_canister_with_cycles, retry_async,
    verify_options_call_headers,
};
use anyhow::anyhow;
use candid::{Encode, Principal};
use hex::encode;
use http::{Method, StatusCode};
use reqwest::Client;
use tokio::runtime::Runtime;
use tracing::info;
use url::Url;

const CANISTER_INITIAL_CYCLES: u128 = 100_000_000_000_000;
const REQUEST_RETRY_TIMEOUT: Duration = Duration::from_secs(50);
const REQUEST_RETRY_INTERVAL: Duration = Duration::from_secs(10);

pub fn cors_headers_test(env: &TestEnv) -> anyhow::Result<()> {
    info!("counter canister installation start ...");
    let canister_id =
        create_canister_with_cycles(&env.pic, Principal::anonymous(), CANISTER_INITIAL_CYCLES);
    env.pic.install_canister(
        canister_id,
        wat::parse_str(COUNTER_WAT).unwrap(),
        Encode!(&()).unwrap(),
        None,
    );
    let module_hash = env
        .pic
        .canister_status(canister_id, None)
        .unwrap()
        .module_hash
        .unwrap();
    let hash_str = encode(module_hash);
    info!("counter canister with id={canister_id} installed, hash={hash_str}");

    let test_cases = [
        TestCase {
            name: "status".into(),
            method: Method::GET,
            expect: StatusCode::OK,
            path: "/api/v2/status".into(),
            allowed_methods: "HEAD, GET".into(),
        },
        TestCase {
            name: "query".into(),
            method: Method::POST,
            expect: StatusCode::BAD_REQUEST,
            path: format!("/api/v2/canister/{canister_id}/query"),
            allowed_methods: "POST".into(),
        },
        TestCase {
            name: "call".into(),
            method: Method::POST,
            expect: StatusCode::BAD_REQUEST,
            path: format!("/api/v2/canister/{canister_id}/call"),
            allowed_methods: "POST".into(),
        },
        TestCase {
            name: "read_state".into(),
            method: Method::POST,
            expect: StatusCode::BAD_REQUEST,
            path: format!("/api/v2/canister/{canister_id}/read_state"),
            allowed_methods: "POST".into(),
        },
    ];

    let http_client = Client::builder()
        .resolve(&env.ic_gateway_domain, env.ic_gateway_addr)
        .build()
        .map_err(|e| anyhow!("failed to build http client: {e}"))?;

    let rt = Runtime::new().map_err(|e| anyhow!("failed to start tokio runtime: {e}"))?;

    for test in test_cases {
        let url = Url::parse(&format!(
            "http://{}:{}{}",
            env.ic_gateway_domain,
            env.ic_gateway_addr.port(),
            test.path.clone(),
        ))
        .map_err(|e| anyhow!("failed to parse url: {e}"))?;

        rt.block_on(retry_async(
            "verifying HTTP responses",
            REQUEST_RETRY_TIMEOUT,
            REQUEST_RETRY_INTERVAL,
            || verify_options_call_headers(&http_client, url.as_str(), test.clone()),
        ))
        .map_err(|e| anyhow!("failed to verify : {e}"))?;
    }

    Ok(())
}

// pub fn cors_headers_test(env: TestEnv) {
//     let logger = env.logger();

//     let boundary_node = env
//         .get_deployed_boundary_node(BOUNDARY_NODE_NAME)
//         .unwrap()
//         .get_snapshot()
//         .expect("failed to get BN snapshot");

//     let client_builder = ClientBuilder::new().redirect(Policy::none());
//     let (client_builder, host_orig) = if let Some(playnet) = boundary_node.get_playnet() {
//         (client_builder, playnet)
//     } else {
//         let host = "ic0.app";
//         let bn_addr = SocketAddrV6::new(boundary_node.ipv6(), 0, 0, 0);
//         let client_builder = client_builder
//             .danger_accept_invalid_certs(true)
//             .resolve(host, bn_addr.into());
//         (client_builder, host.to_string())
//     };
//     let client = client_builder.build().unwrap();

//     let (install_url, effective_canister_id) =
//         get_install_url(&env).expect("failed to get install url");

//     let rt = Runtime::new().expect("failed to create tokio runtime");

//     let cid = rt
//         .block_on(async {
//             info!(&logger, "creating management agent");
//             let agent = assert_create_agent(install_url.as_str()).await;

//             info!(&logger, "creating canister");
//             let cid = create_canister(
//                 &agent,
//                 effective_canister_id,
//                 wat::parse_str(COUNTER_CANISTER_WAT).unwrap().as_slice(),
//                 None,
//             )
//             .await
//             .map_err(|err| anyhow!(format!("failed to create canister: {}", err)))?;

//             info!(&logger, "Waiting for canisters to finish installing...");
//             retry_with_msg_async!(
//                 format!(
//                     "agent of {} observes canister module {}",
//                     install_url.to_string(),
//                     cid.to_string()
//                 ),
//                 &logger,
//                 READY_WAIT_TIMEOUT,
//                 RETRY_BACKOFF,
//                 || async {
//                     match agent_observes_canister_module(&agent, &cid).await {
//                         true => Ok(()),
//                         false => panic!("Canister module not available yet"),
//                     }
//                 }
//             )
//             .await
//             .unwrap();

//             let out: Result<Principal, Error> = Ok(cid);
//             out
//         })
//         .expect("failed to initialize test");

//     let futs = FuturesUnordered::new();

//     struct TestCase {
//         name: String,
//         path: String,
//         method: Method,
//         expect: StatusCode,
//         allowed_methods: String,
//     }

//     let test_cases = [
//         TestCase {
//             name: "status".into(),
//             method: Method::GET,
//             expect: StatusCode::OK,
//             path: "/api/v2/status".into(),
//             allowed_methods: "HEAD, GET".into(),
//         },
//         TestCase {
//             name: "query".into(),
//             method: Method::POST,
//             expect: StatusCode::BAD_REQUEST,
//             path: format!("/api/v2/canister/{cid}/query"),
//             allowed_methods: "POST".into(),
//         },
//         TestCase {
//             name: "call".into(),
//             method: Method::POST,
//             expect: StatusCode::BAD_REQUEST,
//             path: format!("/api/v2/canister/{cid}/call"),
//             allowed_methods: "POST".into(),
//         },
//         TestCase {
//             name: "read_state".into(),
//             method: Method::POST,
//             expect: StatusCode::BAD_REQUEST,
//             path: format!("/api/v2/canister/{cid}/read_state"),
//             allowed_methods: "POST".into(),
//         },
//     ];

//     for tc in test_cases {
//         let client = client.clone();
//         let logger = logger.clone();

//         let TestCase {
//             name,
//             method,
//             expect,
//             path,
//             allowed_methods,
//         } = tc;

//         let host = host_orig.clone();
//         futs.push(rt.spawn(async move {
//             info!(&logger, "Starting subtest {}", name);

//             let mut url = reqwest::Url::parse(&format!("https://{host}"))?;
//             url.set_path(&path);
//             let req = reqwest::Request::new(Method::OPTIONS, url);
//             let res = client.execute(req).await?;

//             // Both 200 and 204 are valid OPTIONS codes
//             if ![StatusCode::NO_CONTENT, StatusCode::OK].contains(&res.status())  {
//                 bail!("{name} OPTIONS failed: {}", res.status())
//             }

//             // Normalize & sort header values so that they can be compared regardless of their order
//             fn normalize(hdr: &str) -> String {
//                 let mut hdr = hdr.split(',').map(|x| x.trim().to_ascii_lowercase()).collect::<Vec<_>>();
//                 hdr.sort();
//                 hdr.join(",")
//             }

//             // Check pre-flight CORS headers
//             for (k, v) in [
//                 ("Access-Control-Allow-Origin", "*"),
//                 ("Access-Control-Allow-Methods", &allowed_methods),
//                 ("Access-Control-Allow-Headers", "DNT,User-Agent,X-Requested-With,If-None-Match,If-Modified-Since,Cache-Control,Content-Type,Range,Cookie,X-Ic-Canister-Id"),
//                 ("Access-Control-Max-Age", "600"),
//             ] {
//                 let hdr = res
//                     .headers()
//                     .get(k)
//                     .ok_or_else(|| anyhow!("{name} OPTIONS failed: missing {k} header"))?.to_str()?;

//                 let hdr = normalize(hdr);
//                 let expect = normalize(v);

//                 if hdr != expect {
//                     bail!("{name} OPTIONS failed: wrong {k} header: {hdr} expected {expect}")
//                 }
//             }

//             // Check non-pre-flight CORS headers
//             let mut url = reqwest::Url::parse(&format!("https://{host}"))?;
//             url.set_path(&path);
//             let req = reqwest::Request::new(method, url);
//             let res = client.execute(req).await?;

//             if res.status() != expect {
//                 bail!("{name} failed: expected {expect}, got {}", res.status())
//             }

//             for (k, v) in [
//                 ("Access-Control-Allow-Origin", "*"),
//                 ("Access-Control-Expose-Headers", "Accept-Ranges,Content-Length,Content-Range,X-Request-Id,X-Ic-Canister-Id"),
//             ] {
//                 let hdr = res
//                     .headers()
//                     .get(k)
//                     .ok_or_else(|| anyhow!("{name} failed: missing {k} header"))?.to_str()?;

//                 let hdr = normalize(hdr);
//                 let expect = normalize(v);

//                 if hdr != expect {
//                     bail!("{name} failed: wrong {k} header: {hdr} expected {expect}")
//                 }
//             }

//             Ok(())
//         }));
//     }

//     rt.block_on(async move {
//         let mut cnt_err = 0;
//         info!(&logger, "Waiting for subtests");

//         for fut in futs {
//             match fut.await {
//                 Ok(Err(err)) => {
//                     error!(logger, "test failed: {}", err);
//                     cnt_err += 1;
//                 }
//                 Err(err) => {
//                     error!(logger, "test panicked: {}", err);
//                     cnt_err += 1;
//                 }
//                 _ => {}
//             }
//         }

//         match cnt_err {
//             0 => Ok(()),
//             _ => bail!("failed with {cnt_err} errors"),
//         }
//     })
//     .expect("test suite failed");
// }
