use crate::helpers::{
    ExpectedResponse, RETRY_INTERVAL, RETRY_TIMEOUT, StaticAsset, TestEnv, check_response,
    get_asset_canister_wasm, get_large_assets_canister_wasm, install_canister, retry_async,
    upload_asset_to_asset_canister,
};
use anyhow::{Context, anyhow, bail};
use candid::Principal;
use http::{HeaderValue, Method, StatusCode};
use reqwest::{Client, Request};
use tracing::info;
use url::Url;

// Test scenario:
// - deploy asset canister via pocket-ic interface
// - upload some sample assets to the canister
//   - root path: "/"
//   - JS file: "/foo.js"
//   - non-root path: "/a/b/c"
//   - invalid data (broken certification): "/invalid_data.txt"
//   - large asset (6mb): "/6mb.txt" (verified streaming)
//   - large asset (10mb): "/10mb.txt" (unverified streaming)
// - retrieve asset via HTTP client through ic-gateway endpoint
// - verify asset integrity

pub async fn basic_http_gateway_test(env: &TestEnv) -> anyhow::Result<()> {
    info!("install asset canister ...");
    let asset_canister_id = install_canister(
        &env.pic,
        Principal::anonymous(),
        None,
        get_asset_canister_wasm(),
    )
    .await;

    info!("setup HTTP client ...");
    let certified_domain = format!("{asset_canister_id}.{}", env.ic_gateway_domain);
    let raw_domain = format!("{asset_canister_id}.raw.{}", env.ic_gateway_domain);

    let http_client = Client::builder()
        .resolve(certified_domain.as_str(), env.ic_gateway_addr)
        .resolve(raw_domain.as_str(), env.ic_gateway_addr)
        .build()
        .context(anyhow!("failed to build http client"))?;

    let test_cases = [
        (
            "certified root".to_string(),
            StaticAsset::new("/", "Hello World!", "text/plain", "identity", None),
            certified_domain.clone(),
            ExpectedResponse::new(
                Some(StatusCode::OK),
                Some("Hello World!".to_string().as_bytes().to_vec()),
                None,
            ),
        ),
        (
            "certified /foo.js".to_string(),
            StaticAsset::new(
                "/foo.js",
                r#"console.log("Hello World!")"#,
                "application/javascript",
                "identity",
                None,
            ),
            certified_domain.clone(),
            ExpectedResponse::new(
                Some(StatusCode::OK),
                Some(r#"console.log("Hello World!")"#.to_string().as_bytes().to_vec()),
                None,
            ),
        ),
        (
            "certified /foo.js over raw".to_string(),
            StaticAsset::new(
                "/foo.js",
                r#"console.log("Hello World!")"#,
                "application/javascript",
                "identity",
                None,
            ),
            raw_domain.clone(),
            ExpectedResponse::new(
                Some(StatusCode::OK),
                Some(r#"console.log("Hello World!")"#.to_string().as_bytes().to_vec()),
                None,
            ),
        ),
        (
            "certified /a/b/c".to_string(),
            StaticAsset::new(
                "/a/b/c",
                "Do re mi, A B C, 1 2 3",
                "text/plain",
                "identity",
                None,
            ),
            certified_domain.clone(),
            ExpectedResponse::new(
                Some(StatusCode::OK),
                Some("Do re mi, A B C, 1 2 3".to_string().as_bytes().to_vec()),
                None,
            ),
        ),
        (
            "uncertified /invalid_data.txt".to_string(),
            StaticAsset::new(
                "/invalid_data.txt",
                "This doesn't checkout",
                "text/plain",
                "identity",
                Some(vec![0; 32]),
            ),
            certified_domain.clone(),
            ExpectedResponse::new(Some(StatusCode::BAD_GATEWAY), None, None),
        ),
        (
            "uncertified /invalid_data.txt over raw".to_string(),
            StaticAsset::new(
                "/invalid_data.txt",
                "This doesn't checkout",
                "text/plain",
                "identity",
                Some(vec![0; 32]),
            ),
            raw_domain.clone(),
            ExpectedResponse::new(
                Some(StatusCode::OK),
                Some("This doesn't checkout".to_string().as_bytes().to_vec()),
                None,
            ),
        ),
        (
            "certified 6mb asset (streaming)".to_string(),
            StaticAsset::new(
                "/6mb.txt",
                "6".repeat(6 * 1024 * 1024),
                "text/plain",
                "identity",
                None,
            ),
            certified_domain.clone(),
            ExpectedResponse::new(
                Some(StatusCode::OK),
                Some("6".repeat(6 * 1024 * 1024).as_bytes().to_vec()),
                None,
            ),
        ),
        (
            "uncertified 6mb asset (streaming)".to_string(),
            StaticAsset::new(
                "/6mb.txt",
                "6".repeat(6 * 1024 * 1024),
                "text/plain",
                "identity",
                Some(vec![0; 32]),
            ),
            certified_domain.clone(),
            ExpectedResponse::new(Some(StatusCode::BAD_GATEWAY), None, None),
        ),
        (
            "certified 10mb asset (unverified)".to_string(),
            StaticAsset::new(
                "/10mb.txt",
                "A".repeat(10 * 1024 * 1024),
                "text/plain",
                "identity",
                None,
            ),
            certified_domain.clone(),
            ExpectedResponse::new(
                Some(StatusCode::OK),
                Some("A".repeat(10 * 1024 * 1024).as_bytes().to_vec()),
                None,
            ),
        ),
        (
            "uncertified 10mb asset (unverified)".to_string(),
            StaticAsset::new(
                "/10mb.txt",
                "A".repeat(10 * 1024 * 1024),
                "text/plain",
                "identity",
                Some(vec![0; 32]),
            ),
            certified_domain.clone(),
            ExpectedResponse::new(
                Some(StatusCode::OK),
                Some("A".repeat(10 * 1024 * 1024).as_bytes().to_vec()),
                None,
            ),
        ),
    ];

    for (test_case_name, asset, domain, expected_response) in test_cases {
        info!("upload {} ...", asset.path);
        upload_asset_to_asset_canister(&env.pic, asset_canister_id, asset.clone()).await;

        let request = {
            let asset_url = Url::parse(&format!(
                "http://{domain}:{}{}",
                env.ic_gateway_addr.port(),
                asset.path,
            ))
            .expect("failed to parse url");
            Request::new(Method::GET, asset_url)
        };

        retry_async(
            format!("verifying HTTP response for '{test_case_name}'"),
            RETRY_TIMEOUT,
            RETRY_INTERVAL,
            || async {
                let response = http_client
                    .execute(request.try_clone().unwrap())
                    .await
                    .context("failed to execute request")?;

                check_response(response, &expected_response).await
            },
        )
        .await
        .context(anyhow!("failed to verify stored asset"))?;
    }

    Ok(())
}

// Test scenario:
// - deploy special large assets canister via pocket-ic interface
// - retrieve three different assets via HTTP client through ic-gateway endpoint
//   - an asset that fits in one chunk
//   - an asset that requires two chunks and streaming
//   - an asset that requires six chunks and streaming
// - verify asset integrity

// Constants copied from long asset canister:
const ASSET_CHUNK_SIZE: usize = 2_000_000;

const ONE_CHUNK_ASSET_LEN: usize = ASSET_CHUNK_SIZE;
const TWO_CHUNKS_ASSET_LEN: usize = ASSET_CHUNK_SIZE + 1;
const SIX_CHUNKS_ASSET_LEN: usize = 5 * ASSET_CHUNK_SIZE + 12;

pub async fn large_assets_http_gateway_test(env: &TestEnv) -> anyhow::Result<()> {
    info!("install large assets canister ...");
    let asset_canister_id = install_canister(
        &env.pic,
        Principal::anonymous(),
        None,
        get_large_assets_canister_wasm(),
    )
    .await;

    info!("setup HTTP client ...");
    let certified_domain = format!("{asset_canister_id}.{}", env.ic_gateway_domain);

    let http_client = Client::builder()
        .resolve(certified_domain.as_str(), env.ic_gateway_addr)
        .build()
        .context(anyhow!("failed to build http client"))?;

    let test_cases = [
        (
            "/long_asset_one_chunk".to_string(),
            StatusCode::OK,
            ONE_CHUNK_ASSET_LEN,
        ),
        (
            "/long_asset_two_chunks".to_string(),
            StatusCode::OK,
            TWO_CHUNKS_ASSET_LEN,
        ),
        (
            "/long_asset_six_chunks".to_string(),
            StatusCode::OK,
            SIX_CHUNKS_ASSET_LEN,
        ),
    ];

    for (path, expected_status_code, expected_response_size) in test_cases {
        let mut request = {
            let asset_url = Url::parse(&format!(
                "http://{certified_domain}:{}{}",
                env.ic_gateway_addr.port(),
                path,
            ))
            .expect("failed to parse url");
            Request::new(Method::GET, asset_url)
        };
        request
            .headers_mut()
            .insert("accept-encoding", HeaderValue::from_static("gzip"));

        retry_async(
            format!("requesting '{path}'"),
            RETRY_TIMEOUT,
            RETRY_INTERVAL,
            || async {
                let response = http_client
                    .execute(request.try_clone().unwrap())
                    .await
                    .context("failed to execute request")?;

                let status = response.status();
                let body_bytes = response.bytes().await?.to_vec();

                if status != expected_status_code {
                    bail!("request failed: got {status}, expected {expected_status_code}");
                }

                if body_bytes.len() != expected_response_size {
                    bail!(
                        "response did not match uploaded content: got {} bytes, expected {} bytes",
                        body_bytes.len(),
                        expected_response_size
                    );
                }

                Ok(())
            },
        )
        .await
        .context(anyhow!("failed to verify stored asset"))?;
    }

    Ok(())
}
