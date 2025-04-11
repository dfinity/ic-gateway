use std::{
    env,
    fs::File,
    io::Read,
    path::PathBuf,
    time::{Duration, Instant},
};

use anyhow::bail;
use candid::Principal;
use http::StatusCode;
use ic_certified_assets::types::{
    BatchOperation, CommitBatchArguments, CreateAssetArguments, CreateBatchResponse,
    CreateChunkArg, CreateChunkResponse, SetAssetContentArguments,
};
use pocket_ic::{PocketIc, update_candid_as};
use reqwest::Client;
use tokio::time::sleep;
use tracing::info;

pub async fn retry_async<S: AsRef<str>, F, Fut, R>(
    msg: S,
    timeout: Duration,
    backoff: Duration,
    f: F,
) -> anyhow::Result<R>
where
    Fut: Future<Output = anyhow::Result<R>>,
    F: Fn() -> Fut,
{
    let msg = msg.as_ref();
    let mut attempt = 1;
    let start = Instant::now();
    info!(
        "Call \"{msg}\" is being retried for the maximum of {timeout:?} with a constant backoff of {backoff:?}"
    );
    loop {
        match f().await {
            Ok(v) => {
                info!(
                    "Call \"{msg}\" succeeded after {:?} on attempt {attempt}",
                    start.elapsed()
                );
                break Ok(v);
            }
            Err(err) => {
                let err_msg = err.to_string();
                if start.elapsed() > timeout {
                    break Err(err.context(format!(
                        "Call \"{msg}\" timed out after {:?} on attempt {attempt}. Last error: {err_msg}",
                        start.elapsed(),
                    )));
                }
                info!(
                    "Call \"{msg}\" failed on attempt {attempt}. Error: {}",
                    truncate_error_msg(err_msg)
                );
                sleep(backoff).await;
                attempt += 1;
            }
        }
    }
}

fn truncate_error_msg(err_str: String) -> String {
    let mut short_e = err_str.replace('\n', "\\n ");
    short_e.truncate(200);
    short_e.push_str("...");
    short_e
}

pub async fn verify_canister_asset(
    http_client: &Client,
    asset_url: &str,
    expected_body: &[u8],
) -> anyhow::Result<()> {
    let response = http_client
        .get(asset_url)
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to send request to {}: {}", asset_url, e))?;

    let status = response.status();
    if status != StatusCode::OK {
        bail!("Received unexpected status code: {}", status);
    }

    let body = response
        .bytes()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to read response body: {}", e))?;

    if body.as_ref() != expected_body {
        bail!(
            "Response body does not match expected content. Got {} bytes, expected {} bytes",
            body.len(),
            expected_body.len()
        );
    }

    Ok(())
}

pub fn get_binary_path(name: &str) -> PathBuf {
    let mut path = PathBuf::from(env::var("CARGO_TARGET_DIR").expect("env variable is not set"));
    path.push(name);
    path
}

pub fn create_canister_with_cycles(
    env: &PocketIc,
    controller: Principal,
    cycles: u128,
) -> Principal {
    let canister_id = env.create_canister_with_settings(Some(controller), None);
    env.add_cycles(canister_id, cycles);
    canister_id
}

pub fn get_asset_canister_wasm() -> Vec<u8> {
    let mut file_path =
        PathBuf::from(env::var("ASSET_CANISTER_DIR").expect("env variable is not set"));
    file_path.push("assetstorage.wasm.gz");
    let mut file = File::open(&file_path)
        .unwrap_or_else(|_| panic!("Failed to open file: {}", file_path.to_str().unwrap()));
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).expect("Failed to read file");
    bytes
}

pub fn upload_asset_to_asset_canister(
    asset_canister_id: Principal,
    asset_name: String,
    env: &PocketIc,
    asset: Vec<u8>,
    chunk_len: usize,
) {
    let chunks: Vec<&[u8]> = asset.chunks(chunk_len).collect();
    info!("uploading {} chunks to asset canister", chunks.len());
    let batch_id = update_candid_as::<_, (CreateBatchResponse,)>(
        env,
        asset_canister_id,
        Principal::anonymous(),
        "create_batch",
        ((),),
    )
    .unwrap()
    .0
    .batch_id;
    let create_asset = CreateAssetArguments {
        key: asset_name.clone(),
        content_type: "application/octet-stream".to_string(),
        max_age: None,
        headers: None,
        enable_aliasing: None,
        allow_raw_access: None,
    };
    let mut chunk_ids = vec![];
    for chunk in chunks {
        let create_chunk_arg = CreateChunkArg {
            batch_id: batch_id.clone(),
            content: chunk.to_vec().into(),
        };
        let create_chunk_response = update_candid_as::<_, (CreateChunkResponse,)>(
            env,
            asset_canister_id,
            Principal::anonymous(),
            "create_chunk",
            (create_chunk_arg,),
        )
        .unwrap()
        .0;
        chunk_ids.push(create_chunk_response.chunk_id);
    }
    let set_asset_content = SetAssetContentArguments {
        key: asset_name.clone(),
        content_encoding: "identity".to_string(),
        chunk_ids,
        sha256: None,
        last_chunk: None,
    };
    let operations = vec![
        BatchOperation::CreateAsset(create_asset),
        BatchOperation::SetAssetContent(set_asset_content),
    ];
    let commit_batch_args: CommitBatchArguments = CommitBatchArguments {
        batch_id,
        operations,
    };
    update_candid_as::<_, ((),)>(
        env,
        asset_canister_id,
        Principal::anonymous(),
        "commit_batch",
        (commit_batch_args,),
    )
    .unwrap();
}
