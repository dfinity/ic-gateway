use std::{
    collections::HashMap,
    env,
    fs::File,
    io::Read,
    net::SocketAddr,
    path::PathBuf,
    process::{Child, Command},
    str::FromStr,
    time::{Duration, Instant},
};

use anyhow::{Context, anyhow};
use candid::Principal;
use http::StatusCode;
use ic_certified_assets::types::{
    BatchOperation, CommitBatchArguments, CreateAssetArguments, CreateBatchResponse,
    CreateChunkArg, CreateChunkResponse, SetAssetContentArguments,
};
use nix::{
    sys::signal::{self, Signal},
    unistd::Pid,
};
use pocket_ic::{PocketIc, PocketIcBuilder, update_candid_as};
use reqwest::Response;
use tokio::time::sleep;
use tracing::info;

const IC_GATEWAY_BIN: &str = "ic-gateway";

pub fn init_logging() {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_test_writer()
        .try_init()
        .expect("failed to init logger")
}

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

pub fn get_binary_path(name: &str) -> PathBuf {
    PathBuf::from(env::var("CARGO_TARGET_DIR").expect("env variable is not set")).join(name)
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

pub fn start_ic_gateway(addr: &str, domain: &str, ic_url: &str) -> Child {
    info!("ic-gateway service starting ...");
    let child = Command::new(get_binary_path(IC_GATEWAY_BIN))
        .arg("--listen-plain")
        .arg(addr)
        .arg("--ic-url")
        .arg(ic_url)
        .arg("--domain")
        .arg(domain)
        .arg("--listen-insecure-serve-http-only")
        .spawn()
        .expect("failed to start ic-gateway service");
    info!("ic-gateway service started");
    child
}

pub fn stop_ic_gateway(process: &mut Child) {
    info!("gracefully terminating ic-gateway process");
    let pid = process.id() as i32;
    match signal::kill(Pid::from_raw(pid), Signal::SIGINT) {
        Ok(_) => info!("Sent SIGINT to process {pid}"),
        Err(e) => info!("Failed to send SIGINT: {}", e),
    }
    let exit_status = process.wait().expect("failed to wait on child process");
    info!("ic-gateway process exited with: {:?}", exit_status);
}

pub struct TestEnv {
    pub pic: PocketIc,
    pub ic_gateway_process: Child,
    pub ic_gateway_addr: SocketAddr,
    pub ic_gateway_domain: String,
}

impl TestEnv {
    pub fn new(ic_gateway_addr: &str, ic_gateway_domain: &str) -> Self {
        init_logging();

        info!("pocket-ic server starting ...");
        let pic = PocketIcBuilder::new().with_nns_subnet().build();
        pic.auto_progress();
        info!("pocket-ic server started");

        let ic_gateway_addr =
            SocketAddr::from_str(ic_gateway_addr).expect("failed to parse address");
        let ic_url = format!("{}instances/{}/", pic.get_server_url(), pic.instance_id());
        let process = start_ic_gateway(&ic_gateway_addr.to_string(), ic_gateway_domain, &ic_url);

        Self {
            ic_gateway_process: process,
            ic_gateway_addr,
            ic_gateway_domain: ic_gateway_domain.to_string(),
            pic,
        }
    }
}

impl Drop for TestEnv {
    fn drop(&mut self) {
        stop_ic_gateway(&mut self.ic_gateway_process);
    }
}

#[derive(Debug)]
pub struct ExpectedResponse {
    pub status: Option<StatusCode>,
    pub body: Option<Vec<u8>>,
    pub headers: Option<HashMap<String, String>>,
}

impl ExpectedResponse {
    pub fn new(
        status: Option<StatusCode>,
        body: Option<Vec<u8>>,
        headers: Option<HashMap<String, String>>,
    ) -> Self {
        Self {
            status,
            body,
            headers,
        }
    }

    pub fn with_header(mut self, key: &str, value: &str) -> Self {
        if let Some(ref mut headers) = self.headers {
            headers.insert(key.to_string(), value.to_string());
        } else {
            self.headers = Some(HashMap::from_iter(vec![(
                key.to_string(),
                value.to_string(),
            )]));
        }
        self
    }
}

pub async fn check_response(response: Response, expected: &ExpectedResponse) -> anyhow::Result<()> {
    let status = response.status();
    let headers = response.headers().clone();
    let body_bytes = response.bytes().await?.to_vec();

    if let Some(expected_status) = expected.status {
        if expected_status != status {
            anyhow::bail!("unexpected status code: got {status}, expected {expected_status}",);
        }
    }

    if let Some(ref expected_body) = expected.body {
        if &body_bytes != expected_body {
            anyhow::bail!(
                "unexpected response body: got size={}, expected={}",
                body_bytes.len(),
                expected_body.len()
            );
        }
    }

    if let Some(ref expected_headers) = expected.headers {
        let mut expected_headers_sorted = HashMap::<String, Vec<String>>::new();
        // sort values in the expected headers for comparison
        for (key, values) in expected_headers {
            let mut values: Vec<String> = values
                .split(',')
                .map(|x| x.trim().to_ascii_lowercase())
                .collect();

            values.sort();

            expected_headers_sorted.insert(key.trim().to_ascii_lowercase(), values);
        }

        let mut actual_headers_sorted: HashMap<String, Vec<String>> = HashMap::new();

        for (header_name, header_value) in headers.iter() {
            let mut values: Vec<String> = header_value
                .to_str()
                .context("invalid UTF-8 in header value")?
                .split(',')
                .map(|x| x.trim().to_ascii_lowercase())
                .collect();

            values.sort();

            actual_headers_sorted
                .insert(header_name.to_string().trim().to_ascii_lowercase(), values);
        }

        // check that expected headers are present in the response
        for (key, expected_values) in expected_headers_sorted.iter() {
            let actual_values = actual_headers_sorted
                .get(key)
                .ok_or_else(|| anyhow!("{key} is not present in response header"))?;
            if actual_values != expected_values {
                anyhow::bail!(
                    "unexpected `{key}` header: got: {:?}, expected {:?}",
                    actual_values,
                    expected_values
                );
            }
        }
    }

    Ok(())
}

pub const COUNTER_WAT: &str = r#"
(module
  (import "ic0" "msg_reply" (func $msg_reply))
  (import "ic0" "msg_reply_data_append"
    (func $msg_reply_data_append (param i32 i32)))
  (func $read
    (i32.store
      (i32.const 0)
      (global.get 0)
    )
    (call $msg_reply_data_append
      (i32.const 0)
      (i32.const 4))
    (call $msg_reply))
  (func $write
    (global.set 0
      (i32.add
        (global.get 0)
        (i32.const 1)
      )
    )
    (call $read)
  )
  (memory $memory 1)
  (export "memory" (memory $memory))
  (global (export "counter_global") (mut i32) (i32.const 0))
  (export "canister_query read" (func $read))
  (export "canister_query inc_read" (func $write))
  (export "canister_update write" (func $write))
)"#;
