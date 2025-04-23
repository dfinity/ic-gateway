use anyhow::{Context, anyhow};
use candid::{Encode, Principal};
use hex::encode;
use http::StatusCode;
use ic_certified_assets::types::{
    BatchOperation, CommitBatchArguments, CreateAssetArguments, CreateBatchResponse,
    CreateChunkArg, CreateChunkResponse, DeleteAssetArguments, SetAssetContentArguments,
};
use nix::{
    sys::signal::{self, Signal},
    unistd::Pid,
};
use pocket_ic::{PocketIc, PocketIcBuilder, update_candid_as};
use reqwest::Response;
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    env,
    fs::File,
    io::{Read, Write},
    net::SocketAddr,
    path::PathBuf,
    process::{Child, Command},
    str::FromStr,
    time::{Duration, Instant},
};
use tokio::time::sleep;
use tracing::info;

const IC_GATEWAY_BIN: &str = "ic-gateway";
const CANISTER_INITIAL_CYCLES: u128 = 100_000_000_000_000;

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

pub fn install_canister(
    pic: &PocketIc,
    controller: Principal,
    canister_wasm_module: Vec<u8>,
) -> Principal {
    info!("installing canister ...");
    let canister_id = pic.create_canister_with_settings(Some(controller), None);
    pic.add_cycles(canister_id, CANISTER_INITIAL_CYCLES);

    pic.install_canister(
        canister_id,
        canister_wasm_module,
        Encode!(&()).unwrap(),
        None,
    );
    let module_hash = pic
        .canister_status(canister_id, None)
        .unwrap()
        .module_hash
        .unwrap();
    let hash_str = encode(module_hash);
    info!("canister with id={canister_id} installed, hash={hash_str}");

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
    pic: &PocketIc,
    canister_id: Principal,
    path: String,
    content: Vec<u8>,
    content_type: String,
    content_encoding: String,
    sha_override: Option<Vec<u8>>,
) {
    let controller = Principal::anonymous();

    // create a batch id for uploading the asset
    let batch_id = update_candid_as::<_, (CreateBatchResponse,)>(
        pic,
        canister_id,
        controller,
        "create_batch",
        ((),),
    )
    .unwrap()
    .0
    .batch_id;

    // compute the hash of the asset content (if not provided)
    let sha = sha_override.clone().unwrap_or_else(|| {
        let mut hasher = Sha256::new();
        hasher.update(content.as_slice());
        let sha = hasher.finalize();
        sha.to_vec()
    });

    // chunk the content into smaller pieces for the upload
    let chunk_size = 1.9 * 1024.0 * 1024.0; // 1.9mb
    let chunks: Vec<&[u8]> = content.chunks(chunk_size as usize).collect();

    // upload each chunk to the asset canister
    let mut chunk_ids = vec![];
    for chunk in chunks {
        let create_chunk_arg = CreateChunkArg {
            batch_id: batch_id.clone(),
            content: chunk.to_vec().into(),
        };
        let create_chunk_response = update_candid_as::<_, (CreateChunkResponse,)>(
            pic,
            canister_id,
            controller,
            "create_chunk",
            (create_chunk_arg,),
        )
        .unwrap()
        .0;
        chunk_ids.push(create_chunk_response.chunk_id);
    }

    // commit the batch with the asset content using the uploaded chunks
    let commit_batch_args: CommitBatchArguments = CommitBatchArguments {
        batch_id,
        operations: vec![
            BatchOperation::DeleteAsset(DeleteAssetArguments { key: path.clone() }),
            BatchOperation::CreateAsset(CreateAssetArguments {
                key: path.clone(),
                content_type: content_type,
                max_age: None,
                headers: None,
                enable_aliasing: None,
                allow_raw_access: None,
            }),
            BatchOperation::SetAssetContent(SetAssetContentArguments {
                key: path.clone(),
                content_encoding: content_encoding,
                chunk_ids,
                sha256: Some(sha.into()),
                last_chunk: None,
            }),
        ],
    };
    update_candid_as::<_, ((),)>(
        pic,
        canister_id,
        controller,
        "commit_batch",
        (commit_batch_args,),
    )
    .unwrap();
}

pub fn start_ic_gateway(addr: &str, domain: &str, ic_url: &str, root_key_path: PathBuf) -> Child {
    info!("ic-gateway service starting ...");
    let child = Command::new(get_binary_path(IC_GATEWAY_BIN))
        .arg("--listen-plain")
        .arg(addr)
        .arg("--ic-url")
        .arg(ic_url)
        .arg("--domain")
        .arg(domain)
        .arg("--ic-root-key")
        .arg(root_key_path.to_str().unwrap())
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

        let root_key = pic.root_key().expect("failed to get root key");
        let mut root_key_path = env::current_dir().expect("failed to get working directory");
        root_key_path.push("root_key.der");
        let mut file = File::create(&root_key_path).expect("failed to create file");
        file.write_all(&root_key)
            .expect("failed to write key to file");

        let ic_gateway_addr =
            SocketAddr::from_str(ic_gateway_addr).expect("failed to parse address");
        let ic_url = format!("{}instances/{}/", pic.get_server_url(), pic.instance_id());
        let process = start_ic_gateway(
            &ic_gateway_addr.to_string(),
            ic_gateway_domain,
            &ic_url,
            root_key_path,
        );

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
