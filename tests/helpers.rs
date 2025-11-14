use std::{
    collections::HashMap,
    env,
    fs::{self, File},
    io::Read,
    net::SocketAddr,
    path::PathBuf,
    process::{Child, Command, ExitStatus},
    str::FromStr,
    time::{Duration, Instant},
};

use anyhow::anyhow;
use candid::{Encode, Principal};
use hex::encode;
use http::StatusCode;
use ic_certified_assets::types::{
    BatchOperation, CommitBatchArguments, CreateAssetArguments, CreateBatchResponse,
    CreateChunkArg, CreateChunkResponse, DeleteAssetArguments, SetAssetContentArguments,
};
use itertools::Itertools;
use nix::{
    sys::signal::{self, Signal},
    unistd::Pid,
};
use pocket_ic::{
    PocketIcBuilder,
    common::rest::HttpsConfig,
    nonblocking::{PocketIc, update_candid_as},
};
use reqwest::Response;
use sha2::{Digest, Sha256};
use tokio::time::sleep;
use tracing::info;

const IC_GATEWAY_BIN: &str = "ic-gateway";
const CANISTER_INITIAL_CYCLES: u128 = 100_000_000_000_000;

pub const RETRY_TIMEOUT: Duration = Duration::from_secs(10);
pub const RETRY_INTERVAL: Duration = Duration::from_secs(1);

pub const DENYLISTED_CANISTER_ID: &str = "22b4i-4aaaa-aaaal-qlzxa-cai";

pub const ROOT_KEY_FILE: &str = "root_key.der";
pub const DENYLIST_FILE: &str = "denylist_seed.json";

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
    short_e.truncate(500);
    short_e.push_str("...");
    short_e
}

pub fn get_binary_path(name: &str) -> PathBuf {
    PathBuf::from(env::var("CARGO_TARGET_DIR").expect("env variable is not set")).join(name)
}

pub async fn install_canister(
    pic: &PocketIc,
    controller: Principal,
    fixed_canister_id: Option<Principal>,
    canister_wasm_module: Vec<u8>,
) -> Principal {
    info!("installing canister ...");
    let canister_id = match fixed_canister_id {
        Some(id) => pic
            .create_canister_with_id(Some(controller), None, id)
            .await
            .unwrap(),
        None => {
            pic.create_canister_with_settings(Some(controller), None)
                .await
        }
    };
    pic.add_cycles(canister_id, CANISTER_INITIAL_CYCLES).await;

    pic.install_canister(
        canister_id,
        canister_wasm_module,
        Encode!(&()).unwrap(),
        None,
    )
    .await;
    let module_hash = pic
        .canister_status(canister_id, None)
        .await
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

pub fn get_large_assets_canister_wasm() -> Vec<u8> {
    let mut file_path =
        PathBuf::from(env::var("ASSET_CANISTER_DIR").expect("env variable is not set"));
    file_path.push("largeassets.wasm.gz");
    let mut file = File::open(&file_path)
        .unwrap_or_else(|_| panic!("Failed to open file: {}", file_path.to_str().unwrap()));
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).expect("Failed to read file");
    bytes
}

#[derive(Clone, derive_new::new)]
pub struct StaticAsset {
    #[new(into)]
    pub path: String,
    #[new(into)]
    pub content: String,
    #[new(into)]
    pub content_type: String,
    #[new(into)]
    pub content_encoding: String,
    pub sha_override: Option<Vec<u8>>,
}

pub async fn upload_asset_to_asset_canister(
    pic: &PocketIc,
    canister_id: Principal,
    asset: StaticAsset,
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
    .await
    .unwrap()
    .0
    .batch_id;

    // compute the hash of the asset content (if not provided)
    let sha = asset.sha_override.clone().unwrap_or_else(|| {
        let mut hasher = Sha256::new();
        hasher.update(asset.content.as_bytes());
        let sha = hasher.finalize();
        sha.to_vec()
    });

    // chunk the content into smaller pieces for the upload
    let chunk_size = 1.9 * 1024.0 * 1024.0; // 1.9mb
    let chunks: Vec<&[u8]> = asset
        .content
        .as_bytes()
        .chunks(chunk_size as usize)
        .collect();

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
        .await
        .unwrap()
        .0;
        chunk_ids.push(create_chunk_response.chunk_id);
    }

    // commit the batch with the asset content using the uploaded chunks
    let commit_batch_args: CommitBatchArguments = CommitBatchArguments {
        batch_id,
        operations: vec![
            BatchOperation::DeleteAsset(DeleteAssetArguments {
                key: asset.path.clone(),
            }),
            BatchOperation::CreateAsset(CreateAssetArguments {
                key: asset.path.clone(),
                content_type: asset.content_type,
                max_age: None,
                headers: None,
                enable_aliasing: None,
                allow_raw_access: None,
            }),
            BatchOperation::SetAssetContent(SetAssetContentArguments {
                key: asset.path.clone(),
                content_encoding: asset.content_encoding,
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
    .await
    .unwrap();
}

fn stop_process(p: &mut Child) -> ExitStatus {
    let pid = p.id() as i32;
    match signal::kill(Pid::from_raw(pid), Signal::SIGINT) {
        Ok(_) => info!("Sent SIGINT to process {pid}"),
        Err(e) => info!("Failed to send SIGINT: {}", e),
    }
    p.wait().expect("failed to wait on child process")
}

pub fn start_ic_boundary(port: &str, replica_addr: &str) -> Child {
    info!("ic-boundary service starting ...");
    let mut cmd = Command::new("./ic-boundary");
    cmd.args([
        "--listen-http-port",
        port,
        "--registry-stub-replica",
        replica_addr,
        "--http-client-timeout-connect",
        "3s",
        "--skip-replica-tls-verification",
        "--obs-log-stdout",
        "--obs-max-logging-level",
        "info",
    ]);

    let child = cmd.spawn().expect("failed to start ic-boundary service");
    info!("ic-boundary service started");
    child
}

pub fn stop_ic_boundary(process: &mut Child) {
    info!("gracefully terminating ic-boundary process");
    info!(
        "ic-boundary process exited with: {:?}",
        stop_process(process)
    );
}

pub fn start_ic_gateway(
    addr: &str,
    domain: &str,
    ic_url: &str,
    root_key_path: PathBuf,
    denylist_seed_path: Option<PathBuf>,
) -> Child {
    info!("ic-gateway service starting ...");
    let mut cmd = Command::new(get_binary_path(IC_GATEWAY_BIN));
    cmd.arg("--listen-plain");
    cmd.arg(addr);
    cmd.arg("--ic-url");
    cmd.arg(ic_url);
    cmd.arg("--domain");
    cmd.arg(domain);
    cmd.arg("--ic-root-key");
    cmd.arg(root_key_path.to_str().unwrap());
    if let Some(v) = denylist_seed_path {
        cmd.arg("--policy-denylist-seed");
        cmd.arg(v.to_str().unwrap());
    }
    cmd.arg("--listen-insecure-serve-http-only");
    cmd.arg("--custom-domains-ic-identity");
    cmd.arg("test_data/test_ic_identity.pem");
    cmd.arg("--custom-domains-canister-id");
    cmd.arg("aaaaa-aa");
    cmd.arg("--custom-domains-cloudflare-token");
    cmd.arg("foobar");
    cmd.arg("--custom-domains-encryption-key");
    cmd.arg("sVq8LeaZwKSU81632y7kelNJ3EwBFhMcbuKB6OYZiKI=");
    cmd.arg("--custom-domains-acme-account");
    cmd.arg("test_data/test_acme_account.json");
    cmd.arg("--log-stdout");
    cmd.arg("--log-level");
    cmd.arg("info");

    let child = cmd.spawn().expect("failed to start ic-gateway service");
    info!("ic-gateway service started");
    child
}

pub fn stop_ic_gateway(process: &mut Child) {
    info!("gracefully terminating ic-gateway process");
    info!(
        "ic-gateway process exited with: {:?}",
        stop_process(process)
    );
}

pub struct TestEnv {
    pub pic: PocketIc,
    pub ic_gateway_process: Child,
    pub ic_boundary_process: Child,
    pub ic_gateway_addr: SocketAddr,
    pub ic_gateway_domain: String,
    pub root_key: Vec<u8>,
}

impl TestEnv {
    pub async fn new(
        ic_gateway_addr: &str,
        ic_gateway_domain: &str,
        ic_boundary_port: &str,
    ) -> Self {
        init_logging();

        info!("pocket-ic server starting ...");
        let mut pic = PocketIcBuilder::new().with_nns_subnet().build_async().await;
        let https_config = HttpsConfig {
            cert_path: "test_data/cert.pem".into(),
            key_path: "test_data/key.pem".into(),
        };
        let ic_url = pic
            .make_live_with_params(None, None, None, Some(https_config))
            .await;
        info!("pocket-ic server started");

        // fetch the root key of "local" IC and save it to a file
        let root_key = pic.root_key().await.expect("failed to get root key");
        fs::write(ROOT_KEY_FILE, &root_key).expect("failed to write key to file");

        // create a static denylist seed file
        let denylist_seed = format!(
            r#"{{
            "$schema": "./schema.json",
            "version": "1",
            "canisters": {{
                "{DENYLISTED_CANISTER_ID}": {{}}
            }}
        }}"#
        );
        fs::write(DENYLIST_FILE, denylist_seed.as_bytes())
            .expect("failed to write denylist to file");

        let ic_boundary_process = start_ic_boundary(
            ic_boundary_port,
            &format!("127.0.0.1:{}", ic_url.port_or_known_default().unwrap()),
        );

        let ic_gateway_addr =
            SocketAddr::from_str(ic_gateway_addr).expect("failed to parse address");
        let ic_gateway_process = start_ic_gateway(
            &ic_gateway_addr.to_string(),
            ic_gateway_domain,
            &format!("http://127.0.0.1:{ic_boundary_port}"),
            ROOT_KEY_FILE.into(),
            Some(DENYLIST_FILE.into()),
        );

        Self {
            ic_gateway_process,
            ic_boundary_process,
            ic_gateway_addr,
            ic_gateway_domain: ic_gateway_domain.to_string(),
            pic,
            root_key,
        }
    }
}

impl Drop for TestEnv {
    fn drop(&mut self) {
        stop_ic_gateway(&mut self.ic_gateway_process);
        stop_ic_boundary(&mut self.ic_boundary_process);
        let _ = std::fs::remove_file("root_key.der");
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

    if let Some(expected_status) = expected.status
        && expected_status != status
    {
        anyhow::bail!(
            "unexpected status code: got {status}, expected {expected_status}, body: {}",
            String::from_utf8_lossy(&body_bytes)
        );
    }

    if let Some(ref expected_body) = expected.body
        && &body_bytes != expected_body
    {
        anyhow::bail!(
            "unexpected response body: got size={}, expected={}, body: {}",
            body_bytes.len(),
            expected_body.len(),
            String::from_utf8_lossy(&body_bytes),
        );
    }

    if let Some(ref expected_headers) = expected.headers {
        let expected_headers_sorted = expected_headers
            .iter()
            .map(|(k, v)| {
                (
                    k.trim().to_ascii_lowercase(),
                    v.split(',')
                        .map(|x| x.trim().to_ascii_lowercase())
                        .sorted()
                        .collect::<Vec<_>>(),
                )
            })
            .collect::<HashMap<_, _>>();

        let actual_headers_sorted = headers
            .iter()
            .map(|(k, v)| {
                (
                    k.to_string().trim().to_ascii_lowercase(),
                    v.to_str()
                        .expect("invalid UTF-8 in header value")
                        .split(',')
                        .map(|x| x.trim().to_ascii_lowercase())
                        .sorted()
                        .collect::<Vec<_>>(),
                )
            })
            .collect::<HashMap<_, _>>();

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
