/// Generates `subnet.bin` and `nns_canister_ranges.bin` test-fixture files
/// from a live IC node (testnet or mainnet).
///
/// The root key is fetched automatically (unsafe – intended for testnets) and
/// printed as a Rust byte-array literal so it can be pasted directly into unit
/// tests that need to verify certificates from those fixture files.
///
/// Usage:
///   cargo run --bin gen-testdata -- \
///     --nns-url http://[<nns-node-ipv6>]:8080 \
///     --subnet-id <nns-subnet-principal> \
///     [--output-dir src/routing/ic/testdata]
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Error};
use candid::Principal;
use clap::Parser;
use ic_bn_lib::ic_agent::{Agent, Certificate, hash_tree::Label};

#[derive(Parser)]
#[command(about = "Fetch subnet.bin and nns_canister_ranges.bin fixture files from a live IC node")]
struct Cli {
    /// URL of the NNS node (e.g. http://[<ipv6>]:8080 or https://ic0.app)
    #[arg(long)]
    nns_url: String,

    /// Principal text of the NNS / root subnet ID
    #[arg(long)]
    subnet_id: String,

    /// Directory to write the output files into
    #[arg(long, default_value = ".")]
    output_dir: PathBuf,
}

fn save_cert(dir: &Path, name: &str, cert: &Certificate) -> Result<(), Error> {
    let bytes = serde_cbor::to_vec(cert).context("failed to serialize certificate to CBOR")?;
    let path = dir.join(name);
    std::fs::write(&path, &bytes)
        .with_context(|| format!("failed to write {}", path.display()))?;
    println!("  Saved {} ({} bytes)", path.display(), bytes.len());
    Ok(())
}

fn print_root_key(key: &[u8]) {
    let hex: String = key.iter().map(|b| format!("{b:02x}")).collect();
    println!("\n=== Root key ({} bytes) ===", key.len());
    println!("Hex:\n  {hex}");
    println!("\nRust byte array (paste into test fixtures as ROOT_KEY):");
    print!("#[rustfmt::skip]\nconst ROOT_KEY: &[u8] = &[");
    for (i, b) in key.iter().enumerate() {
        if i % 16 == 0 {
            print!("\n    ");
        }
        print!("{b}, ");
    }
    println!("\n];");
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    let cli = Cli::parse();

    let subnet_id =
        Principal::from_text(&cli.subnet_id).context("invalid --subnet-id")?;

    println!("NNS URL:    {}", cli.nns_url);
    println!("Subnet ID:  {subnet_id}");
    println!("Output dir: {}", cli.output_dir.display());

    let agent = Arc::new(
        Agent::builder()
            .with_url(&cli.nns_url)
            .build()
            .context("failed to build agent")?,
    );

    println!("\nFetching root key (unsafe)...");
    agent
        .fetch_root_key()
        .await
        .context("failed to fetch root key")?;

    print_root_key(&agent.read_root_key());

    std::fs::create_dir_all(&cli.output_dir)
        .with_context(|| format!("failed to create output dir {}", cli.output_dir.display()))?;

    // --- subnet.bin ---
    println!("\n=== Fetching /subnet certificate (subnet.bin) ===");
    let subnet_cert = agent
        .read_subnet_state_raw(vec![vec!["subnet".into()]], subnet_id)
        .await
        .context("failed to read /subnet from NNS")?;
    save_cert(&cli.output_dir, "subnet.bin", &subnet_cert)?;

    // --- nns_canister_ranges.bin ---
    println!("\n=== Fetching /canister_ranges certificate (nns_canister_ranges.bin) ===");
    let ranges_cert = agent
        .read_subnet_state_raw(
            vec![vec![
                "canister_ranges".into(),
                Label::from_bytes(subnet_id.as_slice()),
            ]],
            subnet_id,
        )
        .await
        .context("failed to read /canister_ranges from NNS")?;
    save_cert(&cli.output_dir, "nns_canister_ranges.bin", &ranges_cert)?;

    println!("\nDone.");
    Ok(())
}
