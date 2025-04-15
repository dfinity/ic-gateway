#!/usr/bin/env bash
set -eEuo pipefail

readonly POCKETIC_VERSION="8.0.0"
readonly POCKETIC_URL="https://github.com/dfinity/pocketic/releases/download/${POCKETIC_VERSION}/pocket-ic-x86_64-linux.gz"
readonly POCKETIC_CHECKSUM="7689eee0a17abb24c0a83e2ff0ea36fd5ba7eb699fe811d9f7b07cb27e8e7170"
readonly ASSET_WASM_URL="https://github.com/dfinity/sdk/raw/fec030f53814e7eaa2f869189e8852b5c0e60e5e/src/distributed/assetstorage.wasm.gz"
readonly ASSET_WASM_CHECKSUM="865eb25df5a6d857147e078bb33c727797957247f7af2635846d65c5397b36a6"
readonly WORKDIR="$(pwd)"
readonly CANISTER_DIR="${WORKDIR}/canister_wasms"
readonly POCKETIC_BIN="${WORKDIR}/pocket-ic"
readonly CARGO_TARGET_DIR="${WORKDIR}/target/debug"

log() { echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] $*" >&2; }

log "Downloading PocketIC v${POCKETIC_VERSION}"
curl -fsSL --retry 3 --retry-delay 5 "${POCKETIC_URL}" -o pocket-ic.gz || {
  log "Failed to download PocketIC"
  exit 1
}
echo "${POCKETIC_CHECKSUM} pocket-ic.gz" | sha256sum -c - || {
  log "PocketIC checksum verification failed"
  exit 1
}
log "Extracting PocketIC"
gzip -df pocket-ic.gz || { log "Failed to extract PocketIC"; exit 1; }
chmod +x "${POCKETIC_BIN}" || { log "Failed to make PocketIC executable"; exit 1; }
export POCKET_IC_BIN="${POCKETIC_BIN}"
log "PocketIC setup completed"

log "Building ic-gateway"
cargo build --verbose || { log "ic-gateway build failed"; exit 1; }
export CARGO_TARGET_DIR
log "ic-gateway build completed"

log "Downloading asset canister WASM"
mkdir -p "${CANISTER_DIR}" || { log "Failed to create canister directory"; exit 1; }
curl -fsSL --retry 3 --retry-delay 5 "${ASSET_WASM_URL}" -o "${CANISTER_DIR}/assetstorage.wasm.gz" || {
  log "Failed to download asset canister WASM"
  exit 1
}
echo "${ASSET_WASM_CHECKSUM} ${CANISTER_DIR}/assetstorage.wasm.gz" | sha256sum -c - || {
  log "Asset canister WASM checksum verification failed"
  exit 1
}
export ASSET_CANISTER_DIR="${CANISTER_DIR}"
log "Asset canister WASM downloaded"

log "Running all tests"
cargo test --all -- --nocapture || { log "Tests failed"; exit 1; }
log "All tests completed successfully"
