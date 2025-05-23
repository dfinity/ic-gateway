#!/usr/bin/env bash
set -eEuo pipefail

# Get the latest IC master hash that passed "CI Main".
# This hash should have binaries published.
readonly IC_COMMIT=$(gh run list --repo dfinity/ic --branch master --workflow "CI Main" --json headSha,status --jq '.[] | select(.status == "completed") | .headSha' | head -n 1)

readonly POCKETIC_VERSION="9.0.1"
readonly POCKETIC_URL="https://github.com/dfinity/pocketic/releases/download/${POCKETIC_VERSION}/pocket-ic-x86_64-linux.gz"
readonly POCKETIC_CHECKSUM="237272216498074e5250a0685813b96632963ff9abbc51a7030d9b625985028d"
readonly IC_BOUNDARY_URL="https://download.dfinity.systems/ic/${IC_COMMIT}/binaries/x86_64-linux/ic-boundary.gz"
readonly ASSET_WASM_URL="https://github.com/dfinity/sdk/raw/fec030f53814e7eaa2f869189e8852b5c0e60e5e/src/distributed/assetstorage.wasm.gz"
readonly ASSET_WASM_CHECKSUM="865eb25df5a6d857147e078bb33c727797957247f7af2635846d65c5397b36a6"
readonly LARGE_ASSETS_WASM_URL="https://github.com/dfinity/http-gateway/raw/42408f658199d7278d8ff3293504a06e1b0ef61d/examples/http-gateway/canister/http_gateway_canister_custom_assets.wasm.gz"
readonly LARGE_ASSETS_WASM_CHECKSUM="eedcbf986c67fd4ebe3042094604a9a5703e825e56433e2509a6a4d0384ccf95"
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

log "Downloading ic-boundary"
curl -fsSL --retry 3 --retry-delay 5 "${IC_BOUNDARY_URL}" -o ic-boundary.gz
gzip -d ic-boundary.gz
chmod +x ic-boundary

log "Building ic-gateway"
cargo build || { log "ic-gateway build failed"; exit 1; }
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
log "Asset canister WASM downloaded"

log "Downloading large assets canister WASM"
mkdir -p "${CANISTER_DIR}" || { log "Failed to create canister directory"; exit 1; }
curl -fsSL --retry 3 --retry-delay 5 "${LARGE_ASSETS_WASM_URL}" -o "${CANISTER_DIR}/largeassets.wasm.gz" || {
  log "Failed to download large assets canister WASM"
  exit 1
}
echo "${LARGE_ASSETS_WASM_CHECKSUM} ${CANISTER_DIR}/largeassets.wasm.gz" | sha256sum -c - || {
  log "Asset canister WASM checksum verification failed"
  exit 1
}
log "Asset canister WASM downloaded"

export ASSET_CANISTER_DIR="${CANISTER_DIR}"

log "Running all tests"
cargo test --all-features --profile dev --workspace -- --nocapture || { log "Tests failed"; exit 1; }
log "All tests completed successfully"
