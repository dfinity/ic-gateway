//! S3 key layout, compatible with object-storage's `icfs-common::s3_utils::paths`.

use candid::Principal;

const BLOB_METADATA_PATH: &str = "blob-metadata";
const CHUNK_PATH: &str = "chunks";

pub fn blob_path_owner_prefix(owner: &Principal) -> String {
    format!("{BLOB_METADATA_PATH}/{owner}/")
}

/// S3 key for blob metadata: `blob-metadata/{owner}/{root_hash}`
pub fn blob_path(owner: &Principal, root_hash: &str) -> String {
    format!("{}{root_hash}", blob_path_owner_prefix(owner))
}

pub fn chunk_path_owner_prefix(owner: &Principal) -> String {
    format!("{CHUNK_PATH}/{owner}/")
}

/// S3 key for a chunk: `chunks/{owner}/{chunk_hash}`
pub fn chunk_path(owner: &Principal, chunk_hash: &str) -> String {
    format!("{}{chunk_hash}", chunk_path_owner_prefix(owner))
}
