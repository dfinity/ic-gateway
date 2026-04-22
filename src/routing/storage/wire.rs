//! Wire-format types for the storage API.
//!
//! These are the serialized representations exchanged with external parties:
//!
//! * HTTP request/response bodies (JSON) for the `/storage/v1/` endpoints,
//!   consumed by Caffeine frontends and the `icfs` CLI.
//! * [`BlobMetadata`] — JSON blob stored in S3 at
//!   `blob-metadata/{owner}/{root_hash}` and read back by `get_blob`.
//! * [`OwnerEgressSignature`] — Candid payload embedded in an IC egress
//!   certificate, verified by [`crate::routing::storage::auth`].
//!
//! These types must stay serde/Candid-compatible with `object-storage`'s
//! `icfs-common` crate (`BlobHashNHeaders`, `BlobHashTree`, etc.). Any
//! schema change here is a breaking API change — coordinate with clients
//! before touching them.

use candid::CandidType;
use serde::{Deserialize, Serialize};

pub const ONE_MIB: usize = 1024 * 1024;
pub const MAX_REQUEST_BODY_SIZE: usize = 10 * ONE_MIB;

/// Blob metadata stored in S3 at `blob-metadata/{owner}/{root_hash}`.
/// JSON-compatible with object-storage's `BlobHashNHeaders`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlobMetadata {
    pub hash_tree: BlobHashTree,
    pub num_blob_bytes: u64,
    #[serde(default)]
    pub headers: Vec<String>,
}

/// Merkle tree over chunk hashes, tagged by tree type.
/// Compatible with object-storage's `BlobHashTree` enum.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "tree_type")]
pub enum BlobHashTree {
    BMT {
        tree: Option<MerkleTreeNode>,
        chunk_hashes: Vec<String>,
        #[serde(default)]
        headers: Vec<String>,
    },
    DSBMTWH {
        tree: MerkleTreeNode,
        chunk_hashes: Vec<String>,
        #[serde(default)]
        headers: Vec<String>,
    },
}

impl BlobHashTree {
    pub fn chunk_hashes(&self) -> &[String] {
        match self {
            Self::BMT { chunk_hashes, .. } | Self::DSBMTWH { chunk_hashes, .. } => chunk_hashes,
        }
    }

    pub fn root_hash(&self) -> Option<&str> {
        match self {
            Self::BMT { tree, .. } => tree.as_ref().map(|t| t.hash.as_str()),
            Self::DSBMTWH { tree, .. } => Some(tree.hash.as_str()),
        }
    }
}

/// A node in the Merkle tree.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleTreeNode {
    pub hash: String,
    pub left: Option<Box<MerkleTreeNode>>,
    pub right: Option<Box<MerkleTreeNode>>,
}

/// Authorization for storage gateway operations.
#[derive(Serialize, Deserialize, Debug, Default)]
pub enum StorageGatewayAuthorization {
    #[default]
    None,
    OwnerEgressSignature(Vec<u8>),
}

/// Parsed payload of an OwnerEgressSignature embedded in a certificate tree.
#[derive(CandidType, Deserialize, Debug, Eq, PartialEq)]
pub struct OwnerEgressSignature {
    pub method: String,
    pub blob_hash: String,
}

/// PUT blob_tree request body.
#[derive(Debug, Serialize, Deserialize)]
pub struct PutBlobTreeRequest {
    pub blob_tree: BlobHashTree,
    pub owner: candid::Principal,
    pub num_blob_bytes: u64,
    #[serde(default)]
    pub headers: Vec<String>,
    #[serde(default)]
    pub auth: StorageGatewayAuthorization,
}

/// PUT blob_tree response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PutBlobTreeResponse {
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub existing_chunks: Vec<String>,
    #[serde(default)]
    pub chunk_check_errors: usize,
}

/// PUT chunk response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PutChunkResponse {
    pub status: String,
}
