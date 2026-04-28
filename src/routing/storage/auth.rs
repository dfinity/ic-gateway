use std::time::{SystemTime, UNIX_EPOCH};

use candid::Principal;
use ic_bn_lib::ic_agent::{Certificate, hash_tree::LookupResult};
use ic_certificate_verification::VerifyCertificate;

use super::wire::{OwnerEgressSignature, PutBlobTreeRequest, StorageGatewayAuthorization};
use crate::routing::error_cause::StorageError;

/// Maximum age of an upload certificate's IC `time` value relative to the
/// gateway's wall clock. After this, the certificate is rejected even if its
/// signature is otherwise valid, narrowing the replay window for leaked or
/// captured certificates.
const CERT_MAX_AGE_NS: u128 = 30 * 60 * 1_000_000_000;

/// Authorization gate for ingress (client-facing) write operations on the
/// storage API.
///
/// Implementations decide whether a given request is allowed to mutate state
/// on behalf of the owner principal it names. The trait is kept narrow — it
/// only covers endpoints where the gateway needs to prove the caller acts on
/// the owner's behalf (currently `PUT /blob_tree`). Read endpoints and chunk
/// uploads are gated by other means (public reads; chunk uploads are bound
/// to an already-authenticated blob tree).
///
/// Must be `Send + Sync` so it can live behind an `Arc<dyn IngressAuth>` in
/// the shared `StorageState` used by the async Axum handlers.
pub trait IngressAuth: Send + Sync {
    /// Check that `request` is authorized to upload its blob tree.
    ///
    /// Returns `Ok(())` if the request carries a valid authorization binding
    /// the caller to the blob tree's root hash. Returns a `StorageError`
    /// (`Unauthorized` / `Forbidden`) otherwise; handlers translate that into
    /// the appropriate HTTP status.
    fn check_put_blob(&self, request: &PutBlobTreeRequest) -> Result<(), StorageError>;
}

/// Production implementation of [`IngressAuth`] that verifies IC egress
/// certificates produced by the owner canister.
///
/// Authorization is delegated to the IC consensus layer: the owner canister
/// signs an `OwnerEgressSignature` (containing `method = "upload"` and the
/// expected `blob_hash`) into its certified data tree, and the client attaches
/// the resulting certificate to the upload request. We verify the certificate
/// against the IC root key, then match the embedded payload against the
/// request's blob root hash.
pub struct IngressAuthImpl {
    root_key: Vec<u8>,
}

impl IngressAuthImpl {
    /// Build a new verifier bound to `root_key`.
    ///
    /// `root_key` is the IC NNS root public key used to validate certificate
    /// signatures and delegation chains. For mainnet this is the well-known
    /// hardcoded key; for local/dev replicas it is fetched at startup via
    /// `Agent::fetch_root_key`. The key is snapshotted at construction time —
    /// runtime rotation is not supported.
    pub fn new(root_key: Vec<u8>) -> Self {
        Self { root_key }
    }

    fn parse_certificate(bytes: &[u8]) -> Result<Certificate, StorageError> {
        serde_cbor::from_slice::<Certificate>(bytes)
            .map_err(|e| StorageError::Forbidden(format!("failed to parse certificate: {e}")))
    }

    /// Verify the BLS signature, delegation, canister-range membership, and
    /// freshness of a certificate. Certificates whose IC `time` is older than
    /// [`CERT_MAX_AGE_NS`] (relative to the gateway's wall clock) are rejected;
    /// this caps the replay window for a leaked certificate even though
    /// `blob_hash`-binding already makes replays idempotent on the same
    /// content.
    fn verify_certificate(
        &self,
        cert: &Certificate,
        canister: Principal,
    ) -> Result<(), StorageError> {
        let now_ns = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| StorageError::Internal(format!("system clock before UNIX epoch: {e}")))?
            .as_nanos();

        cert.verify(canister.as_slice(), &self.root_key, &now_ns, &CERT_MAX_AGE_NS)
            .map_err(|e| StorageError::Forbidden(format!("certificate verification failed: {e}")))
    }

    fn extract_payload(cert: &Certificate) -> Result<OwnerEgressSignature, StorageError> {
        cert.tree
            .list_paths()
            .iter()
            .find_map(|path| {
                if let LookupResult::Found(value) = cert.tree.lookup_path(path) {
                    candid::decode_one::<OwnerEgressSignature>(value).ok()
                } else {
                    None
                }
            })
            .ok_or_else(|| {
                StorageError::Forbidden(
                    "no valid OwnerEgressSignature in certificate tree".into(),
                )
            })
    }

    fn check_payload(
        payload: &OwnerEgressSignature,
        root_hash: &str,
    ) -> Result<(), StorageError> {
        if payload.method != "upload" {
            Err(StorageError::Forbidden(format!(
                "invalid method: {}",
                payload.method
            )))
        } else if payload.blob_hash != root_hash {
            Err(StorageError::Forbidden(format!(
                "blob hash mismatch: expected {root_hash}, got {}",
                payload.blob_hash
            )))
        } else {
            Ok(())
        }
    }
}

impl IngressAuth for IngressAuthImpl {
    fn check_put_blob(&self, request: &PutBlobTreeRequest) -> Result<(), StorageError> {
        let root_hash = request
            .blob_tree
            .root_hash()
            .ok_or_else(|| StorageError::Forbidden("blob tree has no root hash".into()))?
            .to_string();

        match &request.auth {
            StorageGatewayAuthorization::None => Err(StorageError::Unauthorized(
                "no authorization provided".into(),
            )),
            StorageGatewayAuthorization::OwnerEgressSignature(cert_bytes) => {
                let cert = Self::parse_certificate(cert_bytes)?;
                self.verify_certificate(&cert, request.owner)?;
                let payload = Self::extract_payload(&cert)?;
                Self::check_payload(&payload, &root_hash)
            }
        }
    }
}
