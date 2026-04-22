use std::sync::Arc;

use candid::Principal;
use ic_bn_lib::ic_agent::{Agent, Certificate, hash_tree::LookupResult};
use ic_certificate_verification::VerifyCertificate;

use super::wire::{OwnerEgressSignature, PutBlobTreeRequest, StorageGatewayAuthorization};
use crate::routing::error_cause::StorageError;

pub trait IngressAuth: Send + Sync {
    fn check_put_blob(&self, request: &PutBlobTreeRequest) -> Result<(), StorageError>;
}

/// Production implementation: verify IC egress certificate.
pub struct IngressAuthImpl {
    agent: Arc<Agent>,
}

impl IngressAuthImpl {
    pub fn new(agent: Arc<Agent>) -> Self {
        Self { agent }
    }

    fn parse_certificate(bytes: &[u8]) -> Result<Certificate, StorageError> {
        serde_cbor::from_slice::<Certificate>(bytes)
            .map_err(|e| StorageError::Forbidden(format!("failed to parse certificate: {e}")))
    }

    /// Verify the BLS signature, delegation, and canister-range membership of a
    /// certificate. Freshness is intentionally not enforced: the request body is
    /// structurally a canister response, and replay protection comes from the
    /// `blob_hash` binding in the payload rather than the certificate's `time`.
    fn verify_certificate(
        &self,
        cert: &Certificate,
        canister: Principal,
    ) -> Result<(), StorageError> {
        let root_key = self.agent.read_root_key();
        cert.verify(canister.as_slice(), &root_key, &0, &u128::MAX)
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
