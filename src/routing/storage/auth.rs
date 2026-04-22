use std::sync::Arc;

use candid::Principal;
use ic_bn_lib::ic_agent::{Agent, AgentError, Certificate, hash_tree::LookupResult};
use tracing::warn;

use super::wire::{OwnerEgressSignature, PutBlobTreeRequest, StorageGatewayAuthorization};

#[derive(Debug)]
pub enum AuthError {
    MissingAuth(String),
    Forbidden(String),
}

impl std::fmt::Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingAuth(m) => write!(f, "authentication required: {m}"),
            Self::Forbidden(m) => write!(f, "forbidden: {m}"),
        }
    }
}

pub trait IngressAuth: Send + Sync {
    fn check_put_blob(&self, request: &PutBlobTreeRequest) -> Result<(), AuthError>;
}

/// Production implementation: verify IC egress certificate.
pub struct IngressAuthImpl {
    agent: Arc<Agent>,
}

impl IngressAuthImpl {
    pub fn new(agent: Arc<Agent>) -> Self {
        Self { agent }
    }

    fn parse_certificate(bytes: &[u8]) -> Result<Certificate, AuthError> {
        serde_cbor::from_slice::<Certificate>(bytes)
            .map_err(|e| AuthError::Forbidden(format!("failed to parse certificate: {e}")))
    }

    fn verify_certificate(&self, cert: &Certificate, canister: Principal) -> Result<(), AuthError> {
        match self.agent.verify(cert, canister) {
            Ok(()) => Ok(()),
            Err(AgentError::CertificateOutdated(_)) => {
                warn!("Egress certificate is outdated (stale but valid signature)");
                Err(AuthError::Forbidden("certificate outdated".into()))
            }
            Err(e) => Err(AuthError::Forbidden(format!(
                "certificate verification failed: {e}"
            ))),
        }
    }

    fn extract_payload(cert: &Certificate) -> Result<OwnerEgressSignature, AuthError> {
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
                AuthError::Forbidden("no valid OwnerEgressSignature in certificate tree".into())
            })
    }

    fn check_payload(payload: &OwnerEgressSignature, root_hash: &str) -> Result<(), AuthError> {
        if payload.method != "upload" {
            Err(AuthError::Forbidden(format!(
                "invalid method: {}",
                payload.method
            )))
        } else if payload.blob_hash != root_hash {
            Err(AuthError::Forbidden(format!(
                "blob hash mismatch: expected {root_hash}, got {}",
                payload.blob_hash
            )))
        } else {
            Ok(())
        }
    }
}

impl IngressAuth for IngressAuthImpl {
    fn check_put_blob(&self, request: &PutBlobTreeRequest) -> Result<(), AuthError> {
        let root_hash = request
            .blob_tree
            .root_hash()
            .ok_or_else(|| AuthError::Forbidden("blob tree has no root hash".into()))?
            .to_string();

        match &request.auth {
            StorageGatewayAuthorization::None => {
                Err(AuthError::MissingAuth("no authorization provided".into()))
            }
            StorageGatewayAuthorization::OwnerEgressSignature(cert_bytes) => {
                let cert = Self::parse_certificate(cert_bytes)?;
                self.verify_certificate(&cert, request.owner)?;
                let payload = Self::extract_payload(&cert)?;
                Self::check_payload(&payload, &root_hash)
            }
        }
    }
}
