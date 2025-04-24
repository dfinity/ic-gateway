use std::sync::{Arc, Mutex};

use anyhow::Error;
use axum::{extract::State, response::IntoResponse};
use bytes::Bytes;
use sev::firmware::guest::Firmware;

use super::error_cause::ErrorCause;

#[derive(Clone)]
pub struct SevSnpState(Arc<Mutex<Firmware>>);

impl SevSnpState {
    pub fn new() -> Result<Self, Error> {
        Ok(Self(Arc::new(Mutex::new(Firmware::open()?))))
    }
}

pub async fn handler(
    State(state): State<SevSnpState>,
    body: Bytes,
) -> Result<impl IntoResponse, ErrorCause> {
    if body.len() != 64 {
        return Err(ErrorCause::MalformedRequest(
            "The input data should be exactly 64 bytes".into(),
        ));
    }

    let data: [u8; 64] = body.as_ref().try_into().unwrap();

    let report = state
        .0
        .lock()
        .unwrap()
        .get_report(None, Some(data), Some(1))
        .map_err(|e| ErrorCause::Other(format!("Unable to create attestation report: {e}")))?;

    Ok(report)
}
