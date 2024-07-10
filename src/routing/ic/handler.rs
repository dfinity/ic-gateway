use std::sync::Arc;

use axum::{
    extract::{Request, State},
    response::{IntoResponse, Response},
    Extension,
};
use bytes::Bytes;
use http::HeaderValue;
use http_body_util::{BodyExt, LengthLimitError, Limited};
use ic_http_gateway::{CanisterRequest, HttpGatewayClient, HttpGatewayRequestArgs};

use crate::routing::{
    error_cause::ErrorCause,
    ic::{
        transport::{PassHeaders, PASS_HEADERS},
        IcResponseStatus,
    },
    middleware::{self, request_id::RequestId},
    CanisterId, RequestCtx,
};

use super::{BNResponseMetadata, ResponseVerificationVersion};

const MAX_REQUEST_BODY_SIZE: usize = 10 * 1_048_576;

#[derive(derive_new::new)]
pub struct HandlerState {
    client: HttpGatewayClient,
}

// Main HTTP->IC request handler
pub async fn handler(
    State(state): State<Arc<HandlerState>>,
    canister_id: Option<Extension<CanisterId>>,
    Extension(request_id): Extension<RequestId>,
    Extension(ctx): Extension<Arc<RequestCtx>>,
    request: Request,
) -> Result<Response, ErrorCause> {
    let canister_id = canister_id
        .map(|x| (x.0).0)
        .ok_or(ErrorCause::CanisterIdNotFound)?;

    let (parts, body) = request.into_parts();

    // Collect the request body up to the limit
    let body = Limited::new(body, MAX_REQUEST_BODY_SIZE)
        .collect()
        .await
        .map_err(|e| {
            // TODO improve the inferring somehow
            e.downcast_ref::<LengthLimitError>().map_or_else(
                || ErrorCause::UnableToReadBody(e.to_string()),
                |_| ErrorCause::RequestTooLarge,
            )
        })?
        .to_bytes()
        .to_vec();

    let args = HttpGatewayRequestArgs {
        canister_request: CanisterRequest::from_parts(parts, body),
        canister_id,
    };

    // Pass headers in/out the IC request
    let (resp, bn_metadata) = PASS_HEADERS
        .scope(PassHeaders::new(), async {
            PASS_HEADERS.with(|x| {
                let hdr =
                    HeaderValue::from_maybe_shared(Bytes::from(request_id.to_string())).unwrap();

                x.borrow_mut()
                    .headers_out
                    .insert(middleware::X_REQUEST_ID, hdr)
            });

            // Execute the request
            let mut req = state.client.request(args);
            req.unsafe_set_allow_skip_verification(!ctx.verify);
            let resp = req.send().await;

            let bn_metadata =
                PASS_HEADERS.with(|x| BNResponseMetadata::from(&mut x.borrow_mut().headers_in));

            (resp, bn_metadata)
        })
        .await;

    let ic_status = IcResponseStatus::from(&resp);

    // Convert it into Axum response
    let mut response = resp.canister_response.into_response();
    response.extensions_mut().insert(ic_status);
    response.extensions_mut().insert(bn_metadata);
    if let Some(response_verification_version) = resp.metadata.response_verification_version {
        response.extensions_mut().insert(ResponseVerificationVersion(response_verification_version));
    }

    Ok(response)
}
