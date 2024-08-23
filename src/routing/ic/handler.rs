use std::{sync::Arc, time::Duration};

use axum::{
    extract::{Request, State},
    response::{IntoResponse, Response},
    Extension,
};
use bytes::Bytes;
use http::HeaderValue;
use ic_bn_lib::http::{body::buffer_body, headers::X_REQUEST_ID, ConnInfo, Error as IcBnError};
use ic_http_gateway::{CanisterRequest, HttpGatewayClient, HttpGatewayRequestArgs};

use crate::routing::{
    error_cause::ErrorCause,
    ic::{
        transport::{Context, CONTEXT},
        IcResponseStatus,
    },
    middleware::request_id::RequestId,
    CanisterId, RequestCtx,
};

use super::{BNRequestMetadata, BNResponseMetadata};

const MAX_REQUEST_BODY_SIZE: usize = 10 * 1_048_576;

#[derive(derive_new::new)]
pub struct HandlerState {
    client: HttpGatewayClient,
    verify_response: bool,
    body_read_timeout: Duration,
}

// Main HTTP->IC request handler
pub async fn handler(
    State(state): State<Arc<HandlerState>>,
    canister_id: Option<Extension<CanisterId>>,
    Extension(conn_info): Extension<Arc<ConnInfo>>,
    Extension(request_id): Extension<RequestId>,
    Extension(ctx): Extension<Arc<RequestCtx>>,
    request: Request,
) -> Result<Response, ErrorCause> {
    let canister_id = canister_id
        .map(|x| (x.0).0)
        .ok_or(ErrorCause::CanisterIdNotFound)?;

    let (parts, body) = request.into_parts();

    let body = buffer_body(body, MAX_REQUEST_BODY_SIZE, state.body_read_timeout).await;
    let body = match body {
        Ok(v) => v,
        Err(e) => {
            // Close the connection if there was a timeout
            if matches!(e, IcBnError::BodyTimedOut) {
                conn_info.close();
            }

            return Err(ErrorCause::from_client_error(e));
        }
    };

    let args = HttpGatewayRequestArgs {
        canister_request: CanisterRequest::from_parts(parts, body.to_vec()),
        canister_id,
    };

    // Store request context info
    let (resp, bn_req_meta, bn_resp_meta) = CONTEXT
        .scope(Context::new(), async {
            CONTEXT.with(|x| {
                let hdr =
                    HeaderValue::from_maybe_shared(Bytes::from(request_id.to_string())).unwrap();

                x.borrow_mut().headers_out.insert(X_REQUEST_ID, hdr)
            });

            // Execute the request
            let mut req = state.client.request(args);
            // Skip verification if it's disabled globally or if it is a "raw" request.
            req.unsafe_set_skip_verification(!state.verify_response || !ctx.verify);
            let resp = req.send().await;

            let (bn_req_meta, bn_resp_meta) = CONTEXT.with(|x| {
                let mut x = x.borrow_mut();

                (
                    BNRequestMetadata {
                        backend: x.hostname.clone(),
                    },
                    BNResponseMetadata::from(&mut x.headers_in),
                )
            });

            (resp, bn_req_meta, bn_resp_meta)
        })
        .await;

    let ic_status = IcResponseStatus::from(&resp);

    // Convert it into Axum response
    let mut response = resp.canister_response.into_response();
    response.extensions_mut().insert(ic_status);
    response.extensions_mut().insert(bn_req_meta);
    response.extensions_mut().insert(bn_resp_meta);

    Ok(response)
}
