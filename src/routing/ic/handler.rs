use std::{sync::Arc, time::Duration};

use axum::{
    Extension,
    extract::{Request, State},
    response::{IntoResponse, Response},
};
use bytes::Bytes;
use http::{HeaderValue, header::HOST};
use ic_bn_lib::http::{ConnInfo, Error as IcBnError, body::buffer_body, headers::X_REQUEST_ID};
use ic_http_gateway::{CanisterRequest, HttpGatewayClient, HttpGatewayRequestArgs};

use crate::routing::{
    CanisterId, RequestCtx,
    error_cause::ErrorCause,
    ic::{
        IcResponseStatus,
        http_service::{CONTEXT, Context},
    },
    middleware::request_id::RequestId,
};

use super::{BNRequestMetadata, BNResponseMetadata};

#[derive(derive_new::new)]
pub struct HandlerState {
    client: HttpGatewayClient,
    verify_response: bool,
    body_read_timeout: Duration,
    request_max_size: usize,
}

// Main HTTP->IC request handler
//#[axum::debug_handler]
pub async fn handler(
    State(state): State<Arc<HandlerState>>,
    Extension(conn_info): Extension<Arc<ConnInfo>>,
    Extension(request_id): Extension<RequestId>,
    Extension(ctx): Extension<Arc<RequestCtx>>,
    request: Request,
) -> Result<Response, ErrorCause> {
    let canister_id = request
        .extensions()
        .get::<CanisterId>()
        .ok_or(ErrorCause::CanisterIdNotFound)?
        .0;

    let (mut parts, body) = request.into_parts();

    let body = buffer_body(body, state.request_max_size, state.body_read_timeout).await;
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

    // Inject Host header into inner HTTP request.
    // HTTP2 lacks it, but canisters might expect it to be present.
    if parts.headers.get(HOST).is_none() {
        if let Ok(v) = HeaderValue::from_bytes(ctx.authority.as_bytes()) {
            parts.headers.insert(HOST, v);
        }
    }

    let args = HttpGatewayRequestArgs {
        canister_request: CanisterRequest::from_parts(parts, body),
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
                        upstream: x.hostname.clone(),
                    },
                    BNResponseMetadata::from(&mut x.headers_in),
                )
            });

            (resp, bn_req_meta, bn_resp_meta)
        })
        .await;

    let ic_status = IcResponseStatus::from(&resp);

    // Check if an error occured in the HTTP gateway library
    if let Some(e) = resp.metadata.internal_error {
        return Err(ErrorCause::HttpGatewayError(e));
    }

    // Convert the HTTP gateway library response into an Axum response
    let mut response = resp.canister_response.into_response();
    response.extensions_mut().insert(ic_status);
    response.extensions_mut().insert(bn_req_meta);
    response.extensions_mut().insert(bn_resp_meta);

    Ok(response)
}
