use std::sync::Arc;

use axum::{
    extract::{Request, State},
    response::Response,
    Extension,
};
use bytes::Bytes;
use http::{HeaderValue, Uri};
use http_body_util::{BodyExt, LengthLimitError, Limited};
use ic_http_gateway::{CanisterRequest, HttpGatewayClient, HttpGatewayRequestArgs};

use super::{
    error_cause::ErrorCause,
    ic::{
        self,
        transport::{PassHeaders, PASS_HEADERS},
        IcResponseStatus,
    },
    middleware::{self, request_id::RequestId},
    RequestCtx,
};

const MAX_REQUEST_BODY_SIZE: usize = 10 * 1_048_576;

#[derive(derive_new::new)]
pub struct HandlerState {
    client: HttpGatewayClient,
}

pub async fn handler(
    State(state): State<Arc<HandlerState>>,
    Extension(ctx): Extension<Arc<RequestCtx>>,
    Extension(request_id): Extension<RequestId>,
    request: Request,
) -> Result<Response, ErrorCause> {
    let (mut parts, body) = request.into_parts();

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

    parts.uri = Uri::builder()
        .path_and_query(parts.uri.path_and_query().unwrap().as_str())
        .build()
        .unwrap();

    let args = HttpGatewayRequestArgs {
        canister_request: CanisterRequest::from_parts(parts, body),
        canister_id: ctx.canister.id,
    };

    // Pass headers in/out the IC request
    let resp = PASS_HEADERS
        .scope(PassHeaders::new(), async {
            PASS_HEADERS.with(|x| {
                let hdr =
                    HeaderValue::from_maybe_shared(Bytes::from(request_id.to_string())).unwrap();

                x.borrow_mut()
                    .headers_out
                    .insert(middleware::request_id::HEADER, hdr)
            });

            // Execute the request
            state
                .client
                .request(args)
                //.unsafe_allow_skip_verification()
                .send()
                .await
        })
        .await
        .map_err(ErrorCause::from_err)?;

    let ic_status = IcResponseStatus::from(&resp);
    let mut response = ic::convert_response(resp.canister_response);
    response.extensions_mut().insert(ic_status);

    // Convert it into Axum response
    Ok(response)
}
