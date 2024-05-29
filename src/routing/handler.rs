use std::sync::Arc;

use axum::{
    body::Body,
    extract::{Request, State},
    response::{IntoResponse, Response},
    Extension,
};
use bytes::Bytes;
use futures::StreamExt;
use http::Uri;
use http_body::Frame;
use http_body_util::{BodyExt, Full, LengthLimitError, Limited, StreamBody};
use ic_http_gateway::{
    CanisterRequest, HttpGatewayClient, HttpGatewayRequestArgs, HttpGatewayResponse,
    HttpGatewayResponseBody,
};

use super::{error_cause::ErrorCause, RequestCtx};

const MAX_REQUEST_BODY_SIZE: usize = 10_485_760;

#[derive(derive_new::new)]
pub struct HandlerState {
    gw: HttpGatewayClient,
}

fn convert_response(resp: HttpGatewayResponse) -> Response {
    let (parts, body) = resp.canister_response.into_parts();

    match body {
        HttpGatewayResponseBody::Bytes(v) => {
            Response::from_parts(parts, Body::new(Full::new(v.into()))).into_response()
        }

        HttpGatewayResponseBody::Stream(v) => {
            let v = v.map(|x| x.map(|y| Frame::data(Bytes::from(y))));
            let body = StreamBody::new(v);
            let body = Body::new(body);

            Response::from_parts(parts, body).into_response()
        }
    }
}

pub async fn handler(
    State(state): State<Arc<HandlerState>>,
    Extension(ctx): Extension<Arc<RequestCtx>>,
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

    // Execute the request
    let resp = state
        .gw
        .request(args)
        //.unsafe_allow_skip_verification()
        .send()
        .await
        .map_err(ErrorCause::from_err)?;

    // Convert it into Axum response
    Ok(convert_response(resp))
}
