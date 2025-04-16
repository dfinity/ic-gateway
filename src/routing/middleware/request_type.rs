use axum::{
    extract::{MatchedPath, Request},
    middleware::Next,
    response::IntoResponse,
};

use crate::routing::{ErrorCause, RequestType, error_cause::ERROR_CONTEXT};

pub async fn middleware(mut request: Request, next: Next) -> Result<impl IntoResponse, ErrorCause> {
    let request_type = RequestType::from(request.extensions().get::<MatchedPath>());
    request.extensions_mut().insert(request_type);

    // Set error context
    let response = ERROR_CONTEXT
        .scope(request_type, async move {
            // Execute the request
            let mut response = next.run(request).await;
            response.extensions_mut().insert(request_type);
            response
        })
        .await;

    Ok(response)
}
