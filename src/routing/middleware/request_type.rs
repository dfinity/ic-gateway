use axum::{
    extract::{MatchedPath, Request, State},
    middleware::Next,
    response::IntoResponse,
};
use fqdn::FQDN;

use crate::routing::{
    ErrorCause, RequestType,
    error_cause::{ERROR_CONTEXT, ErrorContext},
};

#[derive(Clone)]
pub struct RequestTypeState {
    pub alternate_error_domain: Option<FQDN>,
}

pub async fn middleware(
    State(state): State<RequestTypeState>,
    mut request: Request,
    next: Next,
) -> Result<impl IntoResponse, ErrorCause> {
    let request_type = RequestType::from(request.extensions().get::<MatchedPath>());
    request.extensions_mut().insert(request_type);

    let context = ErrorContext {
        request_type,
        alternate_error_domain: state.alternate_error_domain.clone(),
    };

    let response = ERROR_CONTEXT
        .scope(context, async move {
            let mut response = next.run(request).await;
            response.extensions_mut().insert(request_type);
            response
        })
        .await;

    Ok(response)
}
