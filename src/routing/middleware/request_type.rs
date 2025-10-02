use axum::{
    extract::{MatchedPath, Request, State},
    middleware::Next,
    response::IntoResponse,
};
use fqdn::FQDN;
use std::{cell::RefCell, sync::Arc};

use crate::routing::{
    ErrorCause, RequestType,
    error_cause::{ERROR_CONTEXT, ErrorContext},
};

#[derive(Clone)]
pub struct RequestTypeState {
    pub alternate_error_domain: Option<FQDN>,
}

pub async fn middleware(
    State(state): State<Arc<RequestTypeState>>,
    mut request: Request,
    next: Next,
) -> Result<impl IntoResponse, ErrorCause> {
    let request_type = RequestType::from(request.extensions().get::<MatchedPath>());
    request.extensions_mut().insert(request_type);

    let context = RefCell::new(ErrorContext {
        request_type,
        authority: None,
        alternate_error_domain: state.alternate_error_domain.clone(),
    });

    let response = ERROR_CONTEXT
        .scope(context, async move {
            let mut response = next.run(request).await;
            response.extensions_mut().insert(request_type);
            response
        })
        .await;

    Ok(response)
}
