use std::sync::Arc;

use axum::{
    extract::{Request, State},
    middleware::Next,
    response::Response,
};
use http::header::USER_AGENT;
use isbot::Bots;

#[derive(Clone, Debug)]
pub struct IsBot(pub bool);

#[derive(Default)]
pub struct IsBotState {
    bots: Bots,
}

pub async fn middleware(
    State(state): State<Arc<IsBotState>>,
    mut request: Request,
    next: Next,
) -> Response {
    let ua = request
        .headers()
        .get(USER_AGENT)
        .and_then(|x| x.to_str().ok());

    let is_bot = IsBot(ua.is_some_and(|x| state.bots.is_bot(x)));
    request.extensions_mut().insert(is_bot);

    next.run(request).await
}
