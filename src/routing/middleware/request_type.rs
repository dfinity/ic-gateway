use axum::{
    extract::{MatchedPath, Request, State},
    middleware::Next,
    response::IntoResponse,
};
use fqdn::FQDN;
use http::header::USER_AGENT;
use std::{cell::RefCell, sync::Arc};
use woothee::parser::Parser;

use crate::routing::{
    ErrorCause, RequestType,
    error_cause::{ERROR_CONTEXT, ErrorContext},
};

pub struct RequestTypeState {
    pub alternate_error_domain: Option<FQDN>,
    pub ua_parser: Parser,
}

impl RequestTypeState {
    fn is_browser(&self, ua: &str) -> bool {
        self.ua_parser
            .parse(ua)
            // "mobilephone" are some (old?) japanese phone browsers it seems, but let's treat them as browsers too
            .map(|x| ["pc", "smartphone", "mobilephone"].contains(&x.category))
            .unwrap_or(false)
    }
}

pub async fn middleware(
    State(state): State<Arc<RequestTypeState>>,
    mut request: Request,
    next: Next,
) -> Result<impl IntoResponse, ErrorCause> {
    let request_type = RequestType::from(request.extensions().get::<MatchedPath>());
    request.extensions_mut().insert(request_type);

    // Try to parse User-Agent header to check if the client is a browser.
    let is_browser = request
        .headers()
        .get(USER_AGENT)
        .and_then(|x| x.to_str().ok())
        .is_some_and(|x| state.is_browser(x));

    let context = RefCell::new(ErrorContext {
        request_type,
        is_browser,
        canister_id: None,
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

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_is_browser() {
        let state = RequestTypeState {
            alternate_error_domain: None,
            ua_parser: Parser::new(),
        };

        assert!(!state.is_browser("curl/8.7.1"));
        assert!(!state.is_browser("python-requests/2.25.0"));
        assert!(!state.is_browser(""));

        assert!(state.is_browser(
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"
        ));
        assert!(state.is_browser(
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 15_7_2) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.0 Safari/605.1.15"
        ));
        assert!(state.is_browser(
            "Mozilla/5.0 (iPhone; CPU iPhone OS 18_7_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.0 Mobile/15E148 Safari/604.1"
        ));
        assert!(state.is_browser(
            "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.7444.172 Mobile Safari/537.36"
        ));
    }
}
