use axum::{
    extract::{MatchedPath, Request, State},
    middleware::Next,
    response::IntoResponse,
};
use derive_new::new;
use fqdn::FQDN;
use http::header::USER_AGENT;
use std::{cell::RefCell, sync::Arc};
use woothee::parser::Parser;

use crate::routing::{
    ErrorCause, RequestType,
    error_cause::{ERROR_CONTEXT, ErrorContext},
};

#[derive(new)]
pub struct PreprocessState {
    alternate_error_domain: Option<FQDN>,
    /// Making it a state field and not a global static results in a testable code
    disable_html_error_messages: bool,
    #[new(default)]
    ua_parser: Parser,
}

impl PreprocessState {
    fn is_browser(&self, ua: &str) -> bool {
        self.ua_parser
            .parse(ua)
            // "mobilephone" are some (old?) japanese phone browsers it seems, but let's treat them as browsers too
            .is_some_and(|x| ["pc", "smartphone", "mobilephone"].contains(&x.category))
    }
}

pub async fn middleware(
    State(state): State<Arc<PreprocessState>>,
    mut request: Request,
    next: Next,
) -> Result<impl IntoResponse, ErrorCause> {
    let request_type = RequestType::from(
        request
            .extensions()
            .get::<MatchedPath>()
            .map(|x| x.as_str()),
    );

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
        disable_html_error_messages: state.disable_html_error_messages,
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
        let state = PreprocessState::new(None, false);

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

    /// The middleware sets up the task-local the error pages are rendered from,
    /// and tags the request/response with the derived request type.
    #[tokio::test]
    async fn test_middleware() {
        use axum::{Router, body::Body, middleware::from_fn_with_state, response::Response};
        use fqdn::fqdn;
        use http::{HeaderValue, StatusCode};
        use tower::ServiceExt;

        const UA_BROWSER: &str = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36";

        async fn run(state: PreprocessState, ua: Option<&str>, path: &str) -> Response {
            let router = Router::new()
                .route(
                    "/health",
                    axum::routing::get(|request: Request| async move {
                        // Report what the middleware set up
                        let ctx = ERROR_CONTEXT.with(|x| x.borrow().clone());
                        let rt = request.extensions().get::<RequestType>().copied();
                        let mut resp = Response::new(Body::empty());
                        resp.extensions_mut().insert(ctx);
                        resp.extensions_mut().insert(("req", rt));
                        resp
                    }),
                )
                .fallback(|request: Request| async move {
                    let ctx = ERROR_CONTEXT.with(|x| x.borrow().clone());
                    let rt = request.extensions().get::<RequestType>().copied();
                    let mut resp = Response::new(Body::empty());
                    resp.extensions_mut().insert(ctx);
                    resp.extensions_mut().insert(("req", rt));
                    resp
                })
                .layer(from_fn_with_state(Arc::new(state), middleware));

            let mut req = Request::builder()
                .uri(path)
                .body(Body::empty())
                .unwrap();
            if let Some(v) = ua {
                req.headers_mut()
                    .insert(USER_AGENT, HeaderValue::from_str(v).unwrap());
            }

            router.oneshot(req).await.unwrap()
        }

        // A matched path drives the request type, and it's mirrored onto the
        // response for the metrics layer.
        let mut resp = run(PreprocessState::new(None, false), None, "/health").await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.extensions_mut().remove::<(&str, Option<RequestType>)>(),
            Some(("req", Some(RequestType::Health)))
        );
        let ctx = resp.extensions_mut().remove::<ErrorContext>().unwrap();
        assert_eq!(ctx.request_type, RequestType::Health);
        assert!(!ctx.is_browser);
        assert_eq!(
            resp.extensions_mut().remove::<RequestType>(),
            Some(RequestType::Health)
        );

        // No matched path (the gateway's own fallback) means a plain HTTP request
        let mut resp = run(PreprocessState::new(None, false), None, "/index.html").await;
        let ctx = resp.extensions_mut().remove::<ErrorContext>().unwrap();
        assert_eq!(ctx.request_type, RequestType::Http);

        // A browser User-Agent flips `is_browser`, which is what selects the
        // HTML error pages.
        let mut resp = run(PreprocessState::new(None, false), Some(UA_BROWSER), "/").await;
        let ctx = resp.extensions_mut().remove::<ErrorContext>().unwrap();
        assert!(ctx.is_browser);

        let mut resp = run(PreprocessState::new(None, false), Some("curl/8.7.1"), "/").await;
        let ctx = resp.extensions_mut().remove::<ErrorContext>().unwrap();
        assert!(!ctx.is_browser);

        // Config is threaded through to the context
        let mut resp = run(
            PreprocessState::new(Some(fqdn!("caffeine.ai")), true),
            Some(UA_BROWSER),
            "/",
        )
        .await;
        let ctx = resp.extensions_mut().remove::<ErrorContext>().unwrap();
        assert!(ctx.disable_html_error_messages);
        assert_eq!(ctx.alternate_error_domain, Some(fqdn!("caffeine.ai")));

        // These are filled in later, by `validate`
        assert_eq!(ctx.authority, None);
        assert_eq!(ctx.canister_id, None);
    }

    /// A non-UTF8 User-Agent must not be treated as a browser (nor panic).
    #[tokio::test]
    async fn test_middleware_bad_user_agent() {
        use axum::{Router, body::Body, middleware::from_fn_with_state, response::Response};
        use http::HeaderValue;
        use tower::ServiceExt;

        let router = Router::new()
            .fallback(|| async {
                let ctx = ERROR_CONTEXT.with(|x| x.borrow().clone());
                let mut resp = Response::new(Body::empty());
                resp.extensions_mut().insert(ctx);
                resp
            })
            .layer(from_fn_with_state(
                Arc::new(PreprocessState::new(None, false)),
                middleware,
            ));

        let mut req = Request::builder().uri("/").body(Body::empty()).unwrap();
        req.headers_mut().insert(
            USER_AGENT,
            HeaderValue::from_bytes(&[0xff, 0xfe, 0xfd]).unwrap(),
        );

        let mut resp = router.oneshot(req).await.unwrap();
        let ctx = resp.extensions_mut().remove::<ErrorContext>().unwrap();
        assert!(!ctx.is_browser);
    }
}
