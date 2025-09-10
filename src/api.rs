use std::{str::FromStr, sync::Arc};

use anyhow::{Error, anyhow};
use axum::{
    Router,
    extract::{Path, Request, State},
    middleware::{Next, from_fn_with_state},
    response::{IntoResponse, Response},
    routing::get,
};
use derive_new::new;
use http::{StatusCode, header::AUTHORIZATION};
use ic_bn_lib::http::middleware::waf::{self, WafLayer};
use tracing::Level;
use tracing_core::LevelFilter;
use tracing_subscriber::{Registry, reload::Handle};

use crate::cli::Cli;

#[derive(Debug, new)]
pub struct ApiState {
    token: String,
    log_handle: Arc<Handle<LevelFilter, Registry>>,
}

pub async fn auth_middleware(
    State(state): State<Arc<ApiState>>,
    request: Request,
    next: Next,
) -> Response {
    let Some(auth) = request.headers().get(AUTHORIZATION) else {
        return (StatusCode::UNAUTHORIZED, "Authorization header not found").into_response();
    };

    let auth = auth.as_bytes();
    if !auth.starts_with(b"Bearer ") || auth.len() < 8 {
        return (StatusCode::UNAUTHORIZED, "Incorrect header format").into_response();
    }

    if &auth[7..] != state.token.as_bytes() {
        return (StatusCode::UNAUTHORIZED, "Incorrect bearer token").into_response();
    }

    next.run(request).await
}

pub async fn log_handler(
    State(state): State<Arc<ApiState>>,
    Path(log_level): Path<String>,
) -> Response {
    let Ok(log_level) = Level::from_str(&log_level) else {
        return (
            StatusCode::BAD_REQUEST,
            format!("Unable to parse '{log_level}' as log level"),
        )
            .into_response();
    };
    let level_filter = LevelFilter::from_level(log_level);
    let _ = state.log_handle.modify(|f| *f = level_filter);

    "Ok\n".into_response()
}

pub fn setup_api_router(
    cli: &Cli,
    log_handle: Handle<LevelFilter, Registry>,
    waf_layer: Option<WafLayer>,
) -> Result<Router, Error> {
    let state = Arc::new(ApiState::new(
        cli.api
            .api_token
            .clone()
            .ok_or_else(|| anyhow!("API token not specified"))?,
        Arc::new(log_handle),
    ));

    let auth = from_fn_with_state(state.clone(), auth_middleware);

    let mut router = Router::new().route("/log/{log_level}", get(log_handler).layer(auth.clone()));
    if let Some(v) = waf_layer {
        router = router.nest("/waf", waf::create_router(v).layer(auth))
    }

    Ok(router.with_state(state))
}

#[cfg(test)]
mod test {
    use axum::body::Body;
    use clap::Parser;
    use http::{HeaderValue, Request, Uri};
    use ic_bn_lib::hval;
    use tower::ServiceExt;
    use tracing_subscriber::reload;

    use super::*;

    #[tokio::test]
    async fn test_api_auth() {
        let args: Vec<&str> = vec!["", "--api-token", "deadbeef"];
        let cli = Cli::parse_from(args);

        let (_, reload_handle) = reload::Layer::new(LevelFilter::WARN);
        let router = setup_api_router(&cli, reload_handle, None).unwrap();

        // Bad header
        let mut req = Request::builder()
            .uri("/log/warn")
            .body(Body::empty())
            .unwrap();
        req.headers_mut().insert(AUTHORIZATION, hval!("beef"));

        let resp = router.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        let mut req: Request<Body> = Request::builder()
            .uri("/log/warn")
            .body(Body::empty())
            .unwrap();
        req.headers_mut().insert(AUTHORIZATION, hval!("Bearer "));

        let resp = router.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        // Bad token
        let mut req = Request::builder()
            .uri("/log/warn")
            .body(Body::empty())
            .unwrap();
        req.headers_mut()
            .insert(AUTHORIZATION, hval!("Bearer foobar"));

        let resp = router.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        // Good token
        let mut req = Request::builder()
            .uri("/log/warn")
            .body(Body::empty())
            .unwrap();
        *req.uri_mut() = Uri::from_static("http://foo/log/warn");
        req.headers_mut().insert(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {}", cli.api.api_token.unwrap())).unwrap(),
        );

        let resp = router.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }
}
