use std::{str::FromStr, sync::Arc};

use axum::{
    Router,
    extract::{Path, Request, State},
    middleware::{Next, from_fn_with_state},
    response::{IntoResponse, Response},
    routing::get,
};
use derive_new::new;
use http::{Method, StatusCode, header::AUTHORIZATION};
use ic_bn_lib::{
    health::Healthy,
    http::middleware::waf::{self, WafLayer},
};
use tokio_util::sync::CancellationToken;
use tracing::Level;
use tracing_subscriber::{EnvFilter, Registry, reload::Handle};

use crate::{cli::Cli, routing::middleware::cors};

#[derive(Debug, new)]
pub struct ApiState {
    token: Option<String>,
    log_handle: Arc<Handle<EnvFilter, Registry>>,
    shutdown_token: CancellationToken,
}

pub async fn auth_middleware(
    State(state): State<Arc<ApiState>>,
    request: Request,
    next: Next,
) -> Response {
    let Some(token) = &state.token else {
        return (
            StatusCode::UNAUTHORIZED,
            "Authorization token is not set, this part of API is not available\n",
        )
            .into_response();
    };

    let Some(auth) = request.headers().get(AUTHORIZATION) else {
        return (StatusCode::UNAUTHORIZED, "Authorization header not found\n").into_response();
    };

    let auth = auth.as_bytes();
    if !auth.starts_with(b"Bearer ") || auth.len() < 8 {
        return (StatusCode::UNAUTHORIZED, "Incorrect header format\n").into_response();
    }

    if &auth[7..] != token.as_bytes() {
        return (StatusCode::UNAUTHORIZED, "Incorrect bearer token\n").into_response();
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
    // Maintain hickory_proto::dnssec=error filter when changing log level
    let env_filter = EnvFilter::new(format!("{},{}", log_level, crate::log::LOG_LEVEL_OVERRIDES));
    let _ = state.log_handle.modify(|f| *f = env_filter);

    "Ok\n".into_response()
}

/// Handles shutdown requests
pub async fn shutdown_handler(State(state): State<Arc<ApiState>>) -> Response {
    state.shutdown_token.cancel();
    "Shutting down gracefully\n".into_response()
}

/// Handles health requests
pub async fn health_handler(State(state): State<Arc<dyn Healthy>>) -> impl IntoResponse {
    if state.healthy() {
        StatusCode::NO_CONTENT
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    }
}

/// Creates an Axum router for the API
pub fn setup_api_router(
    cli: &Cli,
    log_handle: Handle<EnvFilter, Registry>,
    healthy: Arc<dyn Healthy>,
    shutdown_token: CancellationToken,
    waf_layer: Option<WafLayer>,
) -> Router {
    let cors_layer = cors::layer(cli.cors.cors_max_age, cli.cors.cors_allow_origin.clone())
        .allow_methods([Method::HEAD, Method::GET]);

    let state = Arc::new(ApiState::new(
        cli.api.api_token.clone(),
        Arc::new(log_handle),
        shutdown_token,
    ));

    let auth = from_fn_with_state(state.clone(), auth_middleware);

    let mut router = Router::new()
        .route("/log/{log_level}", get(log_handler).layer(auth.clone()))
        .route("/shutdown", get(shutdown_handler).layer(auth.clone()))
        .route("/health", get(health_handler).with_state(healthy));

    // Enable WAF if requested
    if let Some(v) = waf_layer {
        router = router.nest("/waf", waf::create_router(v).layer(auth));
    }

    router.layer(cors_layer).with_state(state)
}

#[cfg(test)]
mod test {
    use std::sync::atomic::{AtomicBool, Ordering};

    use axum::body::{Body, to_bytes};
    use clap::Parser;
    use http::{HeaderValue, Request, Uri};
    use ic_bn_lib::{health::HealthManager, hval};
    use tower::ServiceExt;
    use tracing_subscriber::reload;

    use super::*;

    fn cli_with_token(token: Option<&str>) -> Cli {
        let mut args: Vec<&str> = vec![""];
        if let Some(v) = token {
            args.extend_from_slice(&["--api-token", v]);
        }
        Cli::parse_from(args)
    }

    fn reload_handle() -> Handle<EnvFilter, Registry> {
        reload::Layer::new(EnvFilter::new(format!(
            "warn,{}",
            crate::log::LOG_LEVEL_OVERRIDES
        )))
        .1
    }

    fn router_with(
        token: Option<&str>,
        healthy: Arc<dyn Healthy>,
        shutdown_token: CancellationToken,
    ) -> Router {
        setup_api_router(
            &cli_with_token(token),
            reload_handle(),
            healthy,
            shutdown_token,
            None,
        )
    }

    fn get(uri: &str, auth: Option<&str>) -> Request<Body> {
        let mut req = Request::builder().uri(uri).body(Body::empty()).unwrap();
        if let Some(v) = auth {
            req.headers_mut()
                .insert(AUTHORIZATION, HeaderValue::from_str(v).unwrap());
        }
        req
    }

    /// Simple `Healthy` whose state the test controls
    #[derive(Debug)]
    struct TestHealthy(AtomicBool);

    impl Healthy for TestHealthy {
        fn healthy(&self) -> bool {
            self.0.load(Ordering::SeqCst)
        }
    }

    #[tokio::test]
    async fn test_api_auth() {
        let args: Vec<&str> = vec!["", "--api-token", "deadbeef"];
        let cli = Cli::parse_from(args);

        let (_, reload_handle) = reload::Layer::new(EnvFilter::new(format!(
            "warn,{}",
            crate::log::LOG_LEVEL_OVERRIDES
        )));
        let healthy = Arc::new(HealthManager::default());
        let router = setup_api_router(&cli, reload_handle, healthy, CancellationToken::new(), None);

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

    /// Without a configured token the privileged endpoints must stay closed
    /// rather than become open to everyone.
    #[tokio::test]
    async fn test_api_auth_no_token_configured() {
        let router = router_with(
            None,
            Arc::new(HealthManager::default()),
            CancellationToken::new(),
        );

        for auth in [None, Some("Bearer anything")] {
            let resp = router.clone().oneshot(get("/log/warn", auth)).await.unwrap();
            assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "auth {auth:?}");

            let body = to_bytes(resp.into_body(), 1024).await.unwrap();
            assert!(
                String::from_utf8_lossy(&body).contains("token is not set"),
                "auth {auth:?}"
            );
        }
    }

    #[tokio::test]
    async fn test_api_auth_missing_header() {
        let router = router_with(
            Some("deadbeef"),
            Arc::new(HealthManager::default()),
            CancellationToken::new(),
        );

        let resp = router.oneshot(get("/log/warn", None)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        let body = to_bytes(resp.into_body(), 1024).await.unwrap();
        assert!(String::from_utf8_lossy(&body).contains("header not found"));
    }

    #[tokio::test]
    async fn test_api_auth_header_variants() {
        let router = router_with(
            Some("deadbeef"),
            Arc::new(HealthManager::default()),
            CancellationToken::new(),
        );

        let rejected = [
            // Wrong scheme
            "deadbeef",
            "Basic deadbeef",
            // Right prefix but nothing after it
            "Bearer ",
            // Case matters
            "bearer deadbeef",
            // A prefix of the token must not be accepted
            "Bearer dead",
            // Neither must a superstring
            "Bearer deadbeeff",
            // No separating space
            "Bearerdeadbeef",
        ];

        for auth in rejected {
            let resp = router
                .clone()
                .oneshot(get("/log/warn", Some(auth)))
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "auth {auth:?}");
        }

        let resp = router
            .oneshot(get("/log/warn", Some("Bearer deadbeef")))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_log_handler() {
        let router = router_with(
            Some("deadbeef"),
            Arc::new(HealthManager::default()),
            CancellationToken::new(),
        );
        let auth = Some("Bearer deadbeef");

        // Names are matched case-insensitively and 1-5 are accepted as aliases
        // (see `tracing_core::Level`'s FromStr).
        for level in [
            "trace", "debug", "info", "warn", "error", "WARN", "Debug", "1", "5",
        ] {
            let resp = router
                .clone()
                .oneshot(get(&format!("/log/{level}"), auth))
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::OK, "level {level}");
        }

        // Garbage is rejected instead of silently changing nothing.
        // Note "0" is not "off" here - only 1-5 are valid.
        for level in ["foobar", "WARNING", "0", "6", "-1"] {
            let resp = router
                .clone()
                .oneshot(get(&format!("/log/{level}"), auth))
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "level {level}");

            let body = to_bytes(resp.into_body(), 1024).await.unwrap();
            assert!(String::from_utf8_lossy(&body).contains("Unable to parse"));
        }
    }

    /// The hickory DNSSEC suppression must survive a log level change, otherwise
    /// turning on debug logging floods the logs.
    #[tokio::test]
    async fn test_log_handler_keeps_overrides() {
        // The layer has to stay alive - the handle is only usable while it does
        let (_layer, handle) = reload::Layer::new(EnvFilter::new(format!(
            "warn,{}",
            crate::log::LOG_LEVEL_OVERRIDES
        )));

        let state = Arc::new(ApiState::new(
            Some("deadbeef".into()),
            Arc::new(handle),
            CancellationToken::new(),
        ));

        let resp = log_handler(State(state.clone()), Path("debug".into())).await;
        assert_eq!(resp.status(), StatusCode::OK);

        let filter = state.log_handle.with_current(ToString::to_string).unwrap();
        assert!(filter.contains("debug"), "filter: {filter}");
        assert!(
            filter.contains(crate::log::LOG_LEVEL_OVERRIDES),
            "filter: {filter}"
        );
    }

    #[tokio::test]
    async fn test_shutdown_handler() {
        let shutdown_token = CancellationToken::new();
        let router = router_with(
            Some("deadbeef"),
            Arc::new(HealthManager::default()),
            shutdown_token.clone(),
        );

        // Unauthorized requests must not be able to shut us down
        let resp = router
            .clone()
            .oneshot(get("/shutdown", Some("Bearer wrong")))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert!(!shutdown_token.is_cancelled());

        let resp = router
            .oneshot(get("/shutdown", Some("Bearer deadbeef")))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(shutdown_token.is_cancelled());
    }

    /// `/health` is used to bootstrap agent-rs dynamic routing, so it must be
    /// reachable without a token.
    #[tokio::test]
    async fn test_health_handler() {
        let healthy = Arc::new(TestHealthy(AtomicBool::new(true)));
        let router = router_with(
            Some("deadbeef"),
            healthy.clone(),
            CancellationToken::new(),
        );

        let resp = router.clone().oneshot(get("/health", None)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);

        healthy.0.store(false, Ordering::SeqCst);
        let resp = router.oneshot(get("/health", None)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    /// Only HEAD/GET are allowed; everything else is a preflight/method error.
    #[tokio::test]
    async fn test_api_router_methods() {
        let router = router_with(
            Some("deadbeef"),
            Arc::new(HealthManager::default()),
            CancellationToken::new(),
        );

        let mut req = get("/health", None);
        *req.method_mut() = Method::POST;
        let resp = router.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::METHOD_NOT_ALLOWED);

        // An unknown path is a 404, not an auth error
        let resp = router
            .oneshot(get("/nope", Some("Bearer deadbeef")))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }
}
