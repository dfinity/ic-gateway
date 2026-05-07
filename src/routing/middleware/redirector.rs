use std::{str::FromStr, sync::Arc};

use axum::{
    Extension,
    body::Body,
    extract::{OriginalUri, Request, State},
    middleware::Next,
    response::Response,
};
use derive_new::new;
use fqdn::{FQDN, Fqdn};
use http::{Uri, uri::Authority};
use ic_bn_lib_common::traits::http::ClientHttp;

use crate::routing::{
    RequestCtx,
    error_cause::{ClientError, ErrorCause},
    middleware::is_bot::IsBot,
};

const STATIC_ASSET_EXTENSIONS: &[&str] = &[
    ".js",
    ".mjs",
    ".cjs",
    ".css",
    ".map",
    ".json",
    ".xml",
    ".txt",
    ".webmanifest",
    ".ico",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".webp",
    ".avif",
    ".svg",
    ".bmp",
    ".tiff",
    ".heic",
    ".woff",
    ".woff2",
    ".ttf",
    ".otf",
    ".eot",
    ".mp4",
    ".webm",
    ".ogv",
    ".mov",
    ".mp3",
    ".wav",
    ".ogg",
    ".flac",
    ".pdf",
    ".zip",
    ".gz",
    ".br",
    ".tar",
    ".wasm",
];

fn is_static_asset(path: &str) -> bool {
    STATIC_ASSET_EXTENSIONS.iter().any(|x| path.ends_with(*x))
}

#[derive(new)]
pub struct RedirectorState {
    caffeine_domain: FQDN,
    caffeine_renderer: Uri,
    client: Arc<dyn ClientHttp<Body>>,
}

impl RedirectorState {
    fn should_render(&self, authority: &Fqdn, uri: &Uri, is_bot: bool) -> bool {
        if !authority.is_subdomain_of(&self.caffeine_domain) {
            return false;
        }

        if authority
            .labels()
            .next()
            .is_some_and(|x| x.contains("-draft"))
        {
            return false;
        }

        if !is_bot {
            return false;
        }

        let path = uri.path();
        if is_static_asset(path) {
            return false;
        }

        true
    }

    /// Encodes the URI to be usable as a query parameter and attaches it to the render URI
    fn create_render_uri(&self, uri: Uri, authority: &Fqdn) -> Result<Uri, anyhow::Error> {
        // Inject authority into URI since it's missing in Axum
        let mut parts = uri.into_parts();
        let authority = Authority::from_str(&authority.to_string())?;
        parts.authority = Some(authority);
        let uri = Uri::from_parts(parts)?;

        let encoded_uri = urlencoding::encode(&uri.to_string()).to_string();
        let render_uri = Uri::from_str(&format!("{}?url={encoded_uri}", self.caffeine_renderer))?;

        Ok(render_uri)
    }
}

pub async fn middleware(
    State(state): State<Arc<RedirectorState>>,
    Extension(ctx): Extension<Arc<RequestCtx>>,
    Extension(is_bot): Extension<IsBot>,
    OriginalUri(uri): OriginalUri,
    request: Request,
    next: Next,
) -> Result<Response, ErrorCause> {
    if !state.should_render(&ctx.authority, &uri, is_bot.0) {
        return Ok(next.run(request).await);
    }

    // Prepare the request to send to the renderer
    let mut proxy_request = Request::new(Body::empty());
    let encoded_uri = state
        .create_render_uri(uri, &ctx.authority)
        .map_err(|e| ErrorCause::Client(ClientError::MalformedRequest(e.to_string())))?;

    Ok(next.run(request).await)
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use crate::test::TestClient;
    use fqdn::fqdn;

    use super::*;

    #[test]
    fn test_is_static_asset() {
        for path in [
            "/foo/img.png",
            "/foo/img.gif",
            "/bar/img.png?a=b",
            "/foo/img.woff2?a=b&c=d#foo",
        ] {
            assert!(is_static_asset(Uri::from_str(path).unwrap().path()));
        }

        for path in [
            "/script.php",
            "/bar/foo.dat",
            "/foo/x.foo",
            "/foo/bar.faz2?a=b&c=d#foo",
        ] {
            assert!(!is_static_asset(Uri::from_str(path).unwrap().path()));
        }
    }

    #[test]
    fn test_should_render() {
        let state = RedirectorState::new(
            fqdn!("caffeine.xyz"),
            Uri::from_str("http://foo/bar").unwrap(),
            Arc::new(TestClient(1)),
        );

        // ok
        assert!(state.should_render(
            &fqdn!("foo.caffeine.xyz"),
            &Uri::from_static("http://foo/script.php"),
            true
        ));

        // wrong domain
        assert!(!state.should_render(
            &fqdn!("foo.caffeine.foo"),
            &Uri::from_static("http://foo/script.php"),
            true
        ));

        // static asset
        assert!(!state.should_render(
            &fqdn!("foo.caffeine.xyz"),
            &Uri::from_static("http://foo/logo.png"),
            true
        ));

        // not bot
        assert!(!state.should_render(
            &fqdn!("foo.caffeine.xyz"),
            &Uri::from_static("http://foo/script.php"),
            false
        ));

        // draft
        assert!(!state.should_render(
            &fqdn!("foo-draft.caffeine.xyz"),
            &Uri::from_static("http://foo/script.php"),
            true
        ));

        assert!(!state.should_render(
            &fqdn!("foo-draft-foo.caffeine.xyz"),
            &Uri::from_static("http://foo/script.php"),
            true
        ));
    }

    #[test]
    fn test_create_render_uri() {
        let state = RedirectorState::new(
            fqdn!("caffeine.xyz"),
            Uri::from_str("https://prerenderer.caffeine.tech/render").unwrap(),
            Arc::new(TestClient(1)),
        );

        // ok
        assert_eq!(
            state
                .create_render_uri(
                    Uri::from_static("https://foo/bar/baz?q=1"),
                    &fqdn!("foo.caffeine.xyz")
                )
                .unwrap(),
            "https://prerenderer.caffeine.tech/render?url=https%3A%2F%2Ffoo.caffeine.xyz%2Fbar%2Fbaz%3Fq%3D1"
        );

        // bad authority
        assert_eq!(
            state
                .create_render_uri(
                    Uri::from_static("://foo/bar/baz?q=1"),
                    &fqdn!("foo.caffeine.xyz")
                )
                .unwrap(),
            "https://prerenderer.caffeine.tech/render?url=https%3A%2F%2Ffoo.caffeine.xyz%2Fbar%2Fbaz%3Fq%3D1"
        );
    }
}
