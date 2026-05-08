use std::{str::FromStr, sync::Arc, time::Duration};

use axum::{
    Extension,
    extract::{OriginalUri, Request, State},
    middleware::Next,
    response::Response,
};
use bytes::Bytes;
use derive_new::new;
use fqdn::{FQDN, Fqdn};
use http::{
    HeaderName, HeaderValue, Method, Uri,
    header::{CONNECTION, CONTENT_ENCODING, TRANSFER_ENCODING, USER_AGENT},
    uri::Authority,
};
use http_body_util::Full;
use ic_bn_lib::{hname, hval};
use ic_bn_lib_common::traits::http::ClientHttp;
use tokio::time::timeout;

use crate::routing::{
    RequestCtx,
    error_cause::{ClientError, ErrorCause},
    middleware::is_bot::IsBot,
};

const HEADER_SECRET: HeaderName = hname!("x-worker-secret");
const HEADER_X_PRE_RENDERED: HeaderName = hname!("x-pre-rendered");

const HEADERS_TO_REMOVE: [HeaderName; 4] = [
    CONTENT_ENCODING,
    TRANSFER_ENCODING,
    CONNECTION,
    hname!("keep-alive"),
];

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
pub struct PrerenderState {
    domains: Vec<FQDN>,
    url: Uri,
    secret: HeaderValue,
    timeout: Duration,
    client: Arc<dyn ClientHttp<Full<Bytes>>>,
}

impl PrerenderState {
    /// Whether we should prerender this request or pass it through
    fn should_render(&self, authority: &Fqdn, uri: &Uri, method: &Method, is_bot: bool) -> bool {
        if method != Method::GET {
            return false;
        }

        if !self.domains.iter().any(|x| authority.is_subdomain_of(x)) {
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

        if is_static_asset(uri.path()) {
            return false;
        }

        true
    }

    /// Encodes the URI to be usable as a query parameter and attaches it to the render URI
    fn create_renderer_uri(
        &self,
        original_uri: Uri,
        authority: &Fqdn,
    ) -> Result<Uri, anyhow::Error> {
        // Inject authority into URI since it's missing in Axum
        let mut parts = original_uri.into_parts();
        let authority = Authority::from_maybe_shared(Bytes::from(authority.to_string()))?;
        parts.authority = Some(authority);
        let original_uri = Uri::from_parts(parts)?.to_string();

        let original_uri_encoded = urlencoding::encode(&original_uri);
        let renderer_uri = Uri::from_str(&format!("{}?url={original_uri_encoded}", self.url))?;

        Ok(renderer_uri)
    }

    /// Executes the render request with fallbacks
    async fn render_request(
        &self,
        render_request: Request<Full<Bytes>>,
        request: Request,
        next: Next,
    ) -> Response {
        let render_result = timeout(self.timeout, self.client.execute(render_request)).await;
        match render_result {
            Ok(Ok(mut v)) => {
                // If the request succeeded - check return code
                if !v.status().is_success() {
                    // Otherwise pass the request as usual
                    return next.run(request).await;
                }

                // Remove certain headers from the response
                HEADERS_TO_REMOVE.iter().for_each(|x| {
                    v.headers_mut().remove(x);
                });

                // Add marker to show that it was pre-rendered
                v.headers_mut().insert(HEADER_X_PRE_RENDERED, hval!("1"));

                v
            }

            // If we timed out or the request failed - forward as usual
            Err(_) | Ok(Err(_)) => next.run(request).await,
        }
    }
}

pub async fn middleware(
    State(state): State<Arc<PrerenderState>>,
    Extension(ctx): Extension<Arc<RequestCtx>>,
    Extension(is_bot): Extension<IsBot>,
    OriginalUri(uri): OriginalUri,
    request: Request,
    next: Next,
) -> Result<Response, ErrorCause> {
    if !state.should_render(&ctx.authority, &uri, request.method(), is_bot.0) {
        return Ok(next.run(request).await);
    }

    // Prepare the request to send to the renderer
    let mut render_request = Request::new(Full::new(Bytes::new()));
    let renderer_uri = state
        .create_renderer_uri(uri, &ctx.authority)
        .map_err(|e| ErrorCause::Client(ClientError::MalformedRequest(e.to_string())))?;
    *render_request.uri_mut() = renderer_uri;
    *render_request.method_mut() = Method::GET;
    render_request
        .headers_mut()
        .insert(HEADER_SECRET, state.secret.clone());
    if let Some(v) = request.headers().get(USER_AGENT) {
        render_request.headers_mut().insert(USER_AGENT, v.clone());
    }

    // Execute the render request
    Ok(state.render_request(render_request, request, next).await)
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use crate::test::TestClient;
    use fqdn::fqdn;
    use ic_bn_lib::hval;

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
        let state = PrerenderState::new(
            vec![fqdn!("caffeine.xyz"), fqdn!("caffeine.abc")],
            Uri::from_str("http://foo/bar").unwrap(),
            hval!(""),
            Duration::ZERO,
            Arc::new(TestClient(1)),
        );

        // ok
        assert!(state.should_render(
            &fqdn!("foo.caffeine.xyz"),
            &Uri::from_static("http://foo/script.php"),
            &Method::GET,
            true
        ));
        assert!(state.should_render(
            &fqdn!("bar.caffeine.abc"),
            &Uri::from_static("http://foo/script.php"),
            &Method::GET,
            true
        ));

        // wrong domain
        assert!(!state.should_render(
            &fqdn!("foo.caffeine.foo"),
            &Uri::from_static("http://foo/script.php"),
            &Method::GET,
            true
        ));

        // static asset
        assert!(!state.should_render(
            &fqdn!("foo.caffeine.xyz"),
            &Uri::from_static("http://foo/logo.png"),
            &Method::GET,
            true
        ));

        // not bot
        assert!(!state.should_render(
            &fqdn!("foo.caffeine.xyz"),
            &Uri::from_static("http://foo/script.php"),
            &Method::GET,
            false
        ));

        // wrong method
        assert!(!state.should_render(
            &fqdn!("foo.caffeine.xyz"),
            &Uri::from_static("http://foo/script.php"),
            &Method::POST,
            false
        ));

        // draft
        assert!(!state.should_render(
            &fqdn!("foo-draft.caffeine.xyz"),
            &Uri::from_static("http://foo/script.php"),
            &Method::GET,
            true
        ));

        assert!(!state.should_render(
            &fqdn!("foo-draft-foo.caffeine.xyz"),
            &Uri::from_static("http://foo/script.php"),
            &Method::GET,
            true
        ));
    }

    #[test]
    fn test_create_render_uri() {
        let state = PrerenderState::new(
            vec![fqdn!("caffeine.xyz")],
            Uri::from_str("https://prerenderer.caffeine.tech/render").unwrap(),
            hval!(""),
            Duration::ZERO,
            Arc::new(TestClient(1)),
        );

        // ok
        assert_eq!(
            state
                .create_renderer_uri(
                    Uri::from_static("https://foo/bar/baz?q=1"),
                    &fqdn!("foo.caffeine.xyz")
                )
                .unwrap(),
            "https://prerenderer.caffeine.tech/render?url=https%3A%2F%2Ffoo.caffeine.xyz%2Fbar%2Fbaz%3Fq%3D1"
        );

        assert_eq!(
            state
                .create_renderer_uri(
                    Uri::from_static("http://foo/bar/baz?q=1"),
                    &fqdn!("foo.caffeine.abc")
                )
                .unwrap(),
            "https://prerenderer.caffeine.tech/render?url=http%3A%2F%2Ffoo.caffeine.abc%2Fbar%2Fbaz%3Fq%3D1"
        );
    }
}
