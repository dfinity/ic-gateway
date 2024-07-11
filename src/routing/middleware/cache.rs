use std::sync::Arc;

use anyhow::Error;
use axum::{
    body::{to_bytes, Body},
    extract::{Request, State},
    middleware::Next,
    response::{IntoResponse, Response},
};
use bytes::Bytes;
use http::{header::CONTENT_LENGTH, Method};
use tokio::{
    select,
    time::{sleep, Instant},
};

use crate::{
    cache::{extract_key, Cache, CacheBypassReason, CacheKey, CacheStatus},
    routing::error_cause::ErrorCause,
};

pub async fn middleware(
    State(cache): State<Arc<Cache>>,
    request: Request,
    next: Next,
) -> Result<impl IntoResponse, ErrorCause> {
    // Check if request should bypass cache lookup.
    if request.method() != Method::GET {
        return Ok(CacheStatus::Bypass(CacheBypassReason::MethodNotCacheable)
            .with_response(next.run(request).await));
    }

    // Use cached response if found.
    let cache_key = extract_key(&request);
    if let Some(v) = cache.get(&cache_key) {
        return Ok(CacheStatus::Hit.with_response(v));
    }

    // Get synchronization lock to handle parallel requests.
    let lock = cache.get_lock(&cache_key);

    // Record the time spent waiting for the lock.
    let start = Instant::now();

    select! {
        // Only one parallel request should execute the response and populate the cache.
        // Other requests will wait for the lock to be released and get results from the cache.
        _ = lock.lock() => {}
        // We proceed with the request as is if takes too long to get the lock.
        _ = sleep(cache.lock_timeout) => {}
    }

    // Record prometheus metrics for the time spent waiting for the lock.
    cache.metrics().observe(start.elapsed());

    // Check again the cache in case some other request filled it
    // while we were waiting for the lock
    if let Some(v) = cache.get(&cache_key) {
        return Ok(CacheStatus::Hit.with_response(v));
    }

    // Otherwise execute the request
    execute_request(request, next, cache, cache_key).await
}

async fn execute_request(
    request: Request,
    next: Next,
    cache: Arc<Cache>,
    cache_key: CacheKey,
) -> Result<Response, ErrorCause> {
    let now = Instant::now();
    // Execute the response & get the headers
    let response = next.run(request).await;

    // Do not cache non-2xx responses
    if !response.status().is_success() {
        return Ok(CacheStatus::Bypass(CacheBypassReason::HTTPError).with_response(response));
    }

    // Extract content length from the response header if there's one
    let content_length = extract_content_length(&response)
        .map_err(|_| ErrorCause::Other("Malformed Content-Length header in response".into()))?;

    // Do not cache responses that have no known size (probably streaming etc)
    let Some(body_size) = content_length else {
        return Ok(CacheStatus::Bypass(CacheBypassReason::SizeUnknown).with_response(response));
    };

    // Do not cache items larger than configured
    if body_size > cache.max_item_size {
        return Ok(CacheStatus::Bypass(CacheBypassReason::BodyTooBig).with_response(response));
    }

    // Read the response body into a buffer
    let response = read_response(response, body_size).await?;
    let delta = now.elapsed();
    cache.insert(cache_key, delta, response.clone());

    let (parts, body) = response.into_parts();
    let response = Response::from_parts(parts, Body::from(body));

    Ok(CacheStatus::Miss.with_response(response))
}

/// Try to get & parse content-length header
fn extract_content_length(resp: &Response) -> Result<Option<usize>, Error> {
    match resp.headers().get(CONTENT_LENGTH) {
        Some(v) => Ok(Some(v.to_str()?.parse::<usize>()?)),
        None => Ok(None),
    }
}

/// Read the full response into memory while applying a limit on the length
async fn read_response(response: Response, length: usize) -> Result<Response<Bytes>, ErrorCause> {
    let (parts, body) = response.into_parts();
    let body = to_bytes(body, length)
        .await
        .map_err(|x| ErrorCause::UnableToReadBody(x.to_string()))?;
    Ok(Response::from_parts(parts, body))
}

#[cfg(test)]
mod tests {
    use std::{sync::Arc, time::Duration};

    use axum::{
        body::{to_bytes, Body},
        extract::Request,
        middleware,
        response::{IntoResponse, Response},
        routing::{get, post},
        Router,
    };
    use http::{
        header::{CONTENT_LENGTH, RANGE},
        HeaderValue, StatusCode,
    };
    use prometheus::Registry;
    use tokio::time::sleep;
    use tower::{Service, ServiceExt};

    use crate::routing::{
        error_cause::ErrorCause,
        middleware::cache::{self, Cache, CacheBypassReason, CacheStatus},
    };

    const MAX_ITEM_SIZE: usize = 1024;
    const MAX_CACHE_SIZE: u64 = 32768;
    const PROXY_LOCK_TIMEOUT: Duration = Duration::from_secs(1);

    async fn dispatch_get_request(router: &mut Router, uri: String) -> Option<CacheStatus> {
        let req = Request::get(uri).body(Body::from("")).unwrap();
        let result = router.call(req).await.unwrap();
        assert_eq!(result.status(), StatusCode::OK);
        result.extensions().get::<CacheStatus>().cloned()
    }

    async fn handler_bypassing_cache(
        _request: Request<Body>,
    ) -> Result<impl IntoResponse, ErrorCause> {
        // Without content-length header, caching middleware should issue CacheStatus::Bypass
        Ok("test_call".into_response())
    }

    async fn handler_cache_hit(_request: Request<Body>) -> Result<impl IntoResponse, ErrorCause> {
        let mut response = Response::new(Body::from(b"test_body".to_vec()));
        response
            .headers_mut()
            .insert(CONTENT_LENGTH, HeaderValue::from_str("10").unwrap());
        Ok(response)
    }

    async fn handler_proxy_cache_lock(
        request: Request<Body>,
    ) -> Result<impl IntoResponse, ErrorCause> {
        if request.uri().path().contains("slow_response") {
            sleep(2 * PROXY_LOCK_TIMEOUT).await;
        }
        let mut response = Response::new(Body::from(b"test_body".to_vec()));
        response
            .headers_mut()
            .insert(CONTENT_LENGTH, HeaderValue::from_str("10").unwrap());
        Ok(response)
    }

    async fn handler_malformed_content_length_header(
        _request: Request<Body>,
    ) -> Result<impl IntoResponse, ErrorCause> {
        let mut response = Response::new(Body::from(b"foo".to_vec()));
        response
            .headers_mut()
            .insert(CONTENT_LENGTH, HeaderValue::from_str("not an int").unwrap());
        Ok(response)
    }

    async fn handler_content_length_header_too_big(
        _request: Request<Body>,
    ) -> Result<impl IntoResponse, ErrorCause> {
        let mut response = Response::new(Body::from(b"foo".to_vec()));
        let body_size = MAX_ITEM_SIZE + 1;
        response.headers_mut().insert(
            CONTENT_LENGTH,
            HeaderValue::from_str(body_size.to_string().as_str()).unwrap(),
        );
        Ok(response)
    }

    #[test]
    fn test_cache_creation_errors() {
        let cache = Cache::new(
            1024,
            1024,
            Duration::from_secs(60),
            0.0,
            PROXY_LOCK_TIMEOUT,
            &Registry::default(),
        );
        assert!(cache.is_err());
    }

    #[tokio::test]
    async fn test_cache_bypass() {
        let cache = Cache::new(
            MAX_CACHE_SIZE,
            MAX_ITEM_SIZE,
            Duration::from_secs(3600),
            0.0,
            PROXY_LOCK_TIMEOUT,
            &Registry::default(),
        )
        .unwrap();

        let cache = Arc::new(cache);
        let mut app = Router::new()
            .route("/", post(handler_bypassing_cache))
            .route("/", get(handler_bypassing_cache))
            .route(
                "/malformed_content_length_header",
                get(handler_malformed_content_length_header),
            )
            .route(
                "/content_length_header_too_big",
                get(handler_content_length_header_too_big),
            )
            .layer(middleware::from_fn_with_state(
                Arc::clone(&cache),
                cache::middleware,
            ));

        // Test only GET requests are cached.
        let req = Request::post("http://foobar/")
            .body(Body::from(""))
            .unwrap();

        let result = app.call(req).await.unwrap();

        assert_eq!(result.status(), StatusCode::OK);
        let cache_status = result.extensions().get::<CacheStatus>().cloned().unwrap();
        assert_eq!(cache.len(), 0);
        assert_eq!(
            cache_status,
            CacheStatus::Bypass(cache::CacheBypassReason::MethodNotCacheable)
        );

        // Test non-2xx response are not cached
        let req = Request::get("http://foobar/non_existing_path")
            .body(Body::from("foobar"))
            .unwrap();
        let result = app.call(req).await.unwrap();
        let cache_status = result.extensions().get::<CacheStatus>().cloned().unwrap();
        assert_eq!(result.status(), StatusCode::NOT_FOUND);
        assert_eq!(
            cache_status,
            CacheStatus::Bypass(CacheBypassReason::HTTPError)
        );
        assert_eq!(cache.len(), 0);

        // Test malformed Content-Length
        let req = Request::get("http://foobar/malformed_content_length_header")
            .body(Body::from("foobar"))
            .unwrap();
        let result = app.call(req).await.unwrap();
        assert!(result.extensions().get::<CacheStatus>().is_none());
        assert_eq!(result.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(cache.len(), 0);

        // Test Content-Length too big
        let req = Request::get("http://foobar/content_length_header_too_big")
            .body(Body::from("foobar"))
            .unwrap();
        let result = app.call(req).await.unwrap();
        let cache_status = result.extensions().get::<CacheStatus>().cloned().unwrap();
        assert_eq!(
            cache_status,
            CacheStatus::Bypass(CacheBypassReason::BodyTooBig)
        );
        assert_eq!(result.status(), StatusCode::OK);
        assert_eq!(cache.len(), 0);
    }

    #[tokio::test]
    async fn test_cache_hit() {
        let cache_ttl = Duration::from_millis(500);

        let cache = Cache::new(
            MAX_CACHE_SIZE,
            MAX_ITEM_SIZE,
            cache_ttl,
            0.0,
            PROXY_LOCK_TIMEOUT,
            &Registry::default(),
        )
        .unwrap();

        let cache = Arc::new(cache);
        let mut app = Router::new().route("/:key", get(handler_cache_hit)).layer(
            middleware::from_fn_with_state(Arc::clone(&cache), cache::middleware),
        );

        // First request doesn't hit the cache, but is stored in the cache
        let mut req = Request::get("http://foobar/1")
            .body(Body::from(""))
            .unwrap();
        req.headers_mut()
            .append(RANGE, HeaderValue::from_static("some range"));
        let result = app.call(req).await.unwrap();
        let cache_status = result.extensions().get::<CacheStatus>().cloned().unwrap();
        assert_eq!(result.status(), StatusCode::OK);
        assert_eq!(cache_status, CacheStatus::Miss);
        cache.housekeep();
        assert_eq!(cache.len(), 1);

        // Second request with a different Range header doesn't hit the cache, but is stored in the cache
        let mut req = Request::get("http://foobar/1")
            .body(Body::from(""))
            .unwrap();
        req.headers_mut()
            .append(RANGE, HeaderValue::from_static("some other range"));
        let result = app.call(req).await.unwrap();
        let cache_status = result.extensions().get::<CacheStatus>().cloned().unwrap();
        assert_eq!(result.status(), StatusCode::OK);
        assert_eq!(cache_status, CacheStatus::Miss);
        cache.housekeep();
        assert_eq!(cache.len(), 2);

        // Third request with an absent Range header also doesn't hit the cache, but is stored in the cache
        let req = Request::get("http://foobar/1")
            .body(Body::from(""))
            .unwrap();
        let result = app.call(req).await.unwrap();
        let cache_status = result.extensions().get::<CacheStatus>().cloned().unwrap();
        assert_eq!(result.status(), StatusCode::OK);
        assert_eq!(cache_status, CacheStatus::Miss);
        cache.housekeep();
        assert_eq!(cache.len(), 3);

        // Fourth request with the RANGE header identical to the first request finally hits the cache
        let mut req = Request::get("http://foobar/1")
            .body(Body::from(""))
            .unwrap();
        req.headers_mut()
            .append(RANGE, HeaderValue::from_static("some range"));
        let result = app.call(req).await.unwrap();
        let cache_status = result.extensions().get::<CacheStatus>().cloned().unwrap();
        assert_eq!(result.status(), StatusCode::OK);
        assert_eq!(cache_status, CacheStatus::Hit);
        let (_, body) = result.into_parts();
        let body = to_bytes(body, usize::MAX).await.unwrap().to_vec();
        let body = String::from_utf8_lossy(&body);
        assert_eq!("test_body", body);
        cache.housekeep();
        assert_eq!(cache.len(), 3);

        // Fifth request with an absent RANGE header (identical to the third request) also hits the cache
        let mut req = Request::get("http://foobar/1")
            .body(Body::from(""))
            .unwrap();
        req.headers_mut()
            .append(RANGE, HeaderValue::from_static("some range"));
        let result = app.call(req).await.unwrap();
        let cache_status = result.extensions().get::<CacheStatus>().cloned().unwrap();
        assert_eq!(result.status(), StatusCode::OK);
        assert_eq!(cache_status, CacheStatus::Hit);
        cache.housekeep();
        assert_eq!(cache.len(), 3);

        // After ttl, request doesn't hit the cache anymore
        sleep(cache_ttl + Duration::from_millis(100)).await;
        let mut req = Request::get("http://foobar/1")
            .body(Body::from(""))
            .unwrap();
        req.headers_mut()
            .append(RANGE, HeaderValue::from_static("some range"));
        let result = app.call(req).await.unwrap();
        let cache_status = result.extensions().get::<CacheStatus>().cloned().unwrap();
        assert_eq!(result.status(), StatusCode::OK);
        assert_eq!(cache_status, CacheStatus::Miss);

        // Before cache_size limit is reached all requests should be stored in cache.
        cache.clear();
        let req_count = 50;
        // First dispatch round, all requests miss cache.
        for idx in 0..req_count {
            let status = dispatch_get_request(&mut app, format!("http://foobar/{idx}")).await;
            assert_eq!(status.unwrap(), CacheStatus::Miss);
        }
        // Second dispatch round, all requests hit the cache.
        for idx in 0..req_count {
            let status = dispatch_get_request(&mut app, format!("http://foobar/{idx}")).await;
            assert_eq!(status.unwrap(), CacheStatus::Hit);
        }

        // Once cache_size limit is reached some requests should be evicted.
        cache.clear();
        let req_count = 800;
        // First dispatch round, all cache misses.
        for idx in 0..req_count {
            let status = dispatch_get_request(&mut app, format!("http://foobar/{idx}")).await;
            assert_eq!(status.unwrap(), CacheStatus::Miss);
        }
        // Second dispatch round, some requests hit the cache, some don't
        let mut count_misses = 0;
        let mut count_hits = 0;
        for idx in 0..req_count {
            let status = dispatch_get_request(&mut app, format!("http://foobar/{idx}")).await;
            if let Some(CacheStatus::Miss) = status {
                count_misses += 1;
            } else if let Some(CacheStatus::Hit) = status {
                count_hits += 1;
            }
        }
        assert!(count_misses > 0);
        assert!(count_hits > 0);
        cache.housekeep();
        let entry_size = cache.size() / cache.len();
        // Make sure cache size limit was reached.
        // Check that adding one more entry to the cache would overflow its max capacity.
        assert!(MAX_CACHE_SIZE > cache.size());
        assert!(MAX_CACHE_SIZE < cache.size() + entry_size);
    }

    #[tokio::test]
    async fn test_proxy_cache_lock() {
        let cache_ttl = Duration::from_millis(500);
        let cache = Cache::new(
            MAX_CACHE_SIZE,
            MAX_ITEM_SIZE,
            cache_ttl,
            0.0,
            PROXY_LOCK_TIMEOUT,
            &Registry::default(),
        )
        .unwrap();

        let cache = Arc::new(cache);
        let app = Router::new()
            .route("/:key", get(handler_proxy_cache_lock))
            .layer(middleware::from_fn_with_state(
                Arc::clone(&cache),
                cache::middleware,
            ));

        let req_count = 50;
        // Expected cache misses/hits for fast/slow responses, respectively.
        let expected_misses = [1, req_count];
        let expected_hits = [req_count - 1, 0];
        for (idx, uri) in ["http://foobar/fast_response", "http://foobar/slow_response"]
            .iter()
            .enumerate()
        {
            let mut tasks = vec![];
            // Dispatch requests simultaneously.
            for _ in 0..req_count {
                let app = app.clone();
                tasks.push(tokio::spawn(async move {
                    let req = Request::get(*uri).body(Body::from("")).unwrap();
                    let result = app.oneshot(req).await.unwrap();
                    assert_eq!(result.status(), StatusCode::OK);
                    result.extensions().get::<CacheStatus>().cloned()
                }));
            }
            let mut count_hits = 0;
            let mut count_misses = 0;
            for task in tasks {
                task.await
                    .map(|res| match res {
                        Some(CacheStatus::Hit) => count_hits += 1,
                        Some(CacheStatus::Miss) => count_misses += 1,
                        _ => panic!("Unexpected cache status"),
                    })
                    .expect("failed to complete task");
            }
            assert_eq!(count_hits, expected_hits[idx]);
            assert_eq!(count_misses, expected_misses[idx]);
            cache.housekeep();
            cache.clear();
        }
    }
}
