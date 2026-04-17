use std::{cmp::min, ops::Range, sync::Arc, time::Duration};

use axum::{
    body::Body,
    extract::{Query, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
    Json,
};
use axum_extra::extract::Host;
use candid::Principal;
use ic_bn_lib::{hval, http::body::buffer_body};
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::{
    cashier::connector::BillingError,
    s3::bucket::BucketLike,
    storage::{
        self,
        auth::AuthError,
        types::{
            BlobMetadata, MAX_REQUEST_BODY_SIZE, ONE_MIB,
            PutBlobTreeRequest, PutBlobTreeResponse, PutChunkResponse,
        },
    },
};

use super::StorageState;

const BODY_READ_TIMEOUT: Duration = Duration::from_secs(60);

// ---------------------------------------------------------------------------
// Header constants
// ---------------------------------------------------------------------------

const CORS_ORIGIN: header::HeaderValue = hval!("*");
const CORS_METHODS: header::HeaderValue = hval!("GET, PUT, HEAD, DELETE, OPTIONS");
const CORS_HEADERS_VAL: header::HeaderValue = hval!("Content-Type");
const CONTENT_TYPE_OCTET: header::HeaderValue = hval!("application/octet-stream");
const CONTENT_TYPE_JSON: header::HeaderValue = hval!("application/json");
const CONTENT_TYPE_TEXT: header::HeaderValue = hval!("text/plain");
const ACCEPT_RANGES_BYTES: header::HeaderValue = hval!("bytes");

fn cors_headers(headers: &mut HeaderMap) {
    headers.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, CORS_ORIGIN);
    headers.insert(header::ACCESS_CONTROL_ALLOW_METHODS, CORS_METHODS);
    headers.insert(header::ACCESS_CONTROL_ALLOW_HEADERS, CORS_HEADERS_VAL);
}

// ---------------------------------------------------------------------------
// Query param structs
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct BlobQuery {
    pub owner_id: String,
    pub blob_hash: String,
}

#[derive(Deserialize)]
pub struct ChunkGetQuery {
    pub owner_id: String,
    #[allow(dead_code)]
    pub root_hash: String,
    pub chunk_hash: String,
}

#[derive(Deserialize)]
pub struct ChunkPutQuery {
    pub owner_id: String,
    pub blob_hash: String,
    pub chunk_index: usize,
}

#[derive(Deserialize)]
pub struct OwnerQuery {
    pub owner_id: String,
}

// ---------------------------------------------------------------------------
// Error helpers
// ---------------------------------------------------------------------------

fn billing_error_response(e: &BillingError) -> Response {
    match e {
        BillingError::OwnerNotFound | BillingError::InsufficientBalance => {
            (StatusCode::FORBIDDEN, e.to_string()).into_response()
        }
        BillingError::CashierUnavailable(_) => {
            (StatusCode::BAD_GATEWAY, e.to_string()).into_response()
        }
    }
}

fn auth_error_response(e: &AuthError) -> Response {
    match e {
        AuthError::MissingAuth(m) => {
            let mut headers = HeaderMap::new();
            headers.insert(
                header::WWW_AUTHENTICATE,
                hval!("X-ICP-Canister-Signature"),
            );
            (StatusCode::UNAUTHORIZED, headers, m.to_string()).into_response()
        }
        AuthError::Forbidden(m) => (StatusCode::FORBIDDEN, m.to_string()).into_response(),
    }
}

fn parse_principal(s: &str) -> Result<Principal, Response> {
    Principal::from_text(s).map_err(|e| {
        (StatusCode::BAD_REQUEST, format!("invalid owner_id: {e}")).into_response()
    })
}

async fn load_blob_metadata(
    bucket: &Arc<dyn BucketLike>,
    owner: &Principal,
    blob_hash: &str,
) -> Result<BlobMetadata, Response> {
    let path = storage::paths::blob_path(owner, blob_hash);
    let data = bucket
        .get_object(path)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response())?
        .ok_or_else(|| (StatusCode::NOT_FOUND, "blob not found").into_response())?;

    serde_json::from_slice::<BlobMetadata>(&data).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("corrupt blob metadata: {e}"),
        )
            .into_response()
    })
}

// ---------------------------------------------------------------------------
// Range parsing (RFC 7233 single-range only)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
enum ByteRange {
    Inclusive(u64, u64),
    From(u64),
    Last(u64),
}

impl ByteRange {
    fn resolve(&self, total: u64) -> Result<Range<u64>, Response> {
        let range = match self {
            Self::Inclusive(s, e) => {
                if *s <= *e && *e < total {
                    *s..*e + 1
                } else {
                    return Err(range_not_satisfiable(total));
                }
            }
            Self::From(s) => {
                if *s < total {
                    *s..total
                } else {
                    return Err(range_not_satisfiable(total));
                }
            }
            Self::Last(n) => {
                if *n <= total {
                    (total - *n)..total
                } else {
                    return Err(range_not_satisfiable(total));
                }
            }
        };
        Ok(range)
    }
}

fn range_not_satisfiable(total: u64) -> Response {
    let mut headers = HeaderMap::new();
    cors_headers(&mut headers);
    (
        StatusCode::RANGE_NOT_SATISFIABLE,
        headers,
        format!("range not satisfiable; available length: {total}"),
    )
        .into_response()
}

fn parse_range_header(headers: &HeaderMap) -> Result<Option<ByteRange>, Response> {
    let Some(value) = headers.get(header::RANGE) else {
        return Ok(None);
    };
    let s = value.to_str().map_err(|_| {
        (StatusCode::BAD_REQUEST, "invalid Range header encoding").into_response()
    })?;

    let rest = s.strip_prefix("bytes=").ok_or_else(|| {
        (StatusCode::BAD_REQUEST, "only bytes ranges are supported").into_response()
    })?;

    let specs: Vec<&str> = rest.split(',').collect();
    if specs.len() != 1 {
        return Err(
            (StatusCode::BAD_REQUEST, "only single-range requests are supported").into_response(),
        );
    }

    let spec = specs[0].trim();
    let (start_s, end_s) = spec.split_once('-').ok_or_else(|| {
        (StatusCode::BAD_REQUEST, "malformed range spec").into_response()
    })?;

    let parse = |s: &str| -> Result<Option<u64>, Response> {
        let t = s.trim();
        if t.is_empty() {
            Ok(None)
        } else {
            t.parse::<u64>().map(Some).map_err(|_| {
                (StatusCode::BAD_REQUEST, "non-numeric range value").into_response()
            })
        }
    };

    let start = parse(start_s)?;
    let end = parse(end_s)?;

    match (start, end) {
        (None, None) => Err((StatusCode::BAD_REQUEST, "empty range").into_response()),
        (None, Some(n)) => Ok(Some(ByteRange::Last(n))),
        (Some(s), None) => Ok(Some(ByteRange::From(s))),
        (Some(s), Some(e)) => {
            if s <= e {
                Ok(Some(ByteRange::Inclusive(s, e)))
            } else {
                Err((StatusCode::BAD_REQUEST, "range start > end").into_response())
            }
        }
    }
}

/// Map a byte range to (chunk_index_range, start_offset_in_first_chunk, end_offset_in_last_chunk).
fn range_to_chunk_ranges(range: &Range<u64>) -> (Range<usize>, usize, usize) {
    let cs = ONE_MIB as u64;
    let start_chunk = (range.start / cs) as usize;
    let end_chunk = range.end.div_ceil(cs) as usize;
    let start_offset = (range.start % cs) as usize;
    let end_offset = if range.end == 0 {
        0
    } else {
        ((range.end.saturating_sub(1) % cs) + 1) as usize
    };
    (start_chunk..end_chunk, start_offset, end_offset)
}

// ---------------------------------------------------------------------------
// DELETE /owner host gate
// ---------------------------------------------------------------------------

fn check_delete_owner_host(
    host: Option<&str>,
    allowed_env: Option<&str>,
) -> Result<(), Response> {
    let Some(allowed_list) = allowed_env else {
        return Ok(());
    };

    let host = host.ok_or_else(|| {
        (StatusCode::FORBIDDEN, "missing Host header for owner deletion").into_response()
    })?;

    let normalize = |h: &str| {
        h.split_once(':')
            .map(|(h, _)| h.to_lowercase())
            .unwrap_or_else(|| h.to_lowercase())
    };

    let normalized = normalize(host);
    let allowed: Vec<&str> = allowed_list.split(',').map(|s| s.trim()).filter(|s| !s.is_empty()).collect();

    if allowed.iter().any(|a| *a == host || *a == normalized) {
        Ok(())
    } else {
        Err((
            StatusCode::FORBIDDEN,
            format!("host '{host}' is not allowed for owner deletion"),
        )
            .into_response())
    }
}

// ---------------------------------------------------------------------------
// HEAD /v1/blob?owner_id=...&blob_hash=...
// ---------------------------------------------------------------------------

pub async fn head_blob(
    State(state): State<StorageState>,
    Query(q): Query<BlobQuery>,
) -> Result<Response, Response> {
    let owner = parse_principal(&q.owner_id)?;

    state
        .connector
        .charge_blob_tree_download(&owner)
        .await
        .map_err(|e| billing_error_response(&e))?;

    let meta = load_blob_metadata(&state.bucket, &owner, &q.blob_hash).await?;

    let mut headers = HeaderMap::new();
    cors_headers(&mut headers);
    headers.insert(header::CONTENT_LENGTH, meta.num_blob_bytes.into());
    headers.insert(header::ACCEPT_RANGES, ACCEPT_RANGES_BYTES);

    for pair in meta.headers.chunks(2) {
        if let [name, value] = pair {
            if let (Ok(hn), Ok(hv)) = (
                name.parse::<header::HeaderName>(),
                value.parse::<header::HeaderValue>(),
            ) {
                headers.insert(hn, hv);
            }
        }
    }

    Ok((StatusCode::OK, headers).into_response())
}

// ---------------------------------------------------------------------------
// GET /v1/blob?owner_id=...&blob_hash=...  (with Range support)
// ---------------------------------------------------------------------------

pub async fn get_blob(
    State(state): State<StorageState>,
    req_headers: HeaderMap,
    Query(q): Query<BlobQuery>,
) -> Result<Response, Response> {
    let owner = parse_principal(&q.owner_id)?;

    state
        .connector
        .charge_blob_tree_download(&owner)
        .await
        .map_err(|e| billing_error_response(&e))?;

    let meta = load_blob_metadata(&state.bucket, &owner, &q.blob_hash).await?;
    let chunk_hashes: Vec<String> = meta.hash_tree.chunk_hashes().to_vec();
    let total_bytes = meta.num_blob_bytes;

    let range_opt = parse_range_header(&req_headers)?;

    if let Some(byte_range) = range_opt {
        let range = byte_range.resolve(total_bytes)?;
        let content_length = range.end - range.start;
        let (chunk_range, start_offset, end_offset) = range_to_chunk_ranges(&range);

        let connector = state.connector.clone();
        let owner_c = owner;
        let bucket_c = state.bucket.clone();
        let hashes = chunk_hashes;

        let stream: async_stream::__private::AsyncStream<
            Result<bytes::Bytes, std::io::Error>,
            _,
        > = async_stream::try_stream! {
            for (i, chunk_idx) in (chunk_range.start..chunk_range.end).enumerate() {
                connector
                    .charge_chunk_download(&owner_c)
                    .await
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::PermissionDenied, e.to_string()))?;

                let hash = &hashes[chunk_idx];
                let path = storage::paths::chunk_path(&owner_c, hash);
                let data = bucket_c
                    .get_object(path)
                    .await
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?
                    .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "chunk not found"))?;

                let s = if i == 0 { start_offset } else { 0 };
                let e = if chunk_idx == chunk_range.end - 1 {
                    min(end_offset, data.len())
                } else {
                    data.len()
                };

                yield bytes::Bytes::copy_from_slice(&data[s..e]);
            }
        };

        let mut headers = HeaderMap::new();
        cors_headers(&mut headers);
        headers.insert(header::CONTENT_LENGTH, content_length.into());
        headers.insert(header::ACCEPT_RANGES, ACCEPT_RANGES_BYTES);
        headers.insert(header::CONTENT_TYPE, CONTENT_TYPE_OCTET);
        let cr = format!("bytes {}-{}/{total_bytes}", range.start, range.end - 1);
        headers.insert(
            header::CONTENT_RANGE,
            cr.parse().unwrap_or_else(|_| CONTENT_TYPE_TEXT),
        );

        for pair in meta.headers.chunks(2) {
            if let [name, value] = pair {
                if let (Ok(hn), Ok(hv)) = (
                    name.parse::<header::HeaderName>(),
                    value.parse::<header::HeaderValue>(),
                ) {
                    headers.insert(hn, hv);
                }
            }
        }

        Ok((StatusCode::PARTIAL_CONTENT, headers, Body::from_stream(stream)).into_response())
    } else {
        let connector = state.connector.clone();
        let owner_c = owner;
        let bucket_c = state.bucket.clone();

        let stream: async_stream::__private::AsyncStream<
            Result<bytes::Bytes, std::io::Error>,
            _,
        > = async_stream::try_stream! {
            for hash in &chunk_hashes {
                connector
                    .charge_chunk_download(&owner_c)
                    .await
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::PermissionDenied, e.to_string()))?;

                let path = storage::paths::chunk_path(&owner_c, hash);
                let data = bucket_c
                    .get_object(path)
                    .await
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?
                    .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "chunk not found"))?;

                yield bytes::Bytes::from(data);
            }
        };

        let mut headers = HeaderMap::new();
        cors_headers(&mut headers);
        headers.insert(header::CONTENT_LENGTH, total_bytes.into());
        headers.insert(header::ACCEPT_RANGES, ACCEPT_RANGES_BYTES);
        headers.insert(header::CONTENT_TYPE, CONTENT_TYPE_OCTET);

        for pair in meta.headers.chunks(2) {
            if let [name, value] = pair {
                if let (Ok(hn), Ok(hv)) = (
                    name.parse::<header::HeaderName>(),
                    value.parse::<header::HeaderValue>(),
                ) {
                    headers.insert(hn, hv);
                }
            }
        }

        Ok((StatusCode::OK, headers, Body::from_stream(stream)).into_response())
    }
}

// ---------------------------------------------------------------------------
// GET /v1/blob-tree?owner_id=...&blob_hash=...
// ---------------------------------------------------------------------------

pub async fn get_blob_tree(
    State(state): State<StorageState>,
    Query(q): Query<BlobQuery>,
) -> Result<Response, Response> {
    let owner = parse_principal(&q.owner_id)?;

    state
        .connector
        .charge_blob_tree_download(&owner)
        .await
        .map_err(|e| billing_error_response(&e))?;

    let path = storage::paths::blob_path(&owner, &q.blob_hash);
    let data = state.bucket
        .get_object(path)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response())?
        .ok_or_else(|| (StatusCode::NOT_FOUND, "blob not found").into_response())?;

    let mut headers = HeaderMap::new();
    cors_headers(&mut headers);
    headers.insert(header::CONTENT_TYPE, CONTENT_TYPE_JSON);

    Ok((StatusCode::OK, headers, data).into_response())
}

// ---------------------------------------------------------------------------
// GET /v1/chunk?owner_id=...&root_hash=...&chunk_hash=...
// ---------------------------------------------------------------------------

pub async fn get_chunk(
    State(state): State<StorageState>,
    Query(q): Query<ChunkGetQuery>,
) -> Result<Response, Response> {
    let owner = parse_principal(&q.owner_id)?;

    state
        .connector
        .charge_chunk_download(&owner)
        .await
        .map_err(|e| billing_error_response(&e))?;

    let path = storage::paths::chunk_path(&owner, &q.chunk_hash);
    let data = state.bucket
        .get_object(path)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response())?
        .ok_or_else(|| (StatusCode::NOT_FOUND, "chunk not found").into_response())?;

    let mut headers = HeaderMap::new();
    cors_headers(&mut headers);
    headers.insert(header::CONTENT_TYPE, CONTENT_TYPE_OCTET);

    Ok((StatusCode::OK, headers, data).into_response())
}

// ---------------------------------------------------------------------------
// PUT /v1/blob-tree  (JSON body, with auth)
// ---------------------------------------------------------------------------

pub async fn put_blob_tree(
    State(state): State<StorageState>,
    body: Body,
) -> Result<Response, Response> {
    let body_bytes = buffer_body(body, MAX_REQUEST_BODY_SIZE, BODY_READ_TIMEOUT)
        .await
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()).into_response())?;

    let request: PutBlobTreeRequest = serde_json::from_slice(&body_bytes)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("invalid JSON: {e}")).into_response())?;

    state
        .ingress_auth
        .check_put_blob(&request)
        .map_err(|e| auth_error_response(&e))?;

    let owner = request.owner;

    state
        .connector
        .charge_blob_tree_upload(&owner)
        .await
        .map_err(|e| billing_error_response(&e))?;

    let root_hash = request
        .blob_tree
        .root_hash()
        .ok_or_else(|| (StatusCode::BAD_REQUEST, "blob tree has no root hash").into_response())?
        .to_string();

    let metadata = BlobMetadata {
        hash_tree: request.blob_tree,
        num_blob_bytes: request.num_blob_bytes,
        headers: request.headers,
    };

    let data = serde_json::to_vec(&metadata)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response())?;

    let path = storage::paths::blob_path(&owner, &root_hash);
    state.bucket
        .put_object(path, &data)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response())?;

    let chunk_hashes = metadata.hash_tree.chunk_hashes();
    let mut existing_chunks = Vec::new();
    let mut chunk_check_errors: usize = 0;

    for hash in chunk_hashes {
        let path = storage::paths::chunk_path(&owner, hash);
        match state.bucket.object_exists(path).await {
            Ok(true) => existing_chunks.push(hash.clone()),
            Ok(false) => {}
            Err(_) => chunk_check_errors += 1,
        }
    }

    let response = PutBlobTreeResponse {
        status: "blob_tree_accepted".to_string(),
        existing_chunks,
        chunk_check_errors,
    };

    Ok((StatusCode::OK, Json(response)).into_response())
}

// ---------------------------------------------------------------------------
// PUT /v1/chunk?owner_id=...&blob_hash=...&chunk_index=N
// ---------------------------------------------------------------------------

pub async fn put_chunk(
    State(state): State<StorageState>,
    Query(q): Query<ChunkPutQuery>,
    body: Body,
) -> Result<Response, Response> {
    let owner = parse_principal(&q.owner_id)?;

    let body = buffer_body(body, ONE_MIB, BODY_READ_TIMEOUT)
        .await
        .map_err(|e| (StatusCode::PAYLOAD_TOO_LARGE, e.to_string()).into_response())?;

    state
        .connector
        .charge_blob_tree_download(&owner)
        .await
        .map_err(|e| billing_error_response(&e))?;

    let meta = load_blob_metadata(&state.bucket, &owner, &q.blob_hash).await?;
    let chunk_hashes = meta.hash_tree.chunk_hashes();

    if q.chunk_index >= chunk_hashes.len() {
        return Err((StatusCode::BAD_REQUEST, "chunk_index out of range").into_response());
    }

    let expected_hash = &chunk_hashes[q.chunk_index];

    let actual_hash = format!("sha256:{:x}", Sha256::digest(&body));
    if actual_hash != *expected_hash {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("chunk hash mismatch: expected {expected_hash}, got {actual_hash}"),
        )
            .into_response());
    }

    if q.chunk_index + 1 < chunk_hashes.len() && body.len() != ONE_MIB {
        return Err((
            StatusCode::BAD_REQUEST,
            "non-last chunk must be exactly 1 MiB",
        )
            .into_response());
    }

    state
        .connector
        .charge_chunk_upload(&owner)
        .await
        .map_err(|e| billing_error_response(&e))?;

    let path = storage::paths::chunk_path(&owner, expected_hash);
    state.bucket
        .put_object(path, &body)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response())?;

    Ok(Json(PutChunkResponse {
        status: "chunk_accepted".to_string(),
    })
    .into_response())
}

// ---------------------------------------------------------------------------
// DELETE /v1/owner?owner_id=...
// ---------------------------------------------------------------------------

pub async fn delete_owner(
    State(state): State<StorageState>,
    Host(host): Host,
    Query(q): Query<OwnerQuery>,
) -> Result<Response, Response> {
    let owner = parse_principal(&q.owner_id)?;

    check_delete_owner_host(
        Some(&host),
        state.allowed_delete_owner_hosts.as_deref(),
    )?;

    let blob_prefix = storage::paths::blob_path_owner_prefix(&owner);
    let chunk_prefix = storage::paths::chunk_path_owner_prefix(&owner);

    let blobs_deleted = delete_all_with_prefix(&state.bucket, blob_prefix).await?;
    let chunks_deleted = delete_all_with_prefix(&state.bucket, chunk_prefix).await?;

    if blobs_deleted || chunks_deleted {
        Ok((StatusCode::OK, format!("deleted all data for owner: {owner}")).into_response())
    } else {
        Ok((StatusCode::NO_CONTENT).into_response())
    }
}

async fn delete_all_with_prefix(
    bucket: &Arc<dyn BucketLike>,
    prefix: String,
) -> Result<bool, Response> {
    let mut deleted_any = false;
    let mut continuation_token = None;

    loop {
        let (page, _status) = bucket
            .list_page(
                prefix.clone(),
                None,
                continuation_token,
                None,
                Some(1000),
            )
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response())?;

        if page.keys.is_empty() {
            break;
        }

        deleted_any = true;
        for key in &page.keys {
            bucket
                .delete_object(key.clone())
                .await
                .map_err(|e| {
                    (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response()
                })?;
        }

        match page.next_continuation_token {
            Some(token) => continuation_token = Some(token),
            None => break,
        }
    }

    Ok(deleted_any)
}

// ---------------------------------------------------------------------------
// DELETE /v1/blob-tree — intentionally disabled (405)
// ---------------------------------------------------------------------------

pub async fn delete_blob_tree_disabled() -> impl IntoResponse {
    (
        StatusCode::METHOD_NOT_ALLOWED,
        "DELETE /blob-tree endpoint is disabled",
    )
}
