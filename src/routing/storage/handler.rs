use std::{
    cmp::min,
    ops::{Bound, Range},
    sync::Arc,
    time::Duration,
};

use axum::{
    Json,
    body::Body,
    extract::{Path, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use axum_extra::{TypedHeader, extract::Host, headers::Range as HttpRange};
use candid::Principal;
use futures::stream::{self, Stream, StreamExt};
use ic_bn_lib::http::body::buffer_body;
use sha2::{Digest, Sha256};

use crate::routing::{
    ACCEPT_RANGES_BYTES, CONTENT_TYPE_JSON, CONTENT_TYPE_OCTET,
    error_cause::{BackendError, ClientError, StorageError},
};

use super::{
    StorageState,
    bucket::BucketLike,
    wire::{
        BlobMetadata, MAX_REQUEST_BODY_SIZE, ONE_MIB, PutBlobTreeRequest, PutBlobTreeResponse,
        PutChunkResponse,
    },
};

type S = Arc<StorageState>;

const BODY_READ_TIMEOUT: Duration = Duration::from_secs(60);
const BLOB_METADATA_PATH: &str = "blob-metadata";
const CHUNK_PATH: &str = "chunks";

/// Maximum number of chunk fetches kept in flight when streaming a blob
/// download. `buffered(N)` preserves source order, so the response body stays
/// strictly sequential while we prefetch ahead. Bounds peak per-download
/// memory at `CHUNK_DOWNLOAD_PARALLELISM * 1 MiB` (~8 MiB).
const CHUNK_DOWNLOAD_PARALLELISM: usize = 8;

fn blob_path_owner_prefix(owner: &Principal) -> String {
    format!("{BLOB_METADATA_PATH}/{owner}/")
}

/// S3 key for blob metadata: `blob-metadata/{owner}/{root_hash}`.
fn blob_path(owner: &Principal, root_hash: &str) -> String {
    format!("{}{root_hash}", blob_path_owner_prefix(owner))
}

fn chunk_path_owner_prefix(owner: &Principal) -> String {
    format!("{CHUNK_PATH}/{owner}/")
}

/// S3 key for a chunk: `chunks/{owner}/{chunk_hash}`.
fn chunk_path(owner: &Principal, chunk_hash: &str) -> String {
    format!("{}{chunk_hash}", chunk_path_owner_prefix(owner))
}

/// One slice of a blob to download.
///
/// `start`/`end_cap` are byte offsets *within the chunk*. `end_cap` may exceed
/// the actual chunk length (e.g. `usize::MAX` to mean "to the end of the
/// chunk"); it is clamped against `data.len()` after the chunk is fetched.
struct ChunkPart {
    hash: String,
    start: usize,
    end_cap: usize,
}

impl ChunkPart {
    /// Returns the entire chunk verbatim.
    fn full(hash: String) -> Self {
        Self {
            hash,
            start: 0,
            end_cap: usize::MAX,
        }
    }
}

/// Build an ordered streaming download of `parts`, fetching up to
/// [`CHUNK_DOWNLOAD_PARALLELISM`] chunks in parallel. Each chunk is
/// pre-charged via `charge_chunk_download` before its S3 GET; on success
/// the requested slice is yielded as `Bytes` (O(1) — shares the underlying
/// allocation, no memcpy).
///
/// `buffered` preserves source order, so the response body is strictly
/// sequential even though fetches overlap.
///
/// We take an owned `Arc<StorageState>` rather than borrowing because the
/// returned stream has `'static` lifetime — axum keeps polling it after this
/// frame is gone. Each concurrent task `Arc::clone`s the state once
/// (a single atomic increment); that is the minimum cost of independently
/// owning shared state across N parallel futures.
fn chunk_download_stream(
    state: Arc<StorageState>,
    owner: Principal,
    parts: Vec<ChunkPart>,
) -> impl Stream<Item = Result<bytes::Bytes, std::io::Error>> + Send + 'static {
    stream::iter(parts)
        .map(move |part| fetch_chunk(state.clone(), owner, part))
        .buffered(CHUNK_DOWNLOAD_PARALLELISM)
}

/// Charge for and fetch a single chunk slice from S3.
async fn fetch_chunk(
    state: Arc<StorageState>,
    owner: Principal,
    part: ChunkPart,
) -> Result<bytes::Bytes, std::io::Error> {
    state
        .connector
        .charge_chunk_download(&owner)
        .await
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::PermissionDenied, e.to_string()))?;

    let path = chunk_path(&owner, &part.hash);
    let data = state
        .bucket
        .get_object(path)
        .await
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "chunk not found"))?;

    let end = min(part.end_cap, data.len());
    Ok(bytes::Bytes::from(data).slice(part.start..end))
}

// Helpers

/// Build response headers for a blob/chunk download: Content-Length, Accept-Ranges, Content-Type,
/// plus any custom headers stored in the blob metadata.
fn blob_download_headers(content_length: u64, stored_headers: &[String]) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(header::CONTENT_LENGTH, content_length.into());
    headers.insert(header::ACCEPT_RANGES, ACCEPT_RANGES_BYTES);
    headers.insert(header::CONTENT_TYPE, CONTENT_TYPE_OCTET);
    apply_stored_headers(&mut headers, stored_headers);
    headers
}

fn apply_stored_headers(headers: &mut HeaderMap, stored: &[String]) {
    for pair in stored.chunks(2) {
        if let [name, value] = pair {
            if let (Ok(hn), Ok(hv)) = (
                name.parse::<header::HeaderName>(),
                value.parse::<header::HeaderValue>(),
            ) {
                headers.insert(hn, hv);
            }
        }
    }
}

fn parse_principal(s: &str) -> Result<Principal, StorageError> {
    Principal::from_text(s)
        .map_err(|e| ClientError::MalformedRequest(format!("invalid owner_id: {e}")).into())
}

async fn load_blob_metadata(
    bucket: &dyn BucketLike,
    owner: &Principal,
    blob_hash: &str,
) -> Result<BlobMetadata, StorageError> {
    let path = blob_path(owner, blob_hash);
    let data = bucket
        .get_object(path)
        .await
        .map_err(|e| StorageError::from(BackendError::S3(e.to_string())))?
        .ok_or_else(|| StorageError::from(ClientError::NotFound("blob")))?;

    serde_json::from_slice::<BlobMetadata>(&data)
        .map_err(|e| StorageError::Internal(format!("corrupt blob metadata: {e}")))
}

/// Resolve a parsed `Range` header to an inclusive-start/exclusive-end byte
/// range. We only support single-range requests (RFC 9110 §14.2). Multi-range
/// responses would require `multipart/byteranges` which we don't emit.
fn resolve_range(range: &HttpRange, total: u64) -> Result<Range<u64>, StorageError> {
    let unsatisfiable = || StorageError::from(ClientError::RangeNotSatisfiable(total));

    let mut iter = range.satisfiable_ranges(total);
    let first = iter.next().ok_or_else(unsatisfiable)?;
    if iter.next().is_some() {
        return Err(StorageError::from(ClientError::MalformedRequest(
            "only single-range requests are supported".into(),
        )));
    }

    let (start_bound, end_bound) = first;
    let start = match start_bound {
        Bound::Included(n) => n,
        Bound::Excluded(n) => n.saturating_add(1),
        Bound::Unbounded => 0,
    };
    let end = match end_bound {
        Bound::Included(n) => n.saturating_add(1),
        Bound::Excluded(n) => n,
        Bound::Unbounded => total,
    };

    if start >= end || end > total {
        return Err(unsatisfiable());
    }
    Ok(start..end)
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

fn check_delete_owner_host(
    host: Option<&str>,
    allowed_env: Option<&str>,
) -> Result<(), StorageError> {
    let Some(allowed_list) = allowed_env else {
        return Ok(());
    };

    let host = host
        .ok_or_else(|| StorageError::Forbidden("missing Host header for owner deletion".into()))?;

    let normalize = |h: &str| {
        h.split_once(':')
            .map(|(h, _)| h.to_lowercase())
            .unwrap_or_else(|| h.to_lowercase())
    };

    let normalized = normalize(host);
    let allowed: Vec<&str> = allowed_list
        .split(',')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .collect();

    if allowed.iter().any(|a| *a == host || *a == normalized) {
        Ok(())
    } else {
        Err(StorageError::Forbidden(format!(
            "host '{host}' is not allowed for owner deletion"
        )))
    }
}

// HEAD /storage/v1/owner/{owner_id}/blob/{blob_hash}
pub async fn head_blob(
    State(state): State<S>,
    Path((owner_id, blob_hash)): Path<(String, String)>,
) -> Result<Response, StorageError> {
    let owner = parse_principal(&owner_id)?;

    state
        .connector
        .charge_blob_tree_download(&owner)
        .await
        .map_err(|e| StorageError::from(&e))?;

    let meta = load_blob_metadata(&*state.bucket, &owner, &blob_hash).await?;

    // Per RFC 9110 §9.3.2, HEAD must return the same headers as GET would.
    let headers = blob_download_headers(meta.num_blob_bytes, &meta.headers);
    Ok((StatusCode::OK, headers).into_response())
}

// GET /storage/v1/owner/{owner_id}/blob/{blob_hash} (with Range support)
pub async fn get_blob(
    State(state): State<S>,
    range_header: Option<TypedHeader<HttpRange>>,
    Path((owner_id, blob_hash)): Path<(String, String)>,
) -> Result<Response, StorageError> {
    let owner = parse_principal(&owner_id)?;

    state
        .connector
        .charge_blob_tree_download(&owner)
        .await
        .map_err(|e| StorageError::from(&e))?;

    let meta = load_blob_metadata(&*state.bucket, &owner, &blob_hash).await?;
    let chunk_hashes: Vec<String> = meta.hash_tree.chunk_hashes().to_vec();
    let total_bytes = meta.num_blob_bytes;

    if let Some(TypedHeader(http_range)) = range_header {
        let range = resolve_range(&http_range, total_bytes)?;
        let content_length = range.end - range.start;
        let (chunk_range, start_offset, end_offset) = range_to_chunk_ranges(&range);

        // Snapshot just the hashes we'll touch; cheap (small set of ~70-char strings).
        let needed: Vec<String> = chunk_hashes[chunk_range.clone()].to_vec();
        let last_idx = needed.len().saturating_sub(1);

        let parts: Vec<ChunkPart> = needed
            .into_iter()
            .enumerate()
            .map(|(i, hash)| ChunkPart {
                hash,
                start: if i == 0 { start_offset } else { 0 },
                end_cap: if i == last_idx { end_offset } else { usize::MAX },
            })
            .collect();

        let stream = chunk_download_stream(state.clone(), owner, parts);

        let mut headers = blob_download_headers(content_length, &meta.headers);
        let cr = format!("bytes {}-{}/{total_bytes}", range.start, range.end - 1);
        headers.insert(
            header::CONTENT_RANGE,
            cr.parse()
                .expect("Content-Range value is always valid ASCII"),
        );

        Ok((
            StatusCode::PARTIAL_CONTENT,
            headers,
            Body::from_stream(stream),
        )
            .into_response())
    } else {
        let parts: Vec<ChunkPart> = chunk_hashes.into_iter().map(ChunkPart::full).collect();

        let stream = chunk_download_stream(state.clone(), owner, parts);

        let headers = blob_download_headers(total_bytes, &meta.headers);

        Ok((StatusCode::OK, headers, Body::from_stream(stream)).into_response())
    }
}

// GET /storage/v1/owner/{owner_id}/blob_tree/{blob_hash}
pub async fn get_blob_tree(
    State(state): State<S>,
    Path((owner_id, blob_hash)): Path<(String, String)>,
) -> Result<Response, StorageError> {
    let owner = parse_principal(&owner_id)?;

    state
        .connector
        .charge_blob_tree_download(&owner)
        .await
        .map_err(|e| StorageError::from(&e))?;

    let path = blob_path(&owner, &blob_hash);
    let data = state
        .bucket
        .get_object(path)
        .await
        .map_err(|e| StorageError::from(BackendError::S3(e.to_string())))?
        .ok_or_else(|| StorageError::from(ClientError::NotFound("blob")))?;

    Ok(([(header::CONTENT_TYPE, CONTENT_TYPE_JSON)], data).into_response())
}

// GET /storage/v1/owner/{owner_id}/chunk/{chunk_hash}
pub async fn get_chunk(
    State(state): State<S>,
    Path((owner_id, chunk_hash)): Path<(String, String)>,
) -> Result<Response, StorageError> {
    let owner = parse_principal(&owner_id)?;

    state
        .connector
        .charge_chunk_download(&owner)
        .await
        .map_err(|e| StorageError::from(&e))?;

    let path = chunk_path(&owner, &chunk_hash);
    let data = state
        .bucket
        .get_object(path)
        .await
        .map_err(|e| StorageError::from(BackendError::S3(e.to_string())))?
        .ok_or_else(|| StorageError::from(ClientError::NotFound("chunk")))?;

    Ok(([(header::CONTENT_TYPE, CONTENT_TYPE_OCTET)], data).into_response())
}

// PUT /storage/v1/owner/{owner_id}/blob_tree/{blob_hash} (JSON body, with auth)
pub async fn put_blob_tree(
    State(state): State<S>,
    Path((owner_id, blob_hash)): Path<(String, String)>,
    body: Body,
) -> Result<Response, StorageError> {
    let owner = parse_principal(&owner_id)?;

    let body_bytes = buffer_body(body, MAX_REQUEST_BODY_SIZE, BODY_READ_TIMEOUT)
        .await
        .map_err(|e| ClientError::MalformedRequest(e.to_string()))?;

    let request: PutBlobTreeRequest = serde_json::from_slice(&body_bytes)
        .map_err(|e| ClientError::MalformedRequest(format!("invalid JSON: {e}")))?;

    if request.owner != owner {
        return Err(ClientError::MalformedRequest(
            "URL owner_id does not match request body owner".into(),
        )
        .into());
    }

    let root_hash = request
        .blob_tree
        .root_hash()
        .ok_or_else(|| ClientError::MalformedRequest("blob tree has no root hash".into()))?
        .to_string();

    if root_hash != blob_hash {
        return Err(ClientError::MalformedRequest(format!(
            "URL blob_hash {blob_hash} does not match body root_hash {root_hash}"
        ))
        .into());
    }

    state.ingress_auth.check_put_blob(&request)?;

    state
        .connector
        .charge_blob_tree_upload(&owner)
        .await
        .map_err(|e| StorageError::from(&e))?;

    let metadata = BlobMetadata {
        hash_tree: request.blob_tree,
        num_blob_bytes: request.num_blob_bytes,
        headers: request.headers,
    };

    let data = serde_json::to_vec(&metadata).map_err(|e| StorageError::Internal(e.to_string()))?;

    let path = blob_path(&owner, &root_hash);
    state
        .bucket
        .put_object(path, data.into())
        .await
        .map_err(|e| BackendError::S3(e.to_string()))?;

    let chunk_hashes = metadata.hash_tree.chunk_hashes();
    let mut existing_chunks = Vec::new();
    let mut chunk_check_errors: usize = 0;

    for hash in chunk_hashes {
        let path = chunk_path(&owner, hash);
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

// PUT /storage/v1/owner/{owner_id}/blob/{blob_hash}/chunk/{chunk_index}
pub async fn put_chunk(
    State(state): State<S>,
    Path((owner_id, blob_hash, chunk_index)): Path<(String, String, usize)>,
    body: Body,
) -> Result<Response, StorageError> {
    let owner = parse_principal(&owner_id)?;

    let body = buffer_body(body, ONE_MIB, BODY_READ_TIMEOUT)
        .await
        .map_err(|_| ClientError::BodyTooLarge)?;

    state
        .connector
        .charge_blob_tree_download(&owner)
        .await
        .map_err(|e| StorageError::from(&e))?;

    let meta = load_blob_metadata(&*state.bucket, &owner, &blob_hash).await?;
    let chunk_hashes = meta.hash_tree.chunk_hashes();

    if chunk_index >= chunk_hashes.len() {
        return Err(ClientError::MalformedRequest("chunk_index out of range".into()).into());
    }

    let expected_hash = &chunk_hashes[chunk_index];

    let actual_hash = format!("sha256:{:x}", Sha256::digest(&body));
    if actual_hash != *expected_hash {
        return Err(ClientError::MalformedRequest(format!(
            "chunk hash mismatch: expected {expected_hash}, got {actual_hash}"
        ))
        .into());
    }

    if chunk_index + 1 < chunk_hashes.len() && body.len() != ONE_MIB {
        return Err(
            ClientError::MalformedRequest("non-last chunk must be exactly 1 MiB".into()).into(),
        );
    }

    state
        .connector
        .charge_chunk_upload(&owner)
        .await
        .map_err(|e| StorageError::from(&e))?;

    let path = chunk_path(&owner, expected_hash);
    state
        .bucket
        .put_object(path, body)
        .await
        .map_err(|e| BackendError::S3(e.to_string()))?;

    Ok(Json(PutChunkResponse {
        status: "chunk_accepted".to_string(),
    })
    .into_response())
}

// DELETE /storage/v1/owner/{owner_id}
pub async fn delete_owner(
    State(state): State<S>,
    Host(host): Host,
    Path(owner_id): Path<String>,
) -> Result<Response, StorageError> {
    let owner = parse_principal(&owner_id)?;

    check_delete_owner_host(Some(&host), state.allowed_delete_owner_hosts.as_deref())?;

    let blob_prefix = blob_path_owner_prefix(&owner);
    let chunk_prefix = chunk_path_owner_prefix(&owner);

    let blobs_deleted = delete_all_with_prefix(&*state.bucket, blob_prefix).await?;
    let chunks_deleted = delete_all_with_prefix(&*state.bucket, chunk_prefix).await?;

    if blobs_deleted || chunks_deleted {
        Ok((
            StatusCode::OK,
            format!("deleted all data for owner: {owner}"),
        )
            .into_response())
    } else {
        Ok(StatusCode::NO_CONTENT.into_response())
    }
}

async fn delete_all_with_prefix(
    bucket: &dyn BucketLike,
    prefix: String,
) -> Result<bool, StorageError> {
    let mut deleted_any = false;
    let mut continuation_token = None;

    loop {
        let page = bucket
            .list_page(prefix.clone(), continuation_token, Some(1000))
            .await
            .map_err(|e| BackendError::S3(e.to_string()))?;

        if page.keys.is_empty() {
            break;
        }

        deleted_any = true;
        for key in &page.keys {
            bucket
                .delete_object(key.clone())
                .await
                .map_err(|e| BackendError::S3(e.to_string()))?;
        }

        match page.next_continuation_token {
            Some(token) => continuation_token = Some(token),
            None => break,
        }
    }

    Ok(deleted_any)
}

// DELETE /storage/v1/owner/{owner_id}/blob_tree/{blob_hash} — intentionally disabled (405)
pub async fn delete_blob_tree_disabled() -> impl IntoResponse {
    (
        StatusCode::METHOD_NOT_ALLOWED,
        "blob_tree deletion is disabled",
    )
}
