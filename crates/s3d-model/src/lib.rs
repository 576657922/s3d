//! Executable specification reference model (`VR-1`).
//!
//! Pure sequential in-memory implementation of `ObjectStore` using `BTreeMap`.
//! Every semantic branch references its requirement ID (`PR-*`, `FR-*`).

use std::collections::BTreeMap;
use std::future::poll_fn;
use std::sync::Mutex;

use base64::Engine as _;
use bytes::{Bytes, BytesMut};
use crc32fast::Hasher as Crc32Hasher;
use md5::{Digest as _, Md5};
use s3d_types::*;
use sha1::Sha1;
use sha2::Sha256;

#[derive(Debug, Clone)]
pub struct ModelConfig {
    pub region: String,
    pub max_buckets_per_account: usize,
    pub default_object_ownership: ObjectOwnership,
}

impl Default for ModelConfig {
    fn default() -> Self {
        Self {
            region: "us-east-1".to_string(),
            max_buckets_per_account: 10_000,
            default_object_ownership: ObjectOwnership::BucketOwnerEnforced,
        }
    }
}

#[derive(Debug, Clone)]
struct ModelVersion {
    #[allow(dead_code)]
    seq: u64,
    version_id: Option<String>,
    is_delete_marker: bool,
    data: Bytes,
    etag: String,
    checksum: ChecksumState,
    sys_meta: SystemMeta,
    user_meta: Vec<(String, String)>,
    owner: OwnerInfo,
    last_modified_ms: i64,
    part_sizes: Option<Vec<u64>>,
}

#[derive(Debug, Clone)]
struct ModelBucket {
    name: String,
    owner: OwnerInfo,
    region: String,
    created_ms: i64,
    versioning: VersioningStatus,
    ownership: ObjectOwnership,
    objects: BTreeMap<String, Vec<ModelVersion>>, // key -> newest-first versions
}

#[derive(Default)]
struct ModelState {
    next_seq: u64,
    buckets: BTreeMap<String, ModelBucket>,
}

pub struct ModelStore {
    cfg: ModelConfig,
    state: Mutex<ModelState>,
}

impl Default for ModelStore {
    fn default() -> Self {
        Self::new(ModelConfig::default())
    }
}

impl ModelStore {
    pub fn new(cfg: ModelConfig) -> Self {
        Self {
            cfg,
            state: Mutex::new(ModelState::default()),
        }
    }
}

fn require_authenticated(ctx: &CallerContext) -> StoreResult<&OwnerInfo> {
    // [PR-28] Before P1 ACL/Policy, unauthenticated requests are denied.
    ctx.caller
        .as_ref()
        .filter(|_| ctx.is_authenticated)
        .ok_or_else(|| S3Error::new(S3ErrorCode::AccessDenied, "Access Denied"))
}

fn check_bucket_access<'a>(
    state: &'a ModelState,
    ctx: &CallerContext,
    bucket_name: &str,
) -> StoreResult<&'a ModelBucket> {
    let bucket = state.buckets.get(bucket_name).ok_or_else(|| {
        S3Error::new(S3ErrorCode::NoSuchBucket, "The specified bucket does not exist")
            .with_bucket(bucket_name)
    })?;
    let caller = require_authenticated(ctx)?;
    // [PR-29] Expected bucket owner header verification
    if let Some(expected) = &ctx.expected_bucket_owner {
        if expected != &bucket.owner.user_id {
            return Err(S3Error::new(S3ErrorCode::AccessDenied, "Access Denied")
                .with_bucket(bucket_name));
        }
    }
    // [PR-28] Owner-only access in P0
    if caller.user_id != bucket.owner.user_id {
        return Err(
            S3Error::new(S3ErrorCode::AccessDenied, "Access Denied").with_bucket(bucket_name)
        );
    }
    Ok(bucket)
}

fn map_body_err(err: BodyStreamError) -> S3Error {
    match err {
        BodyStreamError::Sha256Mismatch => S3Error::new(
            S3ErrorCode::XAmzContentSHA256Mismatch,
            "The provided 'x-amz-content-sha256' header does not match what was computed.",
        ),
        BodyStreamError::BadDigest => S3Error::new(
            S3ErrorCode::BadDigest,
            "The digest you specified did not match the calculated digest.",
        ),
        BodyStreamError::InvalidChunkedEncoding(msg) => {
            S3Error::new(S3ErrorCode::InvalidRequest, msg)
        }
        BodyStreamError::EntityTooLarge => S3Error::new(
            S3ErrorCode::EntityTooLarge,
            "Your proposed upload exceeds the maximum allowed size",
        ),
        BodyStreamError::EntityTooSmall => S3Error::new(
            S3ErrorCode::EntityTooSmall,
            "Your proposed upload is smaller than the minimum allowed size",
        ),
        BodyStreamError::IncompleteBody => S3Error::new(
            S3ErrorCode::IncompleteBody,
            "You did not provide the number of bytes specified by the Content-Length HTTP header.",
        ),
        BodyStreamError::ClientDisconnected(msg) => S3Error::new(S3ErrorCode::IncompleteBody, msg),
    }
}

fn head_state_of(versions: Option<&Vec<ModelVersion>>) -> HeadState<'_> {
    match versions.and_then(|v| v.first()) {
        None => HeadState::Absent,
        Some(v) if v.is_delete_marker => HeadState::DeleteMarker,
        Some(v) => HeadState::Present { etag: &v.etag },
    }
}

fn encode_token(bucket: &str, key: &str) -> String {
    let raw = format!("v1:{bucket}:{key}");
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw.as_bytes())
}

fn decode_token(bucket: &str, token: &str) -> StoreResult<String> {
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(token)
        .map_err(|_| S3Error::new(S3ErrorCode::InvalidArgument, "The continuation token provided is incorrect"))?;
    let s = std::str::from_utf8(&bytes)
        .map_err(|_| S3Error::new(S3ErrorCode::InvalidArgument, "The continuation token provided is incorrect"))?;
    let prefix = format!("v1:{bucket}:");
    s.strip_prefix(&prefix)
        .map(|k| k.to_string())
        .ok_or_else(|| S3Error::new(S3ErrorCode::InvalidArgument, "The continuation token provided is incorrect"))
}

/// Shared sorted prefix/delimiter collector for V1 and V2 listing (FR-39 ~ FR-44).
enum MergedItem<'a> {
    Object(&'a String, &'a ModelVersion),
    CommonPrefix(String),
}

fn collect_visible_items<'a>(
    objects: &'a BTreeMap<String, Vec<ModelVersion>>,
    prefix: &str,
    delimiter: Option<&str>,
    after_key: Option<&str>,
    max_keys: usize,
) -> (Vec<MergedItem<'a>>, bool) {
    if max_keys == 0 {
        // [FR-41] max-keys=0 returns empty and IsTruncated=false
        return (Vec::new(), false);
    }
    let mut items: Vec<MergedItem<'a>> = Vec::new();
    let mut last_cp: Option<String> = None;
    let mut is_truncated = false;

    for (key, chain) in objects {
        if !key.starts_with(prefix) {
            continue;
        }
        let Some(head) = chain.first() else { continue };
        if head.is_delete_marker {
            continue;
        }
        if let Some(after) = after_key {
            if key.as_str() <= after {
                continue;
            }
        }

        let rest = &key[prefix.len()..];
        if let Some(delim) = delimiter.filter(|d| !d.is_empty()) {
            if let Some(pos) = rest.find(delim) {
                let cp = format!("{}{}", prefix, &rest[..pos + delim.len()]);
                if let Some(after) = after_key {
                    if cp.as_str() <= after {
                        continue;
                    }
                }
                if last_cp.as_deref() == Some(cp.as_str()) {
                    continue;
                }
                if items.len() == max_keys {
                    is_truncated = true;
                    break;
                }
                last_cp = Some(cp.clone());
                items.push(MergedItem::CommonPrefix(cp));
                continue;
            }
        }

        if items.len() == max_keys {
            is_truncated = true;
            break;
        }
        items.push(MergedItem::Object(key, head));
    }

    (items, is_truncated)
}

impl ObjectStore for ModelStore {
    type Reader = MemoryByteReader;

    async fn list_buckets(&self, req: ListBucketsReq) -> StoreResult<ListBucketsResp> {
        let caller = require_authenticated(&req.ctx)?.clone();
        if let Some(max) = req.max_buckets {
            if !(1..=10_000).contains(&max) {
                return Err(S3Error::new(
                    S3ErrorCode::InvalidArgument,
                    "max-buckets must be between 1 and 10000",
                ));
            }
        }
        let after = match &req.continuation_token {
            Some(tok) => Some(decode_token("__buckets__", tok)?),
            None => None,
        };
        let max = req.max_buckets.unwrap_or(10_000);
        let guard = self.state.lock().unwrap();
        let mut buckets = Vec::new();
        let mut next_token = None;
        for b in guard.buckets.values() {
            if b.owner.user_id != caller.user_id {
                continue;
            }
            if let Some(pfx) = &req.prefix {
                if !b.name.starts_with(pfx) {
                    continue;
                }
            }
            if let Some(after_name) = &after {
                if &b.name <= after_name {
                    continue;
                }
            }
            if buckets.len() == max {
                if let Some(last) = buckets.last() {
                    let last_b: &BucketSummary = last;
                    next_token = Some(encode_token("__buckets__", &last_b.name));
                }
                break;
            }
            buckets.push(BucketSummary {
                name: b.name.clone(),
                created_ms: b.created_ms,
                region: b.region.clone(),
            });
        }
        Ok(ListBucketsResp {
            owner: caller,
            buckets,
            next_continuation_token: next_token,
        })
    }

    async fn create_bucket(&self, req: CreateBucketReq) -> StoreResult<BucketMetaSnapshot> {
        let caller = require_authenticated(&req.ctx)?.clone();
        // [FR-48] Bucket naming rules
        validate_bucket_name(&req.bucket)?;

        if let Some(loc) = &req.location_constraint {
            if !loc.is_empty() && loc != &self.cfg.region {
                return Err(S3Error::new(
                    S3ErrorCode::InvalidLocationConstraint,
                    "The specified location-constraint is not valid",
                )
                .with_bucket(&req.bucket));
            }
        }

        let mut guard = self.state.lock().unwrap();
        if let Some(existing) = guard.buckets.get(&req.bucket) {
            // [FR-49] Same owner -> 409 BucketAlreadyOwnedByYou; other -> 409 BucketAlreadyExists
            if existing.owner.user_id == caller.user_id {
                return Err(S3Error::new(
                    S3ErrorCode::BucketAlreadyOwnedByYou,
                    "Your previous request to create the named bucket succeeded and you already own it.",
                )
                .with_bucket(&req.bucket));
            } else {
                return Err(S3Error::new(
                    S3ErrorCode::BucketAlreadyExists,
                    "The requested bucket name is not available.",
                )
                .with_bucket(&req.bucket));
            }
        }

        let owned_count = guard
            .buckets
            .values()
            .filter(|b| b.owner.user_id == caller.user_id)
            .count();
        if owned_count >= self.cfg.max_buckets_per_account {
            return Err(S3Error::new(
                S3ErrorCode::TooManyBuckets,
                "You have attempted to create more buckets than allowed",
            ));
        }

        let ownership = req
            .object_ownership
            .unwrap_or(self.cfg.default_object_ownership);
        let b = ModelBucket {
            name: req.bucket.clone(),
            owner: caller,
            region: self.cfg.region.clone(),
            created_ms: req.ctx.request_time_ms,
            versioning: VersioningStatus::Unversioned,
            ownership,
            objects: BTreeMap::new(),
        };
        let snap = BucketMetaSnapshot {
            name: b.name.clone(),
            owner: b.owner.clone(),
            region: b.region.clone(),
            created_ms: b.created_ms,
            versioning: b.versioning,
            ownership: b.ownership,
        };
        guard.buckets.insert(req.bucket, b);
        Ok(snap)
    }

    async fn head_bucket(&self, req: BucketRef) -> StoreResult<BucketMetaSnapshot> {
        let guard = self.state.lock().unwrap();
        let b = check_bucket_access(&guard, &req.ctx, &req.bucket)?;
        Ok(BucketMetaSnapshot {
            name: b.name.clone(),
            owner: b.owner.clone(),
            region: b.region.clone(),
            created_ms: b.created_ms,
            versioning: b.versioning,
            ownership: b.ownership,
        })
    }

    async fn delete_bucket(&self, req: BucketRef) -> StoreResult<()> {
        let mut guard = self.state.lock().unwrap();
        let b = check_bucket_access(&guard, &req.ctx, &req.bucket)?;
        // [FR-50] Any remaining version or delete marker prevents bucket deletion
        if b.objects.values().any(|chain| !chain.is_empty()) {
            return Err(S3Error::new(
                S3ErrorCode::BucketNotEmpty,
                "The bucket you tried to delete is not empty",
            )
            .with_bucket(&req.bucket));
        }
        guard.buckets.remove(&req.bucket);
        Ok(())
    }

    async fn put_object<S: VerifiedBodyStream>(
        &self,
        req: PutObjectReq,
        mut body: S,
    ) -> StoreResult<PutObjectResp> {
        validate_object_key(&req.bucket, &req.key)?;
        validate_user_metadata(&req.user_meta)?;

        let caller = {
            let guard = self.state.lock().unwrap();
            let _ = check_bucket_access(&guard, &req.ctx, &req.bucket)?;
            require_authenticated(&req.ctx)?.clone()
        };

        // [FR-1, PR-21] Stream & verify digests BEFORE touching visible state
        let mut buf = BytesMut::new();
        while let Some(chunk) = poll_fn(|cx| body.poll_next_chunk(cx))
            .await
            .map_err(map_body_err)?
        {
            if (buf.len() + chunk.len()) as u64 > req.max_bytes_limit {
                return Err(S3Error::new(
                    S3ErrorCode::EntityTooLarge,
                    "Your proposed upload exceeds the maximum allowed size",
                ));
            }
            buf.extend_from_slice(&chunk);
        }
        let digests = body.finish().map_err(map_body_err)?;

        // [FR-17] Evaluate preconditions atomically at commit point
        let mut guard = self.state.lock().unwrap();
        let _ = check_bucket_access(&guard, &req.ctx, &req.bucket)?;
        guard.next_seq += 1;
        let seq = guard.next_seq;

        let bucket = guard.buckets.get_mut(&req.bucket).unwrap();
        let head = head_state_of(bucket.objects.get(&req.key));
        evaluate_write_preconditions(&req.preconditions, &req.bucket, &req.key, head)?;

        // [FR-7, PR-17] Quoted MD5 hex ETag
        let etag = format!("\"{}\"", hex::encode(digests.md5));
        let version_id = match bucket.versioning {
            VersioningStatus::Unversioned => None,
            VersioningStatus::Suspended => Some("null".to_string()),
            VersioningStatus::Enabled => Some(format!("v{seq:016x}")),
        };

        let ver = ModelVersion {
            seq,
            version_id: version_id.clone(),
            is_delete_marker: false,
            data: buf.freeze(),
            etag: etag.clone(),
            checksum: digests.checksum.clone(),
            sys_meta: req.sys_meta,
            user_meta: req.user_meta,
            owner: caller,
            last_modified_ms: req.ctx.request_time_ms,
            part_sizes: None,
        };

        let chain = bucket.objects.entry(req.key).or_default();
        match bucket.versioning {
            VersioningStatus::Unversioned => {
                chain.clear();
                chain.push(ver);
            }
            VersioningStatus::Suspended => {
                chain.retain(|v| v.version_id.as_deref() != Some("null"));
                chain.insert(0, ver);
            }
            VersioningStatus::Enabled => {
                chain.insert(0, ver);
            }
        }

        Ok(PutObjectResp {
            etag,
            version_id,
            checksum: digests.checksum,
        })
    }

    async fn get_object(&self, req: GetObjectReq) -> StoreResult<GetObjectResp<Self::Reader>> {
        let (meta, slice) = self.read_internal(&req, true)?;
        Ok(GetObjectResp {
            meta,
            reader: MemoryByteReader::new(slice),
        })
    }

    async fn head_object(&self, req: GetObjectReq) -> StoreResult<ObjectMetaSnapshot> {
        let (meta, _) = self.read_internal(&req, false)?;
        Ok(meta)
    }

    async fn delete_object(&self, req: DeleteObjectReq) -> StoreResult<DeleteObjectResp> {
        validate_object_key(&req.bucket, &req.key)?;
        let mut guard = self.state.lock().unwrap();
        let _ = check_bucket_access(&guard, &req.ctx, &req.bucket)?;
        let caller = require_authenticated(&req.ctx)?.clone();
        guard.next_seq += 1;
        let seq = guard.next_seq;
        let bucket = guard.buckets.get_mut(&req.bucket).unwrap();

        let head = head_state_of(bucket.objects.get(&req.key));
        evaluate_delete_preconditions(req.if_match.as_deref(), &req.bucket, &req.key, head)?;

        if let Some(vid) = &req.version_id {
            // [FR-36] Permanent version deletion
            if let Some(chain) = bucket.objects.get_mut(&req.key) {
                if let Some(pos) = chain.iter().position(|v| {
                    v.version_id.as_deref().unwrap_or("null") == vid.as_str()
                }) {
                    let removed = chain.remove(pos);
                    if chain.is_empty() {
                        bucket.objects.remove(&req.key);
                    }
                    return Ok(DeleteObjectResp {
                        version_id: removed.version_id,
                        is_delete_marker: removed.is_delete_marker,
                    });
                }
            }
            return Ok(DeleteObjectResp {
                version_id: Some(vid.clone()),
                is_delete_marker: false,
            });
        }

        match bucket.versioning {
            VersioningStatus::Unversioned => {
                bucket.objects.remove(&req.key);
                Ok(DeleteObjectResp {
                    version_id: None,
                    is_delete_marker: false,
                })
            }
            VersioningStatus::Suspended | VersioningStatus::Enabled => {
                // [FR-35] Insert delete marker
                let vid = if bucket.versioning == VersioningStatus::Suspended {
                    "null".to_string()
                } else {
                    format!("v{seq:016x}")
                };
                let dm = ModelVersion {
                    seq,
                    version_id: Some(vid.clone()),
                    is_delete_marker: true,
                    data: Bytes::new(),
                    etag: String::new(),
                    checksum: ChecksumState {
                        algorithm: ChecksumAlgorithm::Crc64Nvme,
                        checksum_type: ChecksumType::FullObject,
                        value_b64: String::new(),
                        client_requested: false,
                    },
                    sys_meta: SystemMeta::default(),
                    user_meta: Vec::new(),
                    owner: caller,
                    last_modified_ms: req.ctx.request_time_ms,
                    part_sizes: None,
                };
                let chain = bucket.objects.entry(req.key).or_default();
                if bucket.versioning == VersioningStatus::Suspended {
                    chain.retain(|v| v.version_id.as_deref() != Some("null"));
                }
                chain.insert(0, dm);
                Ok(DeleteObjectResp {
                    version_id: Some(vid),
                    is_delete_marker: true,
                })
            }
        }
    }

    async fn delete_objects(&self, req: DeleteObjectsReq) -> StoreResult<DeleteObjectsResp> {
        if req.items.is_empty() || req.items.len() > 1000 {
            // [FR-46] 1..=1000 keys limit
            return Err(S3Error::new(
                S3ErrorCode::InvalidRequest,
                "DeleteObjects requires between 1 and 1000 keys.",
            )
            .with_bucket(&req.bucket));
        }
        {
            let guard = self.state.lock().unwrap();
            let _ = check_bucket_access(&guard, &req.ctx, &req.bucket)?;
        }

        let mut deleted = Vec::new();
        let mut errors = Vec::new();
        for item in req.items {
            let sub = DeleteObjectReq {
                ctx: req.ctx.clone(),
                bucket: req.bucket.clone(),
                key: item.key.clone(),
                version_id: item.version_id.clone(),
                if_match: item.etag_if_match,
            };
            match self.delete_object(sub).await {
                Ok(resp) => {
                    if !req.quiet {
                        deleted.push(DeletedEntry {
                            key: item.key,
                            version_id: item.version_id,
                            delete_marker: resp.is_delete_marker,
                            delete_marker_version_id: if resp.is_delete_marker {
                                resp.version_id
                            } else {
                                None
                            },
                        });
                    }
                }
                Err(err) => {
                    errors.push(DeleteErrorEntry {
                        key: item.key,
                        version_id: item.version_id,
                        code: err.code.as_str().to_string(),
                        message: err.message,
                    });
                }
            }
        }
        Ok(DeleteObjectsResp { deleted, errors })
    }

    async fn copy_object(&self, req: CopyObjectReq) -> StoreResult<CopyObjectResp> {
        validate_object_key(&req.dst_bucket, &req.dst_key)?;
        if req.replace_metadata {
            validate_user_metadata(&req.user_meta)?;
        }
        if req.src_bucket == req.dst_bucket
            && req.src_key == req.dst_key
            && req.src_version_id.is_none()
            && !req.replace_metadata
        {
            // [FR-20] Self-copy with no changes -> 400 InvalidRequest
            return Err(S3Error::new(
                S3ErrorCode::InvalidRequest,
                "This copy request is illegal because it is trying to copy an object to itself without changing the object's metadata.",
            ));
        }

        let mut guard = self.state.lock().unwrap();
        let src_b = check_bucket_access(&guard, &req.ctx, &req.src_bucket)?;
        let _ = check_bucket_access(&guard, &req.ctx, &req.dst_bucket)?;
        let caller = require_authenticated(&req.ctx)?.clone();

        let src_ver = match &req.src_version_id {
            None => src_b
                .objects
                .get(&req.src_key)
                .and_then(|c| c.first())
                .filter(|v| !v.is_delete_marker)
                .cloned(),
            Some(vid) => src_b.objects.get(&req.src_key).and_then(|c| {
                c.iter()
                    .find(|v| v.version_id.as_deref().unwrap_or("null") == vid.as_str())
                    .cloned()
            }),
        }
        .ok_or_else(|| {
            S3Error::new(S3ErrorCode::NoSuchKey, "The specified key does not exist.")
                .with_key(&req.src_bucket, &req.src_key)
        })?;

        if src_ver.is_delete_marker {
            return Err(S3Error::new(
                S3ErrorCode::InvalidRequest,
                "The source of a copy request may not specifically refer to a delete marker by version id.",
            ));
        }
        if src_ver.data.len() as u64 > MAX_SINGLE_PUT_BYTES {
            // [FR-21] CopyObject > 5 GiB -> 400 InvalidRequest
            return Err(S3Error::new(
                S3ErrorCode::InvalidRequest,
                "The specified copy source is larger than the maximum allowable size for a copy source: 5368709120",
            ));
        }

        // [FR-22] Copy-source preconditions
        evaluate_copy_source_preconditions(
            &req.src_preconditions,
            &src_ver.etag,
            src_ver.last_modified_ms,
        )?;

        guard.next_seq += 1;
        let seq = guard.next_seq;
        let dst_b = guard.buckets.get_mut(&req.dst_bucket).unwrap();
        let dst_head = head_state_of(dst_b.objects.get(&req.dst_key));
        evaluate_write_preconditions(
            &req.dst_preconditions,
            &req.dst_bucket,
            &req.dst_key,
            dst_head,
        )?;

        let dst_vid = match dst_b.versioning {
            VersioningStatus::Unversioned => None,
            VersioningStatus::Suspended => Some("null".to_string()),
            VersioningStatus::Enabled => Some(format!("v{seq:016x}")),
        };
        let (sys_meta, user_meta) = if req.replace_metadata {
            (req.sys_meta, req.user_meta)
        } else {
            (src_ver.sys_meta.clone(), src_ver.user_meta.clone())
        };
        let md5_raw: [u8; 16] = Md5::digest(&src_ver.data).into();
        let etag = format!("\"{}\"", hex::encode(md5_raw));
        let new_ver = ModelVersion {
            seq,
            version_id: dst_vid.clone(),
            is_delete_marker: false,
            data: src_ver.data.clone(),
            etag: etag.clone(),
            checksum: src_ver.checksum.clone(),
            sys_meta,
            user_meta,
            owner: caller,
            last_modified_ms: req.ctx.request_time_ms,
            part_sizes: None,
        };

        let chain = dst_b.objects.entry(req.dst_key).or_default();
        match dst_b.versioning {
            VersioningStatus::Unversioned => {
                chain.clear();
                chain.push(new_ver);
            }
            VersioningStatus::Suspended => {
                chain.retain(|v| v.version_id.as_deref() != Some("null"));
                chain.insert(0, new_ver);
            }
            VersioningStatus::Enabled => {
                chain.insert(0, new_ver);
            }
        }

        Ok(CopyObjectResp {
            etag,
            last_modified_ms: req.ctx.request_time_ms,
            src_version_id: src_ver.version_id,
            dst_version_id: dst_vid,
            checksum: Some(src_ver.checksum),
        })
    }

    async fn list_objects_v1(&self, req: ListObjectsV1Req) -> StoreResult<ListObjectsV1Resp> {
        let guard = self.state.lock().unwrap();
        let b = check_bucket_access(&guard, &req.ctx, &req.bucket)?;
        let max_keys = req.max_keys.min(1000);
        let marker_str = req.marker.clone().unwrap_or_default();
        let (items, is_truncated) = collect_visible_items(
            &b.objects,
            &req.prefix,
            req.delimiter.as_deref(),
            req.marker.as_deref(),
            max_keys,
        );

        let mut contents = Vec::new();
        let mut common_prefixes = Vec::new();
        let mut last_item_key: Option<String> = None;

        for item in items {
            match item {
                MergedItem::Object(k, v) => {
                    last_item_key = Some(k.clone());
                    contents.push(ObjectListEntry {
                        key: k.clone(),
                        last_modified_ms: v.last_modified_ms,
                        etag: v.etag.clone(),
                        size: v.data.len() as u64,
                        owner: v.owner.clone(),
                        checksum_alg: Some(v.checksum.algorithm),
                        checksum_type: Some(v.checksum.checksum_type),
                    });
                }
                MergedItem::CommonPrefix(cp) => {
                    last_item_key = Some(cp.clone());
                    common_prefixes.push(cp);
                }
            }
        }

        // [FR-44] NextMarker is only returned when truncated AND delimiter is specified
        let next_marker = if is_truncated && req.delimiter.is_some() {
            last_item_key
        } else {
            None
        };

        Ok(ListObjectsV1Resp {
            name: req.bucket,
            prefix: req.prefix,
            marker: marker_str,
            next_marker,
            max_keys: req.max_keys.min(1000),
            delimiter: req.delimiter,
            is_truncated,
            contents,
            common_prefixes,
        })
    }

    async fn list_objects_v2(&self, req: ListObjectsV2Req) -> StoreResult<ListObjectsV2Resp> {
        let guard = self.state.lock().unwrap();
        let b = check_bucket_access(&guard, &req.ctx, &req.bucket)?;
        let max_keys = req.max_keys.min(1000);
        let token_after = match &req.continuation_token {
            Some(tok) => Some(decode_token(&req.bucket, tok)?),
            None => None,
        };
        let effective_after = match (&token_after, &req.start_after) {
            (Some(a), Some(b)) => Some(if a > b { a.as_str() } else { b.as_str() }),
            (Some(a), None) => Some(a.as_str()),
            (None, Some(b)) => Some(b.as_str()),
            (None, None) => None,
        };

        let (items, is_truncated) = collect_visible_items(
            &b.objects,
            &req.prefix,
            req.delimiter.as_deref(),
            effective_after,
            max_keys,
        );

        let mut contents = Vec::new();
        let mut common_prefixes = Vec::new();
        let mut last_item_key: Option<String> = None;

        for item in items {
            match item {
                MergedItem::Object(k, v) => {
                    last_item_key = Some(k.clone());
                    contents.push(ObjectListEntry {
                        key: k.clone(),
                        last_modified_ms: v.last_modified_ms,
                        etag: v.etag.clone(),
                        size: v.data.len() as u64,
                        owner: v.owner.clone(),
                        checksum_alg: Some(v.checksum.algorithm),
                        checksum_type: Some(v.checksum.checksum_type),
                    });
                }
                MergedItem::CommonPrefix(cp) => {
                    last_item_key = Some(cp.clone());
                    common_prefixes.push(cp);
                }
            }
        }

        let key_count = contents.len() + common_prefixes.len();
        let next_continuation_token = if is_truncated {
            last_item_key.map(|k| encode_token(&req.bucket, &k))
        } else {
            None
        };

        Ok(ListObjectsV2Resp {
            name: req.bucket,
            prefix: req.prefix,
            start_after: req.start_after,
            continuation_token: req.continuation_token,
            next_continuation_token,
            key_count,
            max_keys: req.max_keys.min(1000),
            delimiter: req.delimiter,
            is_truncated,
            contents,
            common_prefixes,
        })
    }

    async fn list_object_versions(
        &self,
        req: ListObjectVersionsReq,
    ) -> StoreResult<ListObjectVersionsResp> {
        let guard = self.state.lock().unwrap();
        let b = check_bucket_access(&guard, &req.ctx, &req.bucket)?;
        let max_keys = req.max_keys.min(1000);
        let km = req.key_marker.clone().unwrap_or_default();
        let vm = req.version_id_marker.clone().unwrap_or_default();

        if max_keys == 0 {
            return Ok(ListObjectVersionsResp {
                name: req.bucket,
                prefix: req.prefix,
                key_marker: km,
                version_id_marker: vm,
                next_key_marker: None,
                next_version_id_marker: None,
                max_keys: 0,
                delimiter: req.delimiter,
                is_truncated: false,
                entries: Vec::new(),
                common_prefixes: Vec::new(),
            });
        }

        let mut entries = Vec::new();
        let mut common_prefixes = Vec::new();
        let mut last_cp: Option<String> = None;
        let mut is_truncated = false;
        let mut next_km = None;
        let mut next_vm = None;

        'outer: for (key, chain) in &b.objects {
            if !key.starts_with(&req.prefix) {
                continue;
            }
            if !km.is_empty() && key.as_str() < km.as_str() {
                continue;
            }
            let rest = &key[req.prefix.len()..];
            if let Some(delim) = req.delimiter.as_deref().filter(|d| !d.is_empty()) {
                if let Some(pos) = rest.find(delim) {
                    let cp = format!("{}{}", req.prefix, &rest[..pos + delim.len()]);
                    if !km.is_empty() && cp.as_str() <= km.as_str() {
                        continue;
                    }
                    if last_cp.as_deref() == Some(cp.as_str()) {
                        continue;
                    }
                    if entries.len() + common_prefixes.len() == max_keys {
                        is_truncated = true;
                        break;
                    }
                    next_km = Some(cp.clone());
                    next_vm = None;
                    last_cp = Some(cp.clone());
                    common_prefixes.push(cp);
                    continue;
                }
            }

            let mut skip_until_marker = !km.is_empty() && key == &km;
            for (idx, v) in chain.iter().enumerate() {
                let vid_str = v.version_id.as_deref().unwrap_or("null").to_string();
                if skip_until_marker {
                    if vm.is_empty() {
                        continue 'outer;
                    }
                    if vid_str == vm {
                        skip_until_marker = false;
                    }
                    continue;
                }
                if entries.len() + common_prefixes.len() == max_keys {
                    is_truncated = true;
                    break 'outer;
                }
                next_km = Some(key.clone());
                next_vm = Some(vid_str.clone());
                entries.push(VersionListEntry {
                    key: key.clone(),
                    version_id: vid_str,
                    is_latest: idx == 0,
                    is_delete_marker: v.is_delete_marker,
                    last_modified_ms: v.last_modified_ms,
                    etag: v.etag.clone(),
                    size: v.data.len() as u64,
                    owner: v.owner.clone(),
                });
            }
        }

        if !is_truncated {
            next_km = None;
            next_vm = None;
        }

        Ok(ListObjectVersionsResp {
            name: req.bucket,
            prefix: req.prefix,
            key_marker: km,
            version_id_marker: vm,
            next_key_marker: next_km,
            next_version_id_marker: next_vm,
            max_keys,
            delimiter: req.delimiter,
            is_truncated,
            entries,
            common_prefixes,
        })
    }
}

impl ModelStore {
    fn read_internal(
        &self,
        req: &GetObjectReq,
        need_bytes: bool,
    ) -> StoreResult<(ObjectMetaSnapshot, Bytes)> {
        validate_object_key(&req.bucket, &req.key)?;
        if req.range.is_some() && req.part_number.is_some() {
            return Err(S3Error::new(
                S3ErrorCode::InvalidRequest,
                "Cannot specify both Range header and partNumber query parameter",
            ));
        }

        let guard = self.state.lock().unwrap();
        let b = check_bucket_access(&guard, &req.ctx, &req.bucket)?;
        let ver = match &req.version_id {
            None => {
                let Some(head) = b.objects.get(&req.key).and_then(|c| c.first()) else {
                    return Err(S3Error::new(
                        S3ErrorCode::NoSuchKey,
                        "The specified key does not exist.",
                    )
                    .with_key(&req.bucket, &req.key));
                };
                if head.is_delete_marker {
                    // [FR-37] Current version is delete marker -> 404 + x-amz-delete-marker: true
                    let mut err = S3Error::new(
                        S3ErrorCode::NoSuchKey,
                        "The specified key does not exist.",
                    )
                    .with_key(&req.bucket, &req.key)
                    .with_header("x-amz-delete-marker", "true");
                    if let Some(vid) = &head.version_id {
                        err = err.with_header("x-amz-version-id", vid.clone());
                    }
                    return Err(err);
                }
                head
            }
            Some(vid) => {
                let Some(found) = b.objects.get(&req.key).and_then(|c| {
                    c.iter()
                        .find(|v| v.version_id.as_deref().unwrap_or("null") == vid.as_str())
                }) else {
                    return Err(S3Error::new(
                        S3ErrorCode::NoSuchVersion,
                        "The specified version does not exist.",
                    )
                    .with_key(&req.bucket, &req.key));
                };
                if found.is_delete_marker {
                    // [FR-37] GET/HEAD on delete marker with versionId -> 405 MethodNotAllowed
                    return Err(S3Error::new(
                        S3ErrorCode::MethodNotAllowed,
                        "The specified method is not allowed against this resource.",
                    )
                    .with_header("x-amz-delete-marker", "true")
                    .with_header("Allow", "DELETE"));
                }
                found
            }
        };

        let last_mod_http = httpdate::fmt_http_date(
            std::time::UNIX_EPOCH
                + std::time::Duration::from_millis(ver.last_modified_ms.max(0) as u64),
        );
        evaluate_read_preconditions(
            &req.preconditions,
            &ver.etag,
            ver.last_modified_ms,
            &last_mod_http,
        )?;

        let total_size = ver.data.len() as u64;
        let (start, end, is_partial, parts_count) = if let Some(pn) = req.part_number {
            // [FR-10] partNumber reading
            if pn == 0 || pn > 10_000 {
                return Err(S3Error::new(
                    S3ErrorCode::InvalidArgument,
                    "Part number must be an integer between 1 and 10000, inclusive",
                ));
            }
            match &ver.part_sizes {
                None => {
                    if pn != 1 {
                        return Err(S3Error::new(
                            S3ErrorCode::InvalidPart,
                            "The requested partnumber is not satisfiable",
                        ));
                    }
                    if total_size == 0 {
                        (0, 0, false, Some(1))
                    } else {
                        (0, total_size - 1, true, Some(1))
                    }
                }
                Some(sizes) => {
                    if (pn as usize) > sizes.len() {
                        return Err(S3Error::new(
                            S3ErrorCode::InvalidPart,
                            "The requested partnumber is not satisfiable",
                        ));
                    }
                    let offset: u64 = sizes[..(pn as usize - 1)].iter().sum();
                    let len = sizes[pn as usize - 1];
                    if len == 0 {
                        (offset, offset, false, Some(sizes.len() as u32))
                    } else {
                        (offset, offset + len - 1, true, Some(sizes.len() as u32))
                    }
                }
            }
        } else if let Some(range_spec) = req.range {
            let (s, e) = range_spec.resolve(total_size)?;
            (s, e, true, None)
        } else if total_size == 0 {
            (0, 0, false, None)
        } else {
            (0, total_size - 1, false, None)
        };

        let content_len = if total_size == 0 && !is_partial {
            0
        } else if is_partial && total_size > 0 {
            end - start + 1
        } else {
            total_size
        };

        let content_range = if is_partial && total_size > 0 {
            Some((start, end, total_size))
        } else {
            None
        };

        // [PR-24] Checksum returned only when checksum_mode == ENABLED and reading full object
        let is_full = content_len == total_size;
        let checksum = if req.checksum_mode_enabled && is_full {
            Some(ver.checksum.clone())
        } else {
            None
        };

        let slice = if need_bytes && content_len > 0 {
            ver.data.slice(start as usize..(end as usize + 1))
        } else {
            Bytes::new()
        };

        let meta = ObjectMetaSnapshot {
            bucket: req.bucket.clone(),
            key: req.key.clone(),
            version_id: ver.version_id.clone(),
            is_delete_marker: false,
            total_object_size: total_size,
            content_length: content_len,
            content_range,
            etag: ver.etag.clone(),
            last_modified_ms: ver.last_modified_ms,
            owner: ver.owner.clone(),
            sys_meta: ver.sys_meta.clone(),
            user_meta: ver.user_meta.clone(),
            checksum,
            parts_count,
        };
        Ok((meta, slice))
    }
}

/// Convenience helper for constructing a `VerifiedBodyStream` from in-memory `Bytes` (used in tests & VR-2).
pub struct InMemoryVerifiedStream {
    remaining: Bytes,
    chunk_size: usize,
    total_bytes: u64,
    md5: [u8; 16],
    checksum: ChecksumState,
    inject_end_err: Option<BodyStreamError>,
}

impl InMemoryVerifiedStream {
    pub fn from_bytes(data: impl Into<Bytes>, alg: Option<ChecksumAlgorithm>) -> Self {
        let b: Bytes = data.into();
        let md5: [u8; 16] = Md5::digest(&b).into();
        let (chosen_alg, client_req) = match alg {
            Some(a) => (a, true),
            None => (ChecksumAlgorithm::Crc64Nvme, false),
        };
        let value_b64 = compute_checksum_b64(chosen_alg, &b);
        Self {
            total_bytes: b.len() as u64,
            remaining: b,
            chunk_size: 64 * 1024,
            md5,
            checksum: ChecksumState {
                algorithm: chosen_alg,
                checksum_type: ChecksumType::FullObject,
                value_b64,
                client_requested: client_req,
            },
            inject_end_err: None,
        }
    }

    pub fn with_injected_error(mut self, err: BodyStreamError) -> Self {
        self.inject_end_err = Some(err);
        self
    }
}

impl VerifiedBodyStream for InMemoryVerifiedStream {
    fn poll_next_chunk(
        &mut self,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<Option<Bytes>, BodyStreamError>> {
        if self.remaining.is_empty() {
            return std::task::Poll::Ready(Ok(None));
        }
        let n = self.remaining.len().min(self.chunk_size);
        let chunk = self.remaining.split_to(n);
        std::task::Poll::Ready(Ok(Some(chunk)))
    }

    fn finish(&mut self) -> Result<VerifiedDigests, BodyStreamError> {
        if let Some(err) = self.inject_end_err.take() {
            return Err(err);
        }
        Ok(VerifiedDigests {
            total_bytes: self.total_bytes,
            md5: self.md5,
            checksum: self.checksum.clone(),
        })
    }
}

pub fn compute_checksum_b64(alg: ChecksumAlgorithm, bytes: &[u8]) -> String {
    let b64 = base64::engine::general_purpose::STANDARD;
    match alg {
        ChecksumAlgorithm::Crc32 => {
            let mut h = Crc32Hasher::new();
            h.update(bytes);
            b64.encode(h.finalize().to_be_bytes())
        }
        ChecksumAlgorithm::Crc32c => b64.encode(crc32c::crc32c(bytes).to_be_bytes()),
        ChecksumAlgorithm::Crc64Nvme => {
            let mut d = crc64fast_nvme::Digest::new();
            d.write(bytes);
            b64.encode(d.sum64().to_be_bytes())
        }
        ChecksumAlgorithm::Sha1 => b64.encode(Sha1::digest(bytes)),
        ChecksumAlgorithm::Sha256 => b64.encode(Sha256::digest(bytes)),
    }
}
