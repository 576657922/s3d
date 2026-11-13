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
use sha2::{Sha256, Sha512};
use xxhash_rust::xxh3::Xxh3;
use xxhash_rust::xxh64::Xxh64;

#[derive(Debug, Clone)]
pub struct ModelConfig {
    pub region: String,
    pub max_buckets_per_account: usize,
    pub default_object_ownership: ObjectOwnership,
    pub max_object_size: u64,
    pub completed_upload_retention_ms: i64,
}

impl Default for ModelConfig {
    fn default() -> Self {
        Self {
            region: "us-east-1".to_string(),
            max_buckets_per_account: 10_000,
            default_object_ownership: ObjectOwnership::BucketOwnerEnforced,
            max_object_size: DEFAULT_MAX_OBJECT_BYTES,
            completed_upload_retention_ms: 24 * 60 * 60 * 1000,
        }
    }
}

#[derive(Debug, Clone)]
struct ModelPartBoundary {
    part_number: u32,
    size: u64,
    checksum: Option<(ChecksumAlgorithm, String)>,
    sse_iv: Option<[u8; 16]>,
}

#[derive(Debug, Clone)]
struct ModelVersion {
    seq: u64,
    version_id: Option<String>,
    is_delete_marker: bool,
    data: Bytes,
    etag: String,
    checksum: ChecksumState,
    sys_meta: SystemMeta,
    user_meta: Vec<(String, String)>,
    owner: OwnerInfo,
    acl: AccessControlPolicy,
    tags: BTreeMap<String, String>,
    last_modified_ms: i64,
    parts: Option<Vec<ModelPartBoundary>>,
    sse: SseStoredMeta,
    retention: Option<ObjectRetention>,
    legal_hold: Option<LegalHoldStatus>,
}

#[derive(Debug, Clone)]
struct ModelUploadPart {
    part_number: u32,
    last_modified_ms: i64,
    etag: String,
    data: Bytes,
    md5: [u8; 16],
    checksum: Option<(ChecksumAlgorithm, String)>,
    sse_iv: Option<[u8; 16]>,
}

#[derive(Debug, Clone)]
struct ModelMultipartUpload {
    initiator: OwnerInfo,
    owner: OwnerInfo,
    acl: AccessControlPolicy,
    initiated_ms: i64,
    sys_meta: SystemMeta,
    user_meta: Vec<(String, String)>,
    tags: BTreeMap<String, String>,
    checksum_algorithm: Option<ChecksumAlgorithm>,
    checksum_type: Option<ChecksumType>,
    sse: SseStoredMeta,
    retention: Option<ObjectRetention>,
    legal_hold: Option<LegalHoldStatus>,
    parts: BTreeMap<u32, ModelUploadPart>,
}

#[derive(Debug, Clone)]
struct ModelBucket {
    name: String,
    owner: OwnerInfo,
    acl: AccessControlPolicy,
    region: String,
    created_ms: i64,
    versioning: VersioningStatus,
    explicit_ownership: Option<ObjectOwnership>,
    tags: BTreeMap<String, String>,
    cors: Option<CorsConfiguration>,
    policy: Option<BucketPolicyDoc>,
    public_access_block: Option<PublicAccessBlockConfig>,
    object_lock_enabled: bool,
    object_lock_config: Option<ObjectLockConfiguration>,
    lifecycle: Option<LifecycleConfiguration>,
    encryption: Option<BucketEncryptionConfig>,
    logging: Option<BucketLoggingStatus>,
    objects: BTreeMap<String, Vec<ModelVersion>>, // key -> newest-first versions
    uploads: BTreeMap<(String, String), ModelMultipartUpload>, // (key, upload_id) -> upload
    completed_uploads: BTreeMap<(String, String), (i64, CompleteMultipartUploadResp)>,
}

impl ModelBucket {
    fn effective_ownership(&self, default_ownership: ObjectOwnership) -> ObjectOwnership {
        self.explicit_ownership.unwrap_or(default_ownership)
    }

    fn auth_view(&self, default_ownership: ObjectOwnership) -> BucketAuthView<'_> {
        BucketAuthView {
            name: &self.name,
            owner: &self.owner,
            acl: &self.acl,
            ownership: self.effective_ownership(default_ownership),
            policy: self.policy.as_ref(),
            public_access_block: self.public_access_block.as_ref(),
        }
    }
}

#[derive(Default, Clone)]
struct ModelState {
    next_seq: u64,
    buckets: BTreeMap<String, ModelBucket>,
}

pub struct ModelStore {
    cfg: ModelConfig,
    sse_s3_master_key: [u8; 32],
    state: Mutex<ModelState>,
}

impl Clone for ModelStore {
    fn clone(&self) -> Self {
        let snap = self.state.lock().unwrap().clone();
        Self {
            cfg: self.cfg.clone(),
            sse_s3_master_key: self.sse_s3_master_key,
            state: Mutex::new(snap),
        }
    }
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
            sse_s3_master_key: derive_sse_s3_master_key(b"s3d-model-uuid01"),
            state: Mutex::new(ModelState::default()),
        }
    }
}

fn model_make_iv(seq: u64, sub: u32) -> [u8; 16] {
    let mut iv = [0u8; 16];
    iv[0..8].copy_from_slice(&seq.to_be_bytes());
    iv[8..12].copy_from_slice(&sub.to_be_bytes());
    iv[12..16].copy_from_slice(&0xA55A_33C3u32.to_be_bytes());
    iv
}

fn decrypt_model_version_slice(
    ver: &ModelVersion,
    key_iv: Option<([u8; 32], [u8; 16])>,
    start: u64,
    end_excl: u64,
) -> Bytes {
    if start >= end_excl {
        return Bytes::new();
    }
    let Some((key, ver_iv)) = key_iv else {
        return ver.data.slice(start as usize..end_excl as usize);
    };
    let mut out = ver.data[start as usize..end_excl as usize].to_vec();
    if let Some(parts) = &ver.parts {
        let cipher = Aes256Cipher::new(&key);
        let mut p_off = 0u64;
        for p in parts {
            let p_end = p_off + p.size;
            let ov_s = start.max(p_off);
            let ov_e = end_excl.min(p_end);
            if ov_s < ov_e {
                let dst_s = (ov_s - start) as usize;
                let dst_e = (ov_e - start) as usize;
                let p_iv = p.sse_iv.unwrap_or(ver_iv);
                aes256_ctr_xor_with_cipher(&cipher, &p_iv, ov_s - p_off, &mut out[dst_s..dst_e]);
            }
            p_off = p_end;
            if p_off >= end_excl {
                break;
            }
        }
    } else {
        aes256_ctr_xor(&key, &ver_iv, start, &mut out);
    }
    Bytes::from(out)
}

fn can_bypass_governance_model(
    bucket: &ModelBucket,
    default_ownership: ObjectOwnership,
    ctx: &CallerContext,
    key: &str,
    existing_tags: Option<&BTreeMap<String, String>>,
) -> bool {
    let view = bucket.auth_view(default_ownership);
    let extra = PolicyEvalExtra {
        existing_object_tags: existing_tags,
        ..Default::default()
    };
    authorize_object_action(
        &view,
        ctx,
        key,
        &[S3Action::BypassGovernanceRetention],
        Some(&bucket.owner),
        None,
        true,
        &extra,
    )
}

fn require_authenticated(ctx: &CallerContext) -> StoreResult<&OwnerInfo> {
    ctx.caller
        .as_ref()
        .filter(|_| ctx.is_authenticated)
        .ok_or_else(|| S3Error::new(S3ErrorCode::AccessDenied, "Access Denied"))
}

fn lookup_bucket_checked<'a>(
    state: &'a ModelState,
    ctx: &CallerContext,
    bucket_name: &str,
) -> StoreResult<&'a ModelBucket> {
    let bucket = state.buckets.get(bucket_name).ok_or_else(|| {
        S3Error::new(S3ErrorCode::NoSuchBucket, "The specified bucket does not exist")
            .with_bucket(bucket_name)
    })?;
    // [PR-29] Expected bucket owner header verification (applies to authenticated and anonymous callers)
    if let Some(expected) = &ctx.expected_bucket_owner
        && expected != &bucket.owner.user_id {
            return Err(S3Error::new(S3ErrorCode::AccessDenied, "Access Denied")
                .with_bucket(bucket_name));
        }
    Ok(bucket)
}

fn check_bucket_action<'a>(
    state: &'a ModelState,
    default_ownership: ObjectOwnership,
    ctx: &CallerContext,
    bucket_name: &str,
    actions: &[S3Action],
    acl_needed: Option<AclPermission>,
    extra: &PolicyEvalExtra<'_>,
) -> StoreResult<&'a ModelBucket> {
    let bucket = lookup_bucket_checked(state, ctx, bucket_name)?;
    let view = bucket.auth_view(default_ownership);
    if !authorize_bucket_action(&view, ctx, actions, acl_needed, extra) {
        return Err(
            S3Error::new(S3ErrorCode::AccessDenied, "Access Denied").with_bucket(bucket_name)
        );
    }
    Ok(bucket)
}

fn check_bucket_write_object<'a>(
    state: &'a ModelState,
    default_ownership: ObjectOwnership,
    ctx: &CallerContext,
    bucket_name: &str,
    key: &str,
    req_tags: Option<&BTreeMap<String, String>>,
) -> StoreResult<&'a ModelBucket> {
    let bucket = lookup_bucket_checked(state, ctx, bucket_name)?;
    let view = bucket.auth_view(default_ownership);
    let extra = PolicyEvalExtra {
        request_object_tags: req_tags,
        ..Default::default()
    };
    // If tags are attached on Put/Post/Multipart/Copy, an explicit Deny on PutObjectTagging rejects it.
    if req_tags.is_some_and(|t| !t.is_empty())
        && let Some(pol) = view.policy {
            let arn = format!("arn:aws:s3:::{bucket_name}/{key}");
            if pol.evaluate(ctx, &[S3Action::PutObjectTagging], &arn, &extra)
                == PolicyDecision::ExplicitDeny
            {
                return Err(S3Error::new(S3ErrorCode::AccessDenied, "Access Denied")
                    .with_key(bucket_name, key));
            }
        }
    if !authorize_object_action(
        &view,
        ctx,
        key,
        &[S3Action::PutObject],
        Some(&bucket.owner),
        Some((&bucket.acl, AclPermission::Write)),
        true,
        &extra,
    ) {
        return Err(
            S3Error::new(S3ErrorCode::AccessDenied, "Access Denied").with_key(bucket_name, key)
        );
    }
    Ok(bucket)
}

fn has_upload_perm(
    bucket: &ModelBucket,
    default_ownership: ObjectOwnership,
    key: &str,
    up: &ModelMultipartUpload,
    ctx: &CallerContext,
    actions: &[S3Action],
    needed: AclPermission,
) -> bool {
    let view = bucket.auth_view(default_ownership);
    let arn = format!("arn:aws:s3:::{}/{key}", bucket.name);
    let extra = PolicyEvalExtra::default();
    if let Some(pol) = view.policy {
        match pol.evaluate(ctx, actions, &arn, &extra) {
            PolicyDecision::ExplicitDeny => return false,
            PolicyDecision::ExplicitAllow {
                via_public_statement,
            } => {
                if !(view.restrict_public_buckets()
                    && via_public_statement
                    && !view.is_caller_bucket_owner(ctx))
                {
                    return true;
                }
            }
            PolicyDecision::ImplicitDeny => {}
        }
    }
    let is_initiator = ctx.is_authenticated
        && ctx
            .caller
            .as_ref()
            .is_some_and(|c| c.user_id == up.initiator.user_id);
    if is_initiator || view.is_caller_bucket_owner(ctx) {
        return true;
    }
    authorize_object_action(
        &view,
        ctx,
        key,
        actions,
        Some(&bucket.owner),
        Some((&bucket.acl, needed)),
        true,
        &extra,
    )
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

fn strip_etag_quotes(s: &str) -> &str {
    s.trim().trim_matches('"')
}

fn encode_token(bucket: &str, key: &str) -> String {
    let raw = format!("v1:{bucket}:{key}");
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw.as_bytes())
}

// [FR-42] Opaque V2 continuation-token integrity check; tampering returns 400 InvalidArgument
fn decode_token(bucket: &str, token: &str) -> StoreResult<String> {
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(token)
        .map_err(|_| {
            S3Error::new(
                S3ErrorCode::InvalidArgument,
                "The continuation token provided is incorrect",
            )
        })?;
    let s = std::str::from_utf8(&bytes).map_err(|_| {
        S3Error::new(
            S3ErrorCode::InvalidArgument,
            "The continuation token provided is incorrect",
        )
    })?;
    let prefix = format!("v1:{bucket}:");
    s.strip_prefix(&prefix).map(|k| k.to_string()).ok_or_else(|| {
        S3Error::new(
            S3ErrorCode::InvalidArgument,
            "The continuation token provided is incorrect",
        )
    })
}

fn compute_composite_checksum_b64(alg: ChecksumAlgorithm, part_b64s: &[String]) -> StoreResult<String> {
    let b64 = base64::engine::general_purpose::STANDARD;
    let mut raw_concat = Vec::new();
    for p in part_b64s {
        let decoded = b64
            .decode(p.trim())
            .map_err(|_| S3Error::new(S3ErrorCode::BadDigest, "Invalid part checksum encoding"))?;
        raw_concat.extend_from_slice(&decoded);
    }
    let outer = compute_checksum_b64(alg, &raw_concat);
    Ok(format!("{outer}-{}", part_b64s.len()))
}

fn insert_version_into_chain(
    versioning: VersioningStatus,
    chain: &mut Vec<ModelVersion>,
    ver: ModelVersion,
) {
    match versioning {
        VersioningStatus::Unversioned => {
            chain.clear();
            chain.push(ver);
        }
        VersioningStatus::Suspended => {
            // [FR-34] Versioning Suspended writes "null" versionId and replaces any prior "null" version
            chain.retain(|v| v.version_id.as_deref().unwrap_or("null") != "null");
            chain.insert(0, ver);
        }
        VersioningStatus::Enabled => {
            chain.insert(0, ver);
        }
    }
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

    // [FR-39, FR-43, FR-45] Lexicographical UTF-8 BTreeMap scan over strongly-consistent committed
    // state; raw UTF-8 keys/prefixes are returned here and URL-encoded by s3d-proto when encoding-type=url.
    for (key, chain) in objects {
        if !key.starts_with(prefix) {
            continue;
        }
        let Some(head) = chain.first() else { continue };
        if head.is_delete_marker {
            continue;
        }
        if let Some(after) = after_key
            && key.as_str() <= after {
                continue;
            }

        let rest = &key[prefix.len()..];
        // [FR-40] Arbitrary delimiter folding into deduplicated CommonPrefixes counted toward max-keys
        if let Some(delim) = delimiter.filter(|d| !d.is_empty())
            && let Some(pos) = rest.find(delim) {
                let cp = format!("{}{}", prefix, &rest[..pos + delim.len()]);
                if let Some(after) = after_key
                    && cp.as_str() <= after {
                        continue;
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
        if let Some(max) = req.max_buckets
            && !(1..=10_000).contains(&max) {
                return Err(S3Error::new(
                    S3ErrorCode::InvalidArgument,
                    "max-buckets must be between 1 and 10000",
                ));
            }
        let after = match &req.continuation_token {
            Some(tok) if !tok.is_empty() => Some(decode_token("__buckets__", tok)?),
            _ => None,
        };
        let max = req.max_buckets.unwrap_or(10_000);
        let guard = self.state.lock().unwrap();
        let mut buckets = Vec::new();
        let mut next_token = None;
        for b in guard.buckets.values() {
            if b.owner.user_id != caller.user_id {
                continue;
            }
            if let Some(pfx) = &req.prefix
                && !b.name.starts_with(pfx) {
                    continue;
                }
            if let Some(after_name) = &after
                && &b.name <= after_name {
                    continue;
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

        if let Some(loc) = &req.location_constraint
            && !loc.is_empty() && loc != &self.cfg.region {
                return Err(S3Error::new(
                    S3ErrorCode::InvalidLocationConstraint,
                    "The specified location-constraint is not valid",
                )
                .with_bucket(&req.bucket));
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

        // [FR-51] Configurable default ObjectOwnership (BucketOwnerEnforced vs ObjectWriter)
        let ownership = req
            .object_ownership
            .unwrap_or(self.cfg.default_object_ownership);
        let acl = if ownership == ObjectOwnership::BucketOwnerEnforced {
            if let Some(spec) = &req.acl
                && !matches!(spec, AclSpec::Canned(CannedAcl::Private)) {
                    return Err(S3Error::new(
                        S3ErrorCode::InvalidBucketAclWithObjectOwnership,
                        "Bucket cannot have ACLs set with ObjectOwnership's BucketOwnerEnforced setting",
                    )
                    .with_bucket(&req.bucket));
                }
            AccessControlPolicy::new_private(caller.clone())
        } else {
            match &req.acl {
                None => AccessControlPolicy::new_private(caller.clone()),
                Some(spec) => resolve_target_acl(&caller, Some(&caller), spec)?,
            }
        };

        let explicit_ownership = match req.object_ownership {
            Some(own) => Some(own),
            None if self.cfg.default_object_ownership == ObjectOwnership::BucketOwnerEnforced => {
                Some(ObjectOwnership::BucketOwnerEnforced)
            }
            None => None,
        };
        let initial_versioning = if req.object_lock_enabled {
            VersioningStatus::Enabled
        } else {
            VersioningStatus::Unversioned
        };
        let b = ModelBucket {
            name: req.bucket.clone(),
            owner: caller,
            acl,
            region: self.cfg.region.clone(),
            created_ms: req.ctx.request_time_ms,
            versioning: initial_versioning,
            explicit_ownership,
            tags: BTreeMap::new(),
            cors: None,
            policy: None,
            public_access_block: None,
            object_lock_enabled: req.object_lock_enabled,
            object_lock_config: req
                .object_lock_enabled
                .then_some(ObjectLockConfiguration::default()),
            lifecycle: None,
            encryption: None,
            logging: None,
            objects: BTreeMap::new(),
            uploads: BTreeMap::new(),
            completed_uploads: BTreeMap::new(),
        };
        let snap = BucketMetaSnapshot {
            name: b.name.clone(),
            owner: b.owner.clone(),
            region: b.region.clone(),
            created_ms: b.created_ms,
            versioning: b.versioning,
            ownership,
        };
        guard.buckets.insert(req.bucket, b);
        Ok(snap)
    }

    async fn head_bucket(&self, req: BucketRef) -> StoreResult<BucketMetaSnapshot> {
        let guard = self.state.lock().unwrap();
        let b = check_bucket_action(
            &guard,
            self.cfg.default_object_ownership,
            &req.ctx,
            &req.bucket,
            &[S3Action::ListBucket],
            Some(AclPermission::Read),
            &PolicyEvalExtra::default(),
        )?;
        Ok(BucketMetaSnapshot {
            name: b.name.clone(),
            owner: b.owner.clone(),
            region: b.region.clone(),
            created_ms: b.created_ms,
            versioning: b.versioning,
            ownership: b.effective_ownership(self.cfg.default_object_ownership),
        })
    }

    async fn delete_bucket(&self, req: BucketRef) -> StoreResult<()> {
        let mut guard = self.state.lock().unwrap();
        let b = check_bucket_action(
            &guard,
            self.cfg.default_object_ownership,
            &req.ctx,
            &req.bucket,
            &[S3Action::DeleteBucket],
            None,
            &PolicyEvalExtra::default(),
        )?;
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

    async fn get_bucket_versioning(&self, req: BucketRef) -> StoreResult<VersioningStatus> {
        let guard = self.state.lock().unwrap();
        let b = check_bucket_action(
            &guard,
            self.cfg.default_object_ownership,
            &req.ctx,
            &req.bucket,
            &[S3Action::GetBucketVersioning],
            None,
            &PolicyEvalExtra::default(),
        )?;
        Ok(b.versioning)
    }

    async fn put_bucket_versioning(&self, req: PutBucketVersioningReq) -> StoreResult<()> {
        // [FR-32] Unversioned -> Enabled <-> Suspended; cannot return to Unversioned
        if req.status == VersioningStatus::Unversioned {
            return Err(S3Error::new(
                S3ErrorCode::MalformedXML,
                "Invalid versioning status.",
            ));
        }
        let mut guard = self.state.lock().unwrap();
        let _ = check_bucket_action(
            &guard,
            self.cfg.default_object_ownership,
            &req.ctx,
            &req.bucket,
            &[S3Action::PutBucketVersioning],
            None,
            &PolicyEvalExtra::default(),
        )?;
        let b = guard.buckets.get_mut(&req.bucket).unwrap();
        if b.object_lock_enabled && req.status == VersioningStatus::Suspended {
            return Err(S3Error::new(
                S3ErrorCode::InvalidBucketState,
                "An Object Lock configuration is present on this bucket, so the versioning state cannot be changed.",
            )
            .with_bucket(&req.bucket));
        }
        b.versioning = req.status;
        Ok(())
    }

    async fn get_bucket_acl(&self, req: BucketRef) -> StoreResult<AccessControlPolicy> {
        let guard = self.state.lock().unwrap();
        let b = check_bucket_action(
            &guard,
            self.cfg.default_object_ownership,
            &req.ctx,
            &req.bucket,
            &[S3Action::GetBucketAcl],
            Some(AclPermission::ReadAcp),
            &PolicyEvalExtra::default(),
        )?;
        Ok(b.acl.clone())
    }

    async fn put_bucket_acl(&self, req: PutBucketAclReq) -> StoreResult<()> {
        let mut guard = self.state.lock().unwrap();
        let b = check_bucket_action(
            &guard,
            self.cfg.default_object_ownership,
            &req.ctx,
            &req.bucket,
            &[S3Action::PutBucketAcl],
            Some(AclPermission::WriteAcp),
            &PolicyEvalExtra::default(),
        )?;
        if b.effective_ownership(self.cfg.default_object_ownership)
            == ObjectOwnership::BucketOwnerEnforced
        {
            return Err(S3Error::new(
                S3ErrorCode::AccessControlListNotSupported,
                "The bucket does not allow ACLs",
            )
            .with_bucket(&req.bucket));
        }
        enforce_block_public_acl_spec(
            b.auth_view(self.cfg.default_object_ownership)
                .block_public_acls(),
            Some(&req.acl),
        )
        .map_err(|e| e.with_bucket(&req.bucket))?;
        let new_acl = resolve_target_acl(&b.owner, Some(&b.owner), &req.acl)?;
        guard.buckets.get_mut(&req.bucket).unwrap().acl = new_acl;
        Ok(())
    }

    async fn get_object_acl(&self, req: GetObjectAclReq) -> StoreResult<GetObjectAclResp> {
        validate_object_key(&req.bucket, &req.key)?;
        let guard = self.state.lock().unwrap();
        let b = lookup_bucket_checked(&guard, &req.ctx, &req.bucket)?;
        let actions: &[S3Action] = if req.version_id.is_some() {
            &[S3Action::GetObjectVersionAcl, S3Action::GetObjectAcl]
        } else {
            &[S3Action::GetObjectAcl]
        };
        let ver = self.lookup_version_for_op_checked(
            b,
            &req.ctx,
            &req.bucket,
            &req.key,
            req.version_id.as_deref(),
            actions,
            Some(AclPermission::ReadAcp),
            None,
        )?;
        Ok(GetObjectAclResp {
            version_id: ver.version_id.clone().filter(|v| v != "null"),
            policy: ver.acl.clone(),
        })
    }

    async fn put_object_acl(&self, req: PutObjectAclReq) -> StoreResult<Option<String>> {
        validate_object_key(&req.bucket, &req.key)?;
        let mut guard = self.state.lock().unwrap();
        let b_ro = lookup_bucket_checked(&guard, &req.ctx, &req.bucket)?;
        let actions: &[S3Action] = if req.version_id.is_some() {
            &[S3Action::PutObjectVersionAcl, S3Action::PutObjectAcl]
        } else {
            &[S3Action::PutObjectAcl]
        };
        let (target_seq, ver_owner, vid_out) = {
            let ver = self.lookup_version_for_op_checked(
                b_ro,
                &req.ctx,
                &req.bucket,
                &req.key,
                req.version_id.as_deref(),
                actions,
                Some(AclPermission::WriteAcp),
                None,
            )?;
            (
                ver.seq,
                ver.owner.clone(),
                ver.version_id.clone().filter(|v| v != "null"),
            )
        };
        if b_ro.effective_ownership(self.cfg.default_object_ownership)
            == ObjectOwnership::BucketOwnerEnforced
        {
            return Err(S3Error::new(
                S3ErrorCode::AccessControlListNotSupported,
                "The bucket does not allow ACLs",
            )
            .with_bucket(&req.bucket));
        }
        enforce_block_public_acl_spec(
            b_ro.auth_view(self.cfg.default_object_ownership)
                .block_public_acls(),
            Some(&req.acl),
        )
        .map_err(|e| e.with_key(&req.bucket, &req.key))?;
        let new_acl = resolve_target_acl(&ver_owner, Some(&b_ro.owner), &req.acl)?;
        let b = guard.buckets.get_mut(&req.bucket).unwrap();
        if let Some(chain) = b.objects.get_mut(&req.key)
            && let Some(v) = chain.iter_mut().find(|v| v.seq == target_seq) {
                v.acl = new_acl;
            }
        Ok(vid_out)
    }

    async fn get_bucket_ownership_controls(
        &self,
        req: BucketRef,
    ) -> StoreResult<ObjectOwnership> {
        let guard = self.state.lock().unwrap();
        let b = check_bucket_action(
            &guard,
            self.cfg.default_object_ownership,
            &req.ctx,
            &req.bucket,
            &[S3Action::GetBucketOwnershipControls],
            None,
            &PolicyEvalExtra::default(),
        )?;
        b.explicit_ownership.ok_or_else(|| {
            S3Error::new(
                S3ErrorCode::OwnershipControlsNotFoundError,
                "The bucket ownership controls were not found",
            )
            .with_bucket(&req.bucket)
        })
    }

    async fn put_bucket_ownership_controls(
        &self,
        req: PutBucketOwnershipControlsReq,
    ) -> StoreResult<()> {
        let mut guard = self.state.lock().unwrap();
        let b = check_bucket_action(
            &guard,
            self.cfg.default_object_ownership,
            &req.ctx,
            &req.bucket,
            &[S3Action::PutBucketOwnershipControls],
            None,
            &PolicyEvalExtra::default(),
        )?;
        if req.ownership == ObjectOwnership::BucketOwnerEnforced
            && !b.acl.is_default_private_for(&b.owner)
        {
            return Err(S3Error::new(
                S3ErrorCode::InvalidBucketAclWithObjectOwnership,
                "Bucket cannot have ACLs set with ObjectOwnership's BucketOwnerEnforced setting",
            )
            .with_bucket(&req.bucket));
        }
        guard.buckets.get_mut(&req.bucket).unwrap().explicit_ownership = Some(req.ownership);
        Ok(())
    }

    async fn delete_bucket_ownership_controls(&self, req: BucketRef) -> StoreResult<()> {
        let mut guard = self.state.lock().unwrap();
        let _ = check_bucket_action(
            &guard,
            self.cfg.default_object_ownership,
            &req.ctx,
            &req.bucket,
            &[S3Action::PutBucketOwnershipControls],
            None,
            &PolicyEvalExtra::default(),
        )?;
        guard.buckets.get_mut(&req.bucket).unwrap().explicit_ownership = None;
        Ok(())
    }

    async fn get_bucket_tagging(&self, req: BucketRef) -> StoreResult<BTreeMap<String, String>> {
        let guard = self.state.lock().unwrap();
        let b = check_bucket_action(
            &guard,
            self.cfg.default_object_ownership,
            &req.ctx,
            &req.bucket,
            &[S3Action::GetBucketTagging],
            None,
            &PolicyEvalExtra::default(),
        )?;
        if b.tags.is_empty() {
            return Err(S3Error::new(
                S3ErrorCode::NoSuchTagSet,
                "The TagSet does not exist",
            )
            .with_bucket(&req.bucket));
        }
        Ok(b.tags.clone())
    }

    async fn put_bucket_tagging(&self, req: PutBucketTaggingReq) -> StoreResult<()> {
        let mut guard = self.state.lock().unwrap();
        let _ = check_bucket_action(
            &guard,
            self.cfg.default_object_ownership,
            &req.ctx,
            &req.bucket,
            &[S3Action::PutBucketTagging],
            None,
            &PolicyEvalExtra::default(),
        )?;
        guard.buckets.get_mut(&req.bucket).unwrap().tags = req.tags;
        Ok(())
    }

    async fn delete_bucket_tagging(&self, req: BucketRef) -> StoreResult<()> {
        let mut guard = self.state.lock().unwrap();
        let _ = check_bucket_action(
            &guard,
            self.cfg.default_object_ownership,
            &req.ctx,
            &req.bucket,
            &[S3Action::PutBucketTagging],
            None,
            &PolicyEvalExtra::default(),
        )?;
        guard.buckets.get_mut(&req.bucket).unwrap().tags.clear();
        Ok(())
    }

    async fn get_object_tagging(&self, req: ObjectTaggingRef) -> StoreResult<GetObjectTaggingResp> {
        validate_object_key(&req.bucket, &req.key)?;
        let guard = self.state.lock().unwrap();
        let b = lookup_bucket_checked(&guard, &req.ctx, &req.bucket)?;
        let actions: &[S3Action] = if req.version_id.is_some() {
            &[S3Action::GetObjectVersionTagging, S3Action::GetObjectTagging]
        } else {
            &[S3Action::GetObjectTagging]
        };
        let ver = self.lookup_version_for_op_checked(
            b,
            &req.ctx,
            &req.bucket,
            &req.key,
            req.version_id.as_deref(),
            actions,
            None,
            None,
        )?;
        Ok(GetObjectTaggingResp {
            version_id: ver.version_id.clone().filter(|v| v != "null"),
            tags: ver.tags.clone(),
        })
    }

    async fn put_object_tagging(&self, req: PutObjectTaggingReq) -> StoreResult<Option<String>> {
        validate_object_key(&req.bucket, &req.key)?;
        let mut guard = self.state.lock().unwrap();
        let b_ro = lookup_bucket_checked(&guard, &req.ctx, &req.bucket)?;
        let actions: &[S3Action] = if req.version_id.is_some() {
            &[S3Action::PutObjectVersionTagging, S3Action::PutObjectTagging]
        } else {
            &[S3Action::PutObjectTagging]
        };
        let (target_seq, vid_out) = {
            let ver = self.lookup_version_for_op_checked(
                b_ro,
                &req.ctx,
                &req.bucket,
                &req.key,
                req.version_id.as_deref(),
                actions,
                None,
                Some(&req.tags),
            )?;
            (ver.seq, ver.version_id.clone().filter(|v| v != "null"))
        };
        let b = guard.buckets.get_mut(&req.bucket).unwrap();
        if let Some(chain) = b.objects.get_mut(&req.key)
            && let Some(v) = chain.iter_mut().find(|v| v.seq == target_seq) {
                v.tags = req.tags;
            }
        Ok(vid_out)
    }

    async fn delete_object_tagging(&self, req: ObjectTaggingRef) -> StoreResult<Option<String>> {
        validate_object_key(&req.bucket, &req.key)?;
        let mut guard = self.state.lock().unwrap();
        let b_ro = lookup_bucket_checked(&guard, &req.ctx, &req.bucket)?;
        let actions: &[S3Action] = if req.version_id.is_some() {
            &[
                S3Action::DeleteObjectVersionTagging,
                S3Action::DeleteObjectTagging,
            ]
        } else {
            &[S3Action::DeleteObjectTagging]
        };
        let (target_seq, vid_out) = {
            let ver = self.lookup_version_for_op_checked(
                b_ro,
                &req.ctx,
                &req.bucket,
                &req.key,
                req.version_id.as_deref(),
                actions,
                None,
                None,
            )?;
            (ver.seq, ver.version_id.clone().filter(|v| v != "null"))
        };
        let b = guard.buckets.get_mut(&req.bucket).unwrap();
        if let Some(chain) = b.objects.get_mut(&req.key)
            && let Some(v) = chain.iter_mut().find(|v| v.seq == target_seq) {
                v.tags.clear();
            }
        Ok(vid_out)
    }

    async fn get_bucket_cors(&self, req: BucketRef) -> StoreResult<CorsConfiguration> {
        let guard = self.state.lock().unwrap();
        let b = check_bucket_action(
            &guard,
            self.cfg.default_object_ownership,
            &req.ctx,
            &req.bucket,
            &[S3Action::GetBucketCORS],
            None,
            &PolicyEvalExtra::default(),
        )?;
        b.cors.clone().ok_or_else(|| {
            S3Error::new(
                S3ErrorCode::NoSuchCorsConfiguration,
                "The CORS configuration does not exist",
            )
            .with_bucket(&req.bucket)
        })
    }

    async fn put_bucket_cors(&self, req: PutBucketCorsReq) -> StoreResult<()> {
        req.cors.validate()?;
        let mut guard = self.state.lock().unwrap();
        let _ = check_bucket_action(
            &guard,
            self.cfg.default_object_ownership,
            &req.ctx,
            &req.bucket,
            &[S3Action::PutBucketCORS],
            None,
            &PolicyEvalExtra::default(),
        )?;
        guard.buckets.get_mut(&req.bucket).unwrap().cors = Some(req.cors);
        Ok(())
    }

    async fn delete_bucket_cors(&self, req: BucketRef) -> StoreResult<()> {
        let mut guard = self.state.lock().unwrap();
        let _ = check_bucket_action(
            &guard,
            self.cfg.default_object_ownership,
            &req.ctx,
            &req.bucket,
            &[S3Action::PutBucketCORS],
            None,
            &PolicyEvalExtra::default(),
        )?;
        guard.buckets.get_mut(&req.bucket).unwrap().cors = None;
        Ok(())
    }

    async fn lookup_bucket_cors_unauth(
        &self,
        bucket: &str,
    ) -> StoreResult<Option<CorsConfiguration>> {
        let guard = self.state.lock().unwrap();
        let b = guard.buckets.get(bucket).ok_or_else(|| {
            S3Error::new(
                S3ErrorCode::NoSuchBucket,
                "The specified bucket does not exist",
            )
            .with_bucket(bucket)
        })?;
        Ok(b.cors.clone())
    }

    async fn get_bucket_policy(&self, req: BucketRef) -> StoreResult<String> {
        let guard = self.state.lock().unwrap();
        let b = check_bucket_action(
            &guard,
            self.cfg.default_object_ownership,
            &req.ctx,
            &req.bucket,
            &[S3Action::GetBucketPolicy],
            None,
            &PolicyEvalExtra::default(),
        )?;
        let pol = b.policy.as_ref().ok_or_else(|| {
            S3Error::new(
                S3ErrorCode::NoSuchBucketPolicy,
                "The bucket policy does not exist",
            )
            .with_bucket(&req.bucket)
        })?;
        Ok(pol.raw_json().to_string())
    }

    async fn put_bucket_policy(&self, req: PutBucketPolicyReq) -> StoreResult<()> {
        let mut guard = self.state.lock().unwrap();
        let b = check_bucket_action(
            &guard,
            self.cfg.default_object_ownership,
            &req.ctx,
            &req.bucket,
            &[S3Action::PutBucketPolicy],
            None,
            &PolicyEvalExtra::default(),
        )?;
        let doc = BucketPolicyDoc::parse_and_validate(&req.policy_json, &req.bucket)?;
        if b.auth_view(self.cfg.default_object_ownership)
            .block_public_policy()
            && doc.is_public()
        {
            return Err(
                S3Error::new(S3ErrorCode::AccessDenied, "Access Denied").with_bucket(&req.bucket)
            );
        }
        guard.buckets.get_mut(&req.bucket).unwrap().policy = Some(doc);
        Ok(())
    }

    async fn delete_bucket_policy(&self, req: BucketRef) -> StoreResult<()> {
        let mut guard = self.state.lock().unwrap();
        let _ = check_bucket_action(
            &guard,
            self.cfg.default_object_ownership,
            &req.ctx,
            &req.bucket,
            &[S3Action::DeleteBucketPolicy],
            None,
            &PolicyEvalExtra::default(),
        )?;
        guard.buckets.get_mut(&req.bucket).unwrap().policy = None;
        Ok(())
    }

    async fn get_bucket_policy_status(&self, req: BucketRef) -> StoreResult<bool> {
        let guard = self.state.lock().unwrap();
        let b = check_bucket_action(
            &guard,
            self.cfg.default_object_ownership,
            &req.ctx,
            &req.bucket,
            &[S3Action::GetBucketPolicyStatus],
            None,
            &PolicyEvalExtra::default(),
        )?;
        Ok(b.auth_view(self.cfg.default_object_ownership)
            .compute_is_public())
    }

    async fn get_public_access_block(&self, req: BucketRef) -> StoreResult<PublicAccessBlockConfig> {
        let guard = self.state.lock().unwrap();
        let b = check_bucket_action(
            &guard,
            self.cfg.default_object_ownership,
            &req.ctx,
            &req.bucket,
            &[S3Action::GetBucketPublicAccessBlock],
            None,
            &PolicyEvalExtra::default(),
        )?;
        b.public_access_block.ok_or_else(|| {
            S3Error::new(
                S3ErrorCode::NoSuchPublicAccessBlockConfiguration,
                "The public access block configuration was not found",
            )
            .with_bucket(&req.bucket)
        })
    }

    async fn put_public_access_block(&self, req: PutPublicAccessBlockReq) -> StoreResult<()> {
        let mut guard = self.state.lock().unwrap();
        let _ = check_bucket_action(
            &guard,
            self.cfg.default_object_ownership,
            &req.ctx,
            &req.bucket,
            &[S3Action::PutBucketPublicAccessBlock],
            None,
            &PolicyEvalExtra::default(),
        )?;
        guard.buckets.get_mut(&req.bucket).unwrap().public_access_block = Some(req.config);
        Ok(())
    }

    async fn delete_public_access_block(&self, req: BucketRef) -> StoreResult<()> {
        let mut guard = self.state.lock().unwrap();
        let _ = check_bucket_action(
            &guard,
            self.cfg.default_object_ownership,
            &req.ctx,
            &req.bucket,
            &[S3Action::PutBucketPublicAccessBlock],
            None,
            &PolicyEvalExtra::default(),
        )?;
        guard.buckets.get_mut(&req.bucket).unwrap().public_access_block = None;
        Ok(())
    }

    async fn get_object_lock_configuration(
        &self,
        req: BucketRef,
    ) -> StoreResult<ObjectLockConfiguration> {
        let guard = self.state.lock().unwrap();
        let b = check_bucket_action(
            &guard,
            self.cfg.default_object_ownership,
            &req.ctx,
            &req.bucket,
            &[S3Action::GetBucketObjectLockConfiguration],
            None,
            &PolicyEvalExtra::default(),
        )?;
        if !b.object_lock_enabled {
            return Err(S3Error::new(
                S3ErrorCode::ObjectLockConfigurationNotFoundError,
                "Object Lock configuration does not exist for this bucket",
            )
            .with_bucket(&req.bucket));
        }
        Ok(b.object_lock_config.unwrap_or_default())
    }

    async fn put_object_lock_configuration(
        &self,
        req: PutObjectLockConfigurationReq,
    ) -> StoreResult<()> {
        let mut guard = self.state.lock().unwrap();
        let b_ro = check_bucket_action(
            &guard,
            self.cfg.default_object_ownership,
            &req.ctx,
            &req.bucket,
            &[S3Action::PutBucketObjectLockConfiguration],
            None,
            &PolicyEvalExtra::default(),
        )?;
        if !b_ro.object_lock_enabled && b_ro.versioning != VersioningStatus::Enabled {
            return Err(S3Error::new(
                S3ErrorCode::InvalidBucketState,
                "Versioning must be 'Enabled' on the bucket to apply a Object Lock configuration",
            )
            .with_bucket(&req.bucket));
        }
        let b = guard.buckets.get_mut(&req.bucket).unwrap();
        b.object_lock_enabled = true;
        b.object_lock_config = Some(req.config);
        Ok(())
    }

    async fn get_object_retention(&self, req: ObjectLockRef) -> StoreResult<ObjectRetention> {
        validate_object_key(&req.bucket, &req.key)?;
        let guard = self.state.lock().unwrap();
        let b = lookup_bucket_checked(&guard, &req.ctx, &req.bucket)?;
        let ver = self.lookup_version_for_op_checked(
            b,
            &req.ctx,
            &req.bucket,
            &req.key,
            req.version_id.as_deref(),
            &[S3Action::GetObjectRetention],
            None,
            None,
        )?;
        if !b.object_lock_enabled {
            return Err(S3Error::new(
                S3ErrorCode::InvalidRequest,
                "Bucket is missing Object Lock Configuration",
            )
            .with_bucket(&req.bucket));
        }
        ver.retention.ok_or_else(|| {
            S3Error::new(
                S3ErrorCode::NoSuchObjectLockConfiguration,
                "The specified object does not have a ObjectLock configuration",
            )
            .with_key(&req.bucket, &req.key)
        })
    }

    async fn put_object_retention(&self, req: PutObjectRetentionReq) -> StoreResult<()> {
        validate_object_key(&req.bucket, &req.key)?;
        let mut guard = self.state.lock().unwrap();
        let b_ro = lookup_bucket_checked(&guard, &req.ctx, &req.bucket)?;
        let target_seq = {
            let ver = self.lookup_version_for_op_checked(
                b_ro,
                &req.ctx,
                &req.bucket,
                &req.key,
                req.version_id.as_deref(),
                &[S3Action::PutObjectRetention],
                None,
                None,
            )?;
            if !b_ro.object_lock_enabled {
                return Err(S3Error::new(
                    S3ErrorCode::InvalidRequest,
                    "Bucket is missing Object Lock Configuration",
                )
                .with_bucket(&req.bucket));
            }
            let can_bypass = can_bypass_governance_model(
                b_ro,
                self.cfg.default_object_ownership,
                &req.ctx,
                &req.key,
                Some(&ver.tags),
            );
            check_worm_put_retention(
                ver.retention,
                req.retention,
                req.bypass_governance,
                can_bypass,
                req.ctx.request_time_ms,
            )?;
            ver.seq
        };
        let b = guard.buckets.get_mut(&req.bucket).unwrap();
        if let Some(chain) = b.objects.get_mut(&req.key)
            && let Some(v) = chain.iter_mut().find(|v| v.seq == target_seq)
        {
            v.retention = Some(req.retention);
        }
        Ok(())
    }

    async fn get_object_legal_hold(&self, req: ObjectLockRef) -> StoreResult<LegalHoldStatus> {
        validate_object_key(&req.bucket, &req.key)?;
        let guard = self.state.lock().unwrap();
        let b = lookup_bucket_checked(&guard, &req.ctx, &req.bucket)?;
        let ver = self.lookup_version_for_op_checked(
            b,
            &req.ctx,
            &req.bucket,
            &req.key,
            req.version_id.as_deref(),
            &[S3Action::GetObjectLegalHold],
            None,
            None,
        )?;
        if !b.object_lock_enabled {
            return Err(S3Error::new(
                S3ErrorCode::InvalidRequest,
                "Bucket is missing Object Lock Configuration",
            )
            .with_bucket(&req.bucket));
        }
        ver.legal_hold.ok_or_else(|| {
            S3Error::new(
                S3ErrorCode::NoSuchObjectLockConfiguration,
                "The specified object does not have a ObjectLock configuration",
            )
            .with_key(&req.bucket, &req.key)
        })
    }

    async fn put_object_legal_hold(&self, req: PutObjectLegalHoldReq) -> StoreResult<()> {
        validate_object_key(&req.bucket, &req.key)?;
        let mut guard = self.state.lock().unwrap();
        let b_ro = lookup_bucket_checked(&guard, &req.ctx, &req.bucket)?;
        let target_seq = {
            let ver = self.lookup_version_for_op_checked(
                b_ro,
                &req.ctx,
                &req.bucket,
                &req.key,
                req.version_id.as_deref(),
                &[S3Action::PutObjectLegalHold],
                None,
                None,
            )?;
            if !b_ro.object_lock_enabled {
                return Err(S3Error::new(
                    S3ErrorCode::InvalidRequest,
                    "Bucket is missing Object Lock Configuration",
                )
                .with_bucket(&req.bucket));
            }
            ver.seq
        };
        let b = guard.buckets.get_mut(&req.bucket).unwrap();
        if let Some(chain) = b.objects.get_mut(&req.key)
            && let Some(v) = chain.iter_mut().find(|v| v.seq == target_seq)
        {
            v.legal_hold = Some(req.status);
        }
        Ok(())
    }

    async fn get_bucket_lifecycle_configuration(
        &self,
        req: BucketRef,
    ) -> StoreResult<LifecycleConfiguration> {
        let guard = self.state.lock().unwrap();
        let b = check_bucket_action(
            &guard,
            self.cfg.default_object_ownership,
            &req.ctx,
            &req.bucket,
            &[S3Action::GetLifecycleConfiguration],
            None,
            &PolicyEvalExtra::default(),
        )?;
        b.lifecycle.clone().ok_or_else(|| {
            S3Error::new(
                S3ErrorCode::NoSuchLifecycleConfiguration,
                "The lifecycle configuration does not exist",
            )
            .with_bucket(&req.bucket)
        })
    }

    async fn put_bucket_lifecycle_configuration(
        &self,
        req: PutBucketLifecycleReq,
    ) -> StoreResult<()> {
        let mut guard = self.state.lock().unwrap();
        let _ = check_bucket_action(
            &guard,
            self.cfg.default_object_ownership,
            &req.ctx,
            &req.bucket,
            &[S3Action::PutLifecycleConfiguration],
            None,
            &PolicyEvalExtra::default(),
        )?;
        guard.buckets.get_mut(&req.bucket).unwrap().lifecycle = Some(req.config);
        Ok(())
    }

    async fn delete_bucket_lifecycle(&self, req: BucketRef) -> StoreResult<()> {
        let mut guard = self.state.lock().unwrap();
        let _ = check_bucket_action(
            &guard,
            self.cfg.default_object_ownership,
            &req.ctx,
            &req.bucket,
            &[S3Action::PutLifecycleConfiguration],
            None,
            &PolicyEvalExtra::default(),
        )?;
        guard.buckets.get_mut(&req.bucket).unwrap().lifecycle = None;
        Ok(())
    }

    async fn get_bucket_encryption(&self, req: BucketRef) -> StoreResult<BucketEncryptionConfig> {
        let guard = self.state.lock().unwrap();
        let b = check_bucket_action(
            &guard,
            self.cfg.default_object_ownership,
            &req.ctx,
            &req.bucket,
            &[S3Action::GetEncryptionConfiguration],
            None,
            &PolicyEvalExtra::default(),
        )?;
        b.encryption.clone().ok_or_else(|| {
            S3Error::new(
                S3ErrorCode::ServerSideEncryptionConfigurationNotFoundError,
                "The server side encryption configuration was not found",
            )
            .with_bucket(&req.bucket)
        })
    }

    async fn put_bucket_encryption(&self, req: PutBucketEncryptionReq) -> StoreResult<()> {
        let mut guard = self.state.lock().unwrap();
        let _ = check_bucket_action(
            &guard,
            self.cfg.default_object_ownership,
            &req.ctx,
            &req.bucket,
            &[S3Action::PutEncryptionConfiguration],
            None,
            &PolicyEvalExtra::default(),
        )?;
        guard.buckets.get_mut(&req.bucket).unwrap().encryption = Some(req.config);
        Ok(())
    }

    async fn delete_bucket_encryption(&self, req: BucketRef) -> StoreResult<()> {
        let mut guard = self.state.lock().unwrap();
        let _ = check_bucket_action(
            &guard,
            self.cfg.default_object_ownership,
            &req.ctx,
            &req.bucket,
            &[S3Action::PutEncryptionConfiguration],
            None,
            &PolicyEvalExtra::default(),
        )?;
        guard.buckets.get_mut(&req.bucket).unwrap().encryption = None;
        Ok(())
    }

    async fn get_bucket_logging(&self, req: BucketRef) -> StoreResult<BucketLoggingStatus> {
        let guard = self.state.lock().unwrap();
        let b = check_bucket_action(
            &guard,
            self.cfg.default_object_ownership,
            &req.ctx,
            &req.bucket,
            &[S3Action::GetBucketLogging],
            Some(AclPermission::ReadAcp),
            &PolicyEvalExtra::default(),
        )?;
        Ok(b.logging.clone().unwrap_or_default())
    }

    async fn put_bucket_logging(&self, req: PutBucketLoggingReq) -> StoreResult<()> {
        let mut guard = self.state.lock().unwrap();
        let src_owner_id = {
            let src_b = lookup_bucket_checked(&guard, &req.ctx, &req.bucket)?;
            let view = src_b.auth_view(self.cfg.default_object_ownership);
            if let Some(pol) = view.policy {
                let arn = format!("arn:aws:s3:::{}", req.bucket);
                if pol.evaluate(
                    &req.ctx,
                    &[S3Action::PutBucketLogging],
                    &arn,
                    &PolicyEvalExtra::default(),
                ) == PolicyDecision::ExplicitDeny
                {
                    return Err(S3Error::new(S3ErrorCode::AccessDenied, "Access Denied")
                        .with_bucket(&req.bucket));
                }
            }
            if !view.is_caller_bucket_owner(&req.ctx) {
                return Err(S3Error::new(S3ErrorCode::AccessDenied, "Access Denied")
                    .with_bucket(&req.bucket));
            }
            src_b.owner.user_id.clone()
        };

        if let Some(le) = &req.status.logging_enabled {
            let Some(target_b) = guard.buckets.get(&le.target_bucket) else {
                return Err(S3Error::new(
                    S3ErrorCode::InvalidTargetBucketForLogging,
                    "The target bucket for logging does not exist",
                )
                .with_bucket(&le.target_bucket));
            };
            if le.target_bucket == req.bucket {
                return Err(S3Error::new(
                    S3ErrorCode::InvalidArgument,
                    "Source bucket and target bucket cannot be the same",
                ));
            }
            if target_b
                .logging
                .as_ref()
                .and_then(|s| s.logging_enabled.as_ref())
                .is_some()
                || target_b.encryption.is_some()
            {
                return Err(S3Error::new(
                    S3ErrorCode::InvalidArgument,
                    "Invalid target bucket state for logging",
                ));
            }

            let src_arn = format!("arn:aws:s3:::{}", req.bucket);
            let target_res_arn = format!("arn:aws:s3:::{}/{}", le.target_bucket, le.target_prefix);
            let svc_extra = PolicyEvalExtra {
                source_arn: Some(&src_arn),
                source_account: Some(&src_owner_id),
                ..Default::default()
            };
            let allowed_by_policy = target_b.policy.as_ref().is_some_and(|pol| {
                pol.allows_service(
                    "logging.s3.amazonaws.com",
                    &[S3Action::PutObject],
                    &target_res_arn,
                    &svc_extra,
                )
            });
            let allowed_by_acl = target_b.effective_ownership(self.cfg.default_object_ownership)
                != ObjectOwnership::BucketOwnerEnforced
                && target_b.acl.grants.iter().any(|g| {
                    matches!(&g.grantee, AclGrantee::Group(u) if u == GROUP_LOG_DELIVERY)
                        && matches!(
                            g.permission,
                            AclPermission::Write | AclPermission::FullControl
                        )
                })
                && target_b.acl.grants.iter().any(|g| {
                    matches!(&g.grantee, AclGrantee::Group(u) if u == GROUP_LOG_DELIVERY)
                        && matches!(
                            g.permission,
                            AclPermission::ReadAcp | AclPermission::FullControl
                        )
                });
            if !allowed_by_policy && !allowed_by_acl {
                return Err(S3Error::new(
                    S3ErrorCode::AccessDenied,
                    "Bucket policy on target bucket does not allow logging service PutObject",
                ));
            }
        }

        guard.buckets.get_mut(&req.bucket).unwrap().logging = Some(req.status);
        Ok(())
    }

    async fn put_object<S: VerifiedBodyStream>(
        &self,
        req: PutObjectReq,
        mut body: S,
    ) -> StoreResult<PutObjectResp> {
        validate_object_key(&req.bucket, &req.key)?;
        // [FR-3] Lowercase x-amz-meta-* keys, UTF-8 key+value sum <= 2048 bytes (400 MetadataTooLarge)
        validate_user_metadata(&req.user_meta)?;

        let pre_sse = {
            let guard = self.state.lock().unwrap();
            let b = check_bucket_write_object(
                &guard,
                self.cfg.default_object_ownership,
                &req.ctx,
                &req.bucket,
                &req.key,
                req.tags.as_ref(),
            )?;
            let sse_write = validate_sse_write(&req.raw_sse, b.encryption.is_some())?;
            let _ = resolve_upload_object_lock(
                b.object_lock_enabled,
                b.object_lock_config.as_ref(),
                &req.raw_lock,
                req.ctx.request_time_ms,
            )?;
            enforce_block_public_acl_spec(
                b.auth_view(self.cfg.default_object_ownership)
                    .block_public_acls(),
                req.acl.as_ref(),
            )
            .map_err(|e| e.with_key(&req.bucket, &req.key))?;
            let _ = resolve_object_owner_and_acl(
                b.effective_ownership(self.cfg.default_object_ownership),
                &b.owner,
                req.ctx.caller.as_ref(),
                req.acl.as_ref(),
            )?;
            sse_write
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
        let (obj_owner, obj_acl, sse_write, retention, legal_hold) = {
            let b = check_bucket_write_object(
                &guard,
                self.cfg.default_object_ownership,
                &req.ctx,
                &req.bucket,
                &req.key,
                req.tags.as_ref(),
            )?;
            let sse_w = validate_sse_write(&req.raw_sse, b.encryption.is_some())?;
            let (ret, lh) = resolve_upload_object_lock(
                b.object_lock_enabled,
                b.object_lock_config.as_ref(),
                &req.raw_lock,
                req.ctx.request_time_ms,
            )?;
            enforce_block_public_acl_spec(
                b.auth_view(self.cfg.default_object_ownership)
                    .block_public_acls(),
                req.acl.as_ref(),
            )
            .map_err(|e| e.with_key(&req.bucket, &req.key))?;
            let (own, acl) = resolve_object_owner_and_acl(
                b.effective_ownership(self.cfg.default_object_ownership),
                &b.owner,
                req.ctx.caller.as_ref(),
                req.acl.as_ref(),
            )?;
            (own, acl, sse_w, ret, lh)
        };
        let _ = pre_sse;
        // [FR-2] Concurrent PUTs to the same key serialize at commit point (last writer wins)
        guard.next_seq += 1;
        let seq = guard.next_seq;

        let bucket = guard.buckets.get_mut(&req.bucket).unwrap();
        let head = head_state_of(bucket.objects.get(&req.key));
        evaluate_write_preconditions(&req.preconditions, &req.bucket, &req.key, head)?;

        let iv = model_make_iv(seq, 0);
        let (stored_sse, sse_resp) = match &sse_write {
            ValidatedSseWrite::None => (SseStoredMeta::None, SseResponseHeaders::None),
            ValidatedSseWrite::SseS3 => {
                aes256_ctr_xor(&self.sse_s3_master_key, &iv, 0, &mut buf);
                (SseStoredMeta::SseS3 { iv }, SseResponseHeaders::SseS3)
            }
            ValidatedSseWrite::SseC {
                key,
                key_md5,
                key_md5_b64,
            } => {
                aes256_ctr_xor(key, &iv, 0, &mut buf);
                (
                    SseStoredMeta::SseC {
                        key_md5: *key_md5,
                        iv,
                    },
                    SseResponseHeaders::SseC {
                        key_md5_b64: key_md5_b64.clone(),
                    },
                )
            }
        };

        // [FR-7, PR-17] Quoted MD5 hex ETag
        // [FR-33, FR-34] Versioning Enabled allocates unique ordered versionId; Suspended writes "null"
        let etag = format!("\"{}\"", hex::encode(digests.md5));
        let version_id = match bucket.versioning {
            VersioningStatus::Unversioned => None,
            VersioningStatus::Suspended => Some("null".to_string()),
            VersioningStatus::Enabled => Some(format!("v{seq:016x}")),
        };

        let obj_tags = req.tags.unwrap_or_default();
        let exp_hdr = compute_x_amz_expiration(
            bucket.lifecycle.as_ref(),
            &req.key,
            digests.total_bytes,
            &obj_tags,
            req.ctx.request_time_ms,
        );

        let ver = ModelVersion {
            seq,
            version_id: version_id.clone(),
            is_delete_marker: false,
            data: buf.freeze(),
            etag: etag.clone(),
            checksum: digests.checksum.clone(),
            // [FR-4, FR-5] Persist standard HTTP system metadata (`aws-chunked` already stripped from
            // Content-Encoding at the HTTP protocol layer in s3d-server before constructing PutObjectReq)
            sys_meta: req.sys_meta,
            user_meta: req.user_meta,
            owner: obj_owner,
            acl: obj_acl,
            tags: obj_tags,
            last_modified_ms: req.ctx.request_time_ms,
            parts: None,
            sse: stored_sse,
            retention,
            legal_hold,
        };

        let chain = bucket.objects.entry(req.key).or_default();
        insert_version_into_chain(bucket.versioning, chain, ver);

        // [FR-8] Return ETag, checksum, and versionId (when bucket versioning is enabled/suspended)
        Ok(PutObjectResp {
            etag,
            version_id,
            checksum: digests.checksum,
            sse: sse_resp,
            expiration_header: exp_hdr,
        })
    }

    async fn get_object(&self, req: GetObjectReq) -> StoreResult<GetObjectResp<Self::Reader>> {
        // [FR-11] Response header overrides (`response-*` query params) are validated against
        // anonymous callers and applied to response headers at the HTTP layer in s3d-server.
        let (meta, slice) = self.read_internal(&req, true)?;
        Ok(GetObjectResp {
            meta,
            reader: MemoryByteReader::new(slice),
        })
    }

    async fn head_object(&self, req: GetObjectReq) -> StoreResult<ObjectMetaSnapshot> {
        // [FR-14] HEAD returns identical metadata snapshot as GET (including versionId) without body
        let (meta, _) = self.read_internal(&req, false)?;
        Ok(meta)
    }

    async fn get_object_attributes(
        &self,
        req: GetObjectAttributesReq,
    ) -> StoreResult<GetObjectAttributesResp> {
        validate_object_key(&req.bucket, &req.key)?;
        let guard = self.state.lock().unwrap();
        let b = lookup_bucket_checked(&guard, &req.ctx, &req.bucket)?;
        let actions: &[S3Action] = if req.version_id.is_some() {
            &[
                S3Action::GetObjectVersionAttributes,
                S3Action::GetObjectAttributes,
                S3Action::GetObject,
            ]
        } else {
            &[S3Action::GetObjectAttributes, S3Action::GetObject]
        };
        let ver = self.lookup_version_for_op_checked(
            b,
            &req.ctx,
            &req.bucket,
            &req.key,
            req.version_id.as_deref(),
            actions,
            None,
            None,
        )?;
        let sse_read = validate_sse_read_or_part(&req.raw_sse)?;
        let (_, sse_resp) =
            match_sse_for_stored_object(&ver.sse, &sse_read, &self.sse_s3_master_key)?;

        let object_parts = if req.attrs.object_parts {
            ver.parts.as_ref().map(|all_parts| {
                let total = all_parts.len() as u32;
                // [FR-29] ListParts pagination (<= 1000 parts, part-number-marker)
        let max_p = req.max_parts.min(1000);
                let mut selected = Vec::new();
                let mut is_truncated = false;
                for p in all_parts {
                    if p.part_number <= req.part_number_marker {
                        continue;
                    }
                    if selected.len() == max_p {
                        is_truncated = true;
                        break;
                    }
                    selected.push(ObjectAttributePartEntry {
                        part_number: p.part_number,
                        size: p.size,
                        checksum: p.checksum.clone(),
                    });
                }
                let next_marker = selected.last().map(|p| p.part_number);
                ObjectAttributesPartsResp {
                    total_parts_count: total,
                    part_number_marker: req.part_number_marker,
                    next_part_number_marker: next_marker,
                    max_parts: max_p,
                    is_truncated,
                    parts: selected,
                }
            })
        } else {
            None
        };

        Ok(GetObjectAttributesResp {
            version_id: ver.version_id.clone().filter(|v| v != "null"),
            last_modified_ms: ver.last_modified_ms,
            etag: req.attrs.etag.then(|| strip_etag_quotes(&ver.etag).to_string()),
            checksum: req.attrs.checksum.then(|| ver.checksum.clone()),
            object_parts,
            // [FR-6] Storage class fixed to STANDARD (non-STANDARD rejected with 400 InvalidStorageClass at HTTP layer)
            storage_class: req.attrs.storage_class.then(|| "STANDARD".to_string()),
            object_size: req.attrs.object_size.then_some(ver.data.len() as u64),
            sse: sse_resp,
        })
    }

    async fn delete_object(&self, req: DeleteObjectReq) -> StoreResult<DeleteObjectResp> {
        validate_object_key(&req.bucket, &req.key)?;
        let mut guard = self.state.lock().unwrap();
        let (dm_owner, can_bypass) = {
            let b = lookup_bucket_checked(&guard, &req.ctx, &req.bucket)?;
            let view = b.auth_view(self.cfg.default_object_ownership);
            let actions: &[S3Action] = if req.version_id.is_some() {
                &[S3Action::DeleteObjectVersion, S3Action::DeleteObject]
            } else {
                &[S3Action::DeleteObject]
            };
            let existing_tags = match &req.version_id {
                None => b
                    .objects
                    .get(&req.key)
                    .and_then(|c| c.first())
                    .filter(|v| !v.is_delete_marker)
                    .map(|v| &v.tags),
                Some(vid) => b.objects.get(&req.key).and_then(|c| {
                    c.iter()
                        .find(|v| v.version_id.as_deref().unwrap_or("null") == vid.as_str())
                        .filter(|v| !v.is_delete_marker)
                        .map(|v| &v.tags)
                }),
            };
            let extra = PolicyEvalExtra {
                existing_object_tags: existing_tags,
                ..Default::default()
            };
            if !authorize_object_action(
                &view,
                &req.ctx,
                &req.key,
                actions,
                Some(&b.owner),
                Some((&b.acl, AclPermission::Write)),
                true,
                &extra,
            ) {
                return Err(S3Error::new(S3ErrorCode::AccessDenied, "Access Denied")
                    .with_key(&req.bucket, &req.key));
            }
            let can_byp = can_bypass_governance_model(
                b,
                self.cfg.default_object_ownership,
                &req.ctx,
                &req.key,
                existing_tags,
            );
            (
                req.ctx.caller.clone().unwrap_or_else(|| b.owner.clone()),
                can_byp,
            )
        };
        // [FR-2] Concurrent PUTs to the same key serialize at commit point (last writer wins)
        guard.next_seq += 1;
        let seq = guard.next_seq;
        let bucket = guard.buckets.get_mut(&req.bucket).unwrap();

        // [FR-15, FR-16] DeleteObject / DeleteObjects conditional If-Match (<etag> or *) against current head
        let head = head_state_of(bucket.objects.get(&req.key));
        evaluate_delete_preconditions(req.if_match.as_deref(), &req.bucket, &req.key, head)?;

        if let Some(vid) = &req.version_id {
            // [FR-36] Permanent version deletion
            if let Some(chain) = bucket.objects.get_mut(&req.key)
                && let Some(pos) = chain
                    .iter()
                    .position(|v| v.version_id.as_deref().unwrap_or("null") == vid.as_str())
                {
                    if !chain[pos].is_delete_marker {
                        check_worm_version_delete(
                            chain[pos].retention,
                            chain[pos].legal_hold,
                            req.bypass_governance,
                            can_bypass,
                            req.ctx.request_time_ms,
                        )
                        .map_err(|e| e.with_key(&req.bucket, &req.key))?;
                    }
                    let removed = chain.remove(pos);
                    if chain.is_empty() {
                        bucket.objects.remove(&req.key);
                    }
                    return Ok(DeleteObjectResp {
                        version_id: removed.version_id,
                        is_delete_marker: removed.is_delete_marker,
                    });
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
                let dm_acl = AccessControlPolicy::new_private(dm_owner.clone());
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
                    owner: dm_owner,
                    acl: dm_acl,
                    tags: BTreeMap::new(),
                    last_modified_ms: req.ctx.request_time_ms,
                    parts: None,
                    sse: SseStoredMeta::None,
                    retention: None,
                    legal_hold: None,
                };
                let chain = bucket.objects.entry(req.key).or_default();
                if bucket.versioning == VersioningStatus::Suspended {
                    chain.retain(|v| v.version_id.as_deref().unwrap_or("null") != "null");
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
            let _ = lookup_bucket_checked(&guard, &req.ctx, &req.bucket)?;
        }

        let mut deleted = Vec::new();
        let mut errors = Vec::new();
        // [FR-47] Per-key independent execution (non-atomic batch), missing unversioned key succeeds,
        // and quiet=true suppresses Deleted entries while still reporting per-key Errors.
        for item in req.items {
            let sub = DeleteObjectReq {
                ctx: req.ctx.clone(),
                bucket: req.bucket.clone(),
                key: item.key.clone(),
                version_id: item.version_id.clone(),
                if_match: item.etag_if_match,
                bypass_governance: req.bypass_governance,
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
                        message: err.message.clone(),
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
            && req.acl.is_none()
            && req.tagging_directive == TaggingDirective::Copy
            && req.raw_sse.sse_algorithm.is_none()
            && !req.raw_sse.has_customer_headers()
            && !req.raw_lock.has_any()
        {
            // [FR-20] Self-copy with no changes -> 400 InvalidRequest
            return Err(S3Error::new(
                S3ErrorCode::InvalidRequest,
                "This copy request is illegal because it is trying to copy an object to itself without changing the object's metadata.",
            ));
        }

        // [FR-18, FR-23] Resolve URL-decoded copy source (/{bucket}/{key}?versionId=...);
        // missing source bucket -> 404 NoSuchBucket, missing source key -> 404 NoSuchKey.
        let mut guard = self.state.lock().unwrap();
        let src_b = lookup_bucket_checked(&guard, &req.ctx, &req.src_bucket)?;
        let src_ver = self
            .lookup_version_for_copy_checked(
                src_b,
                &req.ctx,
                &req.src_bucket,
                &req.src_key,
                req.src_version_id.as_deref(),
            )?
            .clone();

        // [FR-19] x-amz-tagging-directive COPY vs REPLACE
        let dst_tags = match req.tagging_directive {
            TaggingDirective::Copy => src_ver.tags.clone(),
            TaggingDirective::Replace => req.tags.clone().unwrap_or_default(),
        };
        let req_tags_for_auth = match req.tagging_directive {
            TaggingDirective::Copy => (!src_ver.tags.is_empty()).then_some(&dst_tags),
            TaggingDirective::Replace => req.tags.as_ref(),
        };

        let (dst_owner, dst_acl, dst_sse_write, retention, legal_hold) = {
            let dst_b = check_bucket_write_object(
                &guard,
                self.cfg.default_object_ownership,
                &req.ctx,
                &req.dst_bucket,
                &req.dst_key,
                req_tags_for_auth,
            )?;
            let dst_sse_w = validate_sse_write(&req.raw_sse, dst_b.encryption.is_some())?;
            let (ret, lh) = resolve_upload_object_lock(
                dst_b.object_lock_enabled,
                dst_b.object_lock_config.as_ref(),
                &req.raw_lock,
                req.ctx.request_time_ms,
            )?;
            enforce_block_public_acl_spec(
                dst_b
                    .auth_view(self.cfg.default_object_ownership)
                    .block_public_acls(),
                req.acl.as_ref(),
            )
            .map_err(|e| e.with_key(&req.dst_bucket, &req.dst_key))?;
            let (own, acl) = resolve_object_owner_and_acl(
                dst_b.effective_ownership(self.cfg.default_object_ownership),
                &dst_b.owner,
                req.ctx.caller.as_ref(),
                req.acl.as_ref(),
            )?;
            (own, acl, dst_sse_w, ret, lh)
        };

        let src_sse_read = validate_copy_source_sse(&req.raw_copy_src_sse)?;
        let (src_key_iv, _) =
            match_sse_for_stored_object(&src_ver.sse, &src_sse_read, &self.sse_s3_master_key)?;

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

        let plain_bytes =
            decrypt_model_version_slice(&src_ver, src_key_iv, 0, src_ver.data.len() as u64);

        // [FR-2] Concurrent PUTs to the same key serialize at commit point (last writer wins)
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
        // [FR-19] x-amz-metadata-directive COPY vs REPLACE
        let (sys_meta, user_meta) = if req.replace_metadata {
            (req.sys_meta, req.user_meta)
        } else {
            (src_ver.sys_meta.clone(), src_ver.user_meta.clone())
        };
        let md5_raw: [u8; 16] = Md5::digest(&plain_bytes).into();
        let etag = format!("\"{}\"", hex::encode(md5_raw));
        let dst_csum = ChecksumState {
            algorithm: src_ver.checksum.algorithm,
            checksum_type: ChecksumType::FullObject,
            value_b64: compute_checksum_b64(src_ver.checksum.algorithm, &plain_bytes),
            client_requested: src_ver.checksum.client_requested,
        };

        let iv = model_make_iv(seq, 0);
        let mut dst_buf = BytesMut::from(plain_bytes.as_ref());
        let (stored_sse, sse_resp) = match &dst_sse_write {
            ValidatedSseWrite::None => (SseStoredMeta::None, SseResponseHeaders::None),
            ValidatedSseWrite::SseS3 => {
                aes256_ctr_xor(&self.sse_s3_master_key, &iv, 0, &mut dst_buf);
                (SseStoredMeta::SseS3 { iv }, SseResponseHeaders::SseS3)
            }
            ValidatedSseWrite::SseC {
                key,
                key_md5,
                key_md5_b64,
            } => {
                aes256_ctr_xor(key, &iv, 0, &mut dst_buf);
                (
                    SseStoredMeta::SseC {
                        key_md5: *key_md5,
                        iv,
                    },
                    SseResponseHeaders::SseC {
                        key_md5_b64: key_md5_b64.clone(),
                    },
                )
            }
        };

        let exp_hdr = compute_x_amz_expiration(
            dst_b.lifecycle.as_ref(),
            &req.dst_key,
            plain_bytes.len() as u64,
            &dst_tags,
            req.ctx.request_time_ms,
        );

        let new_ver = ModelVersion {
            seq,
            version_id: dst_vid.clone(),
            is_delete_marker: false,
            data: dst_buf.freeze(),
            etag: etag.clone(),
            checksum: dst_csum.clone(),
            sys_meta,
            user_meta,
            owner: dst_owner,
            acl: dst_acl,
            tags: dst_tags,
            last_modified_ms: req.ctx.request_time_ms,
            parts: None,
            sse: stored_sse,
            retention,
            legal_hold,
        };

        let chain = dst_b.objects.entry(req.dst_key).or_default();
        insert_version_into_chain(dst_b.versioning, chain, new_ver);

        Ok(CopyObjectResp {
            etag,
            last_modified_ms: req.ctx.request_time_ms,
            src_version_id: src_ver.version_id,
            dst_version_id: dst_vid,
            checksum: dst_csum.client_requested.then_some(dst_csum),
            sse: sse_resp,
            expiration_header: exp_hdr,
        })
    }

    async fn create_multipart_upload(
        &self,
        req: CreateMultipartUploadReq,
    ) -> StoreResult<CreateMultipartUploadResp> {
        validate_object_key(&req.bucket, &req.key)?;
        // [FR-3] Lowercase x-amz-meta-* keys, UTF-8 key+value sum <= 2048 bytes (400 MetadataTooLarge)
        validate_user_metadata(&req.user_meta)?;

        let resolved_type = match (req.checksum_algorithm, req.checksum_type) {
            (Some(alg), explicit) => Some(alg.resolve_multipart_type(explicit)?),
            (None, Some(_)) => {
                return Err(S3Error::new(
                    S3ErrorCode::InvalidRequest,
                    "x-amz-checksum-type requires x-amz-checksum-algorithm.",
                ));
            }
            (None, None) => None,
        };

        let mut guard = self.state.lock().unwrap();
        let (initiator, obj_owner, obj_acl, sse_write, retention, legal_hold) = {
            let b = check_bucket_write_object(
                &guard,
                self.cfg.default_object_ownership,
                &req.ctx,
                &req.bucket,
                &req.key,
                req.tags.as_ref(),
            )?;
            let sse_w = validate_sse_write(&req.raw_sse, b.encryption.is_some())?;
            let (ret, lh) = resolve_upload_object_lock(
                b.object_lock_enabled,
                b.object_lock_config.as_ref(),
                &req.raw_lock,
                req.ctx.request_time_ms,
            )?;
            enforce_block_public_acl_spec(
                b.auth_view(self.cfg.default_object_ownership)
                    .block_public_acls(),
                req.acl.as_ref(),
            )
            .map_err(|e| e.with_key(&req.bucket, &req.key))?;
            let initiator = req.ctx.caller.clone().unwrap_or_else(|| b.owner.clone());
            let (obj_owner, obj_acl) = resolve_object_owner_and_acl(
                b.effective_ownership(self.cfg.default_object_ownership),
                &b.owner,
                req.ctx.caller.as_ref(),
                req.acl.as_ref(),
            )?;
            (initiator, obj_owner, obj_acl, sse_w, ret, lh)
        };
        // [FR-2] Concurrent PUTs to the same key serialize at commit point (last writer wins)
        guard.next_seq += 1;
        let seq = guard.next_seq;
        // [FR-24] Opaque UploadId
        let upload_id = format!("mp{seq:032x}");
        let iv = model_make_iv(seq, 0);
        let (up_sse, sse_resp) = match sse_write {
            ValidatedSseWrite::None => (SseStoredMeta::None, SseResponseHeaders::None),
            ValidatedSseWrite::SseS3 => (SseStoredMeta::SseS3 { iv }, SseResponseHeaders::SseS3),
            ValidatedSseWrite::SseC {
                key_md5,
                key_md5_b64,
                ..
            } => (
                SseStoredMeta::SseC { key_md5, iv },
                SseResponseHeaders::SseC { key_md5_b64 },
            ),
        };

        let b = guard.buckets.get_mut(&req.bucket).unwrap();
        b.uploads.insert(
            (req.key.clone(), upload_id.clone()),
            ModelMultipartUpload {
                initiator,
                owner: obj_owner,
                acl: obj_acl,
                tags: req.tags.unwrap_or_default(),
                initiated_ms: req.ctx.request_time_ms,
                sys_meta: req.sys_meta,
                user_meta: req.user_meta,
                checksum_algorithm: req.checksum_algorithm,
                checksum_type: resolved_type,
                sse: up_sse,
                retention,
                legal_hold,
                parts: BTreeMap::new(),
            },
        );

        Ok(CreateMultipartUploadResp {
            bucket: req.bucket,
            key: req.key,
            upload_id,
            checksum_algorithm: req.checksum_algorithm,
            checksum_type: resolved_type,
            sse: sse_resp,
        })
    }

    async fn upload_part<S: VerifiedBodyStream>(
        &self,
        req: UploadPartReq,
        mut body: S,
    ) -> StoreResult<UploadPartResp> {
        validate_object_key(&req.bucket, &req.key)?;
        // [FR-25] PartNumber 1..=10,000
        if req.part_number == 0 || req.part_number > MAX_PARTS_COUNT {
            return Err(S3Error::new(
                S3ErrorCode::InvalidArgument,
                "Part number must be an integer between 1 and 10000, inclusive",
            ));
        }

        let (upload_csum_info, part_enc_key, sse_resp) = {
            let guard = self.state.lock().unwrap();
            let b = lookup_bucket_checked(&guard, &req.ctx, &req.bucket)?;
            let Some(up) = b.uploads.get(&(req.key.clone(), req.upload_id.clone())) else {
                let view = b.auth_view(self.cfg.default_object_ownership);
                if authorize_object_action(
                    &view,
                    &req.ctx,
                    &req.key,
                    &[S3Action::PutObject],
                    Some(&b.owner),
                    Some((&b.acl, AclPermission::Write)),
                    true,
                    &PolicyEvalExtra::default(),
                ) {
                    return Err(S3Error::new(
                        S3ErrorCode::NoSuchUpload,
                        "The specified upload does not exist.",
                    )
                    .with_upload(&req.bucket, &req.key, &req.upload_id));
                }
                return Err(
                    S3Error::new(S3ErrorCode::AccessDenied, "Access Denied").with_bucket(&req.bucket)
                );
            };
            if !has_upload_perm(
                b,
                self.cfg.default_object_ownership,
                &req.key,
                up,
                &req.ctx,
                &[S3Action::PutObject],
                AclPermission::Write,
            ) {
                return Err(
                    S3Error::new(S3ErrorCode::AccessDenied, "Access Denied").with_bucket(&req.bucket)
                );
            }
            let part_sse_req = validate_sse_read_or_part(&req.raw_sse)?;
            let (key_iv, sse_r) =
                match_sse_for_stored_object(&up.sse, &part_sse_req, &self.sse_s3_master_key)?;
            (
                (up.checksum_algorithm, up.checksum_type),
                key_iv.map(|(k, _)| k),
                sse_r,
            )
        };

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

        if let Some(up_alg) = upload_csum_info.0
            && digests.checksum.client_requested && digests.checksum.algorithm != up_alg {
                return Err(S3Error::new(
                    S3ErrorCode::InvalidRequest,
                    format!(
                        "Checksum algorithm mismatch: upload expects {}",
                        up_alg.as_aws_str()
                    ),
                ));
            }

        let part_csum = upload_csum_info
            .0
            .map(|alg| (alg, compute_checksum_b64(alg, &buf)));
        let resp_csum = if let Some((alg, val)) = &part_csum {
            Some(ChecksumState {
                algorithm: *alg,
                checksum_type: ChecksumType::FullObject,
                value_b64: val.clone(),
                client_requested: true,
            })
        } else if digests.checksum.client_requested {
            Some(digests.checksum)
        } else {
            None
        };

        let etag = format!("\"{}\"", hex::encode(digests.md5));
        let mut guard = self.state.lock().unwrap();
        let b_ro = lookup_bucket_checked(&guard, &req.ctx, &req.bucket)?;
        if let Some(up_ro) = b_ro.uploads.get(&(req.key.clone(), req.upload_id.clone()))
            && !has_upload_perm(
                b_ro,
                self.cfg.default_object_ownership,
                &req.key,
                up_ro,
                &req.ctx,
                &[S3Action::PutObject],
                AclPermission::Write,
            ) {
                return Err(
                    S3Error::new(S3ErrorCode::AccessDenied, "Access Denied").with_bucket(&req.bucket)
                );
            }
        guard.next_seq += 1;
        let p_seq = guard.next_seq;
        let part_iv = if let Some(k) = &part_enc_key {
            let iv = model_make_iv(p_seq, req.part_number);
            aes256_ctr_xor(k, &iv, 0, &mut buf);
            Some(iv)
        } else {
            None
        };
        let data = buf.freeze();

        let b = guard.buckets.get_mut(&req.bucket).unwrap();
        let up = b
            .uploads
            .get_mut(&(req.key.clone(), req.upload_id.clone()))
            .ok_or_else(|| {
                S3Error::new(
                    S3ErrorCode::NoSuchUpload,
                    "The specified upload does not exist.",
                )
                .with_upload(&req.bucket, &req.key, &req.upload_id)
            })?;

        // [FR-25] Re-uploading same partNumber overwrites previous part
        up.parts.insert(
            req.part_number,
            ModelUploadPart {
                part_number: req.part_number,
                last_modified_ms: req.ctx.request_time_ms,
                etag: etag.clone(),
                data,
                md5: digests.md5,
                checksum: part_csum,
                sse_iv: part_iv,
            },
        );

        Ok(UploadPartResp {
            etag,
            checksum: resp_csum,
            sse: sse_resp,
        })
    }

    async fn upload_part_copy(&self, req: UploadPartCopyReq) -> StoreResult<UploadPartCopyResp> {
        validate_object_key(&req.dst_bucket, &req.dst_key)?;
        if req.part_number == 0 || req.part_number > MAX_PARTS_COUNT {
            return Err(S3Error::new(
                S3ErrorCode::InvalidArgument,
                "Part number must be an integer between 1 and 10000, inclusive",
            ));
        }

        let mut guard = self.state.lock().unwrap();
        let src_b = lookup_bucket_checked(&guard, &req.ctx, &req.src_bucket)?;
        let dst_b_ro = lookup_bucket_checked(&guard, &req.ctx, &req.dst_bucket)?;
        let Some(up_ro) = dst_b_ro
            .uploads
            .get(&(req.dst_key.clone(), req.upload_id.clone()))
        else {
            let view = dst_b_ro.auth_view(self.cfg.default_object_ownership);
            if authorize_object_action(
                &view,
                &req.ctx,
                &req.dst_key,
                &[S3Action::PutObject],
                Some(&dst_b_ro.owner),
                Some((&dst_b_ro.acl, AclPermission::Write)),
                true,
                &PolicyEvalExtra::default(),
            ) {
                return Err(S3Error::new(
                    S3ErrorCode::NoSuchUpload,
                    "The specified upload does not exist.",
                )
                .with_upload(&req.dst_bucket, &req.dst_key, &req.upload_id));
            }
            return Err(
                S3Error::new(S3ErrorCode::AccessDenied, "Access Denied").with_bucket(&req.dst_bucket)
            );
        };
        if !has_upload_perm(
            dst_b_ro,
            self.cfg.default_object_ownership,
            &req.dst_key,
            up_ro,
            &req.ctx,
            &[S3Action::PutObject],
            AclPermission::Write,
        ) {
            return Err(
                S3Error::new(S3ErrorCode::AccessDenied, "Access Denied").with_bucket(&req.dst_bucket)
            );
        }
        let up_alg = up_ro.checksum_algorithm;
        let up_sse = up_ro.sse;

        let src_ver = self
            .lookup_version_for_copy_checked(
                src_b,
                &req.ctx,
                &req.src_bucket,
                &req.src_key,
                req.src_version_id.as_deref(),
            )?
            .clone();

        let dst_sse_req = validate_sse_read_or_part(&req.raw_sse)?;
        let (dst_key_iv, sse_resp) =
            match_sse_for_stored_object(&up_sse, &dst_sse_req, &self.sse_s3_master_key)?;
        let src_sse_req = validate_copy_source_sse(&req.raw_copy_src_sse)?;
        let (src_key_iv, _) =
            match_sse_for_stored_object(&src_ver.sse, &src_sse_req, &self.sse_s3_master_key)?;

        evaluate_copy_source_preconditions(
            &req.src_preconditions,
            &src_ver.etag,
            src_ver.last_modified_ms,
        )?;

        let src_len = src_ver.data.len() as u64;
        let (cp_start, cp_end_excl) = if let Some((start, end)) = req.src_range {
            // [FR-31] Out-of-bounds x-amz-copy-source-range -> InvalidRange (or InvalidArgument)
            if start > end || end >= src_len {
                return Err(S3Error::new(
                    S3ErrorCode::InvalidRange,
                    "Range specified is not valid for source object",
                ));
            }
            if end - start + 1 > MAX_PART_SIZE_BYTES {
                return Err(S3Error::new(
                    S3ErrorCode::EntityTooLarge,
                    "Your proposed upload exceeds the maximum allowed size",
                ));
            }
            (start, end + 1)
        } else {
            if src_len > MAX_PART_SIZE_BYTES {
                return Err(S3Error::new(
                    S3ErrorCode::EntityTooLarge,
                    "Your proposed upload exceeds the maximum allowed size",
                ));
            }
            (0, src_len)
        };

        let plain_slice = decrypt_model_version_slice(&src_ver, src_key_iv, cp_start, cp_end_excl);
        let md5: [u8; 16] = Md5::digest(&plain_slice).into();
        let etag = format!("\"{}\"", hex::encode(md5));
        let part_csum = up_alg.map(|alg| (alg, compute_checksum_b64(alg, &plain_slice)));
        let resp_csum = part_csum.as_ref().map(|(alg, val)| ChecksumState {
            algorithm: *alg,
            checksum_type: ChecksumType::FullObject,
            value_b64: val.clone(),
            client_requested: true,
        });

        guard.next_seq += 1;
        let p_seq = guard.next_seq;
        let mut stored_buf = BytesMut::from(plain_slice.as_ref());
        let part_iv = if let Some((dst_k, _)) = &dst_key_iv {
            let iv = model_make_iv(p_seq, req.part_number);
            aes256_ctr_xor(dst_k, &iv, 0, &mut stored_buf);
            Some(iv)
        } else {
            None
        };

        let dst_b = guard.buckets.get_mut(&req.dst_bucket).unwrap();
        let up = dst_b
            .uploads
            .get_mut(&(req.dst_key.clone(), req.upload_id.clone()))
            .unwrap();
        up.parts.insert(
            req.part_number,
            ModelUploadPart {
                part_number: req.part_number,
                last_modified_ms: req.ctx.request_time_ms,
                etag: etag.clone(),
                data: stored_buf.freeze(),
                md5,
                checksum: part_csum,
                sse_iv: part_iv,
            },
        );

        Ok(UploadPartCopyResp {
            etag,
            last_modified_ms: req.ctx.request_time_ms,
            src_version_id: src_ver.version_id,
            checksum: resp_csum,
            sse: sse_resp,
        })
    }

    async fn complete_multipart_upload(
        &self,
        req: CompleteMultipartUploadReq,
    ) -> StoreResult<CompleteMultipartUploadResp> {
        validate_object_key(&req.bucket, &req.key)?;
        // [FR-26] Empty parts list -> 400 MalformedXML
        if req.parts.is_empty() {
            return Err(S3Error::new(
                S3ErrorCode::MalformedXML,
                "The XML you provided was not well-formed or did not validate against our published schema",
            ));
        }

        let mut guard = self.state.lock().unwrap();
        let b_ro = lookup_bucket_checked(&guard, &req.ctx, &req.bucket)?;

        // [FR-27] 24h idempotent replay of completed UploadId
        if let Some((completed_ms, cached_resp)) = b_ro
            .completed_uploads
            .get(&(req.key.clone(), req.upload_id.clone()))
            .cloned()
        {
            let view = b_ro.auth_view(self.cfg.default_object_ownership);
            if !authorize_object_action(
                &view,
                &req.ctx,
                &req.key,
                &[S3Action::PutObject],
                Some(&b_ro.owner),
                Some((&b_ro.acl, AclPermission::Write)),
                true,
                &PolicyEvalExtra::default(),
            ) {
                return Err(
                    S3Error::new(S3ErrorCode::AccessDenied, "Access Denied").with_bucket(&req.bucket)
                );
            }
            if req.ctx.request_time_ms.saturating_sub(completed_ms)
                <= self.cfg.completed_upload_retention_ms
            {
                return Ok(cached_resp);
            }
        }

        let Some(up) = b_ro
            .uploads
            .get(&(req.key.clone(), req.upload_id.clone()))
            .cloned()
        else {
            let view = b_ro.auth_view(self.cfg.default_object_ownership);
            if authorize_object_action(
                &view,
                &req.ctx,
                &req.key,
                &[S3Action::PutObject],
                Some(&b_ro.owner),
                Some((&b_ro.acl, AclPermission::Write)),
                true,
                &PolicyEvalExtra::default(),
            ) {
                return Err(S3Error::new(
                    S3ErrorCode::NoSuchUpload,
                    "The specified upload does not exist.",
                )
                .with_upload(&req.bucket, &req.key, &req.upload_id));
            }
            return Err(
                S3Error::new(S3ErrorCode::AccessDenied, "Access Denied").with_bucket(&req.bucket)
            );
        };
        if !has_upload_perm(
            b_ro,
            self.cfg.default_object_ownership,
            &req.key,
            &up,
            &req.ctx,
            &[S3Action::PutObject],
            AclPermission::Write,
        ) {
            return Err(
                S3Error::new(S3ErrorCode::AccessDenied, "Access Denied").with_bucket(&req.bucket)
            );
        }

        let complete_sse_req = validate_sse_read_or_part(&req.raw_sse)?;
        let (complete_key_iv, sse_resp) =
            match_sse_for_stored_object(&up.sse, &complete_sse_req, &self.sse_s3_master_key)?;

        let deduped_parts = dedup_complete_parts(&req.parts)?;
        let mut concat = BytesMut::new();
        let mut plain_concat = BytesMut::new();
        let mut md5_concat = Vec::with_capacity(deduped_parts.len() * 16);
        let mut boundaries = Vec::with_capacity(deduped_parts.len());
        let mut part_csum_b64s = Vec::with_capacity(deduped_parts.len());

        for (idx, spec) in deduped_parts.iter().enumerate() {
            let Some(uploaded) = up.parts.get(&spec.part_number) else {
                return Err(S3Error::new(
                    S3ErrorCode::InvalidPart,
                    "One or more of the specified parts could not be found.",
                ));
            };
            if strip_etag_quotes(&spec.etag) != strip_etag_quotes(&uploaded.etag) {
                return Err(S3Error::new(
                    S3ErrorCode::InvalidPart,
                    "One or more of the specified parts could not be found.",
                ));
            }

            let part_len = uploaded.data.len() as u64;
            let is_last = idx + 1 == deduped_parts.len();
            if !is_last && part_len < MIN_PART_SIZE_BYTES {
                // [FR-26] Non-final part < 5 MiB -> 400 EntityTooSmall
                return Err(S3Error::new(
                    S3ErrorCode::EntityTooSmall,
                    "Your proposed upload is smaller than the minimum allowed size",
                ));
            }

            if let Some((spec_alg, spec_b64)) = &spec.checksum {
                match (&up.checksum_algorithm, &uploaded.checksum) {
                    (Some(up_alg), Some((_, actual_b64))) if spec_alg == up_alg => {
                        if spec_b64.trim() != actual_b64 {
                            return Err(S3Error::new(
                                S3ErrorCode::BadDigest,
                                "The part checksum did not match.",
                            ));
                        }
                    }
                    _ => {
                        return Err(S3Error::new(
                            S3ErrorCode::BadDigest,
                            "Unexpected or mismatched part checksum.",
                        ));
                    }
                }
            }

            if let Some((_, b64_val)) = &uploaded.checksum {
                part_csum_b64s.push(b64_val.clone());
            }

            concat.extend_from_slice(&uploaded.data);
            if let Some((k, up_iv)) = &complete_key_iv {
                let mut dec = uploaded.data.to_vec();
                aes256_ctr_xor(k, &uploaded.sse_iv.unwrap_or(*up_iv), 0, &mut dec);
                plain_concat.extend_from_slice(&dec);
            } else {
                plain_concat.extend_from_slice(&uploaded.data);
            }
            md5_concat.extend_from_slice(&uploaded.md5);
            boundaries.push(ModelPartBoundary {
                part_number: uploaded.part_number,
                size: part_len,
                checksum: uploaded.checksum.clone(),
                sse_iv: uploaded.sse_iv,
            });
        }

        let full_data = concat.freeze();
        let plain_data = plain_concat.freeze();
        let total_size = full_data.len() as u64;
        if total_size > self.cfg.max_object_size {
            return Err(S3Error::new(
                S3ErrorCode::EntityTooLarge,
                "Your proposed upload exceeds the maximum allowed size",
            ));
        }
        if let Some(exp_size) = req.expected_object_size
            && exp_size != total_size {
                return Err(S3Error::new(
                    S3ErrorCode::PreconditionFailed,
                    "Object size does not match x-amz-mp-object-size.",
                ));
            }

        // [PR-25] Final object checksum over plaintext bytes
        let final_checksum = match (up.checksum_algorithm, up.checksum_type) {
            (Some(alg), Some(ChecksumType::Composite)) => ChecksumState {
                algorithm: alg,
                checksum_type: ChecksumType::Composite,
                value_b64: compute_composite_checksum_b64(alg, &part_csum_b64s)?,
                client_requested: true,
            },
            (Some(alg), Some(ChecksumType::FullObject)) => ChecksumState {
                algorithm: alg,
                checksum_type: ChecksumType::FullObject,
                value_b64: compute_checksum_b64(alg, &plain_data),
                client_requested: true,
            },
            _ => ChecksumState {
                algorithm: ChecksumAlgorithm::Crc64Nvme,
                checksum_type: ChecksumType::FullObject,
                value_b64: compute_checksum_b64(ChecksumAlgorithm::Crc64Nvme, &plain_data),
                client_requested: false,
            },
        };

        if let Some((exp_alg, exp_val)) = &req.expected_checksum
            && (!final_checksum.client_requested
                || *exp_alg != final_checksum.algorithm
                || exp_val.trim() != final_checksum.value_b64)
            {
                return Err(S3Error::new(
                    S3ErrorCode::BadDigest,
                    "The digest you specified did not match the calculated digest.",
                ));
            }

        // [FR-15, FR-17] Evaluate destination preconditions at commit point
        // [FR-2] Concurrent PUTs to the same key serialize at commit point (last writer wins)
        guard.next_seq += 1;
        let seq = guard.next_seq;
        let b = guard.buckets.get_mut(&req.bucket).unwrap();
        let head = head_state_of(b.objects.get(&req.key));
        evaluate_write_preconditions(&req.preconditions, &req.bucket, &req.key, head)?;

        // [FR-7] Composite ETag: MD5(concat(part_md5s))-<N>
        let outer_md5: [u8; 16] = Md5::digest(&md5_concat).into();
        let etag = format!("\"{}-{}\"", hex::encode(outer_md5), deduped_parts.len());
        let version_id = match b.versioning {
            VersioningStatus::Unversioned => None,
            VersioningStatus::Suspended => Some("null".to_string()),
            VersioningStatus::Enabled => Some(format!("v{seq:016x}")),
        };

        let exp_hdr = compute_x_amz_expiration(
            b.lifecycle.as_ref(),
            &req.key,
            total_size,
            &up.tags,
            req.ctx.request_time_ms,
        );

        let ver = ModelVersion {
            seq,
            version_id: version_id.clone(),
            is_delete_marker: false,
            data: full_data,
            etag: etag.clone(),
            checksum: final_checksum.clone(),
            sys_meta: up.sys_meta,
            user_meta: up.user_meta,
            owner: up.owner,
            acl: up.acl,
            tags: up.tags,
            last_modified_ms: req.ctx.request_time_ms,
            // [FR-30] Preserve per-part boundaries & checksums on completed multipart object
            parts: Some(boundaries),
            sse: up.sse,
            retention: up.retention,
            legal_hold: up.legal_hold,
        };

        let chain = b.objects.entry(req.key.clone()).or_default();
        insert_version_into_chain(b.versioning, chain, ver);
        b.uploads.remove(&(req.key.clone(), req.upload_id.clone()));

        let resp = CompleteMultipartUploadResp {
            bucket: req.bucket,
            key: req.key.clone(),
            etag,
            version_id,
            checksum: final_checksum.client_requested.then_some(final_checksum),
            sse: sse_resp,
            expiration_header: exp_hdr,
        };
        b.completed_uploads.insert(
            (req.key, req.upload_id),
            (req.ctx.request_time_ms, resp.clone()),
        );
        Ok(resp)
    }

    async fn abort_multipart_upload(&self, req: AbortMultipartUploadReq) -> StoreResult<()> {
        validate_object_key(&req.bucket, &req.key)?;
        let mut guard = self.state.lock().unwrap();
        let b_ro = lookup_bucket_checked(&guard, &req.ctx, &req.bucket)?;
        if let Some(up) = b_ro.uploads.get(&(req.key.clone(), req.upload_id.clone())) {
            if !has_upload_perm(
                b_ro,
                self.cfg.default_object_ownership,
                &req.key,
                up,
                &req.ctx,
                &[S3Action::AbortMultipartUpload],
                AclPermission::Write,
            ) {
                return Err(
                    S3Error::new(S3ErrorCode::AccessDenied, "Access Denied").with_bucket(&req.bucket)
                );
            }
        } else {
            let view = b_ro.auth_view(self.cfg.default_object_ownership);
            if authorize_object_action(
                &view,
                &req.ctx,
                &req.key,
                &[S3Action::AbortMultipartUpload],
                Some(&b_ro.owner),
                Some((&b_ro.acl, AclPermission::Write)),
                true,
                &PolicyEvalExtra::default(),
            ) {
                return Err(S3Error::new(
                    S3ErrorCode::NoSuchUpload,
                    "The specified upload does not exist.",
                )
                .with_upload(&req.bucket, &req.key, &req.upload_id));
            }
            return Err(
                S3Error::new(S3ErrorCode::AccessDenied, "Access Denied").with_bucket(&req.bucket)
            );
        }
        let b = guard.buckets.get_mut(&req.bucket).unwrap();
        // [FR-28] Repeated Abort returns 404 NoSuchUpload
        b.uploads.remove(&(req.key, req.upload_id));
        Ok(())
    }

    async fn list_parts(&self, req: ListPartsReq) -> StoreResult<ListPartsResp> {
        validate_object_key(&req.bucket, &req.key)?;
        let guard = self.state.lock().unwrap();
        let b = lookup_bucket_checked(&guard, &req.ctx, &req.bucket)?;
        let Some(up) = b.uploads.get(&(req.key.clone(), req.upload_id.clone())) else {
            let view = b.auth_view(self.cfg.default_object_ownership);
            if authorize_object_action(
                &view,
                &req.ctx,
                &req.key,
                &[S3Action::ListMultipartUploadParts],
                Some(&b.owner),
                Some((&b.acl, AclPermission::Read)),
                true,
                &PolicyEvalExtra::default(),
            ) {
                return Err(S3Error::new(
                    S3ErrorCode::NoSuchUpload,
                    "The specified upload does not exist.",
                )
                .with_upload(&req.bucket, &req.key, &req.upload_id));
            }
            return Err(
                S3Error::new(S3ErrorCode::AccessDenied, "Access Denied").with_bucket(&req.bucket)
            );
        };
        if !has_upload_perm(
            b,
            self.cfg.default_object_ownership,
            &req.key,
            up,
            &req.ctx,
            &[S3Action::ListMultipartUploadParts],
            AclPermission::Read,
        ) {
            return Err(
                S3Error::new(S3ErrorCode::AccessDenied, "Access Denied").with_bucket(&req.bucket)
            );
        }

        // [FR-29] ListParts pagination (<= 1000 parts, part-number-marker)
        let max_p = req.max_parts.min(1000);
        let mut parts = Vec::new();
        let mut is_truncated = false;
        if max_p > 0 {
            for p in up.parts.values() {
                if p.part_number <= req.part_number_marker {
                    continue;
                }
                if parts.len() == max_p {
                    is_truncated = true;
                    break;
                }
                parts.push(PartSummary {
                    part_number: p.part_number,
                    last_modified_ms: p.last_modified_ms,
                    etag: p.etag.clone(),
                    size: p.data.len() as u64,
                    checksum: p.checksum.clone(),
                });
            }
        }
        let next_marker = parts
            .last()
            .map(|p| p.part_number)
            .unwrap_or(req.part_number_marker);

        Ok(ListPartsResp {
            bucket: req.bucket,
            key: req.key,
            upload_id: req.upload_id,
            initiator: up.initiator.clone(),
            owner: up.owner.clone(),
            storage_class: "STANDARD".to_string(),
            checksum_algorithm: up.checksum_algorithm,
            checksum_type: up.checksum_type,
            part_number_marker: req.part_number_marker,
            next_part_number_marker: next_marker,
            max_parts: max_p,
            is_truncated,
            parts,
        })
    }

    async fn list_multipart_uploads(
        &self,
        req: ListMultipartUploadsReq,
    ) -> StoreResult<ListMultipartUploadsResp> {
        let guard = self.state.lock().unwrap();
        let extra = PolicyEvalExtra {
            prefix: Some(&req.prefix),
            delimiter: req.delimiter.as_deref(),
            ..Default::default()
        };
        let b = check_bucket_action(
            &guard,
            self.cfg.default_object_ownership,
            &req.ctx,
            &req.bucket,
            &[S3Action::ListBucketMultipartUploads],
            Some(AclPermission::Read),
            &extra,
        )?;
        // [FR-29] ListMultipartUploads pagination (<= 1000 uploads, key-marker + upload-id-marker)
        let max_u = req.max_uploads.min(1000);
        let km = req.key_marker.clone().unwrap_or_default();
        let um = req.upload_id_marker.clone().unwrap_or_default();

        let mut uploads = Vec::new();
        let mut common_prefixes = Vec::new();
        let mut last_cp: Option<String> = None;
        let mut is_truncated = false;
        let mut next_km = None;
        let mut next_um = None;

        if max_u > 0 {
            for ((key, uid), up) in &b.uploads {
                if !key.starts_with(&req.prefix) {
                    continue;
                }
                if !km.is_empty() {
                    if key.as_str() < km.as_str() {
                        continue;
                    }
                    if key == &km && (um.is_empty() || uid.as_str() <= um.as_str()) {
                        continue;
                    }
                }
                let rest = &key[req.prefix.len()..];
                if let Some(delim) = req.delimiter.as_deref().filter(|d| !d.is_empty())
                    && let Some(pos) = rest.find(delim) {
                        let cp = format!("{}{}", req.prefix, &rest[..pos + delim.len()]);
                        if !km.is_empty() && cp.as_str() <= km.as_str() {
                            continue;
                        }
                        if last_cp.as_deref() == Some(cp.as_str()) {
                            continue;
                        }
                        if uploads.len() + common_prefixes.len() == max_u {
                            is_truncated = true;
                            break;
                        }
                        next_km = Some(cp.clone());
                        next_um = None;
                        last_cp = Some(cp.clone());
                        common_prefixes.push(cp);
                        continue;
                    }
                if uploads.len() + common_prefixes.len() == max_u {
                    is_truncated = true;
                    break;
                }
                next_km = Some(key.clone());
                next_um = Some(uid.clone());
                uploads.push(MultipartUploadSummary {
                    key: key.clone(),
                    upload_id: uid.clone(),
                    initiator: up.initiator.clone(),
                    owner: up.owner.clone(),
                    storage_class: "STANDARD".to_string(),
                    initiated_ms: up.initiated_ms,
                    checksum_algorithm: up.checksum_algorithm,
                    checksum_type: up.checksum_type,
                });
            }
        }

        if !is_truncated {
            next_km = None;
            next_um = None;
        }

        Ok(ListMultipartUploadsResp {
            bucket: req.bucket,
            key_marker: km,
            upload_id_marker: um,
            next_key_marker: next_km,
            next_upload_id_marker: next_um,
            prefix: req.prefix,
            delimiter: req.delimiter,
            max_uploads: max_u,
            is_truncated,
            uploads,
            common_prefixes,
        })
    }

    async fn list_objects_v1(&self, req: ListObjectsV1Req) -> StoreResult<ListObjectsV1Resp> {
        let guard = self.state.lock().unwrap();
        let extra = PolicyEvalExtra {
            prefix: Some(&req.prefix),
            delimiter: req.delimiter.as_deref(),
            ..Default::default()
        };
        let b = check_bucket_action(
            &guard,
            self.cfg.default_object_ownership,
            &req.ctx,
            &req.bucket,
            &[S3Action::ListBucket],
            Some(AclPermission::Read),
            &extra,
        )?;
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
        let extra = PolicyEvalExtra {
            prefix: Some(&req.prefix),
            delimiter: req.delimiter.as_deref(),
            ..Default::default()
        };
        let b = check_bucket_action(
            &guard,
            self.cfg.default_object_ownership,
            &req.ctx,
            &req.bucket,
            &[S3Action::ListBucket],
            Some(AclPermission::Read),
            &extra,
        )?;
        let max_keys = req.max_keys.min(1000);
        let token_after = match &req.continuation_token {
            Some(tok) if !tok.is_empty() => Some(decode_token(&req.bucket, tok)?),
            _ => None,
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
        let extra = PolicyEvalExtra {
            prefix: Some(&req.prefix),
            delimiter: req.delimiter.as_deref(),
            ..Default::default()
        };
        let b = check_bucket_action(
            &guard,
            self.cfg.default_object_ownership,
            &req.ctx,
            &req.bucket,
            &[S3Action::ListBucketVersions],
            Some(AclPermission::Read),
            &extra,
        )?;
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

        // [FR-38] ListObjectVersions sorted by key ascending, newest version first,
        // supporting key-marker + version-id-marker pagination, IsLatest, and delete markers.
        'outer: for (key, chain) in &b.objects {
            if !key.starts_with(&req.prefix) {
                continue;
            }
            if !km.is_empty() && key.as_str() < km.as_str() {
                continue;
            }
            let rest = &key[req.prefix.len()..];
            if let Some(delim) = req.delimiter.as_deref().filter(|d| !d.is_empty())
                && let Some(pos) = rest.find(delim) {
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
    fn lookup_version_for_read<'a>(
        &self,
        b: &'a ModelBucket,
        bucket_name: &str,
        key: &str,
        version_id: Option<&str>,
    ) -> StoreResult<&'a ModelVersion> {
        match version_id {
            None => {
                let Some(head) = b.objects.get(key).and_then(|c| c.first()) else {
                    return Err(
                        S3Error::new(S3ErrorCode::NoSuchKey, "The specified key does not exist.")
                            .with_key(bucket_name, key)
                            .with_header("x-amz-delete-marker", "false"),
                    );
                };
                if head.is_delete_marker {
                    // [FR-37] Current version is delete marker -> 404 + x-amz-delete-marker: true
                    let mut err =
                        S3Error::new(S3ErrorCode::NoSuchKey, "The specified key does not exist.")
                            .with_key(bucket_name, key)
                            .with_header("x-amz-delete-marker", "true");
                    if let Some(vid) = &head.version_id {
                        err = err.with_header("x-amz-version-id", vid.clone());
                    }
                    return Err(err);
                }
                Ok(head)
            }
            Some(vid) => {
                let Some(found) = b.objects.get(key).and_then(|c| {
                    c.iter()
                        .find(|v| v.version_id.as_deref().unwrap_or("null") == vid)
                }) else {
                    return Err(S3Error::new(
                        S3ErrorCode::NoSuchVersion,
                        "The specified version does not exist.",
                    )
                    .with_key(bucket_name, key));
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
                Ok(found)
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn lookup_version_for_op_checked<'a>(
        &self,
        b: &'a ModelBucket,
        ctx: &CallerContext,
        bucket_name: &str,
        key: &str,
        version_id: Option<&str>,
        actions: &[S3Action],
        acl_needed: Option<AclPermission>,
        req_tags: Option<&BTreeMap<String, String>>,
    ) -> StoreResult<&'a ModelVersion> {
        let view = b.auth_view(self.cfg.default_object_ownership);
        match self.lookup_version_for_read(b, bucket_name, key, version_id) {
            Ok(ver) => {
                let extra = PolicyEvalExtra {
                    existing_object_tags: Some(&ver.tags),
                    request_object_tags: req_tags,
                    ..Default::default()
                };
                let acl_grant = acl_needed.map(|perm| (&ver.acl, perm));
                if !authorize_object_action(
                    &view,
                    ctx,
                    key,
                    actions,
                    Some(&ver.owner),
                    acl_grant,
                    false,
                    &extra,
                ) {
                    return Err(
                        S3Error::new(S3ErrorCode::AccessDenied, "Access Denied")
                            .with_key(bucket_name, key),
                    );
                }
                Ok(ver)
            }
            Err(err) => {
                if can_reveal_missing_key(&view, ctx, key, version_id.is_some()) {
                    Err(err)
                } else {
                    Err(
                        S3Error::new(S3ErrorCode::AccessDenied, "Access Denied")
                            .with_key(bucket_name, key),
                    )
                }
            }
        }
    }

    fn lookup_version_for_copy_checked<'a>(
        &self,
        b: &'a ModelBucket,
        ctx: &CallerContext,
        bucket_name: &str,
        key: &str,
        version_id: Option<&str>,
    ) -> StoreResult<&'a ModelVersion> {
        let view = b.auth_view(self.cfg.default_object_ownership);
        let actions: &[S3Action] = if version_id.is_some() {
            &[S3Action::GetObjectVersion, S3Action::GetObject]
        } else {
            &[S3Action::GetObject]
        };
        let ver = match version_id {
            None => b
                .objects
                .get(key)
                .and_then(|c| c.first())
                .filter(|v| !v.is_delete_marker),
            Some(vid) => b.objects.get(key).and_then(|c| {
                c.iter()
                    .find(|v| v.version_id.as_deref().unwrap_or("null") == vid)
            }),
        };
        let Some(ver) = ver else {
            if can_reveal_missing_key(&view, ctx, key, version_id.is_some()) {
                return Err(
                    S3Error::new(S3ErrorCode::NoSuchKey, "The specified key does not exist.")
                        .with_key(bucket_name, key),
                );
            }
            return Err(
                S3Error::new(S3ErrorCode::AccessDenied, "Access Denied").with_key(bucket_name, key)
            );
        };
        if ver.is_delete_marker {
            if !can_reveal_missing_key(&view, ctx, key, true) {
                return Err(
                    S3Error::new(S3ErrorCode::AccessDenied, "Access Denied")
                        .with_key(bucket_name, key),
                );
            }
            return Err(S3Error::new(
                S3ErrorCode::InvalidRequest,
                "The source of a copy request may not specifically refer to a delete marker by version id.",
            ));
        }
        let extra = PolicyEvalExtra {
            existing_object_tags: Some(&ver.tags),
            ..Default::default()
        };
        if !authorize_object_action(
            &view,
            ctx,
            key,
            actions,
            Some(&ver.owner),
            Some((&ver.acl, AclPermission::Read)),
            false,
            &extra,
        ) {
            return Err(
                S3Error::new(S3ErrorCode::AccessDenied, "Access Denied").with_key(bucket_name, key)
            );
        }
        Ok(ver)
    }

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
        let b = lookup_bucket_checked(&guard, &req.ctx, &req.bucket)?;
        let actions: &[S3Action] = if req.version_id.is_some() {
            &[S3Action::GetObjectVersion, S3Action::GetObject]
        } else {
            &[S3Action::GetObject]
        };
        let ver = self.lookup_version_for_op_checked(
            b,
            &req.ctx,
            &req.bucket,
            &req.key,
            req.version_id.as_deref(),
            actions,
            Some(AclPermission::Read),
            None,
        )?;
        let sse_read = validate_sse_read_or_part(&req.raw_sse)?;

        let total_size = ver.data.len() as u64;
        let mut part_specific_csum: Option<ChecksumState> = None;

        // Validate partNumber bounds BEFORE SSE-C key match (`test_multipart_sse_c_get_part`)
        let (start, end, is_partial, parts_count) = if let Some(pn) = req.part_number {
            // [FR-10] partNumber reading
            if pn == 0 || pn > MAX_PARTS_COUNT {
                return Err(S3Error::new(
                    S3ErrorCode::InvalidArgument,
                    "Part number must be an integer between 1 and 10000, inclusive",
                ));
            }
            match &ver.parts {
                None => {
                    if pn != 1 {
                        return Err(S3Error::new(
                            S3ErrorCode::InvalidPart,
                            "The requested partnumber is not satisfiable",
                        ));
                    }
                    if total_size == 0 {
                        (0, 0, false, None)
                    } else {
                        (0, total_size - 1, true, None)
                    }
                }
                Some(parts) => {
                    if (pn as usize) > parts.len() {
                        return Err(S3Error::new(
                            S3ErrorCode::InvalidPart,
                            "The requested partnumber is not satisfiable",
                        ));
                    }
                    let offset: u64 = parts[..(pn as usize - 1)].iter().map(|p| p.size).sum();
                    let pinfo = &parts[pn as usize - 1];
                    if let Some((alg, b64_val)) = &pinfo.checksum {
                        part_specific_csum = Some(ChecksumState {
                            algorithm: *alg,
                            checksum_type: ver.checksum.checksum_type,
                            value_b64: b64_val.clone(),
                            client_requested: true,
                        });
                    }
                    if pinfo.size == 0 {
                        (offset, offset, false, Some(parts.len() as u32))
                    } else {
                        (offset, offset + pinfo.size - 1, true, Some(parts.len() as u32))
                    }
                }
            }
        } else if let Some(range_spec) = req.range {
            // [FR-9] Byte-range resolution (bytes=a-b, a-, -n -> 206 + Content-Range; unsatisfiable -> 416 InvalidRange)
            let (s, e) = range_spec.resolve(total_size)?;
            (s, e, true, None)
        } else if total_size == 0 {
            (0, 0, false, None)
        } else {
            (0, total_size - 1, false, None)
        };

        let (key_iv, sse_resp) =
            match_sse_for_stored_object(&ver.sse, &sse_read, &self.sse_s3_master_key)?;

        let last_mod_http = httpdate::fmt_http_date(
            std::time::UNIX_EPOCH
                + std::time::Duration::from_millis(ver.last_modified_ms.max(0) as u64),
        );
        // [FR-12, FR-13] Conditional read headers & RFC 9110 combination precedence
        evaluate_read_preconditions(
            &req.preconditions,
            &ver.etag,
            ver.last_modified_ms,
            &last_mod_http,
        )?;

        let content_len = if let Some(pn) = req.part_number {
            if let Some(parts) = &ver.parts {
                parts[pn as usize - 1].size
            } else {
                total_size
            }
        } else if total_size == 0 && !is_partial {
            0
        } else if is_partial && total_size > 0 {
            end - start + 1
        } else {
            total_size
        };

        let content_range = if is_partial && content_len > 0 {
            Some((start, end, total_size))
        } else {
            None
        };

        // [PR-24] Full-object checksum returned when checksum_mode == ENABLED; part read returns part checksum if present
        let checksum = if part_specific_csum.is_some() {
            part_specific_csum
        } else if req.checksum_mode_enabled && req.range.is_none() && req.part_number.is_none() {
            Some(ver.checksum.clone())
        } else {
            None
        };

        let slice = if need_bytes && content_len > 0 {
            decrypt_model_version_slice(ver, key_iv, start, end + 1)
        } else {
            Bytes::new()
        };

        let is_current = b
            .objects
            .get(&req.key)
            .and_then(|c| c.first())
            .is_some_and(|h| h.seq == ver.seq);
        let exp_hdr = if is_current {
            compute_x_amz_expiration(
                b.lifecycle.as_ref(),
                &req.key,
                total_size,
                &ver.tags,
                ver.last_modified_ms,
            )
        } else {
            None
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
            tags_count: ver.tags.len(),
            sse: sse_resp,
            retention: ver.retention,
            legal_hold: ver.legal_hold,
            expiration_header: exp_hdr,
        };
        Ok((meta, slice))
    }

    /// Execute one lifecycle evaluation sweep across all buckets (`PR-39` ~ `PR-40`).
    pub fn run_lifecycle_tick(&self, now_ms: i64, lc_debug_interval_secs: Option<u64>) {
        let day_ms: i64 = lc_debug_interval_secs
            .map(|s| (s as i64).saturating_mul(1000))
            .unwrap_or(86_400_000);

        let mut guard = self.state.lock().unwrap();
        let bucket_names: Vec<String> = guard.buckets.keys().cloned().collect();

        for bname in bucket_names {
            let Some(lc) = guard
                .buckets
                .get(&bname)
                .and_then(|b| b.lifecycle.clone())
            else {
                continue;
            };

            // 1. Current version Expiration (Days / Date)
            let expired_current_keys: Vec<String> = {
                let b = guard.buckets.get(&bname).unwrap();
                let mut out = Vec::new();
                for (key, chain) in &b.objects {
                    let Some(head) = chain.first() else { continue };
                    if head.is_delete_marker {
                        continue;
                    }
                    let size = head.data.len() as u64;
                    let is_exp = lc.rules.iter().any(|rule| {
                        if rule.status != LifecycleRuleStatus::Enabled {
                            return false;
                        }
                        let Some(exp) = &rule.expiration else {
                            return false;
                        };
                        if !rule.matches_object(key, size, &head.tags) {
                            return false;
                        }
                        if let Some(d) = exp.days {
                            if lc_debug_interval_secs.is_some() {
                                now_ms.saturating_sub(head.last_modified_ms)
                                    >= i64::from(d).saturating_mul(day_ms)
                            } else {
                                let exp_ms = ((head.last_modified_ms.div_euclid(1000))
                                    .div_euclid(86_400)
                                    + i64::from(d)
                                    + 1)
                                    * 86_400_000;
                                now_ms >= exp_ms
                            }
                        } else if let Some(date_us) = exp.date_us {
                            now_ms.saturating_mul(1000) >= date_us
                        } else {
                            false
                        }
                    });
                    if is_exp {
                        out.push(key.clone());
                    }
                }
                out
            };

            for key in expired_current_keys {
                guard.next_seq += 1;
                let seq = guard.next_seq;
                let b = guard.buckets.get_mut(&bname).unwrap();
                match b.versioning {
                    VersioningStatus::Unversioned => {
                        let locked = b
                            .objects
                            .get(&key)
                            .and_then(|c| c.first())
                            .is_some_and(|h| {
                                check_worm_version_delete(
                                    h.retention,
                                    h.legal_hold,
                                    false,
                                    false,
                                    now_ms,
                                )
                                .is_err()
                            });
                        if !locked {
                            b.objects.remove(&key);
                        }
                    }
                    VersioningStatus::Enabled | VersioningStatus::Suspended => {
                        let vid = if b.versioning == VersioningStatus::Suspended {
                            "null".to_string()
                        } else {
                            format!("v{seq:016x}")
                        };
                        let dm_owner = b.owner.clone();
                        let dm_acl = AccessControlPolicy::new_private(dm_owner.clone());
                        let dm = ModelVersion {
                            seq,
                            version_id: Some(vid),
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
                            owner: dm_owner,
                            acl: dm_acl,
                            tags: BTreeMap::new(),
                            last_modified_ms: now_ms,
                            parts: None,
                            sse: SseStoredMeta::None,
                            retention: None,
                            legal_hold: None,
                        };
                        if let Some(chain) = b.objects.get_mut(&key) {
                            if b.versioning == VersioningStatus::Suspended {
                                chain.retain(|v| v.version_id.as_deref().unwrap_or("null") != "null");
                            }
                            chain.insert(0, dm);
                        }
                    }
                }
            }

            // 2. NoncurrentVersionExpiration & 3. ExpiredObjectDeleteMarker
            {
                let b = guard.buckets.get_mut(&bname).unwrap();
                let all_keys: Vec<String> = b.objects.keys().cloned().collect();
                for key in all_keys {
                    let Some(chain) = b.objects.get_mut(&key) else {
                        continue;
                    };
                    if chain.len() >= 2 {
                        let mut remove_seqs: Vec<u64> = Vec::new();
                        let mut newer_nc_seen = 0u32;
                        for idx in 1..chain.len() {
                            let noncurrent_since_ms = chain[idx - 1].last_modified_ms;
                            let ver = &chain[idx];
                            if ver.is_delete_marker {
                                continue;
                            }
                            let cur_newer = newer_nc_seen;
                            newer_nc_seen = newer_nc_seen.saturating_add(1);
                            if check_worm_version_delete(
                                ver.retention,
                                ver.legal_hold,
                                false,
                                false,
                                now_ms,
                            )
                            .is_err()
                            {
                                continue;
                            }
                            let size = ver.data.len() as u64;
                            let should_del = lc.rules.iter().any(|rule| {
                                if rule.status != LifecycleRuleStatus::Enabled {
                                    return false;
                                }
                                let Some(nc) = &rule.noncurrent_version_expiration else {
                                    return false;
                                };
                                if !rule.matches_object(&key, size, &ver.tags) {
                                    return false;
                                }
                                if let Some(keep) = nc.newer_noncurrent_versions
                                    && cur_newer < keep
                                {
                                    return false;
                                }
                                now_ms.saturating_sub(noncurrent_since_ms)
                                    >= i64::from(nc.noncurrent_days).saturating_mul(day_ms)
                            });
                            if should_del {
                                remove_seqs.push(ver.seq);
                            }
                        }
                        if !remove_seqs.is_empty() {
                            chain.retain(|v| !remove_seqs.contains(&v.seq));
                        }
                    }

                    let remove_sole_dm = if chain.len() == 1 && chain[0].is_delete_marker {
                        lc.rules.iter().any(|rule| {
                            rule.status == LifecycleRuleStatus::Enabled
                                && rule
                                    .expiration
                                    .is_some_and(|e| e.expired_object_delete_marker == Some(true))
                                && rule.matches_key_without_tags_or_size(&key)
                        })
                    } else {
                        false
                    };
                    if remove_sole_dm || chain.is_empty() {
                        b.objects.remove(&key);
                    }
                }

                // 4. AbortIncompleteMultipartUpload
                let expired_uploads: Vec<(String, String)> = b
                    .uploads
                    .iter()
                    .filter_map(|((k, uid), up)| {
                        let should_abort = lc.rules.iter().any(|rule| {
                            if rule.status != LifecycleRuleStatus::Enabled {
                                return false;
                            }
                            let Some(ab) = &rule.abort_incomplete_multipart_upload else {
                                return false;
                            };
                            rule.matches_key_without_tags_or_size(k)
                                && now_ms.saturating_sub(up.initiated_ms)
                                    >= i64::from(ab.days_after_initiation).saturating_mul(day_ms)
                        });
                        should_abort.then(|| (k.clone(), uid.clone()))
                    })
                    .collect();
                for ku in expired_uploads {
                    b.uploads.remove(&ku);
                }
            }
        }
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
        ChecksumAlgorithm::Md5 => b64.encode(Md5::digest(bytes)),
        ChecksumAlgorithm::Sha512 => b64.encode(Sha512::digest(bytes)),
        ChecksumAlgorithm::XxHash64 => {
            let mut h = Xxh64::new(0);
            h.update(bytes);
            b64.encode(h.digest().to_be_bytes())
        }
        ChecksumAlgorithm::XxHash3 => {
            let mut h = Xxh3::new();
            h.update(bytes);
            b64.encode(h.digest().to_be_bytes())
        }
        ChecksumAlgorithm::XxHash128 => {
            let mut h = Xxh3::new();
            h.update(bytes);
            b64.encode(h.digest128().to_be_bytes())
        }
    }
}

#[cfg(test)]
mod tests {
    /// `VR-1`: Verify in a single `O(N)` pass that every functional requirement `FR-1` through
    /// `FR-51` is explicitly annotated in the non-test reference model (`crates/s3d-model/src/lib.rs`).
    #[test]
    fn vr1_all_51_fr_annotated_in_model() {
        let bytes = include_bytes!("lib.rs");
        let marker = b"#[cfg(test)]";
        let mut prod_end = bytes.len();
        let mut i = 0;
        while i + marker.len() <= bytes.len() {
            if &bytes[i..i + marker.len()] == marker {
                prod_end = i;
                break;
            }
            i += 1;
        }

        let mut seen = [false; 52];
        let mut pos = 0;
        while pos + 4 <= prod_end {
            if bytes[pos] == b'F' && bytes[pos + 1] == b'R' && bytes[pos + 2] == b'-' {
                let mut num = 0usize;
                let mut d = pos + 3;
                while d < prod_end && bytes[d].is_ascii_digit() {
                    num = num.saturating_mul(10).saturating_add((bytes[d] - b'0') as usize);
                    d += 1;
                }
                if (1..=51).contains(&num) {
                    seen[num] = true;
                }
                pos = d;
            } else {
                pos += 1;
            }
        }

        let missing: Vec<String> = (1..=51)
            .filter(|&n| !seen[n])
            .map(|n| format!("FR-{n}"))
            .collect();
        assert!(
            missing.is_empty(),
            "VR-1 violation: missing FR annotations in crates/s3d-model/src/lib.rs: {missing:?}"
        );
    }
}
