use std::collections::BTreeMap;
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::Bytes;
use serde::{Deserialize, Serialize};

use crate::acl::{AccessControlPolicy, AclSpec};
use crate::cond::Preconditions;
use crate::cors::CorsConfiguration;
use crate::error::StoreResult;
use crate::p2::{
    BucketEncryptionConfig, BucketLoggingStatus, LegalHoldStatus, LifecycleConfiguration,
    ObjectLockConfiguration, ObjectRetention, RawCopySourceSseHeaders, RawSseHeaders,
    RawUploadObjectLockHeaders, SseResponseHeaders,
};
use crate::policy::{PublicAccessBlockConfig, RequestPolicyContext};
use crate::range::ByteRangeSpec;
use crate::tagging::TaggingDirective;

#[derive(Clone, PartialEq, Eq)]
pub struct SecretKey(String);

impl SecretKey {
    pub fn new(raw: impl Into<String>) -> Self {
        Self(raw.into())
    }

    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

impl fmt::Display for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OwnerInfo {
    pub user_id: String,
    pub display_name: String,
    pub email: String,
}

#[derive(Debug, Clone)]
pub struct AccountRecord {
    pub owner: OwnerInfo,
    pub access_key: String,
    pub secret_key: SecretKey,
}

#[derive(Debug, Clone, Default)]
pub struct CallerContext {
    pub caller: Option<OwnerInfo>,
    pub request_time_ms: i64,
    pub expected_bucket_owner: Option<String>,
    pub is_authenticated: bool,
    pub policy_ctx: RequestPolicyContext,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChecksumAlgorithm {
    Crc32,
    Crc32c,
    Crc64Nvme,
    Sha1,
    Sha256,
    Md5,
    Sha512,
    XxHash64,
    XxHash3,
    XxHash128,
}

impl ChecksumAlgorithm {
    pub const ALL: [Self; 10] = [
        Self::Crc32,
        Self::Crc32c,
        Self::Crc64Nvme,
        Self::Sha1,
        Self::Sha256,
        Self::Md5,
        Self::Sha512,
        Self::XxHash64,
        Self::XxHash3,
        Self::XxHash128,
    ];

    pub const fn header_name(self) -> &'static str {
        match self {
            Self::Crc32 => "x-amz-checksum-crc32",
            Self::Crc32c => "x-amz-checksum-crc32c",
            Self::Crc64Nvme => "x-amz-checksum-crc64nvme",
            Self::Sha1 => "x-amz-checksum-sha1",
            Self::Sha256 => "x-amz-checksum-sha256",
            Self::Md5 => "x-amz-checksum-md5",
            Self::Sha512 => "x-amz-checksum-sha512",
            Self::XxHash64 => "x-amz-checksum-xxhash64",
            Self::XxHash3 => "x-amz-checksum-xxhash3",
            Self::XxHash128 => "x-amz-checksum-xxhash128",
        }
    }

    pub const fn as_aws_str(self) -> &'static str {
        match self {
            Self::Crc32 => "CRC32",
            Self::Crc32c => "CRC32C",
            Self::Crc64Nvme => "CRC64NVME",
            Self::Sha1 => "SHA1",
            Self::Sha256 => "SHA256",
            Self::Md5 => "MD5",
            Self::Sha512 => "SHA512",
            Self::XxHash64 => "XXHASH64",
            Self::XxHash3 => "XXHASH3",
            Self::XxHash128 => "XXHASH128",
        }
    }

    pub const fn xml_tag_name(self) -> &'static str {
        match self {
            Self::Crc32 => "ChecksumCRC32",
            Self::Crc32c => "ChecksumCRC32C",
            Self::Crc64Nvme => "ChecksumCRC64NVME",
            Self::Sha1 => "ChecksumSHA1",
            Self::Sha256 => "ChecksumSHA256",
            Self::Md5 => "ChecksumMD5",
            Self::Sha512 => "ChecksumSHA512",
            Self::XxHash64 => "ChecksumXXHASH64",
            Self::XxHash3 => "ChecksumXXHASH3",
            Self::XxHash128 => "ChecksumXXHASH128",
        }
    }

    pub const fn digest_byte_len(self) -> usize {
        match self {
            Self::Crc32 | Self::Crc32c => 4,
            Self::Crc64Nvme | Self::XxHash64 | Self::XxHash3 => 8,
            Self::Md5 | Self::XxHash128 => 16,
            Self::Sha1 => 20,
            Self::Sha256 => 32,
            Self::Sha512 => 64,
        }
    }

    pub fn from_aws_str(s: &str) -> Option<Self> {
        match s.trim().to_ascii_uppercase().as_str() {
            "CRC32" => Some(Self::Crc32),
            "CRC32C" => Some(Self::Crc32c),
            "CRC64NVME" => Some(Self::Crc64Nvme),
            "SHA1" => Some(Self::Sha1),
            "SHA256" => Some(Self::Sha256),
            "MD5" => Some(Self::Md5),
            "SHA512" => Some(Self::Sha512),
            "XXHASH64" => Some(Self::XxHash64),
            "XXHASH3" => Some(Self::XxHash3),
            "XXHASH128" => Some(Self::XxHash128),
            _ => None,
        }
    }

    /// Resolve and validate multipart checksum type per §4.4 matrix & `PR-26`.
    pub fn resolve_multipart_type(self, explicit: Option<ChecksumType>) -> StoreResult<ChecksumType> {
        use crate::error::{S3Error, S3ErrorCode};
        match (self, explicit) {
            (Self::Crc64Nvme, None | Some(ChecksumType::FullObject)) => Ok(ChecksumType::FullObject),
            (Self::Crc64Nvme, Some(ChecksumType::Composite)) => Err(S3Error::new(
                S3ErrorCode::InvalidRequest,
                "The COMPOSITE checksum type cannot be used with the crc64nvme checksum algorithm.",
            )),
            (Self::Crc32 | Self::Crc32c, Some(t)) => Ok(t),
            (Self::Crc32 | Self::Crc32c, None) => Ok(ChecksumType::Composite),
            (
                Self::Sha1
                | Self::Sha256
                | Self::Md5
                | Self::Sha512
                | Self::XxHash64
                | Self::XxHash3
                | Self::XxHash128,
                None | Some(ChecksumType::Composite),
            ) => Ok(ChecksumType::Composite),
            (
                Self::Sha1
                | Self::Sha256
                | Self::Md5
                | Self::Sha512
                | Self::XxHash64
                | Self::XxHash3
                | Self::XxHash128,
                Some(ChecksumType::FullObject),
            ) => Err(S3Error::new(
                S3ErrorCode::InvalidRequest,
                format!(
                    "The FULL_OBJECT checksum type cannot be used with {}.",
                    self.as_aws_str()
                ),
            )),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChecksumType {
    FullObject,
    Composite,
}

impl ChecksumType {
    pub const fn as_aws_str(self) -> &'static str {
        match self {
            Self::FullObject => "FULL_OBJECT",
            Self::Composite => "COMPOSITE",
        }
    }

    pub fn from_aws_str(s: &str) -> Option<Self> {
        match s.trim().to_ascii_uppercase().as_str() {
            "FULL_OBJECT" => Some(Self::FullObject),
            "COMPOSITE" => Some(Self::Composite),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChecksumState {
    pub algorithm: ChecksumAlgorithm,
    pub checksum_type: ChecksumType,
    /// Base64 string (with `-N` suffix when Composite)
    pub value_b64: String,
    /// True if explicitly requested/supplied by client (controls PutObject response echo)
    pub client_requested: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SystemMeta {
    pub content_type: String,
    pub content_encoding: Option<String>,
    pub content_disposition: Option<String>,
    pub content_language: Option<String>,
    pub cache_control: Option<String>,
    pub expires: Option<String>,
}

impl Default for SystemMeta {
    fn default() -> Self {
        Self {
            content_type: "binary/octet-stream".to_string(),
            content_encoding: None,
            content_disposition: None,
            content_language: None,
            cache_control: None,
            expires: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum VersioningStatus {
    #[default]
    Unversioned,
    Enabled,
    Suspended,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum ObjectOwnership {
    #[default]
    BucketOwnerEnforced,
    ObjectWriter,
    BucketOwnerPreferred,
}

impl ObjectOwnership {
    pub const fn as_aws_str(self) -> &'static str {
        match self {
            Self::BucketOwnerEnforced => "BucketOwnerEnforced",
            Self::ObjectWriter => "ObjectWriter",
            Self::BucketOwnerPreferred => "BucketOwnerPreferred",
        }
    }

    pub fn from_aws_str(s: &str) -> Option<Self> {
        match s.trim() {
            "BucketOwnerEnforced" => Some(Self::BucketOwnerEnforced),
            "ObjectWriter" => Some(Self::ObjectWriter),
            "BucketOwnerPreferred" => Some(Self::BucketOwnerPreferred),
            _ => None,
        }
    }
}

// ---- Streaming Body Abstractions ----

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BodyStreamError {
    Sha256Mismatch,
    BadDigest,
    InvalidChunkedEncoding(String),
    EntityTooLarge,
    EntityTooSmall,
    IncompleteBody,
    ClientDisconnected(String),
}

#[derive(Debug, Clone)]
pub struct VerifiedDigests {
    pub total_bytes: u64,
    pub md5: [u8; 16],
    pub checksum: ChecksumState,
}

pub trait VerifiedBodyStream: Send {
    fn poll_next_chunk(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<Bytes>, BodyStreamError>>;

    fn finish(&mut self) -> Result<VerifiedDigests, BodyStreamError>;
}

pub trait AsyncByteReader: Send + Unpin + 'static {
    fn poll_read_chunk(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<StoreResult<Option<Bytes>>>;
}

/// Simple in-memory `AsyncByteReader` backed by `Bytes` (used by `s3d-model` and empty responses).
pub struct MemoryByteReader {
    data: Bytes,
    chunk_size: usize,
}

impl MemoryByteReader {
    pub fn new(data: Bytes) -> Self {
        Self {
            data,
            chunk_size: 64 * 1024,
        }
    }
}

impl AsyncByteReader for MemoryByteReader {
    fn poll_read_chunk(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<StoreResult<Option<Bytes>>> {
        if self.data.is_empty() {
            return Poll::Ready(Ok(None));
        }
        let n = self.data.len().min(self.chunk_size);
        let chunk = self.data.split_to(n);
        Poll::Ready(Ok(Some(chunk)))
    }
}

// ---- Request & Response DTOs ----

#[derive(Debug, Clone)]
pub struct ListBucketsReq {
    pub ctx: CallerContext,
    pub prefix: Option<String>,
    pub max_buckets: Option<usize>,
    pub continuation_token: Option<String>,
}

#[derive(Debug, Clone)]
pub struct BucketSummary {
    pub name: String,
    pub created_ms: i64,
    pub region: String,
}

#[derive(Debug, Clone)]
pub struct ListBucketsResp {
    pub owner: OwnerInfo,
    pub buckets: Vec<BucketSummary>,
    pub next_continuation_token: Option<String>,
}

#[derive(Debug, Clone)]
pub struct CreateBucketReq {
    pub ctx: CallerContext,
    pub bucket: String,
    pub location_constraint: Option<String>,
    pub object_ownership: Option<ObjectOwnership>,
    pub acl: Option<AclSpec>,
    pub object_lock_enabled: bool,
}

#[derive(Debug, Clone)]
pub struct BucketRef {
    pub ctx: CallerContext,
    pub bucket: String,
}

#[derive(Debug, Clone)]
pub struct BucketMetaSnapshot {
    pub name: String,
    pub owner: OwnerInfo,
    pub region: String,
    pub created_ms: i64,
    pub versioning: VersioningStatus,
    pub ownership: ObjectOwnership,
}

#[derive(Debug, Clone)]
pub struct PutObjectReq {
    pub ctx: CallerContext,
    pub bucket: String,
    pub key: String,
    pub sys_meta: SystemMeta,
    pub user_meta: Vec<(String, String)>,
    pub acl: Option<AclSpec>,
    pub tags: Option<BTreeMap<String, String>>,
    pub preconditions: Preconditions,
    pub max_bytes_limit: u64,
    pub raw_sse: RawSseHeaders,
    pub raw_lock: RawUploadObjectLockHeaders,
}

#[derive(Debug, Clone)]
pub struct PutObjectResp {
    pub etag: String,
    pub version_id: Option<String>,
    pub checksum: ChecksumState,
    pub sse: SseResponseHeaders,
    pub expiration_header: Option<String>,
}

#[derive(Debug, Clone)]
pub struct GetObjectReq {
    pub ctx: CallerContext,
    pub bucket: String,
    pub key: String,
    pub version_id: Option<String>,
    pub range: Option<ByteRangeSpec>,
    pub part_number: Option<u32>,
    pub preconditions: Preconditions,
    pub checksum_mode_enabled: bool,
    pub raw_sse: RawSseHeaders,
}

#[derive(Debug, Clone)]
pub struct ObjectMetaSnapshot {
    pub bucket: String,
    pub key: String,
    pub version_id: Option<String>,
    pub is_delete_marker: bool,
    pub total_object_size: u64,
    pub content_length: u64,
    pub content_range: Option<(u64, u64, u64)>,
    pub etag: String,
    pub last_modified_ms: i64,
    pub owner: OwnerInfo,
    pub sys_meta: SystemMeta,
    pub user_meta: Vec<(String, String)>,
    pub checksum: Option<ChecksumState>,
    pub parts_count: Option<u32>,
    pub tags_count: usize,
    pub sse: SseResponseHeaders,
    pub retention: Option<ObjectRetention>,
    pub legal_hold: Option<LegalHoldStatus>,
    pub expiration_header: Option<String>,
}

pub struct GetObjectResp<R> {
    pub meta: ObjectMetaSnapshot,
    pub reader: R,
}

#[derive(Debug, Clone)]
pub struct DeleteObjectReq {
    pub ctx: CallerContext,
    pub bucket: String,
    pub key: String,
    pub version_id: Option<String>,
    pub if_match: Option<Vec<String>>,
    pub bypass_governance: bool,
}

#[derive(Debug, Clone)]
pub struct DeleteObjectResp {
    pub version_id: Option<String>,
    pub is_delete_marker: bool,
}

#[derive(Debug, Clone)]
pub struct DeleteObjectsItem {
    pub key: String,
    pub version_id: Option<String>,
    pub etag_if_match: Option<Vec<String>>,
}

#[derive(Debug, Clone)]
pub struct DeleteObjectsReq {
    pub ctx: CallerContext,
    pub bucket: String,
    pub quiet: bool,
    pub items: Vec<DeleteObjectsItem>,
    pub bypass_governance: bool,
}

#[derive(Debug, Clone)]
pub struct DeletedEntry {
    pub key: String,
    pub version_id: Option<String>,
    pub delete_marker: bool,
    pub delete_marker_version_id: Option<String>,
}

#[derive(Debug, Clone)]
pub struct DeleteErrorEntry {
    pub key: String,
    pub version_id: Option<String>,
    pub code: String,
    pub message: String,
}

#[derive(Debug, Clone)]
pub struct DeleteObjectsResp {
    pub deleted: Vec<DeletedEntry>,
    pub errors: Vec<DeleteErrorEntry>,
}

#[derive(Debug, Clone)]
pub struct CopyObjectReq {
    pub ctx: CallerContext,
    pub src_bucket: String,
    pub src_key: String,
    pub src_version_id: Option<String>,
    pub dst_bucket: String,
    pub dst_key: String,
    pub replace_metadata: bool,
    pub sys_meta: SystemMeta,
    pub user_meta: Vec<(String, String)>,
    pub acl: Option<AclSpec>,
    pub tagging_directive: TaggingDirective,
    pub tags: Option<BTreeMap<String, String>>,
    pub src_preconditions: Preconditions,
    pub dst_preconditions: Preconditions,
    pub raw_sse: RawSseHeaders,
    pub raw_copy_src_sse: RawCopySourceSseHeaders,
    pub raw_lock: RawUploadObjectLockHeaders,
}

#[derive(Debug, Clone)]
pub struct CopyObjectResp {
    pub etag: String,
    pub last_modified_ms: i64,
    pub src_version_id: Option<String>,
    pub dst_version_id: Option<String>,
    pub checksum: Option<ChecksumState>,
    pub sse: SseResponseHeaders,
    pub expiration_header: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ObjectListEntry {
    pub key: String,
    pub last_modified_ms: i64,
    pub etag: String,
    pub size: u64,
    pub owner: OwnerInfo,
    pub checksum_alg: Option<ChecksumAlgorithm>,
    pub checksum_type: Option<ChecksumType>,
}

#[derive(Debug, Clone)]
pub struct ListObjectsV1Req {
    pub ctx: CallerContext,
    pub bucket: String,
    pub prefix: String,
    pub delimiter: Option<String>,
    pub marker: Option<String>,
    pub max_keys: usize,
}

#[derive(Debug, Clone)]
pub struct ListObjectsV1Resp {
    pub name: String,
    pub prefix: String,
    pub marker: String,
    pub next_marker: Option<String>,
    pub max_keys: usize,
    pub delimiter: Option<String>,
    pub is_truncated: bool,
    pub contents: Vec<ObjectListEntry>,
    pub common_prefixes: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct ListObjectsV2Req {
    pub ctx: CallerContext,
    pub bucket: String,
    pub prefix: String,
    pub delimiter: Option<String>,
    pub start_after: Option<String>,
    pub continuation_token: Option<String>,
    pub max_keys: usize,
    pub fetch_owner: bool,
}

#[derive(Debug, Clone)]
pub struct ListObjectsV2Resp {
    pub name: String,
    pub prefix: String,
    pub start_after: Option<String>,
    pub continuation_token: Option<String>,
    pub next_continuation_token: Option<String>,
    pub key_count: usize,
    pub max_keys: usize,
    pub delimiter: Option<String>,
    pub is_truncated: bool,
    pub contents: Vec<ObjectListEntry>,
    pub common_prefixes: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct VersionListEntry {
    pub key: String,
    pub version_id: String,
    pub is_latest: bool,
    pub is_delete_marker: bool,
    pub last_modified_ms: i64,
    pub etag: String,
    pub size: u64,
    pub owner: OwnerInfo,
}

#[derive(Debug, Clone)]
pub struct ListObjectVersionsReq {
    pub ctx: CallerContext,
    pub bucket: String,
    pub prefix: String,
    pub delimiter: Option<String>,
    pub key_marker: Option<String>,
    pub version_id_marker: Option<String>,
    pub max_keys: usize,
}

#[derive(Debug, Clone)]
pub struct ListObjectVersionsResp {
    pub name: String,
    pub prefix: String,
    pub key_marker: String,
    pub version_id_marker: String,
    pub next_key_marker: Option<String>,
    pub next_version_id_marker: Option<String>,
    pub max_keys: usize,
    pub delimiter: Option<String>,
    pub is_truncated: bool,
    pub entries: Vec<VersionListEntry>,
    pub common_prefixes: Vec<String>,
}

// ---- Versioning, ObjectAttributes & Multipart DTOs (M1) ----

#[derive(Debug, Clone)]
pub struct PutBucketVersioningReq {
    pub ctx: CallerContext,
    pub bucket: String,
    pub status: VersioningStatus,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct ObjectAttributesMask {
    pub etag: bool,
    pub checksum: bool,
    pub object_parts: bool,
    pub storage_class: bool,
    pub object_size: bool,
}

#[derive(Debug, Clone)]
pub struct GetObjectAttributesReq {
    pub ctx: CallerContext,
    pub bucket: String,
    pub key: String,
    pub version_id: Option<String>,
    pub attrs: ObjectAttributesMask,
    pub max_parts: usize,
    pub part_number_marker: u32,
    pub raw_sse: RawSseHeaders,
}

#[derive(Debug, Clone)]
pub struct ObjectAttributePartEntry {
    pub part_number: u32,
    pub size: u64,
    pub checksum: Option<(ChecksumAlgorithm, String)>,
}

#[derive(Debug, Clone)]
pub struct ObjectAttributesPartsResp {
    pub total_parts_count: u32,
    pub part_number_marker: u32,
    pub next_part_number_marker: Option<u32>,
    pub max_parts: usize,
    pub is_truncated: bool,
    pub parts: Vec<ObjectAttributePartEntry>,
}

#[derive(Debug, Clone)]
pub struct GetObjectAttributesResp {
    pub version_id: Option<String>,
    pub last_modified_ms: i64,
    pub etag: Option<String>,
    pub checksum: Option<ChecksumState>,
    pub object_parts: Option<ObjectAttributesPartsResp>,
    pub storage_class: Option<String>,
    pub object_size: Option<u64>,
    pub sse: SseResponseHeaders,
}

#[derive(Debug, Clone)]
pub struct CreateMultipartUploadReq {
    pub ctx: CallerContext,
    pub bucket: String,
    pub key: String,
    pub sys_meta: SystemMeta,
    pub user_meta: Vec<(String, String)>,
    pub acl: Option<AclSpec>,
    pub tags: Option<BTreeMap<String, String>>,
    pub checksum_algorithm: Option<ChecksumAlgorithm>,
    pub checksum_type: Option<ChecksumType>,
    pub raw_sse: RawSseHeaders,
    pub raw_lock: RawUploadObjectLockHeaders,
}

#[derive(Debug, Clone)]
pub struct CreateMultipartUploadResp {
    pub bucket: String,
    pub key: String,
    pub upload_id: String,
    pub checksum_algorithm: Option<ChecksumAlgorithm>,
    pub checksum_type: Option<ChecksumType>,
    pub sse: SseResponseHeaders,
}

#[derive(Debug, Clone)]
pub struct UploadPartReq {
    pub ctx: CallerContext,
    pub bucket: String,
    pub key: String,
    pub upload_id: String,
    pub part_number: u32,
    pub max_bytes_limit: u64,
    pub raw_sse: RawSseHeaders,
}

#[derive(Debug, Clone)]
pub struct UploadPartResp {
    pub etag: String,
    pub checksum: Option<ChecksumState>,
    pub sse: SseResponseHeaders,
}

#[derive(Debug, Clone)]
pub struct UploadPartCopyReq {
    pub ctx: CallerContext,
    pub src_bucket: String,
    pub src_key: String,
    pub src_version_id: Option<String>,
    pub src_range: Option<(u64, u64)>,
    pub src_preconditions: Preconditions,
    pub dst_bucket: String,
    pub dst_key: String,
    pub upload_id: String,
    pub part_number: u32,
    pub raw_sse: RawSseHeaders,
    pub raw_copy_src_sse: RawCopySourceSseHeaders,
}

#[derive(Debug, Clone)]
pub struct UploadPartCopyResp {
    pub etag: String,
    pub last_modified_ms: i64,
    pub src_version_id: Option<String>,
    pub checksum: Option<ChecksumState>,
    pub sse: SseResponseHeaders,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompletePartSpec {
    pub part_number: u32,
    pub etag: String,
    pub checksum: Option<(ChecksumAlgorithm, String)>,
}

/// Validate ascending part order and deduplicate consecutive identical `PartNumber` entries
/// by keeping the last entry (`FR-26`, `test_multipart_resend_first_finishes_last`).
pub fn dedup_complete_parts(raw: &[CompletePartSpec]) -> StoreResult<Vec<CompletePartSpec>> {
    use crate::error::{S3Error, S3ErrorCode};
    use crate::validation::MAX_PARTS_COUNT;

    let mut out: Vec<CompletePartSpec> = Vec::with_capacity(raw.len());
    for spec in raw {
        if spec.part_number == 0 || spec.part_number > MAX_PARTS_COUNT {
            return Err(S3Error::new(
                S3ErrorCode::InvalidPart,
                "One or more of the specified parts could not be found.",
            ));
        }
        if let Some(prev) = out.last_mut() {
            if spec.part_number < prev.part_number {
                return Err(S3Error::new(
                    S3ErrorCode::InvalidPartOrder,
                    "The list of parts was not in ascending order.",
                ));
            }
            if spec.part_number == prev.part_number {
                *prev = spec.clone();
                continue;
            }
        }
        out.push(spec.clone());
    }
    Ok(out)
}

#[derive(Debug, Clone)]
pub struct CompleteMultipartUploadReq {
    pub ctx: CallerContext,
    pub bucket: String,
    pub key: String,
    pub upload_id: String,
    pub parts: Vec<CompletePartSpec>,
    pub expected_checksum: Option<(ChecksumAlgorithm, String)>,
    pub expected_object_size: Option<u64>,
    pub preconditions: Preconditions,
    pub raw_sse: RawSseHeaders,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompleteMultipartUploadResp {
    pub bucket: String,
    pub key: String,
    pub etag: String,
    pub version_id: Option<String>,
    pub checksum: Option<ChecksumState>,
    #[serde(default)]
    pub sse: SseResponseHeaders,
    #[serde(default)]
    pub expiration_header: Option<String>,
}

#[derive(Debug, Clone)]
pub struct AbortMultipartUploadReq {
    pub ctx: CallerContext,
    pub bucket: String,
    pub key: String,
    pub upload_id: String,
}

#[derive(Debug, Clone)]
pub struct ListPartsReq {
    pub ctx: CallerContext,
    pub bucket: String,
    pub key: String,
    pub upload_id: String,
    pub max_parts: usize,
    pub part_number_marker: u32,
}

#[derive(Debug, Clone)]
pub struct PartSummary {
    pub part_number: u32,
    pub last_modified_ms: i64,
    pub etag: String,
    pub size: u64,
    pub checksum: Option<(ChecksumAlgorithm, String)>,
}

#[derive(Debug, Clone)]
pub struct ListPartsResp {
    pub bucket: String,
    pub key: String,
    pub upload_id: String,
    pub initiator: OwnerInfo,
    pub owner: OwnerInfo,
    pub storage_class: String,
    pub checksum_algorithm: Option<ChecksumAlgorithm>,
    pub checksum_type: Option<ChecksumType>,
    pub part_number_marker: u32,
    pub next_part_number_marker: u32,
    pub max_parts: usize,
    pub is_truncated: bool,
    pub parts: Vec<PartSummary>,
}

#[derive(Debug, Clone)]
pub struct ListMultipartUploadsReq {
    pub ctx: CallerContext,
    pub bucket: String,
    pub prefix: String,
    pub delimiter: Option<String>,
    pub key_marker: Option<String>,
    pub upload_id_marker: Option<String>,
    pub max_uploads: usize,
}

#[derive(Debug, Clone)]
pub struct MultipartUploadSummary {
    pub key: String,
    pub upload_id: String,
    pub initiator: OwnerInfo,
    pub owner: OwnerInfo,
    pub storage_class: String,
    pub initiated_ms: i64,
    pub checksum_algorithm: Option<ChecksumAlgorithm>,
    pub checksum_type: Option<ChecksumType>,
}

#[derive(Debug, Clone)]
pub struct ListMultipartUploadsResp {
    pub bucket: String,
    pub key_marker: String,
    pub upload_id_marker: String,
    pub next_key_marker: Option<String>,
    pub next_upload_id_marker: Option<String>,
    pub prefix: String,
    pub delimiter: Option<String>,
    pub max_uploads: usize,
    pub is_truncated: bool,
    pub uploads: Vec<MultipartUploadSummary>,
    pub common_prefixes: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct PutBucketAclReq {
    pub ctx: CallerContext,
    pub bucket: String,
    pub acl: AclSpec,
}

#[derive(Debug, Clone)]
pub struct GetObjectAclReq {
    pub ctx: CallerContext,
    pub bucket: String,
    pub key: String,
    pub version_id: Option<String>,
}

#[derive(Debug, Clone)]
pub struct GetObjectAclResp {
    pub version_id: Option<String>,
    pub policy: AccessControlPolicy,
}

#[derive(Debug, Clone)]
pub struct PutObjectAclReq {
    pub ctx: CallerContext,
    pub bucket: String,
    pub key: String,
    pub version_id: Option<String>,
    pub acl: AclSpec,
}

// ---- M2 OwnershipControls, Tagging, CORS, Policy & PublicAccessBlock DTOs ----

#[derive(Debug, Clone)]
pub struct PutBucketOwnershipControlsReq {
    pub ctx: CallerContext,
    pub bucket: String,
    pub ownership: ObjectOwnership,
}

#[derive(Debug, Clone)]
pub struct PutBucketTaggingReq {
    pub ctx: CallerContext,
    pub bucket: String,
    pub tags: BTreeMap<String, String>,
}

#[derive(Debug, Clone)]
pub struct ObjectTaggingRef {
    pub ctx: CallerContext,
    pub bucket: String,
    pub key: String,
    pub version_id: Option<String>,
}

#[derive(Debug, Clone)]
pub struct GetObjectTaggingResp {
    pub version_id: Option<String>,
    pub tags: BTreeMap<String, String>,
}

#[derive(Debug, Clone)]
pub struct PutObjectTaggingReq {
    pub ctx: CallerContext,
    pub bucket: String,
    pub key: String,
    pub version_id: Option<String>,
    pub tags: BTreeMap<String, String>,
}

#[derive(Debug, Clone)]
pub struct PutBucketCorsReq {
    pub ctx: CallerContext,
    pub bucket: String,
    pub cors: CorsConfiguration,
}

#[derive(Debug, Clone)]
pub struct PutBucketPolicyReq {
    pub ctx: CallerContext,
    pub bucket: String,
    pub policy_json: String,
}

#[derive(Debug, Clone)]
pub struct PutPublicAccessBlockReq {
    pub ctx: CallerContext,
    pub bucket: String,
    pub config: PublicAccessBlockConfig,
}

// ---- M4 (P2) Object Lock, Lifecycle, Encryption & Logging DTOs ----

#[derive(Debug, Clone)]
pub struct PutObjectLockConfigurationReq {
    pub ctx: CallerContext,
    pub bucket: String,
    pub config: ObjectLockConfiguration,
}

#[derive(Debug, Clone)]
pub struct ObjectLockRef {
    pub ctx: CallerContext,
    pub bucket: String,
    pub key: String,
    pub version_id: Option<String>,
}

#[derive(Debug, Clone)]
pub struct PutObjectRetentionReq {
    pub ctx: CallerContext,
    pub bucket: String,
    pub key: String,
    pub version_id: Option<String>,
    pub retention: ObjectRetention,
    pub bypass_governance: bool,
}

#[derive(Debug, Clone)]
pub struct PutObjectLegalHoldReq {
    pub ctx: CallerContext,
    pub bucket: String,
    pub key: String,
    pub version_id: Option<String>,
    pub status: LegalHoldStatus,
}

#[derive(Debug, Clone)]
pub struct PutBucketLifecycleReq {
    pub ctx: CallerContext,
    pub bucket: String,
    pub config: LifecycleConfiguration,
}

#[derive(Debug, Clone)]
pub struct PutBucketEncryptionReq {
    pub ctx: CallerContext,
    pub bucket: String,
    pub config: BucketEncryptionConfig,
}

#[derive(Debug, Clone)]
pub struct PutBucketLoggingReq {
    pub ctx: CallerContext,
    pub bucket: String,
    pub status: BucketLoggingStatus,
}

// ---- Core ObjectStore Trait ----

pub trait ObjectStore: Send + Sync + 'static {
    type Reader: AsyncByteReader;

    fn list_buckets(
        &self,
        req: ListBucketsReq,
    ) -> impl Future<Output = StoreResult<ListBucketsResp>> + Send;

    fn create_bucket(
        &self,
        req: CreateBucketReq,
    ) -> impl Future<Output = StoreResult<BucketMetaSnapshot>> + Send;

    fn head_bucket(
        &self,
        req: BucketRef,
    ) -> impl Future<Output = StoreResult<BucketMetaSnapshot>> + Send;

    fn delete_bucket(&self, req: BucketRef) -> impl Future<Output = StoreResult<()>> + Send;

    fn get_bucket_versioning(
        &self,
        req: BucketRef,
    ) -> impl Future<Output = StoreResult<VersioningStatus>> + Send;

    fn put_bucket_versioning(
        &self,
        req: PutBucketVersioningReq,
    ) -> impl Future<Output = StoreResult<()>> + Send;

    fn get_bucket_acl(
        &self,
        req: BucketRef,
    ) -> impl Future<Output = StoreResult<AccessControlPolicy>> + Send;

    fn put_bucket_acl(
        &self,
        req: PutBucketAclReq,
    ) -> impl Future<Output = StoreResult<()>> + Send;

    fn get_object_acl(
        &self,
        req: GetObjectAclReq,
    ) -> impl Future<Output = StoreResult<GetObjectAclResp>> + Send;

    fn put_object_acl(
        &self,
        req: PutObjectAclReq,
    ) -> impl Future<Output = StoreResult<Option<String>>> + Send;

    fn get_bucket_ownership_controls(
        &self,
        req: BucketRef,
    ) -> impl Future<Output = StoreResult<ObjectOwnership>> + Send;

    fn put_bucket_ownership_controls(
        &self,
        req: PutBucketOwnershipControlsReq,
    ) -> impl Future<Output = StoreResult<()>> + Send;

    fn delete_bucket_ownership_controls(
        &self,
        req: BucketRef,
    ) -> impl Future<Output = StoreResult<()>> + Send;

    fn get_bucket_tagging(
        &self,
        req: BucketRef,
    ) -> impl Future<Output = StoreResult<BTreeMap<String, String>>> + Send;

    fn put_bucket_tagging(
        &self,
        req: PutBucketTaggingReq,
    ) -> impl Future<Output = StoreResult<()>> + Send;

    fn delete_bucket_tagging(&self, req: BucketRef) -> impl Future<Output = StoreResult<()>> + Send;

    fn get_object_tagging(
        &self,
        req: ObjectTaggingRef,
    ) -> impl Future<Output = StoreResult<GetObjectTaggingResp>> + Send;

    fn put_object_tagging(
        &self,
        req: PutObjectTaggingReq,
    ) -> impl Future<Output = StoreResult<Option<String>>> + Send;

    fn delete_object_tagging(
        &self,
        req: ObjectTaggingRef,
    ) -> impl Future<Output = StoreResult<Option<String>>> + Send;

    fn get_bucket_cors(
        &self,
        req: BucketRef,
    ) -> impl Future<Output = StoreResult<CorsConfiguration>> + Send;

    fn put_bucket_cors(
        &self,
        req: PutBucketCorsReq,
    ) -> impl Future<Output = StoreResult<()>> + Send;

    fn delete_bucket_cors(&self, req: BucketRef) -> impl Future<Output = StoreResult<()>> + Send;

    fn lookup_bucket_cors_unauth(
        &self,
        bucket: &str,
    ) -> impl Future<Output = StoreResult<Option<CorsConfiguration>>> + Send;

    fn get_bucket_policy(
        &self,
        req: BucketRef,
    ) -> impl Future<Output = StoreResult<String>> + Send;

    fn put_bucket_policy(
        &self,
        req: PutBucketPolicyReq,
    ) -> impl Future<Output = StoreResult<()>> + Send;

    fn delete_bucket_policy(&self, req: BucketRef) -> impl Future<Output = StoreResult<()>> + Send;

    fn get_bucket_policy_status(
        &self,
        req: BucketRef,
    ) -> impl Future<Output = StoreResult<bool>> + Send;

    fn get_public_access_block(
        &self,
        req: BucketRef,
    ) -> impl Future<Output = StoreResult<PublicAccessBlockConfig>> + Send;

    fn put_public_access_block(
        &self,
        req: PutPublicAccessBlockReq,
    ) -> impl Future<Output = StoreResult<()>> + Send;

    fn delete_public_access_block(
        &self,
        req: BucketRef,
    ) -> impl Future<Output = StoreResult<()>> + Send;

    fn get_object_lock_configuration(
        &self,
        req: BucketRef,
    ) -> impl Future<Output = StoreResult<ObjectLockConfiguration>> + Send;

    fn put_object_lock_configuration(
        &self,
        req: PutObjectLockConfigurationReq,
    ) -> impl Future<Output = StoreResult<()>> + Send;

    fn get_object_retention(
        &self,
        req: ObjectLockRef,
    ) -> impl Future<Output = StoreResult<ObjectRetention>> + Send;

    fn put_object_retention(
        &self,
        req: PutObjectRetentionReq,
    ) -> impl Future<Output = StoreResult<()>> + Send;

    fn get_object_legal_hold(
        &self,
        req: ObjectLockRef,
    ) -> impl Future<Output = StoreResult<LegalHoldStatus>> + Send;

    fn put_object_legal_hold(
        &self,
        req: PutObjectLegalHoldReq,
    ) -> impl Future<Output = StoreResult<()>> + Send;

    fn get_bucket_lifecycle_configuration(
        &self,
        req: BucketRef,
    ) -> impl Future<Output = StoreResult<LifecycleConfiguration>> + Send;

    fn put_bucket_lifecycle_configuration(
        &self,
        req: PutBucketLifecycleReq,
    ) -> impl Future<Output = StoreResult<()>> + Send;

    fn delete_bucket_lifecycle(&self, req: BucketRef) -> impl Future<Output = StoreResult<()>> + Send;

    fn get_bucket_encryption(
        &self,
        req: BucketRef,
    ) -> impl Future<Output = StoreResult<BucketEncryptionConfig>> + Send;

    fn put_bucket_encryption(
        &self,
        req: PutBucketEncryptionReq,
    ) -> impl Future<Output = StoreResult<()>> + Send;

    fn delete_bucket_encryption(
        &self,
        req: BucketRef,
    ) -> impl Future<Output = StoreResult<()>> + Send;

    fn get_bucket_logging(
        &self,
        req: BucketRef,
    ) -> impl Future<Output = StoreResult<BucketLoggingStatus>> + Send;

    fn put_bucket_logging(
        &self,
        req: PutBucketLoggingReq,
    ) -> impl Future<Output = StoreResult<()>> + Send;

    fn put_object<S: VerifiedBodyStream>(
        &self,
        req: PutObjectReq,
        body: S,
    ) -> impl Future<Output = StoreResult<PutObjectResp>> + Send;

    fn get_object(
        &self,
        req: GetObjectReq,
    ) -> impl Future<Output = StoreResult<GetObjectResp<Self::Reader>>> + Send;

    fn head_object(
        &self,
        req: GetObjectReq,
    ) -> impl Future<Output = StoreResult<ObjectMetaSnapshot>> + Send;

    fn get_object_attributes(
        &self,
        req: GetObjectAttributesReq,
    ) -> impl Future<Output = StoreResult<GetObjectAttributesResp>> + Send;

    fn delete_object(
        &self,
        req: DeleteObjectReq,
    ) -> impl Future<Output = StoreResult<DeleteObjectResp>> + Send;

    fn delete_objects(
        &self,
        req: DeleteObjectsReq,
    ) -> impl Future<Output = StoreResult<DeleteObjectsResp>> + Send;

    fn copy_object(
        &self,
        req: CopyObjectReq,
    ) -> impl Future<Output = StoreResult<CopyObjectResp>> + Send;

    fn create_multipart_upload(
        &self,
        req: CreateMultipartUploadReq,
    ) -> impl Future<Output = StoreResult<CreateMultipartUploadResp>> + Send;

    fn upload_part<S: VerifiedBodyStream>(
        &self,
        req: UploadPartReq,
        body: S,
    ) -> impl Future<Output = StoreResult<UploadPartResp>> + Send;

    fn upload_part_copy(
        &self,
        req: UploadPartCopyReq,
    ) -> impl Future<Output = StoreResult<UploadPartCopyResp>> + Send;

    fn complete_multipart_upload(
        &self,
        req: CompleteMultipartUploadReq,
    ) -> impl Future<Output = StoreResult<CompleteMultipartUploadResp>> + Send;

    fn abort_multipart_upload(
        &self,
        req: AbortMultipartUploadReq,
    ) -> impl Future<Output = StoreResult<()>> + Send;

    fn list_parts(
        &self,
        req: ListPartsReq,
    ) -> impl Future<Output = StoreResult<ListPartsResp>> + Send;

    fn list_multipart_uploads(
        &self,
        req: ListMultipartUploadsReq,
    ) -> impl Future<Output = StoreResult<ListMultipartUploadsResp>> + Send;

    fn list_objects_v1(
        &self,
        req: ListObjectsV1Req,
    ) -> impl Future<Output = StoreResult<ListObjectsV1Resp>> + Send;

    fn list_objects_v2(
        &self,
        req: ListObjectsV2Req,
    ) -> impl Future<Output = StoreResult<ListObjectsV2Resp>> + Send;

    fn list_object_versions(
        &self,
        req: ListObjectVersionsReq,
    ) -> impl Future<Output = StoreResult<ListObjectVersionsResp>> + Send;
}
