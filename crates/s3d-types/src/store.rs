use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::Bytes;
use serde::{Deserialize, Serialize};

use crate::cond::Preconditions;
use crate::error::StoreResult;
use crate::range::ByteRangeSpec;

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

#[derive(Debug, Clone)]
pub struct CallerContext {
    pub caller: Option<OwnerInfo>,
    pub request_time_ms: i64,
    pub expected_bucket_owner: Option<String>,
    pub is_authenticated: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChecksumAlgorithm {
    Crc32,
    Crc32c,
    Crc64Nvme,
    Sha1,
    Sha256,
}

impl ChecksumAlgorithm {
    pub const fn header_name(self) -> &'static str {
        match self {
            Self::Crc32 => "x-amz-checksum-crc32",
            Self::Crc32c => "x-amz-checksum-crc32c",
            Self::Crc64Nvme => "x-amz-checksum-crc64nvme",
            Self::Sha1 => "x-amz-checksum-sha1",
            Self::Sha256 => "x-amz-checksum-sha256",
        }
    }

    pub const fn as_aws_str(self) -> &'static str {
        match self {
            Self::Crc32 => "CRC32",
            Self::Crc32c => "CRC32C",
            Self::Crc64Nvme => "CRC64NVME",
            Self::Sha1 => "SHA1",
            Self::Sha256 => "SHA256",
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
    pub preconditions: Preconditions,
    pub max_bytes_limit: u64,
}

#[derive(Debug, Clone)]
pub struct PutObjectResp {
    pub etag: String,
    pub version_id: Option<String>,
    pub checksum: ChecksumState,
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
    pub src_preconditions: Preconditions,
    pub dst_preconditions: Preconditions,
}

#[derive(Debug, Clone)]
pub struct CopyObjectResp {
    pub etag: String,
    pub last_modified_ms: i64,
    pub src_version_id: Option<String>,
    pub dst_version_id: Option<String>,
    pub checksum: Option<ChecksumState>,
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
