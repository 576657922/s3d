use std::collections::BTreeMap;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, AtomicU8, AtomicUsize, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};

use bytes::Bytes;
use s3d_disk::{Disk, DiskFile};
use s3d_types::{
    AccessControlPolicy, AsyncByteReader, BucketAuthView, BucketPolicyDoc, ChecksumAlgorithm,
    ChecksumState, ChecksumType, CompleteMultipartUploadResp, CorsConfiguration, ObjectOwnership,
    OwnerInfo, PublicAccessBlockConfig, S3Error, S3ErrorCode, StoreResult, SystemMeta,
    VersioningStatus,
};
use tracing::error;

use crate::format::{decode_block_header, Extent, PartBoundaryInfo, BLOCK_HEADER_LEN};

pub const SEG_STATE_ACTIVE: u8 = 0;
pub const SEG_STATE_SEALED: u8 = 1;
pub const SEG_STATE_PENDING_DELETE: u8 = 2;

pub struct SegmentSlot<D: Disk> {
    pub seg_id: u32,
    pub file: Arc<D::File>,
    pub disk: D,
    pub write_pos: AtomicU64,
    pub live_bytes: AtomicU64,
    pub active_readers: AtomicUsize,
    pub state: AtomicU8,
}

impl<D: Disk> SegmentSlot<D> {
    pub fn try_reclaim_if_unpinned(&self) {
        if self.state.load(Ordering::Acquire) == SEG_STATE_PENDING_DELETE
            && self.active_readers.load(Ordering::Acquire) == 0
        {
            let path = format!("seg/{:08}.seg", self.seg_id);
            let _ = self.disk.remove_file(&path);
            let _ = self.disk.sync_dir("seg");
        }
    }
}

/// RAII pin preventing a segment file from being unlinked while an in-flight GET streams from it (8.5, 8.6).
pub struct SegmentPin<D: Disk> {
    slot: Arc<SegmentSlot<D>>,
}

impl<D: Disk> SegmentPin<D> {
    pub fn acquire(slot: &Arc<SegmentSlot<D>>) -> Self {
        slot.active_readers.fetch_add(1, Ordering::Acquire);
        Self {
            slot: Arc::clone(slot),
        }
    }

    pub fn slot(&self) -> &SegmentSlot<D> {
        &self.slot
    }
}

impl<D: Disk> Drop for SegmentPin<D> {
    fn drop(&mut self) {
        let prev = self.slot.active_readers.fetch_sub(1, Ordering::AcqRel);
        if prev == 1 {
            self.slot.try_reclaim_if_unpinned();
        }
    }
}

#[derive(Debug, Clone)]
pub struct ObjectVersionEntry {
    pub seq: u64,
    pub version_id: Option<String>,
    pub is_delete_marker: bool,
    pub total_size: u64,
    pub etag: String,
    pub checksum: ChecksumState,
    pub sys_meta: SystemMeta,
    pub user_meta: Vec<(String, String)>,
    pub owner: OwnerInfo,
    pub acl: AccessControlPolicy,
    pub tags: BTreeMap<String, String>,
    pub last_modified_ms: i64,
    pub extents: Arc<[Extent]>,
    pub parts: Option<Arc<[PartBoundaryInfo]>>,
}

#[derive(Debug, Clone)]
pub struct UploadPartEntry {
    pub part_seq: u64,
    pub part_number: u32,
    pub last_modified_ms: i64,
    pub etag: String,
    pub size: u64,
    pub md5: [u8; 16],
    pub crc64_nvme: u64,
    pub checksum: Option<(ChecksumAlgorithm, String)>,
    pub extents: Arc<[Extent]>,
}

#[derive(Debug, Clone)]
pub struct MultipartUploadEntry {
    pub upload_id: String,
    pub key: String,
    pub initiator: OwnerInfo,
    pub owner: OwnerInfo,
    pub acl: AccessControlPolicy,
    pub tags: BTreeMap<String, String>,
    pub initiated_ms: i64,
    pub sys_meta: SystemMeta,
    pub user_meta: Vec<(String, String)>,
    pub checksum_algorithm: Option<ChecksumAlgorithm>,
    pub checksum_type: Option<ChecksumType>,
    pub parts: BTreeMap<u32, UploadPartEntry>,
}

#[derive(Debug, Clone)]
pub struct BucketEntry {
    pub name: String,
    pub owner: OwnerInfo,
    pub acl: AccessControlPolicy,
    pub region: String,
    pub created_ms: i64,
    pub versioning: VersioningStatus,
    pub explicit_ownership: Option<ObjectOwnership>,
    pub tags: BTreeMap<String, String>,
    pub cors: Option<CorsConfiguration>,
    pub policy: Option<BucketPolicyDoc>,
    pub public_access_block: Option<PublicAccessBlockConfig>,
    pub objects: BTreeMap<String, Vec<ObjectVersionEntry>>, // newest-first
    pub uploads: BTreeMap<(String, String), MultipartUploadEntry>, // (key, upload_id)
    pub completed_uploads: BTreeMap<(String, String), (i64, CompleteMultipartUploadResp)>,
}

impl BucketEntry {
    pub fn effective_ownership(&self, default_ownership: ObjectOwnership) -> ObjectOwnership {
        self.explicit_ownership.unwrap_or(default_ownership)
    }

    pub fn auth_view(&self, default_ownership: ObjectOwnership) -> BucketAuthView<'_> {
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

#[derive(Default)]
pub struct MemoryCatalog {
    pub next_seq: u64,
    pub buckets: BTreeMap<String, BucketEntry>,
}

/// Lock-free streaming reader verifying per-block CRC32C (`ST-5`) before yielding bytes.
pub struct EngineByteReader<D: Disk> {
    pins: BTreeMap<u32, SegmentPin<D>>,
    slices: Vec<(Extent, usize, usize)>, // (extent, rel_start, rel_end_exclusive)
    idx: usize,
}

impl<D: Disk> EngineByteReader<D> {
    pub fn empty() -> Self {
        Self {
            pins: BTreeMap::new(),
            slices: Vec::new(),
            idx: 0,
        }
    }

    pub fn new(
        pins: BTreeMap<u32, SegmentPin<D>>,
        extents: &[Extent],
        range_start: u64,
        range_end_inclusive: u64,
    ) -> Self {
        let mut slices = Vec::new();
        let mut logical_pos = 0u64;
        for ext in extents {
            let ext_len = ext.len as u64;
            if ext_len == 0 {
                continue;
            }
            let ext_start = logical_pos;
            let ext_end = logical_pos + ext_len - 1;
            if ext_end >= range_start && ext_start <= range_end_inclusive {
                let rel_s = range_start.saturating_sub(ext_start) as usize;
                let rel_e = (range_end_inclusive.min(ext_end) - ext_start + 1) as usize;
                slices.push((*ext, rel_s, rel_e));
            }
            logical_pos += ext_len;
            if logical_pos > range_end_inclusive {
                break;
            }
        }
        Self {
            pins,
            slices,
            idx: 0,
        }
    }
}

impl<D: Disk> AsyncByteReader for EngineByteReader<D> {
    fn poll_read_chunk(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<StoreResult<Option<Bytes>>> {
        if self.idx >= self.slices.len() {
            return Poll::Ready(Ok(None));
        }
        let (ext, rel_s, rel_e) = self.slices[self.idx];
        self.idx += 1;

        let Some(pin) = self.pins.get(&ext.seg_id) else {
            error!(seg_id = ext.seg_id, "missing pinned segment during read");
            return Poll::Ready(Err(S3Error::new(
                S3ErrorCode::InternalError,
                "We encountered an internal error. Please try again.",
            )));
        };

        let total_read = BLOCK_HEADER_LEN as usize + ext.len as usize;
        let mut raw = vec![0u8; total_read];
        if let Err(e) = pin.slot().file.read_exact_at(ext.offset, &mut raw) {
            error!(seg_id = ext.seg_id, offset = ext.offset, ?e, "segment block read error");
            return Poll::Ready(Err(S3Error::new(
                S3ErrorCode::InternalError,
                "We encountered an internal error. Please try again.",
            )));
        }

        // [ST-5] Every block read MUST pass header + CRC32C check; never return corrupt bytes!
        let hdr: [u8; 12] = raw[0..12].try_into().unwrap();
        let (blk_len, blk_crc) = match decode_block_header(&hdr) {
            Ok(v) => v,
            Err(msg) => {
                error!(seg_id = ext.seg_id, offset = ext.offset, %msg, "corrupt segment block header");
                return Poll::Ready(Err(S3Error::new(
                    S3ErrorCode::InternalError,
                    "We encountered an internal error. Please try again.",
                )));
            }
        };
        let payload = &raw[12..];
        let actual_crc = crc32c::crc32c(payload);
        if blk_len != ext.len || blk_crc != ext.crc32c || actual_crc != ext.crc32c {
            error!(
                seg_id = ext.seg_id,
                offset = ext.offset,
                expected_crc = ext.crc32c,
                actual_crc,
                "block CRC32C verification failed (ST-5)"
            );
            return Poll::Ready(Err(S3Error::new(
                S3ErrorCode::InternalError,
                "We encountered an internal error. Please try again.",
            )));
        }

        let out = Bytes::copy_from_slice(&payload[rel_s..rel_e]);
        Poll::Ready(Ok(Some(out)))
    }
}
