use std::collections::BTreeMap;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, AtomicU8, AtomicUsize, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};

use bytes::Bytes;
use s3d_disk::{Disk, DiskFile};
use s3d_types::{
    aes256_ctr_xor_with_cipher, AccessControlPolicy, Aes256Cipher, AsyncByteReader, BucketAuthView,
    BucketEncryptionConfig, BucketLoggingStatus, BucketPolicyDoc, ChecksumAlgorithm, ChecksumState,
    ChecksumType, CompleteMultipartUploadResp, CorsConfiguration, LegalHoldStatus,
    LifecycleConfiguration, ObjectLockConfiguration, ObjectOwnership, ObjectRetention, OwnerInfo,
    PublicAccessBlockConfig, S3Error, S3ErrorCode, SseStoredMeta, StoreResult, SystemMeta,
    VersioningStatus,
};
use tracing::error;

use crate::format::{decode_block_header, Extent, PartBoundaryInfo, BLOCK_HEADER_LEN};

pub const SEG_STATE_ACTIVE: u8 = 0;
pub const SEG_STATE_SEALED: u8 = 1;
pub const SEG_STATE_PENDING_DELETE: u8 = 2;

/// High bit in `SegmentSlot::pin_state` indicating GC has unmapped the segment from `seg_mgr`
/// and scheduled physical reclamation as soon as the active reader count reaches 0.
pub const PIN_PENDING_DELETE_BIT: usize = 1usize << (usize::BITS - 1);

pub struct SegmentSlot<D: Disk> {
    pub seg_id: u32,
    pub file: Arc<D::File>,
    pub disk: D,
    pub write_pos: AtomicU64,
    pub live_bytes: AtomicU64,
    /// Number of in-flight writers that have written blocks to this segment and not yet
    /// completed `catalog.write()` + `live_bytes` accounting. Incremented under `seg_mgr` lock
    /// in `write_data_block`, preventing GC from selecting a newly sealed segment prematurely.
    pub inflight_writers: AtomicUsize,
    /// Packed single-word `(PIN_PENDING_DELETE_BIT | active_readers)`.
    /// Using a single atomic guarantees a total modification order under C++11/Rust `AcqRel`
    /// (verified exhaustively by `VR-4` `loom_segment_pin_vs_delete`).
    pub pin_state: AtomicUsize,
    pub state: AtomicU8,
}

/// RAII guard preventing GC from compacting/deleting a segment while an in-flight writer
/// has written blocks to it that have not yet been committed to `catalog` and `live_bytes`.
pub struct InflightWriteGuard<D: Disk> {
    slot: Arc<SegmentSlot<D>>,
}

impl<D: Disk> InflightWriteGuard<D> {
    pub fn acquire(slot: &Arc<SegmentSlot<D>>) -> Self {
        slot.inflight_writers.fetch_add(1, Ordering::Relaxed);
        Self {
            slot: Arc::clone(slot),
        }
    }

    pub fn slot(&self) -> &Arc<SegmentSlot<D>> {
        &self.slot
    }

    pub fn seg_id(&self) -> u32 {
        self.slot.seg_id
    }
}

impl<D: Disk> Drop for InflightWriteGuard<D> {
    fn drop(&mut self) {
        self.slot.inflight_writers.fetch_sub(1, Ordering::Release);
    }
}

impl<D: Disk> SegmentSlot<D> {
    fn reclaim_now(&self) {
        let path = format!("seg/{:08}.seg", self.seg_id);
        let _ = self.disk.remove_file(&path);
        let _ = self.disk.sync_dir("seg");
    }

    /// Called by GC *after* removing `seg_id` from `seg_mgr.segments` so no new `SegmentPin`
    /// can ever be acquired. Unlinks immediately if `active_readers == 0`; otherwise the last
    /// `SegmentPin::drop` observes `PIN_PENDING_DELETE_BIT | 1` and unlinks.
    pub fn mark_pending_delete_and_maybe_reclaim(&self) {
        self.state
            .store(SEG_STATE_PENDING_DELETE, Ordering::Release);
        let prev = self
            .pin_state
            .fetch_or(PIN_PENDING_DELETE_BIT, Ordering::AcqRel);
        if prev == 0 {
            self.reclaim_now();
        }
    }
}

/// RAII pin preventing a segment file from being unlinked while an in-flight GET streams from it (8.5, 8.6).
pub struct SegmentPin<D: Disk> {
    slot: Arc<SegmentSlot<D>>,
}

impl<D: Disk> SegmentPin<D> {
    pub fn acquire(slot: &Arc<SegmentSlot<D>>) -> Self {
        let prev = slot.pin_state.fetch_add(1, Ordering::Relaxed);
        debug_assert_eq!(
            prev & PIN_PENDING_DELETE_BIT,
            0,
            "SegmentPin acquired after PIN_PENDING_DELETE_BIT was set"
        );
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
        let prev = self.slot.pin_state.fetch_sub(1, Ordering::AcqRel);
        if prev == (PIN_PENDING_DELETE_BIT | 1) {
            self.slot.reclaim_now();
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
    pub sys_meta: Arc<SystemMeta>,
    pub user_meta: Vec<(String, String)>,
    pub owner: Arc<OwnerInfo>,
    pub acl: Arc<AccessControlPolicy>,
    pub tags: BTreeMap<String, String>,
    pub last_modified_ms: i64,
    pub extents: Arc<[Extent]>,
    pub parts: Option<Arc<[PartBoundaryInfo]>>,
    pub sse: SseStoredMeta,
    pub retention: Option<ObjectRetention>,
    pub legal_hold: Option<LegalHoldStatus>,
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
    pub sse_iv: Option<[u8; 16]>,
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
    pub sse: SseStoredMeta,
    pub retention: Option<ObjectRetention>,
    pub legal_hold: Option<LegalHoldStatus>,
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
    pub object_lock_enabled: bool,
    pub object_lock_config: Option<ObjectLockConfiguration>,
    pub lifecycle: Option<LifecycleConfiguration>,
    pub encryption: Option<BucketEncryptionConfig>,
    pub logging: Option<BucketLoggingStatus>,
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

#[derive(Debug, Default)]
pub struct MemoryCatalog {
    pub next_seq: u64,
    pub buckets: BTreeMap<String, BucketEntry>,
}

#[derive(Debug, Clone, Copy)]
pub struct ReadSlice {
    pub ext: Extent,
    pub rel_s: usize,
    pub rel_e: usize,
    pub ctr: Option<([u8; 16], u64)>, // (iv, part_or_object_relative_offset)
}

/// Decompose `[range_start, range_end_excl)` across `extents` (and `parts` when encrypted multipart)
/// so each returned slice has an exact CTR `(iv, counter_byte_offset)` if encrypted.
pub fn build_extent_read_slices(
    extents: &[Extent],
    parts: Option<&[PartBoundaryInfo]>,
    ver_iv_opt: Option<[u8; 16]>,
    range_start: u64,
    range_end_excl: u64,
) -> Vec<ReadSlice> {
    if range_start >= range_end_excl {
        return Vec::new();
    }
    let mut slices = Vec::new();
    let mut logical_pos = 0u64;
    for ext in extents {
        let ext_len = ext.len as u64;
        if ext_len == 0 {
            continue;
        }
        let ext_start = logical_pos;
        let ext_end_excl = logical_pos + ext_len;
        logical_pos = ext_end_excl;

        if ext_end_excl <= range_start {
            continue;
        }
        if ext_start >= range_end_excl {
            break;
        }

        let req_s = range_start.max(ext_start);
        let req_e = range_end_excl.min(ext_end_excl);
        match (ver_iv_opt, parts) {
            (None, _) => {
                slices.push(ReadSlice {
                    ext: *ext,
                    rel_s: (req_s - ext_start) as usize,
                    rel_e: (req_e - ext_start) as usize,
                    ctr: None,
                });
            }
            (Some(ver_iv), None) => {
                slices.push(ReadSlice {
                    ext: *ext,
                    rel_s: (req_s - ext_start) as usize,
                    rel_e: (req_e - ext_start) as usize,
                    ctr: Some((ver_iv, req_s)),
                });
            }
            (Some(ver_iv), Some(ps)) => {
                let mut p_off = 0u64;
                for p in ps {
                    let p_end = p_off + p.size;
                    let sub_s = req_s.max(p_off);
                    let sub_e = req_e.min(p_end);
                    if sub_s < sub_e {
                        let p_iv = p.sse_iv.unwrap_or(ver_iv);
                        slices.push(ReadSlice {
                            ext: *ext,
                            rel_s: (sub_s - ext_start) as usize,
                            rel_e: (sub_e - ext_start) as usize,
                            ctr: Some((p_iv, sub_s - p_off)),
                        });
                    }
                    p_off = p_end;
                    if p_off >= req_e {
                        break;
                    }
                }
            }
        }
    }
    slices
}

/// Lock-free streaming reader verifying per-block CRC32C (`ST-5`) before yielding (and optionally decrypting) bytes.
pub struct EngineByteReader<D: Disk> {
    pins: BTreeMap<u32, SegmentPin<D>>,
    cipher: Option<Arc<Aes256Cipher>>,
    slices: Vec<ReadSlice>,
    idx: usize,
}

impl<D: Disk> EngineByteReader<D> {
    pub fn empty() -> Self {
        Self {
            pins: BTreeMap::new(),
            cipher: None,
            slices: Vec::new(),
            idx: 0,
        }
    }

    pub fn new(
        pins: BTreeMap<u32, SegmentPin<D>>,
        extents: &[Extent],
        parts: Option<&[PartBoundaryInfo]>,
        key_iv: Option<([u8; 32], [u8; 16])>,
        range_start: u64,
        range_end_inclusive: u64,
    ) -> Self {
        let (cipher, ver_iv_opt) = match key_iv {
            Some((k, iv)) => (Some(Arc::new(Aes256Cipher::new(&k))), Some(iv)),
            None => (None, None),
        };
        let slices = build_extent_read_slices(
            extents,
            parts,
            ver_iv_opt,
            range_start,
            range_end_inclusive.saturating_add(1),
        );
        Self {
            pins,
            cipher,
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
        let rs = self.slices[self.idx];
        self.idx += 1;
        let ext = rs.ext;

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

        // [ST-5] Every block read MUST pass header + CRC32C check BEFORE decryption; never return corrupt bytes!
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

        if let (Some((iv, ctr_off)), Some(cipher)) = (rs.ctr, &self.cipher) {
            let mut dec = raw[(12 + rs.rel_s)..(12 + rs.rel_e)].to_vec();
            aes256_ctr_xor_with_cipher(cipher, &iv, ctr_off, &mut dec);
            Poll::Ready(Ok(Some(Bytes::from(dec))))
        } else {
            let out = Bytes::from(raw).slice((12 + rs.rel_s)..(12 + rs.rel_e));
            Poll::Ready(Ok(Some(out)))
        }
    }
}
