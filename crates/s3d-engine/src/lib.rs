//! Crash-safe log-structured object storage engine (`s3d-engine`).

pub mod catalog;
pub mod checkpoint;
mod checksum_util;
pub mod format;
pub mod telemetry;

use std::collections::{BTreeMap, BTreeSet};
use std::future::poll_fn;
use std::ops::Bound;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use bytes::BytesMut;
use md5::{Digest as _, Md5};
use rand::RngCore;
use serde::Serialize;
use s3d_disk::{Disk, DiskError, DiskFile, OpenOpts};
use s3d_types::*;
use thiserror::Error;
use tracing::{error, info, warn};

use crate::catalog::{
    build_extent_read_slices, BucketEntry, EngineByteReader, InflightWriteGuard, MemoryCatalog,
    MultipartUploadEntry, ObjectVersionEntry, SegmentPin, SegmentSlot, UploadPartEntry,
    SEG_STATE_ACTIVE, SEG_STATE_SEALED,
};
use crate::checkpoint::{read_checkpoint_from_file, write_checkpoint_to_file};
pub use crate::checkpoint::{decode_checkpoint_bytes, LoadedCheckpoint};
use crate::checksum_util::{
    combine_crc32, combine_crc32c, combine_crc64_nvme, compute_composite_checksum_b64,
    decode_u32_be_b64, encode_u32_be_b64, encode_u64_be_b64, ActiveHasher,
};
use crate::format::*;
pub use crate::telemetry::{EngineMetricsSnapshot, EngineTelemetry, HistogramSnapshot};

const KEY_LOCK_STRIPES: usize = 256;

#[derive(Debug, Clone)]
pub struct EngineConfig {
    pub region: String,
    pub segment_size: u64,
    pub wal_file_size: u64,
    pub checkpoint_wal_bytes: u64,
    pub checkpoint_interval_ms: u64,
    pub max_block_payload: usize,
    pub reserved_disk_bytes: u64,
    pub max_buckets_per_account: usize,
    pub max_object_size: u64,
    pub completed_upload_retention_ms: i64,
    pub default_object_ownership: ObjectOwnership,
    pub gc_live_ratio: f64,
    pub group_commit_window_ms: u64,
    pub group_commit_max_batch: usize,
}

impl Default for EngineConfig {
    fn default() -> Self {
        Self {
            region: "us-east-1".to_string(),
            segment_size: 1024 * 1024 * 1024, // 1 GiB
            wal_file_size: 256 * 1024 * 1024, // 256 MiB
            checkpoint_wal_bytes: 256 * 1024 * 1024, // 256 MiB (8.7)
            checkpoint_interval_ms: 10 * 60 * 1000, // 10 min (8.7)
            max_block_payload: DEFAULT_MAX_BLOCK_PAYLOAD,
            reserved_disk_bytes: 2 * 1024 * 1024 * 1024, // 2 GiB (NFR-16)
            max_buckets_per_account: 10_000,
            max_object_size: MAX_MULTIPART_OBJECT_BYTES,
            completed_upload_retention_ms: 24 * 60 * 60 * 1000,
            default_object_ownership: ObjectOwnership::BucketOwnerEnforced,
            gc_live_ratio: 0.5,
            group_commit_window_ms: 0,
            group_commit_max_batch: 64,
        }
    }
}

#[derive(Debug, Error)]
pub enum EngineOpenError {
    #[error("disk error: {0}")]
    Disk(#[from] DiskError),
    #[error("corrupt metadata/WAL: {0}")]
    Corrupt(String),
}

struct WalWriterState<D: Disk> {
    wal_seq: u32,
    file: D::File,
    write_pos: u64,
    next_lsn: u64,
    synced_lsn: u64,
    bytes_since_checkpoint: u64,
}

struct PendingCommitItem<D: Disk> {
    segs: BTreeMap<u32, Arc<SegmentSlot<D>>>,
    op: WalOp,
    tx: tokio::sync::oneshot::Sender<StoreResult<u64>>,
}

struct GroupCommitQueue<D: Disk> {
    leader_active: bool,
    pending: Vec<PendingCommitItem<D>>,
}

impl<D: Disk> Default for GroupCommitQueue<D> {
    fn default() -> Self {
        Self {
            leader_active: false,
            pending: Vec::new(),
        }
    }
}

struct SegmentManager<D: Disk> {
    active_seg_id: u32,
    next_seg_id: u32,
    segments: BTreeMap<u32, Arc<SegmentSlot<D>>>,
}

pub struct Engine<D: Disk> {
    disk: D,
    cfg: EngineConfig,
    format: FormatFile,
    sse_s3_master_key: [u8; 32],
    _lock_guard: Box<dyn Send + Sync>,
    read_only_poisoned: AtomicBool,
    next_seq: AtomicU64,
    catalog: RwLock<MemoryCatalog>,
    seg_mgr: Mutex<SegmentManager<D>>,
    wal: Mutex<WalWriterState<D>>,
    group_commit_queue: Mutex<GroupCommitQueue<D>>,
    batch_full_notify: tokio::sync::Notify,
    ckpt_gate: tokio::sync::RwLock<()>,
    key_locks: Vec<tokio::sync::Mutex<()>>,
    telemetry: EngineTelemetry,
}

fn parse_ckpt_filename(name: &str) -> Option<u64> {
    let hex_part = name.strip_prefix("ckpt-")?;
    if hex_part.len() != 16 || !hex_part.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    u64::from_str_radix(hex_part, 16).ok()
}

impl<D: Disk> Engine<D> {
    /// Open or initialize `<data_dir>`, running the crash recovery protocol (02-storage-engine §6.1).
    pub fn open(disk: D, cfg: EngineConfig) -> Result<Arc<Self>, EngineOpenError> {
        // 1. Exclusive process lock
        let lock_guard = disk.try_lock_exclusive()?;

        disk.create_dir_all("wal")?;
        disk.create_dir_all("ckpt")?;
        disk.create_dir_all("seg")?;
        disk.create_dir_all("tmp")?;

        // 2. Clean tmp/ unconditionally
        for name in disk.read_dir("tmp")? {
            let _ = disk.remove_file(&format!("tmp/{name}"));
        }
        disk.sync_dir("tmp")?;

        // 3. Load or initialize FORMAT
        let format = if disk.exists("FORMAT")? {
            let f = disk.open("FORMAT", OpenOpts::read_only())?;
            if f.len()? != FORMAT_FILE_LEN as u64 {
                return Err(EngineOpenError::Corrupt("FORMAT invalid size".into()));
            }
            let mut buf = [0u8; FORMAT_FILE_LEN];
            f.read_exact_at(0, &mut buf)?;
            FormatFile::decode(&buf).map_err(EngineOpenError::Corrupt)?
        } else {
            let mut uuid = [0u8; 16];
            rand::thread_rng().fill_bytes(&mut uuid);
            let now_ms = now_epoch_ms();
            let fmt = FormatFile {
                format_ver: FORMAT_VERSION,
                flags: 0,
                instance_uuid: uuid,
                created_ms: now_ms,
            };
            let encoded = fmt.encode();
            let tmp_f = disk.open("tmp/FORMAT.tmp", OpenOpts::create_truncate_rw())?;
            tmp_f.write_all_at(0, &encoded)?;
            tmp_f.sync_data()?;
            drop(tmp_f);
            disk.rename("tmp/FORMAT.tmp", "FORMAT")?;
            disk.sync_dir("")?;
            fmt
        };

        // 4. Load highest-LSN complete checkpoint in `ckpt/` if present (`ST-8`)
        let mut ckpt_files: Vec<(u64, String)> = Vec::new();
        for name in disk.read_dir("ckpt")? {
            if let Some(lsn) = parse_ckpt_filename(&name) {
                ckpt_files.push((lsn, format!("ckpt/{name}")));
            }
        }
        ckpt_files.sort_by_key(|(lsn, _)| *lsn);

        let (mut catalog, base_lsn, ckpt_next_seg_id, ckpt_live_segments) =
            if let Some(&(latest_lsn, ref rel_path)) = ckpt_files.last() {
                let cf = disk.open(rel_path, OpenOpts::read_only())?;
                let loaded =
                    read_checkpoint_from_file(&cf, Some(latest_lsn), Some(format.uuid_lo()))
                        .map_err(EngineOpenError::Corrupt)?;
                (
                    loaded.catalog,
                    loaded.ckpt_lsn,
                    loaded.next_seg_id,
                    loaded.live_segments,
                )
            } else {
                (MemoryCatalog::default(), 0u64, 1u32, BTreeSet::new())
            };

        // 5. Replay WAL files in ascending order for LSN > base_lsn (`ST-6`, `ST-8`)
        let mut wal_files: Vec<(u32, String)> = Vec::new();
        for name in disk.read_dir("wal")? {
            if let Some(stem) = name.strip_suffix(".log")
                && let Ok(seq) = stem.parse::<u32>() {
                    wal_files.push((seq, format!("wal/{name}")));
                }
        }
        wal_files.sort_by_key(|(seq, _)| *seq);

        let ckpt_next_lsn = base_lsn + 1;
        let mut expected_lsn = ckpt_next_lsn;
        let mut cur_lsn: Option<u64> = None;
        let mut deleted_segments: BTreeSet<u32> = BTreeSet::new();
        let mut created_segments: BTreeSet<u32> = BTreeSet::new();
        let mut last_wal_state: Option<(u32, u64)> = None;
        let mut post_ckpt_wal_bytes = 0u64;
        let mut scanned_wals: Vec<(u32, String, u64)> = Vec::new();

        let total_wals = wal_files.len();
        for (idx, (wal_seq, rel_path)) in wal_files.into_iter().enumerate() {
            let is_last_wal = idx + 1 == total_wals;
            let f = disk.open(&rel_path, OpenOpts::open_rw())?;
            let file_len = f.len()?;
            if file_len < WAL_HEADER_LEN {
                let prev_reached_ckpt = cur_lsn.unwrap_or(1) >= ckpt_next_lsn;
                if is_last_wal && prev_reached_ckpt {
                    // Unfinished rollover at tail: discard empty/torn new WAL file
                    drop(f);
                    disk.remove_file(&rel_path)?;
                    disk.sync_dir("wal")?;
                    break;
                } else {
                    return Err(EngineOpenError::Corrupt(format!(
                        "{rel_path} truncated header in WAL"
                    )));
                }
            }

            let mut raw = vec![0u8; file_len as usize];
            f.read_exact_at(0, &mut raw)?;
            let hdr: [u8; 32] = raw[0..32].try_into().unwrap();
            let first_lsn = match decode_wal_header(&hdr, wal_seq, format.uuid_lo()) {
                Ok(lsn) => lsn,
                Err(msg) => {
                    let prev_reached_ckpt = cur_lsn.unwrap_or(1) >= ckpt_next_lsn;
                    if is_last_wal && idx > 0 && prev_reached_ckpt {
                        drop(f);
                        disk.remove_file(&rel_path)?;
                        disk.sync_dir("wal")?;
                        break;
                    }
                    return Err(EngineOpenError::Corrupt(msg));
                }
            };

            let mut scan_lsn = match cur_lsn {
                None => {
                    if first_lsn > ckpt_next_lsn {
                        return Err(EngineOpenError::Corrupt(format!(
                            "{rel_path}: missing WAL gap after ckpt_lsn {base_lsn}, earliest first_lsn is {first_lsn}"
                        )));
                    }
                    first_lsn
                }
                Some(c) => {
                    if first_lsn != c {
                        if c < first_lsn && first_lsn <= ckpt_next_lsn {
                            // [ST-8] Gap `[c, first_lsn)` is strictly `<= base_lsn` (already durably
                            // captured in verified `ckpt-<base_lsn>`): an earlier pre-checkpoint WAL
                            // survived an interrupted post-checkpoint WAL prune while an intermediate
                            // pre-checkpoint WAL's `unlink` persisted before `sync_dir("wal")`.
                            first_lsn
                        } else {
                            return Err(EngineOpenError::Corrupt(format!(
                                "{rel_path}: expected first_lsn {c}, got {first_lsn}"
                            )));
                        }
                    } else {
                        c
                    }
                }
            };

            let mut pos = WAL_HEADER_LEN as usize;
            while pos < raw.len() {
                match decode_wal_record(&raw[pos..]) {
                    Ok(rec) => {
                        if rec.lsn != scan_lsn {
                            if is_last_wal
                                && scan_lsn > base_lsn
                                && !has_later_committed_record(&raw[pos..], scan_lsn)
                            {
                                warn!(
                                    rel_path,
                                    pos,
                                    scan_lsn,
                                    got_lsn = rec.lsn,
                                    "truncating out-of-order un-synced WAL tail (ST-6)"
                                );
                                f.set_len(pos as u64)?;
                                f.sync_data()?;
                                break;
                            }
                            return Err(EngineOpenError::Corrupt(format!(
                                "{rel_path}@{pos}: LSN gap expected {scan_lsn}, got {}",
                                rec.lsn
                            )));
                        }
                        if scan_lsn > base_lsn {
                            apply_wal_op(
                                &mut catalog,
                                &mut created_segments,
                                &mut deleted_segments,
                                rec.op,
                            );
                            post_ckpt_wal_bytes += rec.total_frame_bytes as u64;
                        }
                        scan_lsn += 1;
                        pos += rec.total_frame_bytes;
                    }
                    Err(_err) => {
                        // [ST-6] Distinguish torn tail vs mid-WAL corruption!
                        // Records <= base_lsn were guaranteed fdatasync'd before checkpoint, so
                        // corruption at scan_lsn <= base_lsn is NEVER a torn tail!
                        if is_last_wal
                            && scan_lsn > base_lsn
                            && !has_later_committed_record(&raw[pos..], scan_lsn)
                        {
                            warn!(
                                rel_path,
                                pos,
                                scan_lsn,
                                "truncating torn WAL tail at un-synced boundary (ST-6)"
                            );
                            f.set_len(pos as u64)?;
                            f.sync_data()?;
                            break;
                        } else {
                            return Err(EngineOpenError::Corrupt(format!(
                                "{rel_path}@{pos}: mid-WAL corruption detected at LSN {scan_lsn}"
                            )));
                        }
                    }
                }
            }
            cur_lsn = Some(scan_lsn);
            last_wal_state = Some((wal_seq, pos as u64));
            scanned_wals.push((wal_seq, rel_path, first_lsn));
        }

        if let Some(c) = cur_lsn {
            if c < ckpt_next_lsn {
                return Err(EngineOpenError::Corrupt(format!(
                    "WAL ended at LSN {} before checkpoint LSN {base_lsn}",
                    c.saturating_sub(1)
                )));
            }
            expected_lsn = c;
        } else if base_lsn > 0 {
            return Err(EngineOpenError::Corrupt(format!(
                "no WAL files found for checkpoint LSN {base_lsn}"
            )));
        }

        // [ST-8] Finish pruning any obsolete pre-checkpoint WAL files left behind by an interrupted prune
        if base_lsn > 0
            && scanned_wals.len() > 1
            && let Some(keep_from) = scanned_wals
                .iter()
                .rposition(|(_, _, flsn)| *flsn <= ckpt_next_lsn)
            && keep_from > 0
        {
            for (_, rel_i, _) in &scanned_wals[..keep_from] {
                let _ = disk.remove_file(rel_i);
            }
            disk.sync_dir("wal")?;
        }

        // Open or create active WAL file
        let wal_state = match last_wal_state {
            Some((wal_seq, write_pos)) => {
                let f = disk.open(&format!("wal/{wal_seq:08}.log"), OpenOpts::open_rw())?;
                WalWriterState {
                    wal_seq,
                    file: f,
                    write_pos,
                    next_lsn: expected_lsn,
                    synced_lsn: expected_lsn.saturating_sub(1),
                    bytes_since_checkpoint: post_ckpt_wal_bytes,
                }
            }
            None => {
                let wal_seq = 1u32;
                let path = format!("wal/{wal_seq:08}.log");
                let f = disk.open(&path, OpenOpts::create_truncate_rw())?;
                let hdr = encode_wal_header(wal_seq, expected_lsn, format.uuid_lo());
                f.write_all_at(0, &hdr)?;
                f.sync_data()?;
                disk.sync_dir("wal")?;
                WalWriterState {
                    wal_seq,
                    file: f,
                    write_pos: WAL_HEADER_LEN,
                    next_lsn: expected_lsn,
                    synced_lsn: expected_lsn.saturating_sub(1),
                    bytes_since_checkpoint: 0,
                }
            }
        };

        // Prune expired 24h completed_uploads on startup (02-storage-engine §6.1 step 7)
        let startup_now_ms = now_epoch_ms();
        let retention_ms = cfg.completed_upload_retention_ms;
        for b in catalog.buckets.values_mut() {
            b.completed_uploads
                .retain(|_, (cms, _)| startup_now_ms.saturating_sub(*cms) <= retention_ms);
        }

        // 6. Reconcile segment files & verify referenced extents (both objects AND active uploads!)
        let mut live_bytes_map: BTreeMap<u32, u64> = BTreeMap::new();
        let mut max_ref_end: BTreeMap<u32, u64> = BTreeMap::new();
        for b in catalog.buckets.values() {
            for chain in b.objects.values() {
                for v in chain {
                    for ext in v.extents.iter() {
                        *live_bytes_map.entry(ext.seg_id).or_default() += ext.physical_bytes();
                        let end = ext.offset + ext.physical_bytes();
                        let entry = max_ref_end.entry(ext.seg_id).or_default();
                        if end > *entry {
                            *entry = end;
                        }
                    }
                }
            }
            for up in b.uploads.values() {
                for p in up.parts.values() {
                    for ext in p.extents.iter() {
                        *live_bytes_map.entry(ext.seg_id).or_default() += ext.physical_bytes();
                        let end = ext.offset + ext.physical_bytes();
                        let entry = max_ref_end.entry(ext.seg_id).or_default();
                        if end > *entry {
                            *entry = end;
                        }
                    }
                }
            }
        }

        let mut segments: BTreeMap<u32, Arc<SegmentSlot<D>>> = BTreeMap::new();
        let mut max_seg_id = ckpt_next_seg_id.saturating_sub(1);

        for name in disk.read_dir("seg")? {
            if let Some(stem) = name.strip_suffix(".seg")
                && let Ok(seg_id) = stem.parse::<u32>() {
                    let deleted_before_ckpt = base_lsn > 0
                        && seg_id < ckpt_next_seg_id
                        && !ckpt_live_segments.contains(&seg_id);
                    if deleted_segments.contains(&seg_id) || deleted_before_ckpt {
                        // [ST-7] Finish interrupted segment deletion recorded in WAL or prior to checkpoint
                        let _ = disk.remove_file(&format!("seg/{name}"));
                        let _ = disk.sync_dir("seg");
                        continue;
                    }
                    let f = disk.open(&format!("seg/{name}"), OpenOpts::open_rw())?;
                    let len = f.len()?;
                    let required_end = max_ref_end.get(&seg_id).copied().unwrap_or(0);
                    if len < SEG_HEADER_LEN {
                        if required_end == 0 {
                            drop(f);
                            let _ = disk.remove_file(&format!("seg/{name}"));
                            let _ = disk.sync_dir("seg");
                            continue;
                        }
                        return Err(EngineOpenError::Corrupt(format!(
                            "segment {seg_id} truncated below header"
                        )));
                    }
                    let mut hdr = [0u8; 32];
                    f.read_exact_at(0, &mut hdr)?;
                    if let Err(msg) = verify_seg_header(&hdr, seg_id, format.uuid_lo()) {
                        if required_end == 0 {
                            drop(f);
                            let _ = disk.remove_file(&format!("seg/{name}"));
                            let _ = disk.sync_dir("seg");
                            continue;
                        }
                        return Err(EngineOpenError::Corrupt(msg));
                    }
                    if len < required_end {
                        return Err(EngineOpenError::Corrupt(format!(
                            "segment {seg_id} len {len} < committed extent end {required_end} (ST-1 violation)"
                        )));
                    }
                    if seg_id > max_seg_id {
                        max_seg_id = seg_id;
                    }
                    segments.insert(
                        seg_id,
                        Arc::new(SegmentSlot {
                            seg_id,
                            file: Arc::new(f),
                            disk: disk.clone(),
                            write_pos: AtomicU64::new(len),
                            live_bytes: AtomicU64::new(
                                live_bytes_map.get(&seg_id).copied().unwrap_or(0),
                            ),
                            inflight_writers: AtomicUsize::new(0),
                            pin_state: AtomicUsize::new(0),
                            state: AtomicU8::new(SEG_STATE_SEALED),
                        }),
                    );
                }
        }

        // Verify no committed extent references a missing segment!
        for (&seg_id, &req_end) in &max_ref_end {
            if req_end > 0 && !segments.contains_key(&seg_id) {
                return Err(EngineOpenError::Corrupt(format!(
                    "committed extent references missing segment {seg_id}"
                )));
            }
        }

        // Ensure an active writable segment exists
        let active_seg_id = if let Some((&last_id, slot)) = segments.iter().next_back() {
            slot.state.store(SEG_STATE_ACTIVE, Ordering::Release);
            last_id
        } else {
            let seg_id = max_seg_id + 1;
            let slot = create_segment_slot(&disk, seg_id, format.uuid_lo())?;
            max_seg_id = seg_id;
            segments.insert(seg_id, slot);
            seg_id
        };

        let key_locks = (0..KEY_LOCK_STRIPES)
            .map(|_| tokio::sync::Mutex::new(()))
            .collect();

        let initial_next_seq = catalog.next_seq + 1;
        let telemetry = EngineTelemetry::default();
        telemetry
            .last_checkpoint_lsn
            .store(base_lsn, Ordering::Relaxed);

        let sse_s3_master_key = derive_sse_s3_master_key(&format.instance_uuid);

        Ok(Arc::new(Self {
            disk,
            cfg,
            format,
            sse_s3_master_key,
            _lock_guard: lock_guard,
            read_only_poisoned: AtomicBool::new(false),
            next_seq: AtomicU64::new(initial_next_seq),
            catalog: RwLock::new(catalog),
            seg_mgr: Mutex::new(SegmentManager {
                active_seg_id,
                next_seg_id: max_seg_id + 1,
                segments,
            }),
            wal: Mutex::new(wal_state),
            group_commit_queue: Mutex::new(GroupCommitQueue::default()),
            batch_full_notify: tokio::sync::Notify::new(),
            ckpt_gate: tokio::sync::RwLock::new(()),
            key_locks,
            telemetry,
        }))
    }

    fn alloc_seq(&self) -> u64 {
        self.next_seq.fetch_add(1, Ordering::SeqCst)
    }

    pub fn is_read_only_poisoned(&self) -> bool {
        self.read_only_poisoned.load(Ordering::SeqCst)
    }

    fn poison_read_only(&self, context: &str, err: DiskError) -> S3Error {
        self.read_only_poisoned.store(true, Ordering::SeqCst);
        error!(%context, ?err, "CRITICAL: fsync/IO failed; engine entering irreversible ReadOnlyPoisoned state (§10)");
        S3Error::new(
            S3ErrorCode::InternalError,
            "Storage engine entered read-only failed state due to disk sync error.",
        )
    }

    fn check_writable(&self, require_free_space: bool) -> StoreResult<()> {
        if self.is_read_only_poisoned() {
            return Err(S3Error::new(
                S3ErrorCode::InternalError,
                "Storage engine is in read-only failed state.",
            ));
        }
        if require_free_space {
            // [NFR-16] Reject new writes with 503 SlowDown if free disk space < reserved threshold
            match self.disk.available_bytes() {
                Ok(avail) if avail < self.cfg.reserved_disk_bytes => {
                    return Err(S3Error::new(
                        S3ErrorCode::SlowDown,
                        "Insufficient free disk space; writes temporarily throttled.",
                    ));
                }
                Ok(_) => {}
                Err(_) => {
                    return Err(S3Error::new(
                        S3ErrorCode::InternalError,
                        "Failed to query available disk space.",
                    ));
                }
            }
        }
        Ok(())
    }

    fn key_stripe(&self, bucket: &str, key: &str) -> &tokio::sync::Mutex<()> {
        // FNV-1a hash across (bucket, 0x00, key)
        let mut h: u64 = 0xcbf29ce484222325;
        for &b in bucket.as_bytes().iter().chain(&[0u8]).chain(key.as_bytes()) {
            h ^= b as u64;
            h = h.wrapping_mul(0x100000001b3);
        }
        &self.key_locks[(h as usize) % KEY_LOCK_STRIPES]
    }

    fn make_random_iv(&self) -> [u8; 16] {
        let mut iv = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut iv);
        iv
    }

    /// Write a single framed data block (`<= max_block_payload`) into the active segment.
    fn write_data_block(&self, payload: &[u8]) -> StoreResult<(Extent, InflightWriteGuard<D>)> {
        let mut frame = Vec::with_capacity(BLOCK_HEADER_LEN as usize + payload.len());
        self.write_data_block_reuse(payload, &mut frame)
    }

    fn write_stream_block_maybe_enc(
        &self,
        plain_block: &[u8],
        enc_ctx: Option<(&Aes256Cipher, &[u8; 16], u64)>,
        enc_scratch: &mut Vec<u8>,
        frame_buf: &mut Vec<u8>,
    ) -> StoreResult<(Extent, InflightWriteGuard<D>)> {
        match enc_ctx {
            None => self.write_data_block_reuse(plain_block, frame_buf),
            Some((cipher, iv, plain_offset)) => {
                enc_scratch.clear();
                enc_scratch.extend_from_slice(plain_block);
                aes256_ctr_xor_with_cipher(cipher, iv, plain_offset, enc_scratch);
                self.write_data_block_reuse(enc_scratch, frame_buf)
            }
        }
    }

    fn write_data_block_reuse(
        &self,
        payload: &[u8],
        frame: &mut Vec<u8>,
    ) -> StoreResult<(Extent, InflightWriteGuard<D>)> {
        let payload_len = payload.len() as u32;
        let payload_crc = crc32c::crc32c(payload);
        let hdr = encode_block_header(payload_len, payload_crc);
        let frame_len = BLOCK_HEADER_LEN + payload_len as u64;

        let (guard, offset) = {
            let mut mgr = self.seg_mgr.lock().unwrap();
            let cur_id = mgr.active_seg_id;
            let cur_slot = Arc::clone(mgr.segments.get(&cur_id).unwrap());
            let cur_pos = cur_slot.write_pos.load(Ordering::SeqCst);

            let (chosen_slot, off) =
                if cur_pos > SEG_HEADER_LEN && cur_pos + frame_len > self.cfg.segment_size {
                    cur_slot.state.store(SEG_STATE_SEALED, Ordering::Release);
                    let new_id = mgr.next_seg_id;
                    mgr.next_seg_id += 1;
                    let new_slot = create_segment_slot(&self.disk, new_id, self.format.uuid_lo())
                        .map_err(|e| self.poison_read_only("create_segment", e))?;
                    let off = new_slot.write_pos.fetch_add(frame_len, Ordering::SeqCst);
                    mgr.active_seg_id = new_id;
                    mgr.segments.insert(new_id, Arc::clone(&new_slot));
                    (new_slot, off)
                } else {
                    let off = cur_slot.write_pos.fetch_add(frame_len, Ordering::SeqCst);
                    (cur_slot, off)
                };
            (InflightWriteGuard::acquire(&chosen_slot), off)
        };

        frame.clear();
        frame.reserve(frame_len as usize);
        frame.extend_from_slice(&hdr);
        frame.extend_from_slice(payload);
        guard.slot().file.write_all_at(offset, frame).map_err(|e| {
            error!(seg_id = guard.seg_id(), offset, ?e, "segment write failed");
            S3Error::new(S3ErrorCode::InternalError, "Disk write error")
        })?;
        const ASYNC_WRITEBACK_WINDOW: u64 = 16 * 1024 * 1024;
        if (offset + frame_len) / ASYNC_WRITEBACK_WINDOW > offset / ASYNC_WRITEBACK_WINDOW {
            guard.slot().file.hint_async_writeback();
        }

        Ok((
            Extent {
                seg_id: guard.seg_id(),
                offset,
                len: payload_len,
                crc32c: payload_crc,
            },
            guard,
        ))
    }

    /// Flush coalesced data segments + a batch of WAL operations in a single group commit (§8.3).
    /// On `EIO`, immediately poisons read-only WITHOUT updating `synced_lsn` or catalog (§10).
    fn flush_wal_batch(
        &self,
        segs: &BTreeMap<u32, Arc<SegmentSlot<D>>>,
        ops: &[WalOp],
    ) -> Vec<StoreResult<u64>> {
        if ops.is_empty() {
            return Vec::new();
        }
        if self.is_read_only_poisoned() {
            let err = S3Error::new(
                S3ErrorCode::InternalError,
                "Storage engine is in read-only failed state.",
            );
            return vec![Err(err); ops.len()];
        }

        // Step 3 (coalesced across group-commit batch): sync each touched segment once (`ST-1`, §8.3)
        for slot in segs.values() {
            let t0 = Instant::now();
            if let Err(e) = slot.file.sync_data() {
                let err = self.poison_read_only("group_commit_seg_fdatasync", e);
                return vec![Err(err); ops.len()];
            }
            self.telemetry
                .seg_fsync_us
                .observe(t0.elapsed().as_micros() as u64);
        }

        let mut wal = self.wal.lock().unwrap();
        if self.is_read_only_poisoned() {
            let err = S3Error::new(
                S3ErrorCode::InternalError,
                "Storage engine is in read-only failed state.",
            );
            return vec![Err(err); ops.len()];
        }

        self.telemetry
            .group_commit_batch_size
            .observe(ops.len() as u64);

        let first_lsn = wal.next_lsn;
        let prev_synced = wal.synced_lsn;
        let mut encoded = Vec::with_capacity(256 * ops.len());
        let mut lsns = Vec::with_capacity(ops.len());
        for (i, op) in ops.iter().enumerate() {
            let lsn = first_lsn + i as u64;
            encode_wal_record(lsn, prev_synced, op, &mut encoded);
            lsns.push(lsn);
        }

        // Roll WAL file if current file exceeds wal_file_size
        if wal.write_pos > WAL_HEADER_LEN
            && wal.write_pos + encoded.len() as u64 > self.cfg.wal_file_size
        {
            let new_seq = wal.wal_seq + 1;
            let rel_path = format!("wal/{new_seq:08}.log");
            let roll_res: Result<D::File, S3Error> = (|| {
                let nf = self
                    .disk
                    .open(&rel_path, OpenOpts::create_truncate_rw())
                    .map_err(|e| self.poison_read_only("wal_roll_open", e))?;
                let hdr = encode_wal_header(new_seq, first_lsn, self.format.uuid_lo());
                nf.write_all_at(0, &hdr)
                    .map_err(|e| self.poison_read_only("wal_roll_hdr_write", e))?;
                nf.sync_data()
                    .map_err(|e| self.poison_read_only("wal_roll_hdr_sync", e))?;
                self.disk
                    .sync_dir("wal")
                    .map_err(|e| self.poison_read_only("wal_roll_dir_sync", e))?;
                Ok(nf)
            })();
            match roll_res {
                Ok(new_file) => {
                    wal.wal_seq = new_seq;
                    wal.file = new_file;
                    wal.write_pos = WAL_HEADER_LEN;
                }
                Err(err) => return vec![Err(err); ops.len()],
            }
        }

        let offset = wal.write_pos;
        if let Err(e) = wal.file.write_all_at(offset, &encoded) {
            let err = self.poison_read_only("wal_write", e);
            return vec![Err(err); ops.len()];
        }
        let t_wal = Instant::now();
        if let Err(e) = wal.file.sync_data() {
            let err = self.poison_read_only("wal_fdatasync", e);
            return vec![Err(err); ops.len()];
        }
        self.telemetry
            .wal_fsync_us
            .observe(t_wal.elapsed().as_micros() as u64);

        let last_lsn = *lsns.last().unwrap();
        wal.write_pos += encoded.len() as u64;
        wal.bytes_since_checkpoint += encoded.len() as u64;
        wal.next_lsn = last_lsn + 1;
        wal.synced_lsn = last_lsn;
        lsns.into_iter().map(Ok).collect()
    }

    fn drain_pending_group_commits_sync(&self) {
        let max_batch = self.cfg.group_commit_max_batch.max(1);
        loop {
            let chunk: Vec<PendingCommitItem<D>> = {
                let mut q = self.group_commit_queue.lock().unwrap();
                if q.pending.is_empty() {
                    q.leader_active = false;
                    return;
                }
                let take = q.pending.len().min(max_batch);
                q.pending.drain(..take).collect()
            };
            let mut merged_segs = BTreeMap::new();
            let mut ops = Vec::with_capacity(chunk.len());
            for item in &chunk {
                for (&sid, slot) in &item.segs {
                    merged_segs.entry(sid).or_insert_with(|| Arc::clone(slot));
                }
                ops.push(item.op.clone());
            }
            let results = self.flush_wal_batch(&merged_segs, &ops);
            for (item, res) in chunk.into_iter().zip(results) {
                let _ = item.tx.send(res);
            }
        }
    }

    async fn commit_wal(&self, op: WalOp) -> StoreResult<tokio::sync::RwLockReadGuard<'_, ()>> {
        self.commit_wal_with_segments(&BTreeMap::new(), op).await
    }

    /// Group-Commit segment `fdatasync` + WAL append & `fdatasync` (§8.3).
    /// Returns a `ckpt_gate` read guard that MUST be held until the caller finishes updating `catalog`.
    async fn commit_wal_with_segments(
        &self,
        seg_guards: &BTreeMap<u32, InflightWriteGuard<D>>,
        op: WalOp,
    ) -> StoreResult<tokio::sync::RwLockReadGuard<'_, ()>> {
        let mut segs: BTreeMap<u32, Arc<SegmentSlot<D>>> = seg_guards
            .iter()
            .map(|(&sid, g)| (sid, Arc::clone(g.slot())))
            .collect();
        let ckpt_guard = self.ckpt_gate.read().await;
        if self.is_read_only_poisoned() {
            return Err(S3Error::new(
                S3ErrorCode::InternalError,
                "Storage engine is in read-only failed state.",
            ));
        }

        let max_batch = self.cfg.group_commit_max_batch.max(1);
        let follower_rx = {
            let mut q = self.group_commit_queue.lock().unwrap();
            if q.leader_active {
                let (tx, rx) = tokio::sync::oneshot::channel();
                q.pending.push(PendingCommitItem {
                    segs: std::mem::take(&mut segs),
                    op: op.clone(),
                    tx,
                });
                if 1 + q.pending.len() >= max_batch {
                    self.batch_full_notify.notify_one();
                }
                Some(rx)
            } else {
                q.leader_active = true;
                None
            }
        };

        if let Some(rx) = follower_rx {
            let _lsn = rx.await.unwrap_or_else(|_| {
                Err(S3Error::new(
                    S3ErrorCode::InternalError,
                    "Group commit channel closed",
                ))
            })?;
            return Ok(ckpt_guard);
        }

        struct LeaderDropGuard<'a, D: Disk> {
            engine: &'a Engine<D>,
            disarmed: bool,
        }
        impl<D: Disk> Drop for LeaderDropGuard<'_, D> {
            fn drop(&mut self) {
                if !self.disarmed {
                    self.engine.drain_pending_group_commits_sync();
                }
            }
        }

        let mut guard = LeaderDropGuard {
            engine: self,
            disarmed: false,
        };

        if self.cfg.group_commit_window_ms > 0 && max_batch > 1 {
            let already_full = {
                let q = self.group_commit_queue.lock().unwrap();
                1 + q.pending.len() >= max_batch
            };
            if !already_full {
                tokio::select! {
                    _ = tokio::time::sleep(Duration::from_millis(self.cfg.group_commit_window_ms)) => {}
                    _ = self.batch_full_notify.notified() => {}
                }
            }
        } else {
            tokio::task::yield_now().await;
        }

        let max_followers = max_batch.saturating_sub(1);
        let followers: Vec<PendingCommitItem<D>> = {
            let mut q = self.group_commit_queue.lock().unwrap();
            let take = q.pending.len().min(max_followers);
            q.pending.drain(..take).collect()
        };

        let mut batch_ops = Vec::with_capacity(1 + followers.len());
        batch_ops.push(op);
        for f in &followers {
            for (&sid, slot) in &f.segs {
                segs.entry(sid).or_insert_with(|| Arc::clone(slot));
            }
            batch_ops.push(f.op.clone());
        }

        let mut results = self.flush_wal_batch(&segs, &batch_ops);
        let my_res = results.remove(0);
        for (f, res) in followers.into_iter().zip(results) {
            let _ = f.tx.send(res);
        }

        self.drain_pending_group_commits_sync();
        guard.disarmed = true;
        my_res?;
        Ok(ckpt_guard)
    }

    /// Check whether WAL bytes accumulated since the last checkpoint exceed `checkpoint_wal_bytes` (§8.7).
    pub fn should_checkpoint(&self) -> bool {
        if self.is_read_only_poisoned() {
            return false;
        }
        let wal = self.wal.lock().unwrap();
        wal.synced_lsn > self.telemetry.last_checkpoint_lsn.load(Ordering::Relaxed)
            && wal.bytes_since_checkpoint >= self.cfg.checkpoint_wal_bytes
    }

    /// Write an atomic full metadata checkpoint (`ckpt/ckpt-%016x`, `ST-8`) and prune obsolete checkpoints/WALs.
    pub async fn write_checkpoint(&self) -> StoreResult<u64> {
        self.check_writable(false)?;
        let _exclusive = self.ckpt_gate.write().await;
        self.check_writable(false)?;

        let (ckpt_lsn, active_wal_seq) = {
            let wal = self.wal.lock().unwrap();
            (wal.synced_lsn, wal.wal_seq)
        };
        if ckpt_lsn == 0 {
            return Ok(0);
        }
        let prev_ckpt = self.telemetry.last_checkpoint_lsn.load(Ordering::Relaxed);
        if ckpt_lsn <= prev_ckpt {
            return Ok(ckpt_lsn);
        }

        let tmp_path = format!("tmp/ckpt-{ckpt_lsn:016x}.tmp");
        let final_path = format!("ckpt/ckpt-{ckpt_lsn:016x}");

        let tmp_file = self
            .disk
            .open(&tmp_path, OpenOpts::create_truncate_rw())
            .map_err(|e| self.poison_read_only("ckpt_open_tmp", e))?;

        {
            let cat = self.catalog.read().unwrap();
            let (next_seg_id, live_segments) = {
                let mgr = self.seg_mgr.lock().unwrap();
                let live: BTreeSet<u32> = mgr.segments.keys().copied().collect();
                (mgr.next_seg_id, live)
            };
            let next_seq = self.next_seq.load(Ordering::SeqCst);
            write_checkpoint_to_file(
                &tmp_file,
                self.format.uuid_lo(),
                ckpt_lsn,
                next_seq,
                next_seg_id,
                &live_segments,
                &cat,
            )
            .map_err(|e| self.poison_read_only("ckpt_write_tmp", e))?;
        }

        let t0 = Instant::now();
        tmp_file
            .sync_data()
            .map_err(|e| self.poison_read_only("ckpt_fdatasync", e))?;
        drop(tmp_file);
        self.disk
            .rename(&tmp_path, &final_path)
            .map_err(|e| self.poison_read_only("ckpt_rename", e))?;
        self.disk
            .sync_dir("ckpt")
            .map_err(|e| self.poison_read_only("ckpt_sync_dir", e))?;
        self.telemetry
            .ckpt_fsync_us
            .observe(t0.elapsed().as_micros() as u64);

        {
            let mut wal = self.wal.lock().unwrap();
            wal.bytes_since_checkpoint = 0;
        }
        self.telemetry
            .checkpoints_total
            .fetch_add(1, Ordering::Relaxed);
        self.telemetry
            .last_checkpoint_lsn
            .store(ckpt_lsn, Ordering::Relaxed);

        // Prune older checkpoints in `ckpt/` (`< ckpt_lsn`) now that `final_path` is durable
        if let Ok(entries) = self.disk.read_dir("ckpt") {
            let mut removed_any = false;
            for name in entries {
                if let Some(lsn) = parse_ckpt_filename(&name)
                    && lsn < ckpt_lsn {
                        let _ = self.disk.remove_file(&format!("ckpt/{name}"));
                        removed_any = true;
                    }
            }
            if removed_any {
                let _ = self.disk.sync_dir("ckpt");
            }
        }

        // Prune sealed WAL files strictly covered by `ckpt_lsn` (`next_file.first_lsn <= ckpt_lsn + 1`)
        if let Ok(entries) = self.disk.read_dir("wal") {
            let mut wal_headers: Vec<(u32, String, u64)> = Vec::new();
            for name in entries {
                if let Some(stem) = name.strip_suffix(".log")
                    && let Ok(seq) = stem.parse::<u32>() {
                        let rel = format!("wal/{name}");
                        if let Ok(wf) = self.disk.open(&rel, OpenOpts::read_only()) {
                            let mut hdr = [0u8; 32];
                            if wf.read_exact_at(0, &mut hdr).is_ok()
                                && let Ok(first_lsn) =
                                    decode_wal_header(&hdr, seq, self.format.uuid_lo())
                                {
                                    wal_headers.push((seq, rel, first_lsn));
                                }
                        }
                    }
            }
            wal_headers.sort_by_key(|(seq, _, _)| *seq);
            let mut removed_wal = false;
            for i in 0..wal_headers.len().saturating_sub(1) {
                let (seq_i, ref rel_i, _) = wal_headers[i];
                let (_, _, next_first_lsn) = wal_headers[i + 1];
                if seq_i < active_wal_seq && next_first_lsn <= ckpt_lsn + 1 {
                    let _ = self.disk.remove_file(rel_i);
                    removed_wal = true;
                }
            }
            if removed_wal {
                let _ = self.disk.sync_dir("wal");
            }
        }

        info!(ckpt_lsn, "checkpoint written and old WALs pruned");
        Ok(ckpt_lsn)
    }

    /// Collect engine-level Prometheus metrics snapshot (`NFR-11`).
    pub fn metrics_snapshot(&self) -> EngineMetricsSnapshot {
        let mut wal_bytes = 0u64;
        if let Ok(entries) = self.disk.read_dir("wal") {
            for name in entries {
                if name.ends_with(".log")
                    && let Ok(wf) = self.disk.open(&format!("wal/{name}"), OpenOpts::read_only()) {
                        wal_bytes += wf.len().unwrap_or(0);
                    }
            }
        }

        let (seg_live, seg_total) = {
            let mgr = self.seg_mgr.lock().unwrap();
            let mut live = 0u64;
            let mut total = 0u64;
            for slot in mgr.segments.values() {
                live += slot.live_bytes.load(Ordering::Relaxed);
                total += slot
                    .write_pos
                    .load(Ordering::Relaxed)
                    .saturating_sub(SEG_HEADER_LEN);
            }
            (live, total)
        };
        let seg_ratio = if seg_total == 0 {
            1.0
        } else {
            (seg_live as f64) / (seg_total as f64)
        };

        let (buckets, versions, uploads) = {
            let cat = self.catalog.read().unwrap();
            let b_cnt = cat.buckets.len() as u64;
            let mut v_cnt = 0u64;
            let mut u_cnt = 0u64;
            for b in cat.buckets.values() {
                for chain in b.objects.values() {
                    v_cnt += chain.len() as u64;
                }
                u_cnt += b.uploads.len() as u64;
            }
            (b_cnt, v_cnt, u_cnt)
        };

        EngineMetricsSnapshot {
            wal_fsync_us: self.telemetry.wal_fsync_us.snapshot(),
            seg_fsync_us: self.telemetry.seg_fsync_us.snapshot(),
            ckpt_fsync_us: self.telemetry.ckpt_fsync_us.snapshot(),
            group_commit_batch_size: self.telemetry.group_commit_batch_size.snapshot(),
            wal_bytes,
            segment_live_bytes: seg_live,
            segment_total_bytes: seg_total,
            segment_live_ratio: seg_ratio,
            gc_runs_total: self.telemetry.gc_runs_total.load(Ordering::Relaxed),
            gc_compacted_segments_total: self
                .telemetry
                .gc_compacted_segments_total
                .load(Ordering::Relaxed),
            gc_relocated_bytes_total: self
                .telemetry
                .gc_relocated_bytes_total
                .load(Ordering::Relaxed),
            gc_in_progress: self.telemetry.gc_in_progress.load(Ordering::Relaxed),
            checkpoints_total: self.telemetry.checkpoints_total.load(Ordering::Relaxed),
            last_checkpoint_lsn: self.telemetry.last_checkpoint_lsn.load(Ordering::Relaxed),
            catalog_buckets: buckets,
            catalog_object_versions: versions,
            catalog_open_uploads: uploads,
        }
    }

    /// Trigger online segment compaction / GC (`s3d compact`, §8.5).
    pub async fn compact(&self) -> StoreResult<usize> {
        self.check_writable(false)?;
        struct GcActiveGuard<'a>(&'a AtomicBool);
        impl Drop for GcActiveGuard<'_> {
            fn drop(&mut self) {
                self.0.store(false, Ordering::Release);
            }
        }
        self.telemetry.gc_runs_total.fetch_add(1, Ordering::Relaxed);
        self.telemetry.gc_in_progress.store(true, Ordering::Release);
        let _gc_active = GcActiveGuard(&self.telemetry.gc_in_progress);

        let candidates: Vec<Arc<SegmentSlot<D>>> = {
            let mgr = self.seg_mgr.lock().unwrap();
            mgr.segments
                .values()
                .filter(|s| {
                    if s.state.load(Ordering::Acquire) != SEG_STATE_SEALED {
                        return false;
                    }
                    if s.inflight_writers.load(Ordering::Acquire) > 0 {
                        return false;
                    }
                    let total = s.write_pos.load(Ordering::Acquire).saturating_sub(SEG_HEADER_LEN);
                    let live = s.live_bytes.load(Ordering::Acquire);
                    total == 0 || (live as f64) <= (total as f64) * self.cfg.gc_live_ratio
                })
                .cloned()
                .collect()
        };

        let mut compacted = 0usize;
        for old_slot in candidates {
            let old_id = old_slot.seg_id;
            // Collect live references pointing to `old_id` across both objects and active uploads
            let mut to_move_obj = Vec::new();
            let mut to_move_part = Vec::new();
            {
                let cat = self.catalog.read().unwrap();
                for (bname, b) in &cat.buckets {
                    for (key, chain) in &b.objects {
                        for v in chain {
                            for (eidx, ext) in v.extents.iter().enumerate() {
                                if ext.seg_id == old_id {
                                    to_move_obj.push((bname.clone(), key.clone(), v.seq, eidx, *ext));
                                }
                            }
                        }
                    }
                    for ((key, uid), up) in &b.uploads {
                        for p in up.parts.values() {
                            for (eidx, ext) in p.extents.iter().enumerate() {
                                if ext.seg_id == old_id {
                                    to_move_part.push((
                                        bname.clone(),
                                        key.clone(),
                                        uid.clone(),
                                        p.part_number,
                                        p.part_seq,
                                        eidx,
                                        *ext,
                                    ));
                                }
                            }
                        }
                    }
                }
            }

            let mut touched_new_slots: BTreeMap<u32, InflightWriteGuard<D>> = BTreeMap::new();
            let mut copied_obj = Vec::with_capacity(to_move_obj.len());
            let mut copied_part = Vec::with_capacity(to_move_part.len());

            for (bname, key, seq, eidx, ext) in to_move_obj {
                let mut raw = vec![0u8; ext.physical_bytes() as usize];
                old_slot
                    .file
                    .read_exact_at(ext.offset, &mut raw)
                    .map_err(|_| S3Error::new(S3ErrorCode::InternalError, "GC read failed"))?;
                let payload = &raw[12..];
                if crc32c::crc32c(payload) != ext.crc32c {
                    return Err(S3Error::new(
                        S3ErrorCode::InternalError,
                        "GC detected block CRC mismatch",
                    ));
                }
                let (new_ext, new_guard) = self.write_data_block(payload)?;
                touched_new_slots.entry(new_guard.seg_id()).or_insert(new_guard);
                copied_obj.push((bname, key, seq, eidx, ext, new_ext));
            }

            for (bname, key, uid, pn, pseq, eidx, ext) in to_move_part {
                let mut raw = vec![0u8; ext.physical_bytes() as usize];
                old_slot
                    .file
                    .read_exact_at(ext.offset, &mut raw)
                    .map_err(|_| S3Error::new(S3ErrorCode::InternalError, "GC read failed"))?;
                let payload = &raw[12..];
                if crc32c::crc32c(payload) != ext.crc32c {
                    return Err(S3Error::new(
                        S3ErrorCode::InternalError,
                        "GC detected block CRC mismatch",
                    ));
                }
                let (new_ext, new_guard) = self.write_data_block(payload)?;
                touched_new_slots.entry(new_guard.seg_id()).or_insert(new_guard);
                copied_part.push((bname, key, uid, pn, pseq, eidx, ext, new_ext));
            }

            for g in touched_new_slots.values() {
                let t0 = Instant::now();
                g.slot()
                    .file
                    .sync_data()
                    .map_err(|e| self.poison_read_only("gc_seg_sync", e))?;
                self.telemetry
                    .seg_fsync_us
                    .observe(t0.elapsed().as_micros() as u64);
            }

            // Re-verify under key stripe lock / catalog write lock and relocate still-live extents
            for (bname, key, seq, eidx, old_ext, new_ext) in copied_obj {
                let _kl = self.key_stripe(&bname, &key).lock().await;
                let still_live = {
                    let cat = self.catalog.read().unwrap();
                    cat.buckets
                        .get(&bname)
                        .and_then(|b| b.objects.get(&key))
                        .and_then(|c| c.iter().find(|v| v.seq == seq))
                        .and_then(|v| v.extents.get(eidx))
                        .is_some_and(|cur| {
                            cur.seg_id == old_ext.seg_id && cur.offset == old_ext.offset
                        })
                };
                if still_live {
                    let rel = RelocatedExtent {
                        bucket: bname.clone(),
                        key: key.clone(),
                        seq,
                        extent_idx: eidx,
                        old_seg_id: old_ext.seg_id,
                        old_offset: old_ext.offset,
                        new_extent: new_ext,
                    };
                    let _cg = self
                        .commit_wal(WalOp::RelocateExtents {
                            items: vec![rel],
                            part_items: Vec::new(),
                        })
                        .await?;
                    {
                        let mut cat = self.catalog.write().unwrap();
                        if let Some(v) = cat
                            .buckets
                            .get_mut(&bname)
                            .and_then(|b| b.objects.get_mut(&key))
                            .and_then(|c| c.iter_mut().find(|v| v.seq == seq))
                        {
                            let mut exts = v.extents.to_vec();
                            exts[eidx] = new_ext;
                            v.extents = exts.into();
                        }
                    }
                    old_slot
                        .live_bytes
                        .fetch_sub(old_ext.physical_bytes(), Ordering::AcqRel);
                    if let Some(ns) = touched_new_slots.get(&new_ext.seg_id) {
                        ns.slot()
                            .live_bytes
                            .fetch_add(new_ext.physical_bytes(), Ordering::AcqRel);
                    }
                    self.telemetry
                        .gc_relocated_bytes_total
                        .fetch_add(new_ext.len as u64, Ordering::Relaxed);
                }
            }

            for (bname, key, uid, pn, pseq, eidx, old_ext, new_ext) in copied_part {
                let _kl = self.key_stripe(&bname, &key).lock().await;
                let still_live = {
                    let cat = self.catalog.read().unwrap();
                    cat.buckets
                        .get(&bname)
                        .and_then(|b| b.uploads.get(&(key.clone(), uid.clone())))
                        .and_then(|up| up.parts.get(&pn))
                        .filter(|p| p.part_seq == pseq)
                        .and_then(|p| p.extents.get(eidx))
                        .is_some_and(|cur| {
                            cur.seg_id == old_ext.seg_id && cur.offset == old_ext.offset
                        })
                };
                if still_live {
                    let rel = RelocatedPartExtent {
                        bucket: bname.clone(),
                        key: key.clone(),
                        upload_id: uid.clone(),
                        part_number: pn,
                        part_seq: pseq,
                        extent_idx: eidx,
                        old_seg_id: old_ext.seg_id,
                        old_offset: old_ext.offset,
                        new_extent: new_ext,
                    };
                    let _cg = self
                        .commit_wal(WalOp::RelocateExtents {
                            items: Vec::new(),
                            part_items: vec![rel],
                        })
                        .await?;
                    {
                        let mut cat = self.catalog.write().unwrap();
                        if let Some(p) = cat
                            .buckets
                            .get_mut(&bname)
                            .and_then(|b| b.uploads.get_mut(&(key, uid)))
                            .and_then(|up| up.parts.get_mut(&pn))
                            .filter(|p| p.part_seq == pseq)
                        {
                            let mut exts = p.extents.to_vec();
                            exts[eidx] = new_ext;
                            p.extents = exts.into();
                        }
                    }
                    old_slot
                        .live_bytes
                        .fetch_sub(old_ext.physical_bytes(), Ordering::AcqRel);
                    if let Some(ns) = touched_new_slots.get(&new_ext.seg_id) {
                        ns.slot()
                            .live_bytes
                            .fetch_add(new_ext.physical_bytes(), Ordering::AcqRel);
                    }
                    self.telemetry
                        .gc_relocated_bytes_total
                        .fetch_add(new_ext.len as u64, Ordering::Relaxed);
                }
            }

            if old_slot.live_bytes.load(Ordering::Acquire) == 0 {
                // [ST-7] Record deletion intent in WAL BEFORE unlinking file!
                let _cg = self
                    .commit_wal(WalOp::DeleteSegment { seg_id: old_id })
                    .await?;
                {
                    // Remove from `mgr.segments` BEFORE setting `PIN_PENDING_DELETE_BIT`
                    // so no future `pin_extents` can acquire a pin on `old_slot`!
                    let mut mgr = self.seg_mgr.lock().unwrap();
                    mgr.segments.remove(&old_id);
                }
                drop(_cg);
                old_slot.mark_pending_delete_and_maybe_reclaim();
                compacted += 1;
                self.telemetry
                    .gc_compacted_segments_total
                    .fetch_add(1, Ordering::Relaxed);
            }
        }
        Ok(compacted)
    }
}

fn create_segment_slot<D: Disk>(
    disk: &D,
    seg_id: u32,
    uuid_lo: u64,
) -> Result<Arc<SegmentSlot<D>>, DiskError> {
    let path = format!("seg/{seg_id:08}.seg");
    let f = disk.open(&path, OpenOpts::create_truncate_rw())?;
    let now_sec = (now_epoch_ms().max(0) / 1000) as u32;
    let hdr = encode_seg_header(seg_id, uuid_lo, now_sec);
    f.write_all_at(0, &hdr)?;
    f.sync_data()?;
    // [ST-7] fsync parent directory after creating a new segment file!
    disk.sync_dir("seg")?;
    Ok(Arc::new(SegmentSlot {
        seg_id,
        file: Arc::new(f),
        disk: disk.clone(),
        write_pos: AtomicU64::new(SEG_HEADER_LEN),
        live_bytes: AtomicU64::new(0),
        inflight_writers: std::sync::atomic::AtomicUsize::new(0),
        pin_state: std::sync::atomic::AtomicUsize::new(0),
        state: std::sync::atomic::AtomicU8::new(SEG_STATE_ACTIVE),
    }))
}

fn insert_version_chain(
    versioning: VersioningStatus,
    chain: &mut Vec<ObjectVersionEntry>,
    entry: ObjectVersionEntry,
    reclaimed: &mut Vec<Extent>,
) {
    match versioning {
        VersioningStatus::Unversioned => {
            for old in chain.drain(..) {
                reclaimed.extend(old.extents.iter().copied());
            }
            chain.push(entry);
        }
        VersioningStatus::Suspended => {
            chain.retain(|old| {
                if old.version_id.as_deref().unwrap_or("null") == "null" {
                    reclaimed.extend(old.extents.iter().copied());
                    false
                } else {
                    true
                }
            });
            chain.insert(0, entry);
        }
        VersioningStatus::Enabled => {
            chain.insert(0, entry);
        }
    }
}

fn apply_wal_op(
    catalog: &mut MemoryCatalog,
    created_segments: &mut BTreeSet<u32>,
    deleted_segments: &mut BTreeSet<u32>,
    op: WalOp,
) {
    match op {
        WalOp::CreateBucket {
            name,
            owner,
            acl,
            region,
            created_ms,
            explicit_ownership,
            object_lock_enabled,
        } => {
            catalog.buckets.insert(
                name.clone(),
                BucketEntry {
                    name,
                    owner,
                    acl,
                    region,
                    created_ms,
                    versioning: if object_lock_enabled {
                        VersioningStatus::Enabled
                    } else {
                        VersioningStatus::Unversioned
                    },
                    explicit_ownership,
                    tags: BTreeMap::new(),
                    cors: None,
                    policy: None,
                    public_access_block: None,
                    object_lock_enabled,
                    object_lock_config: object_lock_enabled
                        .then_some(ObjectLockConfiguration::default()),
                    lifecycle: None,
                    encryption: None,
                    logging: None,
                    objects: BTreeMap::new(),
                    uploads: BTreeMap::new(),
                    completed_uploads: BTreeMap::new(),
                },
            );
        }
        WalOp::UpdateBucketVersioning { name, versioning } => {
            if let Some(b) = catalog.buckets.get_mut(&name) {
                b.versioning = versioning;
            }
        }
        WalOp::UpdateBucketAcl { name, acl } => {
            if let Some(b) = catalog.buckets.get_mut(&name) {
                b.acl = acl;
            }
        }
        WalOp::UpdateBucketOwnershipControls { name, ownership } => {
            if let Some(b) = catalog.buckets.get_mut(&name) {
                b.explicit_ownership = ownership;
            }
        }
        WalOp::UpdateBucketTagging { name, tags } => {
            if let Some(b) = catalog.buckets.get_mut(&name) {
                b.tags = tags;
            }
        }
        WalOp::UpdateBucketCors { name, cors } => {
            if let Some(b) = catalog.buckets.get_mut(&name) {
                b.cors = cors;
            }
        }
        WalOp::UpdateBucketPolicy { name, policy_json } => {
            if let Some(b) = catalog.buckets.get_mut(&name) {
                b.policy =
                    policy_json.and_then(|raw| BucketPolicyDoc::parse_and_validate(&raw, &name).ok());
            }
        }
        WalOp::UpdatePublicAccessBlock { name, config } => {
            if let Some(b) = catalog.buckets.get_mut(&name) {
                b.public_access_block = config;
            }
        }
        WalOp::UpdateBucketObjectLock { name, config } => {
            if let Some(b) = catalog.buckets.get_mut(&name) {
                b.object_lock_enabled = true;
                b.object_lock_config = Some(config);
            }
        }
        WalOp::UpdateBucketLifecycle { name, config } => {
            if let Some(b) = catalog.buckets.get_mut(&name) {
                b.lifecycle = config;
            }
        }
        WalOp::UpdateBucketEncryption { name, config } => {
            if let Some(b) = catalog.buckets.get_mut(&name) {
                b.encryption = config;
            }
        }
        WalOp::UpdateBucketLogging { name, status } => {
            if let Some(b) = catalog.buckets.get_mut(&name) {
                b.logging = status;
            }
        }
        WalOp::DeleteBucket { name } => {
            catalog.buckets.remove(&name);
        }
        WalOp::PutVersion {
            bucket,
            key,
            seq,
            version_id,
            is_delete_marker,
            total_size,
            etag,
            checksum,
            sys_meta,
            user_meta,
            owner,
            acl,
            tags,
            last_modified_ms,
            extents,
            parts,
            sse,
            retention,
            legal_hold,
        } => {
            if seq > catalog.next_seq {
                catalog.next_seq = seq;
            }
            if let Some(b) = catalog.buckets.get_mut(&bucket) {
                let entry = ObjectVersionEntry {
                    seq,
                    version_id,
                    is_delete_marker,
                    total_size,
                    etag,
                    checksum,
                    sys_meta: Arc::new(sys_meta),
                    user_meta,
                    owner: Arc::new(owner),
                    acl: Arc::new(acl),
                    tags,
                    last_modified_ms,
                    extents: extents.into(),
                    parts: parts.map(Into::into),
                    sse,
                    retention,
                    legal_hold,
                };
                let chain = b.objects.entry(key).or_default();
                let mut _unused = Vec::new();
                insert_version_chain(b.versioning, chain, entry, &mut _unused);
            }
        }
        WalOp::UpdateObjectAcl {
            bucket,
            key,
            seq,
            acl,
        } => {
            if let Some(v) = catalog
                .buckets
                .get_mut(&bucket)
                .and_then(|b| b.objects.get_mut(&key))
                .and_then(|c| c.iter_mut().find(|v| v.seq == seq))
            {
                v.acl = Arc::new(acl);
            }
        }
        WalOp::UpdateObjectTagging {
            bucket,
            key,
            seq,
            tags,
        } => {
            if let Some(v) = catalog
                .buckets
                .get_mut(&bucket)
                .and_then(|b| b.objects.get_mut(&key))
                .and_then(|c| c.iter_mut().find(|v| v.seq == seq))
            {
                v.tags = tags;
            }
        }
        WalOp::UpdateObjectRetention {
            bucket,
            key,
            seq,
            retention,
        } => {
            if let Some(v) = catalog
                .buckets
                .get_mut(&bucket)
                .and_then(|b| b.objects.get_mut(&key))
                .and_then(|c| c.iter_mut().find(|v| v.seq == seq))
            {
                v.retention = Some(retention);
            }
        }
        WalOp::UpdateObjectLegalHold {
            bucket,
            key,
            seq,
            status,
        } => {
            if let Some(v) = catalog
                .buckets
                .get_mut(&bucket)
                .and_then(|b| b.objects.get_mut(&key))
                .and_then(|c| c.iter_mut().find(|v| v.seq == seq))
            {
                v.legal_hold = Some(status);
            }
        }
        WalOp::DeleteVersion {
            bucket,
            key,
            version_id,
        } => {
            if let Some(b) = catalog.buckets.get_mut(&bucket) {
                match version_id {
                    None => {
                        b.objects.remove(&key);
                    }
                    Some(vid) => {
                        if let Some(chain) = b.objects.get_mut(&key) {
                            chain.retain(|v| {
                                v.version_id.as_deref().unwrap_or("null") != vid.as_str()
                            });
                            if chain.is_empty() {
                                b.objects.remove(&key);
                            }
                        }
                    }
                }
            }
        }
        WalOp::DeleteVersionBySeq { bucket, key, seq } => {
            if let Some(b) = catalog.buckets.get_mut(&bucket)
                && let Some(chain) = b.objects.get_mut(&key)
            {
                chain.retain(|v| v.seq != seq);
                if chain.is_empty() {
                    b.objects.remove(&key);
                }
            }
        }
        WalOp::CreateMultipartUpload {
            bucket,
            key,
            upload_id,
            initiator,
            owner,
            acl,
            tags,
            initiated_ms,
            sys_meta,
            user_meta,
            checksum_algorithm,
            checksum_type,
            sse,
            retention,
            legal_hold,
        } => {
            if let Some(b) = catalog.buckets.get_mut(&bucket) {
                b.uploads.insert(
                    (key.clone(), upload_id.clone()),
                    MultipartUploadEntry {
                        upload_id,
                        key,
                        initiator,
                        owner,
                        acl,
                        tags,
                        initiated_ms,
                        sys_meta,
                        user_meta,
                        checksum_algorithm,
                        checksum_type,
                        sse,
                        retention,
                        legal_hold,
                        parts: BTreeMap::new(),
                    },
                );
            }
        }
        WalOp::PutUploadPart {
            bucket,
            key,
            upload_id,
            part_seq,
            part_number,
            last_modified_ms,
            etag,
            size,
            md5,
            crc64_nvme,
            checksum,
            extents,
            sse_iv,
        } => {
            if part_seq > catalog.next_seq {
                catalog.next_seq = part_seq;
            }
            if let Some(up) = catalog
                .buckets
                .get_mut(&bucket)
                .and_then(|b| b.uploads.get_mut(&(key, upload_id)))
            {
                up.parts.insert(
                    part_number,
                    UploadPartEntry {
                        part_seq,
                        part_number,
                        last_modified_ms,
                        etag,
                        size,
                        md5,
                        crc64_nvme,
                        checksum,
                        extents: extents.into(),
                        sse_iv,
                    },
                );
            }
        }
        WalOp::CompleteMultipartUpload {
            bucket,
            key,
            upload_id,
            seq,
            version_id,
            total_size,
            etag,
            checksum,
            sys_meta,
            user_meta,
            owner,
            acl,
            tags,
            completed_ms,
            extents,
            parts,
            sse,
            retention,
            legal_hold,
            resp,
        } => {
            if seq > catalog.next_seq {
                catalog.next_seq = seq;
            }
            if let Some(b) = catalog.buckets.get_mut(&bucket) {
                let entry = ObjectVersionEntry {
                    seq,
                    version_id,
                    is_delete_marker: false,
                    total_size,
                    etag,
                    checksum,
                    sys_meta: Arc::new(sys_meta),
                    user_meta,
                    owner: Arc::new(owner),
                    acl: Arc::new(acl),
                    tags,
                    last_modified_ms: completed_ms,
                    extents: extents.into(),
                    parts: Some(parts.into()),
                    sse,
                    retention,
                    legal_hold,
                };
                let chain = b.objects.entry(key.clone()).or_default();
                let mut _unused = Vec::new();
                insert_version_chain(b.versioning, chain, entry, &mut _unused);
                b.uploads.remove(&(key.clone(), upload_id.clone()));
                b.completed_uploads
                    .insert((key, upload_id), (completed_ms, resp));
            }
        }
        WalOp::AbortMultipartUpload {
            bucket,
            key,
            upload_id,
        } => {
            if let Some(b) = catalog.buckets.get_mut(&bucket) {
                b.uploads.remove(&(key, upload_id));
            }
        }
        WalOp::CreateSegment { seg_id } => {
            created_segments.insert(seg_id);
        }
        WalOp::RelocateExtents { items, part_items } => {
            for item in items {
                if let Some(v) = catalog
                    .buckets
                    .get_mut(&item.bucket)
                    .and_then(|b| b.objects.get_mut(&item.key))
                    .and_then(|c| c.iter_mut().find(|v| v.seq == item.seq))
                    && let Some(cur) = v.extents.get(item.extent_idx)
                        && cur.seg_id == item.old_seg_id && cur.offset == item.old_offset {
                            let mut exts = v.extents.to_vec();
                            exts[item.extent_idx] = item.new_extent;
                            v.extents = exts.into();
                        }
            }
            for pitem in part_items {
                if let Some(p) = catalog
                    .buckets
                    .get_mut(&pitem.bucket)
                    .and_then(|b| b.uploads.get_mut(&(pitem.key, pitem.upload_id)))
                    .and_then(|up| up.parts.get_mut(&pitem.part_number))
                    .filter(|p| p.part_seq == pitem.part_seq)
                    && let Some(cur) = p.extents.get(pitem.extent_idx)
                        && cur.seg_id == pitem.old_seg_id && cur.offset == pitem.old_offset {
                            let mut exts = p.extents.to_vec();
                            exts[pitem.extent_idx] = pitem.new_extent;
                            p.extents = exts.into();
                        }
            }
        }
        WalOp::DeleteSegment { seg_id } => {
            deleted_segments.insert(seg_id);
        }
    }
}

fn now_epoch_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

fn can_bypass_governance_engine(
    bucket: &BucketEntry,
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
    cat: &'a MemoryCatalog,
    ctx: &CallerContext,
    bucket_name: &str,
) -> StoreResult<&'a BucketEntry> {
    let b = cat.buckets.get(bucket_name).ok_or_else(|| {
        S3Error::new(S3ErrorCode::NoSuchBucket, "The specified bucket does not exist")
            .with_bucket(bucket_name)
    })?;
    if let Some(expected) = &ctx.expected_bucket_owner
        && expected != &b.owner.user_id {
            return Err(S3Error::new(S3ErrorCode::AccessDenied, "Access Denied")
                .with_bucket(bucket_name));
        }
    Ok(b)
}

fn check_bucket_action<'a>(
    cat: &'a MemoryCatalog,
    default_ownership: ObjectOwnership,
    ctx: &CallerContext,
    bucket_name: &str,
    actions: &[S3Action],
    acl_needed: Option<AclPermission>,
    extra: &PolicyEvalExtra<'_>,
) -> StoreResult<&'a BucketEntry> {
    let b = lookup_bucket_checked(cat, ctx, bucket_name)?;
    let view = b.auth_view(default_ownership);
    if !authorize_bucket_action(&view, ctx, actions, acl_needed, extra) {
        return Err(
            S3Error::new(S3ErrorCode::AccessDenied, "Access Denied").with_bucket(bucket_name)
        );
    }
    Ok(b)
}

fn check_bucket_write_object<'a>(
    cat: &'a MemoryCatalog,
    default_ownership: ObjectOwnership,
    ctx: &CallerContext,
    bucket_name: &str,
    key: &str,
    req_tags: Option<&BTreeMap<String, String>>,
) -> StoreResult<&'a BucketEntry> {
    let b = lookup_bucket_checked(cat, ctx, bucket_name)?;
    let view = b.auth_view(default_ownership);
    let extra = PolicyEvalExtra {
        request_object_tags: req_tags,
        ..Default::default()
    };
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
        Some(&b.owner),
        Some((&b.acl, AclPermission::Write)),
        true,
        &extra,
    ) {
        return Err(
            S3Error::new(S3ErrorCode::AccessDenied, "Access Denied").with_key(bucket_name, key)
        );
    }
    Ok(b)
}

fn has_upload_perm(
    bucket: &BucketEntry,
    default_ownership: ObjectOwnership,
    key: &str,
    up: &MultipartUploadEntry,
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

fn head_state_of(versions: Option<&Vec<ObjectVersionEntry>>) -> HeadState<'_> {
    match versions.and_then(|v| v.first()) {
        None => HeadState::Absent,
        Some(v) if v.is_delete_marker => HeadState::DeleteMarker,
        Some(v) => HeadState::Present { etag: &v.etag },
    }
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

pub fn encode_continuation_token(bucket: &str, key: &str) -> String {
    encode_token(bucket, key)
}

pub fn decode_continuation_token(bucket: &str, token: &str) -> StoreResult<String> {
    decode_token(bucket, token)
}

fn encode_token(bucket: &str, key: &str) -> String {
    let raw = format!("v1:{bucket}:{key}");
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw.as_bytes())
}

fn decode_token(bucket: &str, token: &str) -> StoreResult<String> {
    if token.len() > 4096 {
        return Err(S3Error::new(
            S3ErrorCode::InvalidArgument,
            "The continuation token provided is incorrect",
        ));
    }
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

enum MergedItem<'a> {
    Object(&'a String, &'a ObjectVersionEntry),
    CommonPrefix(String),
}

fn next_prefix_upper_bound(s: &str) -> Option<String> {
    let mut chars: Vec<char> = s.chars().collect();
    while let Some(last) = chars.pop() {
        let code = last as u32;
        let next_code = if code == 0xD7FF {
            Some(0xE000)
        } else if code < 0x10FFFF {
            Some(code + 1)
        } else {
            None
        };
        if let Some(nc) = next_code
            && let Some(nc_char) = char::from_u32(nc) {
                chars.push(nc_char);
                return Some(chars.into_iter().collect());
            }
    }
    None
}

fn collect_visible_items<'a>(
    objects: &'a BTreeMap<String, Vec<ObjectVersionEntry>>,
    prefix: &str,
    delimiter: Option<&str>,
    after_key: Option<&str>,
    max_keys: usize,
) -> (Vec<MergedItem<'a>>, bool) {
    if max_keys == 0 {
        return (Vec::new(), false);
    }
    let mut items: Vec<MergedItem<'a>> = Vec::new();
    let mut last_cp: Option<String> = None;
    let mut is_truncated = false;
    let delim = delimiter.filter(|d| !d.is_empty());

    let mut cur_bound: Bound<String> = match after_key {
        Some(a) if a >= prefix => Bound::Excluded(a.to_string()),
        _ => Bound::Included(prefix.to_string()),
    };

    'leap: loop {
        let mut jump_to: Option<String> = None;
        for (key, chain) in objects.range::<String, _>((cur_bound.as_ref(), Bound::Unbounded)) {
            if !key.starts_with(prefix) {
                return (items, false);
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
            if let Some(d) = delim
                && let Some(pos) = rest.find(d) {
                    let cp = format!("{}{}", prefix, &rest[..pos + d.len()]);
                    if let Some(after) = after_key
                        && cp.as_str() <= after {
                            jump_to = next_prefix_upper_bound(&cp);
                            if jump_to.is_none() {
                                return (items, false);
                            }
                            break;
                        }
                    if last_cp.as_deref() == Some(cp.as_str()) {
                        jump_to = next_prefix_upper_bound(&cp);
                        if jump_to.is_none() {
                            return (items, false);
                        }
                        break;
                    }
                    if items.len() == max_keys {
                        is_truncated = true;
                        break 'leap;
                    }
                    let next_ub = next_prefix_upper_bound(&cp);
                    last_cp = Some(cp.clone());
                    items.push(MergedItem::CommonPrefix(cp));
                    if let Some(ub) = next_ub {
                        jump_to = Some(ub);
                        break;
                    } else {
                        return (items, false);
                    }
                }

            if items.len() == max_keys {
                is_truncated = true;
                break 'leap;
            }
            items.push(MergedItem::Object(key, head));
        }

        match jump_to {
            Some(ub) => {
                cur_bound = Bound::Included(ub);
            }
            None => break,
        }
    }

    (items, is_truncated)
}

fn strip_etag_quotes(s: &str) -> &str {
    s.trim().trim_matches('"')
}

impl<D: Disk> ObjectStore for Engine<D> {
    type Reader = EngineByteReader<D>;

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
        let cat = self.catalog.read().unwrap();
        let mut buckets: Vec<BucketSummary> = Vec::new();
        let mut next_token = None;
        for b in cat.buckets.values() {
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
                    next_token = Some(encode_token("__buckets__", &last.name));
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
        validate_bucket_name(&req.bucket)?;
        self.check_writable(true)?;

        if let Some(loc) = &req.location_constraint
            && !loc.is_empty() && loc != &self.cfg.region {
                return Err(S3Error::new(
                    S3ErrorCode::InvalidLocationConstraint,
                    "The specified location-constraint is not valid",
                )
                .with_bucket(&req.bucket));
            }

        let _kl = self.key_stripe(&req.bucket, "").lock().await;
        {
            let cat = self.catalog.read().unwrap();
            if let Some(existing) = cat.buckets.get(&req.bucket) {
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
            let owned = cat
                .buckets
                .values()
                .filter(|b| b.owner.user_id == caller.user_id)
                .count();
            if owned >= self.cfg.max_buckets_per_account {
                return Err(S3Error::new(
                    S3ErrorCode::TooManyBuckets,
                    "You have attempted to create more buckets than allowed",
                ));
            }
        }

        let ownership = req
            .object_ownership
            .unwrap_or(self.cfg.default_object_ownership);
        let explicit_ownership = match req.object_ownership {
            Some(own) => Some(own),
            None if self.cfg.default_object_ownership == ObjectOwnership::BucketOwnerEnforced => {
                Some(ObjectOwnership::BucketOwnerEnforced)
            }
            None => None,
        };
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

        let initial_versioning = if req.object_lock_enabled {
            VersioningStatus::Enabled
        } else {
            VersioningStatus::Unversioned
        };

        let op = WalOp::CreateBucket {
            name: req.bucket.clone(),
            owner: caller.clone(),
            acl: acl.clone(),
            region: self.cfg.region.clone(),
            created_ms: req.ctx.request_time_ms,
            explicit_ownership,
            object_lock_enabled: req.object_lock_enabled,
        };
        let _cg = self.commit_wal(op).await?;

        let mut cat = self.catalog.write().unwrap();
        cat.buckets.insert(
            req.bucket.clone(),
            BucketEntry {
                name: req.bucket.clone(),
                owner: caller.clone(),
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
            },
        );
        drop(cat);
        drop(_cg);

        Ok(BucketMetaSnapshot {
            name: req.bucket,
            owner: caller,
            region: self.cfg.region.clone(),
            created_ms: req.ctx.request_time_ms,
            versioning: initial_versioning,
            ownership,
        })
    }

    async fn head_bucket(&self, req: BucketRef) -> StoreResult<BucketMetaSnapshot> {
        let cat = self.catalog.read().unwrap();
        let b = check_bucket_action(
            &cat,
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
        self.check_writable(false)?;
        let _kl = self.key_stripe(&req.bucket, "").lock().await;
        {
            let cat = self.catalog.read().unwrap();
            let b = check_bucket_action(
                &cat,
                self.cfg.default_object_ownership,
                &req.ctx,
                &req.bucket,
                &[S3Action::DeleteBucket],
                None,
                &PolicyEvalExtra::default(),
            )?;
            if b.objects.values().any(|c| !c.is_empty()) {
                return Err(S3Error::new(
                    S3ErrorCode::BucketNotEmpty,
                    "The bucket you tried to delete is not empty",
                )
                .with_bucket(&req.bucket));
            }
        }
        let _cg = self
            .commit_wal(WalOp::DeleteBucket {
                name: req.bucket.clone(),
            })
            .await?;
        let mut reclaimed = Vec::new();
        {
            let mut cat = self.catalog.write().unwrap();
            if let Some(removed) = cat.buckets.remove(&req.bucket) {
                for up in removed.uploads.into_values() {
                    for p in up.parts.into_values() {
                        reclaimed.extend(p.extents.iter().copied());
                    }
                }
            }
        }
        if !reclaimed.is_empty() {
            self.adjust_live_bytes(&[], &reclaimed);
        }
        drop(_cg);
        Ok(())
    }

    async fn get_bucket_versioning(&self, req: BucketRef) -> StoreResult<VersioningStatus> {
        let cat = self.catalog.read().unwrap();
        let b = check_bucket_action(
            &cat,
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
        if req.status == VersioningStatus::Unversioned {
            return Err(S3Error::new(
                S3ErrorCode::MalformedXML,
                "Invalid versioning status.",
            ));
        }
        self.check_writable(false)?;
        let _kl = self.key_stripe(&req.bucket, "").lock().await;
        {
            let cat = self.catalog.read().unwrap();
            let b = check_bucket_action(
                &cat,
                self.cfg.default_object_ownership,
                &req.ctx,
                &req.bucket,
                &[S3Action::PutBucketVersioning],
                None,
                &PolicyEvalExtra::default(),
            )?;
            if b.object_lock_enabled && req.status == VersioningStatus::Suspended {
                return Err(S3Error::new(
                    S3ErrorCode::InvalidBucketState,
                    "An Object Lock configuration is present on this bucket, so the versioning state cannot be changed.",
                )
                .with_bucket(&req.bucket));
            }
        }
        let _cg = self
            .commit_wal(WalOp::UpdateBucketVersioning {
                name: req.bucket.clone(),
                versioning: req.status,
            })
            .await?;
        {
            let mut cat = self.catalog.write().unwrap();
            if let Some(b) = cat.buckets.get_mut(&req.bucket) {
                b.versioning = req.status;
            }
        }
        drop(_cg);
        Ok(())
    }

    async fn get_bucket_acl(&self, req: BucketRef) -> StoreResult<AccessControlPolicy> {
        let cat = self.catalog.read().unwrap();
        let b = check_bucket_action(
            &cat,
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
        self.check_writable(false)?;
        let _kl = self.key_stripe(&req.bucket, "").lock().await;
        let new_acl = {
            let cat = self.catalog.read().unwrap();
            let b = check_bucket_action(
                &cat,
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
            resolve_target_acl(&b.owner, Some(&b.owner), &req.acl)?
        };
        let _cg = self
            .commit_wal(WalOp::UpdateBucketAcl {
                name: req.bucket.clone(),
                acl: new_acl.clone(),
            })
            .await?;
        {
            let mut cat = self.catalog.write().unwrap();
            if let Some(b) = cat.buckets.get_mut(&req.bucket) {
                b.acl = new_acl;
            }
        }
        drop(_cg);
        Ok(())
    }

    async fn get_object_acl(&self, req: GetObjectAclReq) -> StoreResult<GetObjectAclResp> {
        validate_object_key(&req.bucket, &req.key)?;
        let cat = self.catalog.read().unwrap();
        let b = lookup_bucket_checked(&cat, &req.ctx, &req.bucket)?;
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
            policy: (*ver.acl).clone(),
        })
    }

    async fn put_object_acl(&self, req: PutObjectAclReq) -> StoreResult<Option<String>> {
        validate_object_key(&req.bucket, &req.key)?;
        self.check_writable(false)?;
        let _kl = self.key_stripe(&req.bucket, &req.key).lock().await;
        let actions: &[S3Action] = if req.version_id.is_some() {
            &[S3Action::PutObjectVersionAcl, S3Action::PutObjectAcl]
        } else {
            &[S3Action::PutObjectAcl]
        };
        let (target_seq, new_acl, vid_out) = {
            let cat = self.catalog.read().unwrap();
            let b = lookup_bucket_checked(&cat, &req.ctx, &req.bucket)?;
            let ver = self.lookup_version_for_op_checked(
                b,
                &req.ctx,
                &req.bucket,
                &req.key,
                req.version_id.as_deref(),
                actions,
                Some(AclPermission::WriteAcp),
                None,
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
            .map_err(|e| e.with_key(&req.bucket, &req.key))?;
            let acl = resolve_target_acl(&ver.owner, Some(&b.owner), &req.acl)?;
            let vid = ver.version_id.clone().filter(|v| v != "null");
            (ver.seq, acl, vid)
        };

        let _cg = self
            .commit_wal(WalOp::UpdateObjectAcl {
                bucket: req.bucket.clone(),
                key: req.key.clone(),
                seq: target_seq,
                acl: new_acl.clone(),
            })
            .await?;

        {
            let mut cat = self.catalog.write().unwrap();
            if let Some(v) = cat
                .buckets
                .get_mut(&req.bucket)
                .and_then(|b| b.objects.get_mut(&req.key))
                .and_then(|c| c.iter_mut().find(|v| v.seq == target_seq))
            {
                v.acl = Arc::new(new_acl);
            }
        }
        drop(_cg);
        Ok(vid_out)
    }

    async fn get_bucket_ownership_controls(
        &self,
        req: BucketRef,
    ) -> StoreResult<ObjectOwnership> {
        let cat = self.catalog.read().unwrap();
        let b = check_bucket_action(
            &cat,
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
        self.check_writable(false)?;
        let _kl = self.key_stripe(&req.bucket, "").lock().await;
        {
            let cat = self.catalog.read().unwrap();
            let b = check_bucket_action(
                &cat,
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
        }
        let _cg = self
            .commit_wal(WalOp::UpdateBucketOwnershipControls {
                name: req.bucket.clone(),
                ownership: Some(req.ownership),
            })
            .await?;
        {
            let mut cat = self.catalog.write().unwrap();
            if let Some(b) = cat.buckets.get_mut(&req.bucket) {
                b.explicit_ownership = Some(req.ownership);
            }
        }
        drop(_cg);
        Ok(())
    }

    async fn delete_bucket_ownership_controls(&self, req: BucketRef) -> StoreResult<()> {
        self.check_writable(false)?;
        let _kl = self.key_stripe(&req.bucket, "").lock().await;
        {
            let cat = self.catalog.read().unwrap();
            let _ = check_bucket_action(
                &cat,
                self.cfg.default_object_ownership,
                &req.ctx,
                &req.bucket,
                &[S3Action::PutBucketOwnershipControls],
                None,
                &PolicyEvalExtra::default(),
            )?;
        }
        let _cg = self
            .commit_wal(WalOp::UpdateBucketOwnershipControls {
                name: req.bucket.clone(),
                ownership: None,
            })
            .await?;
        {
            let mut cat = self.catalog.write().unwrap();
            if let Some(b) = cat.buckets.get_mut(&req.bucket) {
                b.explicit_ownership = None;
            }
        }
        drop(_cg);
        Ok(())
    }

    async fn get_bucket_tagging(&self, req: BucketRef) -> StoreResult<BTreeMap<String, String>> {
        let cat = self.catalog.read().unwrap();
        let b = check_bucket_action(
            &cat,
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
        self.check_writable(false)?;
        let _kl = self.key_stripe(&req.bucket, "").lock().await;
        {
            let cat = self.catalog.read().unwrap();
            let _ = check_bucket_action(
                &cat,
                self.cfg.default_object_ownership,
                &req.ctx,
                &req.bucket,
                &[S3Action::PutBucketTagging],
                None,
                &PolicyEvalExtra::default(),
            )?;
        }
        let _cg = self
            .commit_wal(WalOp::UpdateBucketTagging {
                name: req.bucket.clone(),
                tags: req.tags.clone(),
            })
            .await?;
        {
            let mut cat = self.catalog.write().unwrap();
            if let Some(b) = cat.buckets.get_mut(&req.bucket) {
                b.tags = req.tags;
            }
        }
        drop(_cg);
        Ok(())
    }

    async fn delete_bucket_tagging(&self, req: BucketRef) -> StoreResult<()> {
        self.check_writable(false)?;
        let _kl = self.key_stripe(&req.bucket, "").lock().await;
        {
            let cat = self.catalog.read().unwrap();
            let _ = check_bucket_action(
                &cat,
                self.cfg.default_object_ownership,
                &req.ctx,
                &req.bucket,
                &[S3Action::PutBucketTagging],
                None,
                &PolicyEvalExtra::default(),
            )?;
        }
        let _cg = self
            .commit_wal(WalOp::UpdateBucketTagging {
                name: req.bucket.clone(),
                tags: BTreeMap::new(),
            })
            .await?;
        {
            let mut cat = self.catalog.write().unwrap();
            if let Some(b) = cat.buckets.get_mut(&req.bucket) {
                b.tags.clear();
            }
        }
        drop(_cg);
        Ok(())
    }

    async fn get_object_tagging(&self, req: ObjectTaggingRef) -> StoreResult<GetObjectTaggingResp> {
        validate_object_key(&req.bucket, &req.key)?;
        let cat = self.catalog.read().unwrap();
        let b = lookup_bucket_checked(&cat, &req.ctx, &req.bucket)?;
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
        self.check_writable(false)?;
        let _kl = self.key_stripe(&req.bucket, &req.key).lock().await;
        let actions: &[S3Action] = if req.version_id.is_some() {
            &[S3Action::PutObjectVersionTagging, S3Action::PutObjectTagging]
        } else {
            &[S3Action::PutObjectTagging]
        };
        let (target_seq, vid_out) = {
            let cat = self.catalog.read().unwrap();
            let b = lookup_bucket_checked(&cat, &req.ctx, &req.bucket)?;
            let ver = self.lookup_version_for_op_checked(
                b,
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
        let _cg = self
            .commit_wal(WalOp::UpdateObjectTagging {
                bucket: req.bucket.clone(),
                key: req.key.clone(),
                seq: target_seq,
                tags: req.tags.clone(),
            })
            .await?;
        {
            let mut cat = self.catalog.write().unwrap();
            if let Some(v) = cat
                .buckets
                .get_mut(&req.bucket)
                .and_then(|b| b.objects.get_mut(&req.key))
                .and_then(|c| c.iter_mut().find(|v| v.seq == target_seq))
            {
                v.tags = req.tags;
            }
        }
        drop(_cg);
        Ok(vid_out)
    }

    async fn delete_object_tagging(&self, req: ObjectTaggingRef) -> StoreResult<Option<String>> {
        validate_object_key(&req.bucket, &req.key)?;
        self.check_writable(false)?;
        let _kl = self.key_stripe(&req.bucket, &req.key).lock().await;
        let actions: &[S3Action] = if req.version_id.is_some() {
            &[
                S3Action::DeleteObjectVersionTagging,
                S3Action::DeleteObjectTagging,
            ]
        } else {
            &[S3Action::DeleteObjectTagging]
        };
        let (target_seq, vid_out) = {
            let cat = self.catalog.read().unwrap();
            let b = lookup_bucket_checked(&cat, &req.ctx, &req.bucket)?;
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
            (ver.seq, ver.version_id.clone().filter(|v| v != "null"))
        };
        let _cg = self
            .commit_wal(WalOp::UpdateObjectTagging {
                bucket: req.bucket.clone(),
                key: req.key.clone(),
                seq: target_seq,
                tags: BTreeMap::new(),
            })
            .await?;
        {
            let mut cat = self.catalog.write().unwrap();
            if let Some(v) = cat
                .buckets
                .get_mut(&req.bucket)
                .and_then(|b| b.objects.get_mut(&req.key))
                .and_then(|c| c.iter_mut().find(|v| v.seq == target_seq))
            {
                v.tags.clear();
            }
        }
        drop(_cg);
        Ok(vid_out)
    }

    async fn get_bucket_cors(&self, req: BucketRef) -> StoreResult<CorsConfiguration> {
        let cat = self.catalog.read().unwrap();
        let b = check_bucket_action(
            &cat,
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
        self.check_writable(false)?;
        let _kl = self.key_stripe(&req.bucket, "").lock().await;
        {
            let cat = self.catalog.read().unwrap();
            let _ = check_bucket_action(
                &cat,
                self.cfg.default_object_ownership,
                &req.ctx,
                &req.bucket,
                &[S3Action::PutBucketCORS],
                None,
                &PolicyEvalExtra::default(),
            )?;
        }
        let _cg = self
            .commit_wal(WalOp::UpdateBucketCors {
                name: req.bucket.clone(),
                cors: Some(req.cors.clone()),
            })
            .await?;
        {
            let mut cat = self.catalog.write().unwrap();
            if let Some(b) = cat.buckets.get_mut(&req.bucket) {
                b.cors = Some(req.cors);
            }
        }
        drop(_cg);
        Ok(())
    }

    async fn delete_bucket_cors(&self, req: BucketRef) -> StoreResult<()> {
        self.check_writable(false)?;
        let _kl = self.key_stripe(&req.bucket, "").lock().await;
        {
            let cat = self.catalog.read().unwrap();
            let _ = check_bucket_action(
                &cat,
                self.cfg.default_object_ownership,
                &req.ctx,
                &req.bucket,
                &[S3Action::PutBucketCORS],
                None,
                &PolicyEvalExtra::default(),
            )?;
        }
        let _cg = self
            .commit_wal(WalOp::UpdateBucketCors {
                name: req.bucket.clone(),
                cors: None,
            })
            .await?;
        {
            let mut cat = self.catalog.write().unwrap();
            if let Some(b) = cat.buckets.get_mut(&req.bucket) {
                b.cors = None;
            }
        }
        drop(_cg);
        Ok(())
    }

    async fn lookup_bucket_cors_unauth(
        &self,
        bucket: &str,
    ) -> StoreResult<Option<CorsConfiguration>> {
        let cat = self.catalog.read().unwrap();
        let b = cat.buckets.get(bucket).ok_or_else(|| {
            S3Error::new(
                S3ErrorCode::NoSuchBucket,
                "The specified bucket does not exist",
            )
            .with_bucket(bucket)
        })?;
        Ok(b.cors.clone())
    }

    async fn get_bucket_policy(&self, req: BucketRef) -> StoreResult<String> {
        let cat = self.catalog.read().unwrap();
        let b = check_bucket_action(
            &cat,
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
        self.check_writable(false)?;
        let _kl = self.key_stripe(&req.bucket, "").lock().await;
        let doc = {
            let cat = self.catalog.read().unwrap();
            let b = check_bucket_action(
                &cat,
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
                    S3Error::new(S3ErrorCode::AccessDenied, "Access Denied")
                        .with_bucket(&req.bucket),
                );
            }
            doc
        };
        let _cg = self
            .commit_wal(WalOp::UpdateBucketPolicy {
                name: req.bucket.clone(),
                policy_json: Some(req.policy_json),
            })
            .await?;
        {
            let mut cat = self.catalog.write().unwrap();
            if let Some(b) = cat.buckets.get_mut(&req.bucket) {
                b.policy = Some(doc);
            }
        }
        drop(_cg);
        Ok(())
    }

    async fn delete_bucket_policy(&self, req: BucketRef) -> StoreResult<()> {
        self.check_writable(false)?;
        let _kl = self.key_stripe(&req.bucket, "").lock().await;
        {
            let cat = self.catalog.read().unwrap();
            let _ = check_bucket_action(
                &cat,
                self.cfg.default_object_ownership,
                &req.ctx,
                &req.bucket,
                &[S3Action::DeleteBucketPolicy],
                None,
                &PolicyEvalExtra::default(),
            )?;
        }
        let _cg = self
            .commit_wal(WalOp::UpdateBucketPolicy {
                name: req.bucket.clone(),
                policy_json: None,
            })
            .await?;
        {
            let mut cat = self.catalog.write().unwrap();
            if let Some(b) = cat.buckets.get_mut(&req.bucket) {
                b.policy = None;
            }
        }
        drop(_cg);
        Ok(())
    }

    async fn get_bucket_policy_status(&self, req: BucketRef) -> StoreResult<bool> {
        let cat = self.catalog.read().unwrap();
        let b = check_bucket_action(
            &cat,
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
        let cat = self.catalog.read().unwrap();
        let b = check_bucket_action(
            &cat,
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
        self.check_writable(false)?;
        let _kl = self.key_stripe(&req.bucket, "").lock().await;
        {
            let cat = self.catalog.read().unwrap();
            let _ = check_bucket_action(
                &cat,
                self.cfg.default_object_ownership,
                &req.ctx,
                &req.bucket,
                &[S3Action::PutBucketPublicAccessBlock],
                None,
                &PolicyEvalExtra::default(),
            )?;
        }
        let _cg = self
            .commit_wal(WalOp::UpdatePublicAccessBlock {
                name: req.bucket.clone(),
                config: Some(req.config),
            })
            .await?;
        {
            let mut cat = self.catalog.write().unwrap();
            if let Some(b) = cat.buckets.get_mut(&req.bucket) {
                b.public_access_block = Some(req.config);
            }
        }
        drop(_cg);
        Ok(())
    }

    async fn delete_public_access_block(&self, req: BucketRef) -> StoreResult<()> {
        self.check_writable(false)?;
        let _kl = self.key_stripe(&req.bucket, "").lock().await;
        {
            let cat = self.catalog.read().unwrap();
            let _ = check_bucket_action(
                &cat,
                self.cfg.default_object_ownership,
                &req.ctx,
                &req.bucket,
                &[S3Action::PutBucketPublicAccessBlock],
                None,
                &PolicyEvalExtra::default(),
            )?;
        }
        let _cg = self
            .commit_wal(WalOp::UpdatePublicAccessBlock {
                name: req.bucket.clone(),
                config: None,
            })
            .await?;
        {
            let mut cat = self.catalog.write().unwrap();
            if let Some(b) = cat.buckets.get_mut(&req.bucket) {
                b.public_access_block = None;
            }
        }
        drop(_cg);
        Ok(())
    }

    async fn get_object_lock_configuration(
        &self,
        req: BucketRef,
    ) -> StoreResult<ObjectLockConfiguration> {
        let cat = self.catalog.read().unwrap();
        let b = check_bucket_action(
            &cat,
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
        self.check_writable(false)?;
        let _kl = self.key_stripe(&req.bucket, "").lock().await;
        {
            let cat = self.catalog.read().unwrap();
            let b = check_bucket_action(
                &cat,
                self.cfg.default_object_ownership,
                &req.ctx,
                &req.bucket,
                &[S3Action::PutBucketObjectLockConfiguration],
                None,
                &PolicyEvalExtra::default(),
            )?;
            if !b.object_lock_enabled && b.versioning != VersioningStatus::Enabled {
                return Err(S3Error::new(
                    S3ErrorCode::InvalidBucketState,
                    "Versioning must be 'Enabled' on the bucket to apply a Object Lock configuration",
                )
                .with_bucket(&req.bucket));
            }
        }
        let _cg = self
            .commit_wal(WalOp::UpdateBucketObjectLock {
                name: req.bucket.clone(),
                config: req.config,
            })
            .await?;
        {
            let mut cat = self.catalog.write().unwrap();
            if let Some(b) = cat.buckets.get_mut(&req.bucket) {
                b.object_lock_enabled = true;
                b.object_lock_config = Some(req.config);
            }
        }
        drop(_cg);
        Ok(())
    }

    async fn get_object_retention(&self, req: ObjectLockRef) -> StoreResult<ObjectRetention> {
        validate_object_key(&req.bucket, &req.key)?;
        let cat = self.catalog.read().unwrap();
        let b = lookup_bucket_checked(&cat, &req.ctx, &req.bucket)?;
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
        self.check_writable(false)?;
        let _kl = self.key_stripe(&req.bucket, &req.key).lock().await;
        let target_seq = {
            let cat = self.catalog.read().unwrap();
            let b = lookup_bucket_checked(&cat, &req.ctx, &req.bucket)?;
            let ver = self.lookup_version_for_op_checked(
                b,
                &req.ctx,
                &req.bucket,
                &req.key,
                req.version_id.as_deref(),
                &[S3Action::PutObjectRetention],
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
            let can_bypass = can_bypass_governance_engine(
                b,
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
        let _cg = self
            .commit_wal(WalOp::UpdateObjectRetention {
                bucket: req.bucket.clone(),
                key: req.key.clone(),
                seq: target_seq,
                retention: req.retention,
            })
            .await?;
        {
            let mut cat = self.catalog.write().unwrap();
            if let Some(v) = cat
                .buckets
                .get_mut(&req.bucket)
                .and_then(|b| b.objects.get_mut(&req.key))
                .and_then(|c| c.iter_mut().find(|v| v.seq == target_seq))
            {
                v.retention = Some(req.retention);
            }
        }
        drop(_cg);
        Ok(())
    }

    async fn get_object_legal_hold(&self, req: ObjectLockRef) -> StoreResult<LegalHoldStatus> {
        validate_object_key(&req.bucket, &req.key)?;
        let cat = self.catalog.read().unwrap();
        let b = lookup_bucket_checked(&cat, &req.ctx, &req.bucket)?;
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
        self.check_writable(false)?;
        let _kl = self.key_stripe(&req.bucket, &req.key).lock().await;
        let target_seq = {
            let cat = self.catalog.read().unwrap();
            let b = lookup_bucket_checked(&cat, &req.ctx, &req.bucket)?;
            let ver = self.lookup_version_for_op_checked(
                b,
                &req.ctx,
                &req.bucket,
                &req.key,
                req.version_id.as_deref(),
                &[S3Action::PutObjectLegalHold],
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
            ver.seq
        };
        let _cg = self
            .commit_wal(WalOp::UpdateObjectLegalHold {
                bucket: req.bucket.clone(),
                key: req.key.clone(),
                seq: target_seq,
                status: req.status,
            })
            .await?;
        {
            let mut cat = self.catalog.write().unwrap();
            if let Some(v) = cat
                .buckets
                .get_mut(&req.bucket)
                .and_then(|b| b.objects.get_mut(&req.key))
                .and_then(|c| c.iter_mut().find(|v| v.seq == target_seq))
            {
                v.legal_hold = Some(req.status);
            }
        }
        drop(_cg);
        Ok(())
    }

    async fn get_bucket_lifecycle_configuration(
        &self,
        req: BucketRef,
    ) -> StoreResult<LifecycleConfiguration> {
        let cat = self.catalog.read().unwrap();
        let b = check_bucket_action(
            &cat,
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
        self.check_writable(false)?;
        let _kl = self.key_stripe(&req.bucket, "").lock().await;
        {
            let cat = self.catalog.read().unwrap();
            let _ = check_bucket_action(
                &cat,
                self.cfg.default_object_ownership,
                &req.ctx,
                &req.bucket,
                &[S3Action::PutLifecycleConfiguration],
                None,
                &PolicyEvalExtra::default(),
            )?;
        }
        let _cg = self
            .commit_wal(WalOp::UpdateBucketLifecycle {
                name: req.bucket.clone(),
                config: Some(req.config.clone()),
            })
            .await?;
        {
            let mut cat = self.catalog.write().unwrap();
            if let Some(b) = cat.buckets.get_mut(&req.bucket) {
                b.lifecycle = Some(req.config);
            }
        }
        drop(_cg);
        Ok(())
    }

    async fn delete_bucket_lifecycle(&self, req: BucketRef) -> StoreResult<()> {
        self.check_writable(false)?;
        let _kl = self.key_stripe(&req.bucket, "").lock().await;
        {
            let cat = self.catalog.read().unwrap();
            let _ = check_bucket_action(
                &cat,
                self.cfg.default_object_ownership,
                &req.ctx,
                &req.bucket,
                &[S3Action::PutLifecycleConfiguration],
                None,
                &PolicyEvalExtra::default(),
            )?;
        }
        let _cg = self
            .commit_wal(WalOp::UpdateBucketLifecycle {
                name: req.bucket.clone(),
                config: None,
            })
            .await?;
        {
            let mut cat = self.catalog.write().unwrap();
            if let Some(b) = cat.buckets.get_mut(&req.bucket) {
                b.lifecycle = None;
            }
        }
        drop(_cg);
        Ok(())
    }

    async fn get_bucket_encryption(&self, req: BucketRef) -> StoreResult<BucketEncryptionConfig> {
        let cat = self.catalog.read().unwrap();
        let b = check_bucket_action(
            &cat,
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
        self.check_writable(false)?;
        let _kl = self.key_stripe(&req.bucket, "").lock().await;
        {
            let cat = self.catalog.read().unwrap();
            let _ = check_bucket_action(
                &cat,
                self.cfg.default_object_ownership,
                &req.ctx,
                &req.bucket,
                &[S3Action::PutEncryptionConfiguration],
                None,
                &PolicyEvalExtra::default(),
            )?;
        }
        let _cg = self
            .commit_wal(WalOp::UpdateBucketEncryption {
                name: req.bucket.clone(),
                config: Some(req.config.clone()),
            })
            .await?;
        {
            let mut cat = self.catalog.write().unwrap();
            if let Some(b) = cat.buckets.get_mut(&req.bucket) {
                b.encryption = Some(req.config);
            }
        }
        drop(_cg);
        Ok(())
    }

    async fn delete_bucket_encryption(&self, req: BucketRef) -> StoreResult<()> {
        self.check_writable(false)?;
        let _kl = self.key_stripe(&req.bucket, "").lock().await;
        {
            let cat = self.catalog.read().unwrap();
            let _ = check_bucket_action(
                &cat,
                self.cfg.default_object_ownership,
                &req.ctx,
                &req.bucket,
                &[S3Action::PutEncryptionConfiguration],
                None,
                &PolicyEvalExtra::default(),
            )?;
        }
        let _cg = self
            .commit_wal(WalOp::UpdateBucketEncryption {
                name: req.bucket.clone(),
                config: None,
            })
            .await?;
        {
            let mut cat = self.catalog.write().unwrap();
            if let Some(b) = cat.buckets.get_mut(&req.bucket) {
                b.encryption = None;
            }
        }
        drop(_cg);
        Ok(())
    }

    async fn get_bucket_logging(&self, req: BucketRef) -> StoreResult<BucketLoggingStatus> {
        let cat = self.catalog.read().unwrap();
        let b = check_bucket_action(
            &cat,
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
        self.check_writable(false)?;
        let _kl = self.key_stripe(&req.bucket, "").lock().await;
        {
            let cat = self.catalog.read().unwrap();
            let src_b = lookup_bucket_checked(&cat, &req.ctx, &req.bucket)?;
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
            let src_owner_id = src_b.owner.user_id.clone();

            if let Some(le) = &req.status.logging_enabled {
                let Some(target_b) = cat.buckets.get(&le.target_bucket) else {
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
                let target_res_arn =
                    format!("arn:aws:s3:::{}/{}", le.target_bucket, le.target_prefix);
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
        }
        let _cg = self
            .commit_wal(WalOp::UpdateBucketLogging {
                name: req.bucket.clone(),
                status: Some(req.status.clone()),
            })
            .await?;
        {
            let mut cat = self.catalog.write().unwrap();
            if let Some(b) = cat.buckets.get_mut(&req.bucket) {
                b.logging = Some(req.status);
            }
        }
        drop(_cg);
        Ok(())
    }

    async fn put_object<S: VerifiedBodyStream>(
        &self,
        req: PutObjectReq,
        mut body: S,
    ) -> StoreResult<PutObjectResp> {
        validate_object_key(&req.bucket, &req.key)?;
        validate_user_metadata(&req.user_meta)?;
        self.check_writable(true)?;

        let sse_write = {
            let cat = self.catalog.read().unwrap();
            let b = check_bucket_write_object(
                &cat,
                self.cfg.default_object_ownership,
                &req.ctx,
                &req.bucket,
                &req.key,
                req.tags.as_ref(),
            )?;
            let sse_w = validate_sse_write(&req.raw_sse, b.encryption.is_some())?;
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
            sse_w
        };

        let iv = self.make_random_iv();
        let (cipher_opt, stored_sse, sse_resp) = match &sse_write {
            ValidatedSseWrite::None => (None, SseStoredMeta::None, SseResponseHeaders::None),
            ValidatedSseWrite::SseS3 => (
                Some(Aes256Cipher::new(&self.sse_s3_master_key)),
                SseStoredMeta::SseS3 { iv },
                SseResponseHeaders::SseS3,
            ),
            ValidatedSseWrite::SseC {
                key,
                key_md5,
                key_md5_b64,
            } => (
                Some(Aes256Cipher::new(key)),
                SseStoredMeta::SseC {
                    key_md5: *key_md5,
                    iv,
                },
                SseResponseHeaders::SseC {
                    key_md5_b64: key_md5_b64.clone(),
                },
            ),
        };

        // 1. Stream data into segment blocks (<= max_block_payload), encrypting at-rest if needed
        let mut block_buf = BytesMut::with_capacity(self.cfg.max_block_payload.min(64 * 1024));
        let mut enc_scratch: Vec<u8> = Vec::new();
        let mut frame_buf: Vec<u8> = Vec::new();
        let mut extents: Vec<Extent> = Vec::new();
        let mut touched_slots: BTreeMap<u32, InflightWriteGuard<D>> = BTreeMap::new();
        let mut seen_bytes = 0u64;
        let mut plain_offset = 0u64;

        while let Some(chunk) = poll_fn(|cx| body.poll_next_chunk(cx))
            .await
            .map_err(map_body_err)?
        {
            seen_bytes += chunk.len() as u64;
            if seen_bytes > req.max_bytes_limit {
                return Err(S3Error::new(
                    S3ErrorCode::EntityTooLarge,
                    "Your proposed upload exceeds the maximum allowed size",
                ));
            }
            let mut slice: &[u8] = &chunk;
            while !slice.is_empty() {
                if block_buf.is_empty() && slice.len() >= self.cfg.max_block_payload {
                    let blk = &slice[..self.cfg.max_block_payload];
                    let enc_ctx = cipher_opt.as_ref().map(|c| (c, &iv, plain_offset));
                    let (ext, guard) = self.write_stream_block_maybe_enc(
                        blk,
                        enc_ctx,
                        &mut enc_scratch,
                        &mut frame_buf,
                    )?;
                    plain_offset += blk.len() as u64;
                    touched_slots.entry(guard.seg_id()).or_insert(guard);
                    extents.push(ext);
                    slice = &slice[self.cfg.max_block_payload..];
                    continue;
                }
                let space = self.cfg.max_block_payload - block_buf.len();
                let take = space.min(slice.len());
                block_buf.extend_from_slice(&slice[..take]);
                slice = &slice[take..];
                if block_buf.len() == self.cfg.max_block_payload {
                    let enc_ctx = cipher_opt.as_ref().map(|c| (c, &iv, plain_offset));
                    let (ext, guard) = self.write_stream_block_maybe_enc(
                        &block_buf,
                        enc_ctx,
                        &mut enc_scratch,
                        &mut frame_buf,
                    )?;
                    plain_offset += block_buf.len() as u64;
                    touched_slots.entry(guard.seg_id()).or_insert(guard);
                    extents.push(ext);
                    block_buf.clear();
                }
            }
        }
        if !block_buf.is_empty() {
            let enc_ctx = cipher_opt.as_ref().map(|c| (c, &iv, plain_offset));
            let (ext, guard) = self.write_stream_block_maybe_enc(
                &block_buf,
                enc_ctx,
                &mut enc_scratch,
                &mut frame_buf,
            )?;
            touched_slots.entry(guard.seg_id()).or_insert(guard);
            extents.push(ext);
        }
        drop(block_buf);
        drop(enc_scratch);
        drop(frame_buf);

        // 2. Verify SHA-256 / Content-MD5 / Checksum BEFORE syncing or writing WAL! (PR-21)
        let digests = body.finish().map_err(map_body_err)?;

        // 3. Acquire KeyLock, re-evaluate preconditions & ACL at commit point (FR-17),
        //    then coalesce segment fdatasync + WAL fdatasync in group commit (ST-1, §8.3)
        let _kl = self.key_stripe(&req.bucket, &req.key).lock().await;
        let obj_tags = req.tags.clone().unwrap_or_default();
        let (versioning, obj_owner, obj_acl, retention, legal_hold, exp_hdr) = {
            let cat = self.catalog.read().unwrap();
            let b = check_bucket_write_object(
                &cat,
                self.cfg.default_object_ownership,
                &req.ctx,
                &req.bucket,
                &req.key,
                req.tags.as_ref(),
            )?;
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
            let (owner, acl) = resolve_object_owner_and_acl(
                b.effective_ownership(self.cfg.default_object_ownership),
                &b.owner,
                req.ctx.caller.as_ref(),
                req.acl.as_ref(),
            )?;
            let head = head_state_of(b.objects.get(&req.key));
            evaluate_write_preconditions(&req.preconditions, &req.bucket, &req.key, head)?;
            let exp_h = compute_x_amz_expiration(
                b.lifecycle.as_ref(),
                &req.key,
                digests.total_bytes,
                &obj_tags,
                req.ctx.request_time_ms,
            );
            (b.versioning, owner, acl, ret, lh, exp_h)
        };
        let seq = self.alloc_seq();

        let etag = format!("\"{}\"", hex::encode(digests.md5));
        let version_id = match versioning {
            VersioningStatus::Unversioned => None,
            VersioningStatus::Suspended => Some("null".to_string()),
            VersioningStatus::Enabled => Some(format!("v{seq:016x}")),
        };

        let op = WalOp::PutVersion {
            bucket: req.bucket.clone(),
            key: req.key.clone(),
            seq,
            version_id: version_id.clone(),
            is_delete_marker: false,
            total_size: digests.total_bytes,
            etag: etag.clone(),
            checksum: digests.checksum.clone(),
            sys_meta: req.sys_meta.clone(),
            user_meta: req.user_meta.clone(),
            owner: obj_owner.clone(),
            acl: obj_acl.clone(),
            tags: obj_tags.clone(),
            last_modified_ms: req.ctx.request_time_ms,
            extents: extents.clone(),
            parts: None,
            sse: stored_sse,
            retention,
            legal_hold,
        };
        let _cg = self.commit_wal_with_segments(&touched_slots, op).await?;

        // 4. Commit to in-memory catalog & update live_bytes accounting
        let mut reclaimed_extents: Vec<Extent> = Vec::new();
        {
            let mut cat = self.catalog.write().unwrap();
            if seq > cat.next_seq {
                cat.next_seq = seq;
            }
            if let Some(b) = cat.buckets.get_mut(&req.bucket) {
                let chain = b.objects.entry(req.key).or_default();
                let entry = ObjectVersionEntry {
                    seq,
                    version_id: version_id.clone(),
                    is_delete_marker: false,
                    total_size: digests.total_bytes,
                    etag: etag.clone(),
                    checksum: digests.checksum.clone(),
                    sys_meta: Arc::new(req.sys_meta),
                    user_meta: req.user_meta,
                    owner: Arc::new(obj_owner),
                    acl: Arc::new(obj_acl),
                    tags: obj_tags,
                    last_modified_ms: req.ctx.request_time_ms,
                    extents: extents.clone().into(),
                    parts: None,
                    sse: stored_sse,
                    retention,
                    legal_hold,
                };
                insert_version_chain(b.versioning, chain, entry, &mut reclaimed_extents);
            }
        }

        self.adjust_live_bytes(&extents, &reclaimed_extents);
        drop(touched_slots);
        drop(_cg);

        Ok(PutObjectResp {
            etag,
            version_id,
            checksum: digests.checksum,
            sse: sse_resp,
            expiration_header: exp_hdr,
        })
    }

    async fn get_object(&self, req: GetObjectReq) -> StoreResult<GetObjectResp<Self::Reader>> {
        let (meta, reader) = self.read_internal(&req, true)?;
        Ok(GetObjectResp { meta, reader })
    }

    async fn head_object(&self, req: GetObjectReq) -> StoreResult<ObjectMetaSnapshot> {
        let (meta, _) = self.read_internal(&req, false)?;
        Ok(meta)
    }

    async fn get_object_attributes(
        &self,
        req: GetObjectAttributesReq,
    ) -> StoreResult<GetObjectAttributesResp> {
        validate_object_key(&req.bucket, &req.key)?;
        let cat = self.catalog.read().unwrap();
        let b = lookup_bucket_checked(&cat, &req.ctx, &req.bucket)?;
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
                let max_p = req.max_parts.min(1000);
                let mut selected = Vec::new();
                let mut is_truncated = false;
                for p in all_parts.iter() {
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
            storage_class: req.attrs.storage_class.then(|| "STANDARD".to_string()),
            object_size: req.attrs.object_size.then_some(ver.total_size),
            sse: sse_resp,
        })
    }

    async fn delete_object(&self, req: DeleteObjectReq) -> StoreResult<DeleteObjectResp> {
        validate_object_key(&req.bucket, &req.key)?;
        self.check_writable(false)?;

        let _kl = self.key_stripe(&req.bucket, &req.key).lock().await;
        let (versioning, dm_owner) = {
            let cat = self.catalog.read().unwrap();
            let b = lookup_bucket_checked(&cat, &req.ctx, &req.bucket)?;
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
            let can_bypass = can_bypass_governance_engine(
                b,
                self.cfg.default_object_ownership,
                &req.ctx,
                &req.key,
                existing_tags,
            );
            let dm_owner = req.ctx.caller.clone().unwrap_or_else(|| b.owner.clone());
            let head = head_state_of(b.objects.get(&req.key));
            evaluate_delete_preconditions(req.if_match.as_deref(), &req.bucket, &req.key, head)?;
            if let Some(vid) = &req.version_id
                && let Some(chain) = b.objects.get(&req.key)
                && let Some(v) = chain
                    .iter()
                    .find(|v| v.version_id.as_deref().unwrap_or("null") == vid.as_str())
                && !v.is_delete_marker
            {
                check_worm_version_delete(
                    v.retention,
                    v.legal_hold,
                    req.bypass_governance,
                    can_bypass,
                    req.ctx.request_time_ms,
                )
                .map_err(|e| e.with_key(&req.bucket, &req.key))?;
            }
            (b.versioning, dm_owner)
        };
        let seq = self.alloc_seq();

        if let Some(vid) = &req.version_id {
            let _cg = self
                .commit_wal(WalOp::DeleteVersion {
                    bucket: req.bucket.clone(),
                    key: req.key.clone(),
                    version_id: Some(vid.clone()),
                })
                .await?;
            let mut reclaimed = Vec::new();
            let mut out_resp = DeleteObjectResp {
                version_id: Some(vid.clone()),
                is_delete_marker: false,
            };
            {
                let mut cat = self.catalog.write().unwrap();
                if let Some(b) = cat.buckets.get_mut(&req.bucket)
                    && let Some(chain) = b.objects.get_mut(&req.key)
                        && let Some(pos) = chain.iter().position(|v| {
                            v.version_id.as_deref().unwrap_or("null") == vid.as_str()
                        }) {
                            let removed = chain.remove(pos);
                            reclaimed.extend(removed.extents.iter().copied());
                            out_resp = DeleteObjectResp {
                                version_id: removed.version_id,
                                is_delete_marker: removed.is_delete_marker,
                            };
                            if chain.is_empty() {
                                b.objects.remove(&req.key);
                            }
                        }
            }
            self.adjust_live_bytes(&[], &reclaimed);
            drop(_cg);
            return Ok(out_resp);
        }

        match versioning {
            VersioningStatus::Unversioned => {
                let _cg = self
                    .commit_wal(WalOp::DeleteVersion {
                        bucket: req.bucket.clone(),
                        key: req.key.clone(),
                        version_id: None,
                    })
                    .await?;
                let mut reclaimed = Vec::new();
                {
                    let mut cat = self.catalog.write().unwrap();
                    if let Some(b) = cat.buckets.get_mut(&req.bucket)
                        && let Some(removed_chain) = b.objects.remove(&req.key) {
                            for v in removed_chain {
                                reclaimed.extend(v.extents.iter().copied());
                            }
                        }
                }
                self.adjust_live_bytes(&[], &reclaimed);
                drop(_cg);
                Ok(DeleteObjectResp {
                    version_id: None,
                    is_delete_marker: false,
                })
            }
            VersioningStatus::Suspended | VersioningStatus::Enabled => {
                let vid = if versioning == VersioningStatus::Suspended {
                    "null".to_string()
                } else {
                    format!("v{seq:016x}")
                };
                let dummy_csum = ChecksumState {
                    algorithm: ChecksumAlgorithm::Crc64Nvme,
                    checksum_type: ChecksumType::FullObject,
                    value_b64: String::new(),
                    client_requested: false,
                };
                let dm_acl = AccessControlPolicy::new_private(dm_owner.clone());
                let _cg = self
                    .commit_wal(WalOp::PutVersion {
                        bucket: req.bucket.clone(),
                        key: req.key.clone(),
                        seq,
                        version_id: Some(vid.clone()),
                        is_delete_marker: true,
                        total_size: 0,
                        etag: String::new(),
                        checksum: dummy_csum.clone(),
                        sys_meta: SystemMeta::default(),
                        user_meta: Vec::new(),
                        owner: dm_owner.clone(),
                        acl: dm_acl.clone(),
                        tags: BTreeMap::new(),
                        last_modified_ms: req.ctx.request_time_ms,
                        extents: Vec::new(),
                        parts: None,
                        sse: SseStoredMeta::None,
                        retention: None,
                        legal_hold: None,
                    })
                    .await?;

                let mut reclaimed = Vec::new();
                {
                    let mut cat = self.catalog.write().unwrap();
                    if seq > cat.next_seq {
                        cat.next_seq = seq;
                    }
                    if let Some(b) = cat.buckets.get_mut(&req.bucket) {
                        let chain = b.objects.entry(req.key).or_default();
                        if versioning == VersioningStatus::Suspended {
                            chain.retain(|old| {
                                if old.version_id.as_deref().unwrap_or("null") == "null" {
                                    reclaimed.extend(old.extents.iter().copied());
                                    false
                                } else {
                                    true
                                }
                            });
                        }
                        chain.insert(
                            0,
                            ObjectVersionEntry {
                                seq,
                                version_id: Some(vid.clone()),
                                is_delete_marker: true,
                                total_size: 0,
                                etag: String::new(),
                                checksum: dummy_csum,
                                sys_meta: Arc::new(SystemMeta::default()),
                                user_meta: Vec::new(),
                                owner: Arc::new(dm_owner),
                                acl: Arc::new(dm_acl),
                                tags: BTreeMap::new(),
                                last_modified_ms: req.ctx.request_time_ms,
                                extents: Arc::new([]),
                                parts: None,
                                sse: SseStoredMeta::None,
                                retention: None,
                                legal_hold: None,
                            },
                        );
                    }
                }
                self.adjust_live_bytes(&[], &reclaimed);
                drop(_cg);
                Ok(DeleteObjectResp {
                    version_id: Some(vid),
                    is_delete_marker: true,
                })
            }
        }
    }

    async fn delete_objects(&self, req: DeleteObjectsReq) -> StoreResult<DeleteObjectsResp> {
        if req.items.is_empty() || req.items.len() > 1000 {
            return Err(S3Error::new(
                S3ErrorCode::InvalidRequest,
                "DeleteObjects requires between 1 and 1000 keys.",
            )
            .with_bucket(&req.bucket));
        }
        self.check_writable(false)?;
        {
            let cat = self.catalog.read().unwrap();
            let _ = lookup_bucket_checked(&cat, &req.ctx, &req.bucket)?;
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
            return Err(S3Error::new(
                S3ErrorCode::InvalidRequest,
                "This copy request is illegal because it is trying to copy an object to itself without changing the object's metadata.",
            ));
        }
        self.check_writable(true)?;

        // 1. Lock-free snapshot read of source metadata & pin its segments
        let (src_ver, src_pins, dst_tags, src_key_iv, dst_sse_write) = {
            let cat = self.catalog.read().unwrap();
            let src_b = lookup_bucket_checked(&cat, &req.ctx, &req.src_bucket)?;
            let found = self
                .lookup_version_for_copy_checked(
                    src_b,
                    &req.ctx,
                    &req.src_bucket,
                    &req.src_key,
                    req.src_version_id.as_deref(),
                )?
                .clone();
            let dst_tags = match req.tagging_directive {
                TaggingDirective::Copy => found.tags.clone(),
                TaggingDirective::Replace => req.tags.clone().unwrap_or_default(),
            };
            let req_tags_for_auth = match req.tagging_directive {
                TaggingDirective::Copy => (!found.tags.is_empty()).then_some(&dst_tags),
                TaggingDirective::Replace => req.tags.as_ref(),
            };
            let dst_b = check_bucket_write_object(
                &cat,
                self.cfg.default_object_ownership,
                &req.ctx,
                &req.dst_bucket,
                &req.dst_key,
                req_tags_for_auth,
            )?;
            let dst_sse_w = validate_sse_write(&req.raw_sse, dst_b.encryption.is_some())?;
            let _ = resolve_upload_object_lock(
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
            let _ = resolve_object_owner_and_acl(
                dst_b.effective_ownership(self.cfg.default_object_ownership),
                &dst_b.owner,
                req.ctx.caller.as_ref(),
                req.acl.as_ref(),
            )?;

            let src_sse_read = validate_copy_source_sse(&req.raw_copy_src_sse)?;
            let (s_key_iv, _) =
                match_sse_for_stored_object(&found.sse, &src_sse_read, &self.sse_s3_master_key)?;

            if found.total_size > MAX_SINGLE_PUT_BYTES {
                return Err(S3Error::new(
                    S3ErrorCode::InvalidRequest,
                    "The specified copy source is larger than the maximum allowable size for a copy source: 5368709120",
                ));
            }
            evaluate_copy_source_preconditions(
                &req.src_preconditions,
                &found.etag,
                found.last_modified_ms,
            )?;

            let pins = self.pin_extents(&found.extents)?;
            (found, pins, dst_tags, s_key_iv, dst_sse_w)
        };

        let src_cipher = src_key_iv.map(|(k, _)| Aes256Cipher::new(&k));
        let dst_iv = self.make_random_iv();
        let (dst_cipher, stored_sse, sse_resp) = match &dst_sse_write {
            ValidatedSseWrite::None => (None, SseStoredMeta::None, SseResponseHeaders::None),
            ValidatedSseWrite::SseS3 => (
                Some(Aes256Cipher::new(&self.sse_s3_master_key)),
                SseStoredMeta::SseS3 { iv: dst_iv },
                SseResponseHeaders::SseS3,
            ),
            ValidatedSseWrite::SseC {
                key,
                key_md5,
                key_md5_b64,
            } => (
                Some(Aes256Cipher::new(key)),
                SseStoredMeta::SseC {
                    key_md5: *key_md5,
                    iv: dst_iv,
                },
                SseResponseHeaders::SseC {
                    key_md5_b64: key_md5_b64.clone(),
                },
            ),
        };

        // 2. Copy blocks sequentially into active segment (decrypting source & re-encrypting destination if needed)
        let mut new_extents = Vec::with_capacity(src_ver.extents.len());
        let mut touched_slots: BTreeMap<u32, InflightWriteGuard<D>> = BTreeMap::new();
        let mut md5_hasher = Md5::new();
        let mut csum_hasher = ActiveHasher::new(src_ver.checksum.algorithm);
        let mut block_buf = BytesMut::with_capacity(self.cfg.max_block_payload.min(64 * 1024));
        let mut enc_scratch: Vec<u8> = Vec::new();
        let mut frame_buf: Vec<u8> = Vec::new();
        let mut dst_plain_offset = 0u64;

        let slices = build_extent_read_slices(
            &src_ver.extents,
            src_ver.parts.as_deref(),
            src_key_iv.map(|(_, iv)| iv),
            0,
            src_ver.total_size,
        );
        let mut cached_ext: Option<(u32, u64)> = None;
        let mut raw_buf: Vec<u8> = Vec::new();
        let mut dec_buf: Vec<u8> = Vec::new();

        for rs in slices {
            let ext = rs.ext;
            if cached_ext != Some((ext.seg_id, ext.offset)) {
                let Some(pin) = src_pins.get(&ext.seg_id) else {
                    return Err(S3Error::new(
                        S3ErrorCode::InternalError,
                        "Missing source segment",
                    ));
                };
                raw_buf.resize(ext.physical_bytes() as usize, 0);
                pin.slot()
                    .file
                    .read_exact_at(ext.offset, &mut raw_buf)
                    .map_err(|_| S3Error::new(S3ErrorCode::InternalError, "Source read failed"))?;
                let hdr: [u8; 12] = raw_buf[0..12].try_into().unwrap();
                let (blk_len, blk_crc) = decode_block_header(&hdr).map_err(|_| {
                    S3Error::new(S3ErrorCode::InternalError, "Source block header corrupt")
                })?;
                let payload = &raw_buf[12..];
                if blk_len != ext.len || blk_crc != ext.crc32c || crc32c::crc32c(payload) != ext.crc32c
                {
                    return Err(S3Error::new(
                        S3ErrorCode::InternalError,
                        "Source block CRC32C mismatch",
                    ));
                }
                cached_ext = Some((ext.seg_id, ext.offset));
            }

            dec_buf.clear();
            dec_buf.extend_from_slice(&raw_buf[(12 + rs.rel_s)..(12 + rs.rel_e)]);
            if let (Some((iv, ctr_off)), Some(sc)) = (rs.ctr, &src_cipher) {
                aes256_ctr_xor_with_cipher(sc, &iv, ctr_off, &mut dec_buf);
            }
            md5_hasher.update(&dec_buf);
            csum_hasher.update(&dec_buf);

            let mut slice: &[u8] = &dec_buf;
            while !slice.is_empty() {
                let space = self.cfg.max_block_payload - block_buf.len();
                let take = space.min(slice.len());
                block_buf.extend_from_slice(&slice[..take]);
                slice = &slice[take..];
                if block_buf.len() == self.cfg.max_block_payload {
                    let enc_ctx = dst_cipher.as_ref().map(|c| (c, &dst_iv, dst_plain_offset));
                    let (new_ext, guard) = self.write_stream_block_maybe_enc(
                        &block_buf,
                        enc_ctx,
                        &mut enc_scratch,
                        &mut frame_buf,
                    )?;
                    dst_plain_offset += block_buf.len() as u64;
                    touched_slots.entry(guard.seg_id()).or_insert(guard);
                    new_extents.push(new_ext);
                    block_buf.clear();
                }
            }
        }
        if !block_buf.is_empty() {
            let enc_ctx = dst_cipher.as_ref().map(|c| (c, &dst_iv, dst_plain_offset));
            let (new_ext, guard) = self.write_stream_block_maybe_enc(
                &block_buf,
                enc_ctx,
                &mut enc_scratch,
                &mut frame_buf,
            )?;
            touched_slots.entry(guard.seg_id()).or_insert(guard);
            new_extents.push(new_ext);
        }
        drop(src_pins);

        // 3. Commit under destination key lock (coalescing segment + WAL fdatasync in group commit)
        let _kl = self.key_stripe(&req.dst_bucket, &req.dst_key).lock().await;
        let req_tags_for_auth = match req.tagging_directive {
            TaggingDirective::Copy => (!src_ver.tags.is_empty()).then_some(&dst_tags),
            TaggingDirective::Replace => req.tags.as_ref(),
        };
        let (dst_versioning, dst_owner, dst_acl, retention, legal_hold, exp_hdr) = {
            let cat = self.catalog.read().unwrap();
            let dst_b = check_bucket_write_object(
                &cat,
                self.cfg.default_object_ownership,
                &req.ctx,
                &req.dst_bucket,
                &req.dst_key,
                req_tags_for_auth,
            )?;
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
            let (owner, acl) = resolve_object_owner_and_acl(
                dst_b.effective_ownership(self.cfg.default_object_ownership),
                &dst_b.owner,
                req.ctx.caller.as_ref(),
                req.acl.as_ref(),
            )?;
            let dst_head = head_state_of(dst_b.objects.get(&req.dst_key));
            evaluate_write_preconditions(
                &req.dst_preconditions,
                &req.dst_bucket,
                &req.dst_key,
                dst_head,
            )?;
            let exp_h = compute_x_amz_expiration(
                dst_b.lifecycle.as_ref(),
                &req.dst_key,
                src_ver.total_size,
                &dst_tags,
                req.ctx.request_time_ms,
            );
            (dst_b.versioning, owner, acl, ret, lh, exp_h)
        };
        let seq = self.alloc_seq();

        let dst_vid = match dst_versioning {
            VersioningStatus::Unversioned => None,
            VersioningStatus::Suspended => Some("null".to_string()),
            VersioningStatus::Enabled => Some(format!("v{seq:016x}")),
        };
        let (sys_meta_val, sys_meta_arc, user_meta) = if req.replace_metadata {
            let sm = req.sys_meta;
            let arc = Arc::new(sm.clone());
            (sm, arc, req.user_meta)
        } else {
            (
                (*src_ver.sys_meta).clone(),
                Arc::clone(&src_ver.sys_meta),
                src_ver.user_meta.clone(),
            )
        };
        let md5_raw: [u8; 16] = md5_hasher.finalize().into();
        let etag = format!("\"{}\"", hex::encode(md5_raw));
        let dst_csum = ChecksumState {
            algorithm: src_ver.checksum.algorithm,
            checksum_type: ChecksumType::FullObject,
            value_b64: csum_hasher.finalize_b64(),
            client_requested: src_ver.checksum.client_requested,
        };

        let op = WalOp::PutVersion {
            bucket: req.dst_bucket.clone(),
            key: req.dst_key.clone(),
            seq,
            version_id: dst_vid.clone(),
            is_delete_marker: false,
            total_size: src_ver.total_size,
            etag: etag.clone(),
            checksum: dst_csum.clone(),
            sys_meta: sys_meta_val,
            user_meta: user_meta.clone(),
            owner: dst_owner.clone(),
            acl: dst_acl.clone(),
            tags: dst_tags.clone(),
            last_modified_ms: req.ctx.request_time_ms,
            extents: new_extents.clone(),
            parts: None,
            sse: stored_sse,
            retention,
            legal_hold,
        };
        let _cg = self.commit_wal_with_segments(&touched_slots, op).await?;

        let mut reclaimed = Vec::new();
        {
            let mut cat = self.catalog.write().unwrap();
            if seq > cat.next_seq {
                cat.next_seq = seq;
            }
            if let Some(dst_b) = cat.buckets.get_mut(&req.dst_bucket) {
                let chain = dst_b.objects.entry(req.dst_key).or_default();
                let entry = ObjectVersionEntry {
                    seq,
                    version_id: dst_vid.clone(),
                    is_delete_marker: false,
                    total_size: src_ver.total_size,
                    etag: etag.clone(),
                    checksum: dst_csum.clone(),
                    sys_meta: sys_meta_arc,
                    user_meta,
                    owner: Arc::new(dst_owner),
                    acl: Arc::new(dst_acl),
                    tags: dst_tags,
                    last_modified_ms: req.ctx.request_time_ms,
                    extents: new_extents.clone().into(),
                    parts: None,
                    sse: stored_sse,
                    retention,
                    legal_hold,
                };
                insert_version_chain(dst_versioning, chain, entry, &mut reclaimed);
            }
        }
        self.adjust_live_bytes(&new_extents, &reclaimed);
        drop(touched_slots);
        drop(_cg);

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

        self.check_writable(true)?;
        let _kl = self.key_stripe(&req.bucket, &req.key).lock().await;
        let (initiator, obj_owner, obj_acl, sse_write, retention, legal_hold) = {
            let cat = self.catalog.read().unwrap();
            let b = check_bucket_write_object(
                &cat,
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

        let seq = self.alloc_seq();
        let mut entropy = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut entropy);
        // [FR-24] >= 128-bit random entropy UploadId
        let upload_id = format!("mp{seq:016x}{}", hex::encode(entropy));
        let up_tags = req.tags.unwrap_or_default();
        let iv = self.make_random_iv();
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

        let _cg = self
            .commit_wal(WalOp::CreateMultipartUpload {
                bucket: req.bucket.clone(),
                key: req.key.clone(),
                upload_id: upload_id.clone(),
                initiator: initiator.clone(),
                owner: obj_owner.clone(),
                acl: obj_acl.clone(),
                tags: up_tags.clone(),
                initiated_ms: req.ctx.request_time_ms,
                sys_meta: req.sys_meta.clone(),
                user_meta: req.user_meta.clone(),
                checksum_algorithm: req.checksum_algorithm,
                checksum_type: resolved_type,
                sse: up_sse,
                retention,
                legal_hold,
            })
            .await?;

        {
            let mut cat = self.catalog.write().unwrap();
            if seq > cat.next_seq {
                cat.next_seq = seq;
            }
            if let Some(b) = cat.buckets.get_mut(&req.bucket) {
                b.uploads.insert(
                    (req.key.clone(), upload_id.clone()),
                    MultipartUploadEntry {
                        upload_id: upload_id.clone(),
                        key: req.key.clone(),
                        initiator,
                        owner: obj_owner,
                        acl: obj_acl,
                        tags: up_tags,
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
            }
        }
        drop(_cg);

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
        if req.part_number == 0 || req.part_number > MAX_PARTS_COUNT {
            return Err(S3Error::new(
                S3ErrorCode::InvalidArgument,
                "Part number must be an integer between 1 and 10000, inclusive",
            ));
        }
        self.check_writable(true)?;

        let (up_alg, part_enc_key, sse_resp) = {
            let cat = self.catalog.read().unwrap();
            let b = lookup_bucket_checked(&cat, &req.ctx, &req.bucket)?;
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
                    S3Error::new(S3ErrorCode::AccessDenied, "Access Denied")
                        .with_bucket(&req.bucket),
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
                    S3Error::new(S3ErrorCode::AccessDenied, "Access Denied")
                        .with_bucket(&req.bucket),
                );
            }
            let part_sse_req = validate_sse_read_or_part(&req.raw_sse)?;
            let (key_iv, sse_r) =
                match_sse_for_stored_object(&up.sse, &part_sse_req, &self.sse_s3_master_key)?;
            (up.checksum_algorithm, key_iv.map(|(k, _)| k), sse_r)
        };

        let part_iv = self.make_random_iv();
        let part_cipher = part_enc_key.map(|k| Aes256Cipher::new(&k));
        let part_iv_opt = part_cipher.as_ref().map(|_| part_iv);

        let mut block_buf = BytesMut::with_capacity(self.cfg.max_block_payload.min(64 * 1024));
        let mut enc_scratch: Vec<u8> = Vec::new();
        let mut frame_buf: Vec<u8> = Vec::new();
        let mut extents: Vec<Extent> = Vec::new();
        let mut touched_slots: BTreeMap<u32, InflightWriteGuard<D>> = BTreeMap::new();
        let mut seen_bytes = 0u64;
        let mut part_plain_offset = 0u64;
        let mut crc64_hasher = crc64fast_nvme::Digest::new();
        let mut up_csum_hasher = up_alg.map(ActiveHasher::new);

        while let Some(chunk) = poll_fn(|cx| body.poll_next_chunk(cx))
            .await
            .map_err(map_body_err)?
        {
            seen_bytes += chunk.len() as u64;
            if seen_bytes > req.max_bytes_limit {
                return Err(S3Error::new(
                    S3ErrorCode::EntityTooLarge,
                    "Your proposed upload exceeds the maximum allowed size",
                ));
            }
            crc64_hasher.write(&chunk);
            if let Some(h) = &mut up_csum_hasher {
                h.update(&chunk);
            }
            let mut slice: &[u8] = &chunk;
            while !slice.is_empty() {
                if block_buf.is_empty() && slice.len() >= self.cfg.max_block_payload {
                    let blk = &slice[..self.cfg.max_block_payload];
                    let enc_ctx = part_cipher.as_ref().map(|c| (c, &part_iv, part_plain_offset));
                    let (ext, guard) = self.write_stream_block_maybe_enc(
                        blk,
                        enc_ctx,
                        &mut enc_scratch,
                        &mut frame_buf,
                    )?;
                    part_plain_offset += blk.len() as u64;
                    touched_slots.entry(guard.seg_id()).or_insert(guard);
                    extents.push(ext);
                    slice = &slice[self.cfg.max_block_payload..];
                    continue;
                }
                let space = self.cfg.max_block_payload - block_buf.len();
                let take = space.min(slice.len());
                block_buf.extend_from_slice(&slice[..take]);
                slice = &slice[take..];
                if block_buf.len() == self.cfg.max_block_payload {
                    let enc_ctx = part_cipher.as_ref().map(|c| (c, &part_iv, part_plain_offset));
                    let (ext, guard) = self.write_stream_block_maybe_enc(
                        &block_buf,
                        enc_ctx,
                        &mut enc_scratch,
                        &mut frame_buf,
                    )?;
                    part_plain_offset += block_buf.len() as u64;
                    touched_slots.entry(guard.seg_id()).or_insert(guard);
                    extents.push(ext);
                    block_buf.clear();
                }
            }
        }
        if !block_buf.is_empty() {
            let enc_ctx = part_cipher.as_ref().map(|c| (c, &part_iv, part_plain_offset));
            let (ext, guard) = self.write_stream_block_maybe_enc(
                &block_buf,
                enc_ctx,
                &mut enc_scratch,
                &mut frame_buf,
            )?;
            touched_slots.entry(guard.seg_id()).or_insert(guard);
            extents.push(ext);
        }
        drop(block_buf);
        drop(enc_scratch);
        drop(frame_buf);

        let digests = body.finish().map_err(map_body_err)?;
        if let Some(alg) = up_alg
            && digests.checksum.client_requested && digests.checksum.algorithm != alg {
                return Err(S3Error::new(
                    S3ErrorCode::InvalidRequest,
                    format!(
                        "Checksum algorithm mismatch: upload expects {}",
                        alg.as_aws_str()
                    ),
                ));
            }

        let part_crc64 = crc64_hasher.sum64();
        let part_csum = up_alg
            .zip(up_csum_hasher)
            .map(|(alg, h)| (alg, h.finalize_b64()));
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

        let _kl = self.key_stripe(&req.bucket, &req.key).lock().await;
        {
            let cat = self.catalog.read().unwrap();
            let b = lookup_bucket_checked(&cat, &req.ctx, &req.bucket)?;
            let Some(up) = b.uploads.get(&(req.key.clone(), req.upload_id.clone())) else {
                return Err(S3Error::new(
                    S3ErrorCode::NoSuchUpload,
                    "The specified upload does not exist.",
                )
                .with_upload(&req.bucket, &req.key, &req.upload_id));
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
                    S3Error::new(S3ErrorCode::AccessDenied, "Access Denied")
                        .with_bucket(&req.bucket),
                );
            }
        }
        let part_seq = self.alloc_seq();

        let _cg = self
            .commit_wal_with_segments(
                &touched_slots,
                WalOp::PutUploadPart {
                    bucket: req.bucket.clone(),
                    key: req.key.clone(),
                    upload_id: req.upload_id.clone(),
                    part_seq,
                    part_number: req.part_number,
                    last_modified_ms: req.ctx.request_time_ms,
                    etag: etag.clone(),
                    size: digests.total_bytes,
                    md5: digests.md5,
                    crc64_nvme: part_crc64,
                    checksum: part_csum.clone(),
                    extents: extents.clone(),
                    sse_iv: part_iv_opt,
                },
            )
            .await?;

        let mut reclaimed = Vec::new();
        {
            let mut cat = self.catalog.write().unwrap();
            if part_seq > cat.next_seq {
                cat.next_seq = part_seq;
            }
            if let Some(up) = cat
                .buckets
                .get_mut(&req.bucket)
                .and_then(|b| b.uploads.get_mut(&(req.key, req.upload_id)))
                && let Some(old_part) = up.parts.insert(
                    req.part_number,
                    UploadPartEntry {
                        part_seq,
                        part_number: req.part_number,
                        last_modified_ms: req.ctx.request_time_ms,
                        etag: etag.clone(),
                        size: digests.total_bytes,
                        md5: digests.md5,
                        crc64_nvme: part_crc64,
                        checksum: part_csum,
                        extents: extents.clone().into(),
                        sse_iv: part_iv_opt,
                    },
                ) {
                    reclaimed.extend(old_part.extents.iter().copied());
                }
        }
        self.adjust_live_bytes(&extents, &reclaimed);
        drop(touched_slots);
        drop(_cg);

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
        self.check_writable(true)?;

        let (src_ver, src_pins, up_alg, slice_start, slice_end_excl, src_key_iv, dst_enc_key, sse_resp) = {
            let cat = self.catalog.read().unwrap();
            let src_b = lookup_bucket_checked(&cat, &req.ctx, &req.src_bucket)?;
            let dst_b = lookup_bucket_checked(&cat, &req.ctx, &req.dst_bucket)?;
            let Some(up) = dst_b
                .uploads
                .get(&(req.dst_key.clone(), req.upload_id.clone()))
            else {
                let view = dst_b.auth_view(self.cfg.default_object_ownership);
                if authorize_object_action(
                    &view,
                    &req.ctx,
                    &req.dst_key,
                    &[S3Action::PutObject],
                    Some(&dst_b.owner),
                    Some((&dst_b.acl, AclPermission::Write)),
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
                    S3Error::new(S3ErrorCode::AccessDenied, "Access Denied")
                        .with_bucket(&req.dst_bucket),
                );
            };
            if !has_upload_perm(
                dst_b,
                self.cfg.default_object_ownership,
                &req.dst_key,
                up,
                &req.ctx,
                &[S3Action::PutObject],
                AclPermission::Write,
            ) {
                return Err(
                    S3Error::new(S3ErrorCode::AccessDenied, "Access Denied")
                        .with_bucket(&req.dst_bucket),
                );
            }
            let up_alg = up.checksum_algorithm;
            let up_sse = up.sse;

            let found = self
                .lookup_version_for_copy_checked(
                    src_b,
                    &req.ctx,
                    &req.src_bucket,
                    &req.src_key,
                    req.src_version_id.as_deref(),
                )?
                .clone();

            let dst_sse_req = validate_sse_read_or_part(&req.raw_sse)?;
            let (dst_key_iv, sse_r) =
                match_sse_for_stored_object(&up_sse, &dst_sse_req, &self.sse_s3_master_key)?;
            let src_sse_req = validate_copy_source_sse(&req.raw_copy_src_sse)?;
            let (s_key_iv, _) =
                match_sse_for_stored_object(&found.sse, &src_sse_req, &self.sse_s3_master_key)?;

            evaluate_copy_source_preconditions(
                &req.src_preconditions,
                &found.etag,
                found.last_modified_ms,
            )?;

            let src_len = found.total_size;
            let (s, e_excl) = if let Some((start, end)) = req.src_range {
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

            let pins = if s < e_excl {
                self.pin_extents(&found.extents)?
            } else {
                BTreeMap::new()
            };
            (
                found,
                pins,
                up_alg,
                s,
                e_excl,
                s_key_iv,
                dst_key_iv.map(|(k, _)| k),
                sse_r,
            )
        };

        let src_cipher = src_key_iv.map(|(k, _)| Aes256Cipher::new(&k));
        let part_iv = self.make_random_iv();
        let dst_part_cipher = dst_enc_key.map(|k| Aes256Cipher::new(&k));
        let part_iv_opt = dst_part_cipher.as_ref().map(|_| part_iv);

        let mut block_buf = BytesMut::with_capacity(self.cfg.max_block_payload.min(64 * 1024));
        let mut enc_scratch: Vec<u8> = Vec::new();
        let mut frame_buf: Vec<u8> = Vec::new();
        let mut extents: Vec<Extent> = Vec::new();
        let mut touched_slots: BTreeMap<u32, InflightWriteGuard<D>> = BTreeMap::new();
        let mut md5_hasher = Md5::new();
        let mut crc64_hasher = crc64fast_nvme::Digest::new();
        let mut up_csum_hasher = up_alg.map(ActiveHasher::new);
        let mut dst_part_plain_offset = 0u64;

        if slice_start < slice_end_excl {
            let slices = build_extent_read_slices(
                &src_ver.extents,
                src_ver.parts.as_deref(),
                src_key_iv.map(|(_, iv)| iv),
                slice_start,
                slice_end_excl,
            );
            let mut cached_ext: Option<(u32, u64)> = None;
            let mut raw_buf: Vec<u8> = Vec::new();
            let mut dec_buf: Vec<u8> = Vec::new();

            for rs in slices {
                let ext = rs.ext;
                if cached_ext != Some((ext.seg_id, ext.offset)) {
                    let Some(pin) = src_pins.get(&ext.seg_id) else {
                        return Err(S3Error::new(
                            S3ErrorCode::InternalError,
                            "Missing source segment",
                        ));
                    };
                    raw_buf.resize(ext.physical_bytes() as usize, 0);
                    pin.slot()
                        .file
                        .read_exact_at(ext.offset, &mut raw_buf)
                        .map_err(|_| {
                            S3Error::new(S3ErrorCode::InternalError, "Source read failed")
                        })?;
                    let hdr: [u8; 12] = raw_buf[0..12].try_into().unwrap();
                    let (blk_len, blk_crc) = decode_block_header(&hdr).map_err(|_| {
                        S3Error::new(S3ErrorCode::InternalError, "Source block header corrupt")
                    })?;
                    let payload = &raw_buf[12..];
                    if blk_len != ext.len
                        || blk_crc != ext.crc32c
                        || crc32c::crc32c(payload) != ext.crc32c
                    {
                        return Err(S3Error::new(
                            S3ErrorCode::InternalError,
                            "Source block CRC32C mismatch",
                        ));
                    }
                    cached_ext = Some((ext.seg_id, ext.offset));
                }

                dec_buf.clear();
                dec_buf.extend_from_slice(&raw_buf[(12 + rs.rel_s)..(12 + rs.rel_e)]);
                if let (Some((iv, ctr_off)), Some(sc)) = (rs.ctr, &src_cipher) {
                    aes256_ctr_xor_with_cipher(sc, &iv, ctr_off, &mut dec_buf);
                }

                md5_hasher.update(&dec_buf);
                crc64_hasher.write(&dec_buf);
                if let Some(h) = &mut up_csum_hasher {
                    h.update(&dec_buf);
                }

                let mut slice: &[u8] = &dec_buf;
                while !slice.is_empty() {
                    let space = self.cfg.max_block_payload - block_buf.len();
                    let take = space.min(slice.len());
                    block_buf.extend_from_slice(&slice[..take]);
                    slice = &slice[take..];
                    if block_buf.len() == self.cfg.max_block_payload {
                        let enc_ctx = dst_part_cipher
                            .as_ref()
                            .map(|c| (c, &part_iv, dst_part_plain_offset));
                        let (new_ext, guard) = self.write_stream_block_maybe_enc(
                            &block_buf,
                            enc_ctx,
                            &mut enc_scratch,
                            &mut frame_buf,
                        )?;
                        dst_part_plain_offset += block_buf.len() as u64;
                        touched_slots.entry(guard.seg_id()).or_insert(guard);
                        extents.push(new_ext);
                        block_buf.clear();
                    }
                }
            }
            if !block_buf.is_empty() {
                let enc_ctx = dst_part_cipher
                    .as_ref()
                    .map(|c| (c, &part_iv, dst_part_plain_offset));
                let (new_ext, guard) = self.write_stream_block_maybe_enc(
                    &block_buf,
                    enc_ctx,
                    &mut enc_scratch,
                    &mut frame_buf,
                )?;
                touched_slots.entry(guard.seg_id()).or_insert(guard);
                extents.push(new_ext);
                block_buf.clear();
            }
        }
        drop(src_pins);

        let part_len = slice_end_excl - slice_start;
        let md5: [u8; 16] = md5_hasher.finalize().into();
        let etag = format!("\"{}\"", hex::encode(md5));
        let part_crc64 = crc64_hasher.sum64();
        let part_csum = up_alg
            .zip(up_csum_hasher)
            .map(|(alg, h)| (alg, h.finalize_b64()));
        let resp_csum = part_csum.as_ref().map(|(alg, val)| ChecksumState {
            algorithm: *alg,
            checksum_type: ChecksumType::FullObject,
            value_b64: val.clone(),
            client_requested: true,
        });

        let _kl = self.key_stripe(&req.dst_bucket, &req.dst_key).lock().await;
        {
            let cat = self.catalog.read().unwrap();
            let dst_b = lookup_bucket_checked(&cat, &req.ctx, &req.dst_bucket)?;
            let Some(up) = dst_b
                .uploads
                .get(&(req.dst_key.clone(), req.upload_id.clone()))
            else {
                return Err(S3Error::new(
                    S3ErrorCode::NoSuchUpload,
                    "The specified upload does not exist.",
                )
                .with_upload(&req.dst_bucket, &req.dst_key, &req.upload_id));
            };
            if !has_upload_perm(
                dst_b,
                self.cfg.default_object_ownership,
                &req.dst_key,
                up,
                &req.ctx,
                &[S3Action::PutObject],
                AclPermission::Write,
            ) {
                return Err(
                    S3Error::new(S3ErrorCode::AccessDenied, "Access Denied")
                        .with_bucket(&req.dst_bucket),
                );
            }
        }
        let part_seq = self.alloc_seq();

        let _cg = self
            .commit_wal_with_segments(
                &touched_slots,
                WalOp::PutUploadPart {
                    bucket: req.dst_bucket.clone(),
                    key: req.dst_key.clone(),
                    upload_id: req.upload_id.clone(),
                    part_seq,
                    part_number: req.part_number,
                    last_modified_ms: req.ctx.request_time_ms,
                    etag: etag.clone(),
                    size: part_len,
                    md5,
                    crc64_nvme: part_crc64,
                    checksum: part_csum.clone(),
                    extents: extents.clone(),
                    sse_iv: part_iv_opt,
                },
            )
            .await?;

        let mut reclaimed = Vec::new();
        {
            let mut cat = self.catalog.write().unwrap();
            if part_seq > cat.next_seq {
                cat.next_seq = part_seq;
            }
            if let Some(up) = cat
                .buckets
                .get_mut(&req.dst_bucket)
                .and_then(|b| b.uploads.get_mut(&(req.dst_key, req.upload_id)))
                && let Some(old_part) = up.parts.insert(
                    req.part_number,
                    UploadPartEntry {
                        part_seq,
                        part_number: req.part_number,
                        last_modified_ms: req.ctx.request_time_ms,
                        etag: etag.clone(),
                        size: part_len,
                        md5,
                        crc64_nvme: part_crc64,
                        checksum: part_csum,
                        extents: extents.clone().into(),
                        sse_iv: part_iv_opt,
                    },
                ) {
                    reclaimed.extend(old_part.extents.iter().copied());
                }
        }
        self.adjust_live_bytes(&extents, &reclaimed);
        drop(touched_slots);
        drop(_cg);

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
        if req.parts.is_empty() {
            return Err(S3Error::new(
                S3ErrorCode::MalformedXML,
                "The XML you provided was not well-formed or did not validate against our published schema",
            ));
        }
        self.check_writable(false)?;

        let _kl = self.key_stripe(&req.bucket, &req.key).lock().await;
        let (up, versioning, sse_resp) = {
            let cat = self.catalog.read().unwrap();
            let b = lookup_bucket_checked(&cat, &req.ctx, &req.bucket)?;

            // [FR-27] 24h idempotent replay of completed UploadId
            if let Some((completed_ms, cached_resp)) = b
                .completed_uploads
                .get(&(req.key.clone(), req.upload_id.clone()))
            {
                let view = b.auth_view(self.cfg.default_object_ownership);
                if !authorize_object_action(
                    &view,
                    &req.ctx,
                    &req.key,
                    &[S3Action::PutObject],
                    Some(&b.owner),
                    Some((&b.acl, AclPermission::Write)),
                    true,
                    &PolicyEvalExtra::default(),
                ) {
                    return Err(
                        S3Error::new(S3ErrorCode::AccessDenied, "Access Denied")
                            .with_bucket(&req.bucket),
                    );
                }
                if req.ctx.request_time_ms.saturating_sub(*completed_ms)
                    <= self.cfg.completed_upload_retention_ms
                {
                    return Ok(cached_resp.clone());
                }
            }

            let Some(up) = b
                .uploads
                .get(&(req.key.clone(), req.upload_id.clone()))
                .cloned()
            else {
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
                    S3Error::new(S3ErrorCode::AccessDenied, "Access Denied")
                        .with_bucket(&req.bucket),
                );
            };
            if !has_upload_perm(
                b,
                self.cfg.default_object_ownership,
                &req.key,
                &up,
                &req.ctx,
                &[S3Action::PutObject],
                AclPermission::Write,
            ) {
                return Err(
                    S3Error::new(S3ErrorCode::AccessDenied, "Access Denied")
                        .with_bucket(&req.bucket),
                );
            }
            let complete_sse_req = validate_sse_read_or_part(&req.raw_sse)?;
            let (_, sse_r) =
                match_sse_for_stored_object(&up.sse, &complete_sse_req, &self.sse_s3_master_key)?;
            (up, b.versioning, sse_r)
        };

        let deduped_parts = dedup_complete_parts(&req.parts)?;
        let mut total_size = 0u64;
        let mut combined_extents = Vec::new();
        let mut md5_concat = Vec::with_capacity(deduped_parts.len() * 16);
        let mut boundaries = Vec::with_capacity(deduped_parts.len());
        let mut part_csum_b64s = Vec::with_capacity(deduped_parts.len());
        let mut selected_pns = BTreeSet::new();

        let mut crc32_acc = 0u32;
        let mut crc32c_acc = 0u32;
        let mut crc64_acc = 0u64;

        for (idx, spec) in deduped_parts.iter().enumerate() {
            selected_pns.insert(spec.part_number);

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
            };

            let part_len = uploaded.size;
            let is_last = idx + 1 == deduped_parts.len();
            if !is_last && part_len < MIN_PART_SIZE_BYTES {
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

            if let Some((alg, b64_val)) = &uploaded.checksum {
                part_csum_b64s.push(b64_val.clone());
                if up.checksum_type == Some(ChecksumType::FullObject) {
                    match alg {
                        ChecksumAlgorithm::Crc32 => {
                            let c = decode_u32_be_b64(b64_val)?;
                            crc32_acc = if idx == 0 {
                                c
                            } else {
                                combine_crc32(crc32_acc, c, part_len)
                            };
                        }
                        ChecksumAlgorithm::Crc32c => {
                            let c = decode_u32_be_b64(b64_val)?;
                            crc32c_acc = if idx == 0 {
                                c
                            } else {
                                combine_crc32c(crc32c_acc, c, part_len)
                            };
                        }
                        ChecksumAlgorithm::Crc64Nvme => {}
                        ChecksumAlgorithm::Sha1
                        | ChecksumAlgorithm::Sha256
                        | ChecksumAlgorithm::Md5
                        | ChecksumAlgorithm::Sha512
                        | ChecksumAlgorithm::XxHash64
                        | ChecksumAlgorithm::XxHash3
                        | ChecksumAlgorithm::XxHash128 => {}
                    }
                }
            }

            crc64_acc = if idx == 0 {
                uploaded.crc64_nvme
            } else {
                combine_crc64_nvme(crc64_acc, uploaded.crc64_nvme, part_len)
            };

            total_size += part_len;
            combined_extents.extend(uploaded.extents.iter().copied());
            md5_concat.extend_from_slice(&uploaded.md5);
            boundaries.push(PartBoundaryInfo {
                part_number: uploaded.part_number,
                size: part_len,
                checksum: uploaded.checksum.clone(),
                sse_iv: uploaded.sse_iv,
            });
        }

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

        // [PR-25] Combine checksums mathematically WITHOUT re-reading part data!
        let final_checksum = match (up.checksum_algorithm, up.checksum_type) {
            (Some(alg), Some(ChecksumType::Composite)) => ChecksumState {
                algorithm: alg,
                checksum_type: ChecksumType::Composite,
                value_b64: compute_composite_checksum_b64(alg, &part_csum_b64s)?,
                client_requested: true,
            },
            (Some(ChecksumAlgorithm::Crc32), Some(ChecksumType::FullObject)) => ChecksumState {
                algorithm: ChecksumAlgorithm::Crc32,
                checksum_type: ChecksumType::FullObject,
                value_b64: encode_u32_be_b64(crc32_acc),
                client_requested: true,
            },
            (Some(ChecksumAlgorithm::Crc32c), Some(ChecksumType::FullObject)) => ChecksumState {
                algorithm: ChecksumAlgorithm::Crc32c,
                checksum_type: ChecksumType::FullObject,
                value_b64: encode_u32_be_b64(crc32c_acc),
                client_requested: true,
            },
            (Some(ChecksumAlgorithm::Crc64Nvme), Some(ChecksumType::FullObject)) => ChecksumState {
                algorithm: ChecksumAlgorithm::Crc64Nvme,
                checksum_type: ChecksumType::FullObject,
                value_b64: encode_u64_be_b64(crc64_acc),
                client_requested: true,
            },
            _ => ChecksumState {
                algorithm: ChecksumAlgorithm::Crc64Nvme,
                checksum_type: ChecksumType::FullObject,
                value_b64: encode_u64_be_b64(crc64_acc),
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

        // [FR-15, FR-17] Evaluate destination preconditions & lifecycle header at commit point
        let exp_hdr = {
            let cat = self.catalog.read().unwrap();
            let b = lookup_bucket_checked(&cat, &req.ctx, &req.bucket)?;
            let head = head_state_of(b.objects.get(&req.key));
            evaluate_write_preconditions(&req.preconditions, &req.bucket, &req.key, head)?;
            compute_x_amz_expiration(
                b.lifecycle.as_ref(),
                &req.key,
                total_size,
                &up.tags,
                req.ctx.request_time_ms,
            )
        };

        let seq = self.alloc_seq();
        let outer_md5: [u8; 16] = Md5::digest(&md5_concat).into();
        let etag = format!("\"{}-{}\"", hex::encode(outer_md5), deduped_parts.len());
        let version_id = match versioning {
            VersioningStatus::Unversioned => None,
            VersioningStatus::Suspended => Some("null".to_string()),
            VersioningStatus::Enabled => Some(format!("v{seq:016x}")),
        };

        let resp = CompleteMultipartUploadResp {
            bucket: req.bucket.clone(),
            key: req.key.clone(),
            etag: etag.clone(),
            version_id: version_id.clone(),
            checksum: final_checksum
                .client_requested
                .then(|| final_checksum.clone()),
            sse: sse_resp,
            expiration_header: exp_hdr,
        };

        let _cg = self
            .commit_wal(WalOp::CompleteMultipartUpload {
                bucket: req.bucket.clone(),
                key: req.key.clone(),
                upload_id: req.upload_id.clone(),
                seq,
                version_id: version_id.clone(),
                total_size,
                etag: etag.clone(),
                checksum: final_checksum.clone(),
                sys_meta: up.sys_meta.clone(),
                user_meta: up.user_meta.clone(),
                owner: up.owner.clone(),
                acl: up.acl.clone(),
                tags: up.tags.clone(),
                completed_ms: req.ctx.request_time_ms,
                extents: combined_extents.clone(),
                parts: boundaries.clone(),
                sse: up.sse,
                retention: up.retention,
                legal_hold: up.legal_hold,
                resp: resp.clone(),
            })
            .await?;

        let mut reclaimed = Vec::new();
        {
            let mut cat = self.catalog.write().unwrap();
            if seq > cat.next_seq {
                cat.next_seq = seq;
            }
            if let Some(b) = cat.buckets.get_mut(&req.bucket) {
                let entry = ObjectVersionEntry {
                    seq,
                    version_id,
                    is_delete_marker: false,
                    total_size,
                    etag,
                    checksum: final_checksum,
                    sys_meta: Arc::new(up.sys_meta),
                    user_meta: up.user_meta,
                    owner: Arc::new(up.owner),
                    acl: Arc::new(up.acl),
                    tags: up.tags,
                    last_modified_ms: req.ctx.request_time_ms,
                    extents: combined_extents.into(),
                    parts: Some(boundaries.into()),
                    sse: up.sse,
                    retention: up.retention,
                    legal_hold: up.legal_hold,
                };
                let chain = b.objects.entry(req.key.clone()).or_default();
                insert_version_chain(b.versioning, chain, entry, &mut reclaimed);
                if let Some(removed_up) = b.uploads.remove(&(req.key.clone(), req.upload_id.clone()))
                {
                    for (pn, p) in removed_up.parts {
                        if !selected_pns.contains(&pn) {
                            reclaimed.extend(p.extents.iter().copied());
                        }
                    }
                }
                b.completed_uploads
                    .insert((req.key, req.upload_id), (req.ctx.request_time_ms, resp.clone()));
            }
        }
        if !reclaimed.is_empty() {
            self.adjust_live_bytes(&[], &reclaimed);
        }
        drop(_cg);

        Ok(resp)
    }

    async fn abort_multipart_upload(&self, req: AbortMultipartUploadReq) -> StoreResult<()> {
        validate_object_key(&req.bucket, &req.key)?;
        self.check_writable(false)?;

        let _kl = self.key_stripe(&req.bucket, &req.key).lock().await;
        {
            let cat = self.catalog.read().unwrap();
            let b = lookup_bucket_checked(&cat, &req.ctx, &req.bucket)?;
            let Some(up) = b.uploads.get(&(req.key.clone(), req.upload_id.clone())) else {
                let view = b.auth_view(self.cfg.default_object_ownership);
                if authorize_object_action(
                    &view,
                    &req.ctx,
                    &req.key,
                    &[S3Action::AbortMultipartUpload],
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
                    S3Error::new(S3ErrorCode::AccessDenied, "Access Denied")
                        .with_bucket(&req.bucket),
                );
            };
            if !has_upload_perm(
                b,
                self.cfg.default_object_ownership,
                &req.key,
                up,
                &req.ctx,
                &[S3Action::AbortMultipartUpload],
                AclPermission::Write,
            ) {
                return Err(
                    S3Error::new(S3ErrorCode::AccessDenied, "Access Denied")
                        .with_bucket(&req.bucket),
                );
            }
        }

        let _cg = self
            .commit_wal(WalOp::AbortMultipartUpload {
                bucket: req.bucket.clone(),
                key: req.key.clone(),
                upload_id: req.upload_id.clone(),
            })
            .await?;

        let mut reclaimed = Vec::new();
        {
            let mut cat = self.catalog.write().unwrap();
            if let Some(b) = cat.buckets.get_mut(&req.bucket)
                && let Some(removed_up) = b.uploads.remove(&(req.key, req.upload_id)) {
                    for p in removed_up.parts.into_values() {
                        reclaimed.extend(p.extents.iter().copied());
                    }
                }
        }
        if !reclaimed.is_empty() {
            self.adjust_live_bytes(&[], &reclaimed);
        }
        drop(_cg);
        Ok(())
    }

    async fn list_parts(&self, req: ListPartsReq) -> StoreResult<ListPartsResp> {
        validate_object_key(&req.bucket, &req.key)?;
        let cat = self.catalog.read().unwrap();
        let b = lookup_bucket_checked(&cat, &req.ctx, &req.bucket)?;
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
                S3Error::new(S3ErrorCode::AccessDenied, "Access Denied")
                    .with_bucket(&req.bucket),
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
                S3Error::new(S3ErrorCode::AccessDenied, "Access Denied")
                    .with_bucket(&req.bucket),
            );
        }

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
                    size: p.size,
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
        let cat = self.catalog.read().unwrap();
        let extra = PolicyEvalExtra {
            prefix: Some(&req.prefix),
            delimiter: req.delimiter.as_deref(),
            ..Default::default()
        };
        let b = check_bucket_action(
            &cat,
            self.cfg.default_object_ownership,
            &req.ctx,
            &req.bucket,
            &[S3Action::ListBucketMultipartUploads],
            Some(AclPermission::Read),
            &extra,
        )?;
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
            let lower_key = if km.as_str() > req.prefix.as_str() {
                km.clone()
            } else {
                req.prefix.clone()
            };
            for ((key, uid), up) in b.uploads.range((lower_key, String::new())..) {
                if !key.starts_with(&req.prefix) {
                    break;
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
        let cat = self.catalog.read().unwrap();
        let extra = PolicyEvalExtra {
            prefix: Some(&req.prefix),
            delimiter: req.delimiter.as_deref(),
            ..Default::default()
        };
        let b = check_bucket_action(
            &cat,
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
        let mut last_item_key = None;

        for item in items {
            match item {
                MergedItem::Object(k, v) => {
                    last_item_key = Some(k.clone());
                    contents.push(ObjectListEntry {
                        key: k.clone(),
                        last_modified_ms: v.last_modified_ms,
                        etag: v.etag.clone(),
                        size: v.total_size,
                        owner: (*v.owner).clone(),
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
            max_keys,
            delimiter: req.delimiter,
            is_truncated,
            contents,
            common_prefixes,
        })
    }

    async fn list_objects_v2(&self, req: ListObjectsV2Req) -> StoreResult<ListObjectsV2Resp> {
        let cat = self.catalog.read().unwrap();
        let extra = PolicyEvalExtra {
            prefix: Some(&req.prefix),
            delimiter: req.delimiter.as_deref(),
            ..Default::default()
        };
        let b = check_bucket_action(
            &cat,
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
            (Some(a), Some(s)) => Some(if a > s { a.as_str() } else { s.as_str() }),
            (Some(a), None) => Some(a.as_str()),
            (None, Some(s)) => Some(s.as_str()),
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
        let mut last_item_key = None;

        for item in items {
            match item {
                MergedItem::Object(k, v) => {
                    last_item_key = Some(k.clone());
                    contents.push(ObjectListEntry {
                        key: k.clone(),
                        last_modified_ms: v.last_modified_ms,
                        etag: v.etag.clone(),
                        size: v.total_size,
                        owner: (*v.owner).clone(),
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
            max_keys,
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
        let cat = self.catalog.read().unwrap();
        let extra = PolicyEvalExtra {
            prefix: Some(&req.prefix),
            delimiter: req.delimiter.as_deref(),
            ..Default::default()
        };
        let b = check_bucket_action(
            &cat,
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

        let lower_key: &str = if km.as_str() > req.prefix.as_str() {
            km.as_str()
        } else {
            req.prefix.as_str()
        };
        'outer: for (key, chain) in b
            .objects
            .range::<str, _>((Bound::Included(lower_key), Bound::Unbounded))
        {
            if !key.starts_with(&req.prefix) {
                break 'outer;
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
                    size: v.total_size,
                    owner: (*v.owner).clone(),
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

impl<D: Disk> Engine<D> {
    fn adjust_live_bytes(&self, added: &[Extent], removed: &[Extent]) {
        let mgr = self.seg_mgr.lock().unwrap();
        for ext in added {
            if let Some(slot) = mgr.segments.get(&ext.seg_id) {
                slot.live_bytes
                    .fetch_add(ext.physical_bytes(), Ordering::AcqRel);
            }
        }
        for ext in removed {
            if let Some(slot) = mgr.segments.get(&ext.seg_id) {
                slot.live_bytes
                    .fetch_sub(ext.physical_bytes(), Ordering::AcqRel);
            }
        }
    }

    fn pin_extents(&self, extents: &[Extent]) -> StoreResult<BTreeMap<u32, SegmentPin<D>>> {
        let mgr = self.seg_mgr.lock().unwrap();
        let mut pins = BTreeMap::new();
        for ext in extents {
            if let std::collections::btree_map::Entry::Vacant(e) = pins.entry(ext.seg_id) {
                let slot = mgr.segments.get(&ext.seg_id).ok_or_else(|| {
                    S3Error::new(
                        S3ErrorCode::InternalError,
                        "Referenced segment missing from segment table",
                    )
                })?;
                e.insert(SegmentPin::acquire(slot));
            }
        }
        Ok(pins)
    }

    fn lookup_version_for_read<'a>(
        &self,
        b: &'a BucketEntry,
        bucket_name: &str,
        key: &str,
        version_id: Option<&str>,
    ) -> StoreResult<&'a ObjectVersionEntry> {
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
                let Some(v) = b.objects.get(key).and_then(|c| {
                    c.iter()
                        .find(|v| v.version_id.as_deref().unwrap_or("null") == vid)
                }) else {
                    return Err(S3Error::new(
                        S3ErrorCode::NoSuchVersion,
                        "The specified version does not exist.",
                    )
                    .with_key(bucket_name, key));
                };
                if v.is_delete_marker {
                    return Err(S3Error::new(
                        S3ErrorCode::MethodNotAllowed,
                        "The specified method is not allowed against this resource.",
                    )
                    .with_header("x-amz-delete-marker", "true")
                    .with_header("Allow", "DELETE"));
                }
                Ok(v)
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn lookup_version_for_op_checked<'a>(
        &self,
        b: &'a BucketEntry,
        ctx: &CallerContext,
        bucket_name: &str,
        key: &str,
        version_id: Option<&str>,
        actions: &[S3Action],
        acl_needed: Option<AclPermission>,
        req_tags: Option<&BTreeMap<String, String>>,
    ) -> StoreResult<&'a ObjectVersionEntry> {
        let view = b.auth_view(self.cfg.default_object_ownership);
        match self.lookup_version_for_read(b, bucket_name, key, version_id) {
            Ok(ver) => {
                let extra = PolicyEvalExtra {
                    existing_object_tags: Some(&ver.tags),
                    request_object_tags: req_tags,
                    ..Default::default()
                };
                let acl_grant = acl_needed.map(|perm| (&*ver.acl, perm));
                if !authorize_object_action(
                    &view,
                    ctx,
                    key,
                    actions,
                    Some(&*ver.owner),
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
        b: &'a BucketEntry,
        ctx: &CallerContext,
        bucket_name: &str,
        key: &str,
        version_id: Option<&str>,
    ) -> StoreResult<&'a ObjectVersionEntry> {
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
            Some(&*ver.owner),
            Some((&*ver.acl, AclPermission::Read)),
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
        need_reader: bool,
    ) -> StoreResult<(ObjectMetaSnapshot, EngineByteReader<D>)> {
        validate_object_key(&req.bucket, &req.key)?;
        if req.range.is_some() && req.part_number.is_some() {
            return Err(S3Error::new(
                S3ErrorCode::InvalidRequest,
                "Cannot specify both Range header and partNumber query parameter",
            ));
        }

        // Snapshot version metadata and pin segments while holding brief catalog read lock (8.6)
        let actions: &[S3Action] = if req.version_id.is_some() {
            &[S3Action::GetObjectVersion, S3Action::GetObject]
        } else {
            &[S3Action::GetObject]
        };
        let (ver, pins, exp_hdr) = {
            let cat = self.catalog.read().unwrap();
            let b = lookup_bucket_checked(&cat, &req.ctx, &req.bucket)?;
            let found = self
                .lookup_version_for_op_checked(
                    b,
                    &req.ctx,
                    &req.bucket,
                    &req.key,
                    req.version_id.as_deref(),
                    actions,
                    Some(AclPermission::Read),
                    None,
                )?
                .clone();

            let is_current = b
                .objects
                .get(&req.key)
                .and_then(|c| c.first())
                .is_some_and(|h| h.seq == found.seq);
            let exp_h = if is_current {
                compute_x_amz_expiration(
                    b.lifecycle.as_ref(),
                    &req.key,
                    found.total_size,
                    &found.tags,
                    found.last_modified_ms,
                )
            } else {
                None
            };

            let pins = if need_reader {
                self.pin_extents(&found.extents)?
            } else {
                BTreeMap::new()
            };
            (found, pins, exp_h)
        };

        let sse_read = validate_sse_read_or_part(&req.raw_sse)?;
        let total_size = ver.total_size;
        let mut part_specific_csum: Option<ChecksumState> = None;

        // Validate partNumber bounds BEFORE SSE-C key match (`test_multipart_sse_c_get_part`)
        let (start, end, is_partial, parts_count) = if let Some(pn) = req.part_number {
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
            UNIX_EPOCH + std::time::Duration::from_millis(ver.last_modified_ms.max(0) as u64),
        );
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

        let checksum = if part_specific_csum.is_some() {
            part_specific_csum
        } else if req.checksum_mode_enabled && req.range.is_none() && req.part_number.is_none() {
            Some(ver.checksum.clone())
        } else {
            None
        };

        let reader = if need_reader && content_len > 0 {
            EngineByteReader::new(pins, &ver.extents, ver.parts.as_deref(), key_iv, start, end)
        } else {
            EngineByteReader::empty()
        };

        let meta = ObjectMetaSnapshot {
            bucket: req.bucket.clone(),
            key: req.key.clone(),
            version_id: ver.version_id,
            is_delete_marker: false,
            total_object_size: total_size,
            content_length: content_len,
            content_range,
            etag: ver.etag,
            last_modified_ms: ver.last_modified_ms,
            owner: (*ver.owner).clone(),
            sys_meta: (*ver.sys_meta).clone(),
            user_meta: ver.user_meta,
            checksum,
            parts_count,
            tags_count: ver.tags.len(),
            sse: sse_resp,
            retention: ver.retention,
            legal_hold: ver.legal_hold,
            expiration_header: exp_hdr,
        };
        Ok((meta, reader))
    }

    /// Execute one crash-safe lifecycle evaluation sweep across all buckets (`PR-39` ~ `PR-40`).
    pub async fn run_lifecycle_tick(
        &self,
        now_ms: i64,
        lc_debug_interval_secs: Option<u64>,
    ) -> StoreResult<()> {
        if self.is_read_only_poisoned() {
            return Ok(());
        }
        let day_ms: i64 = lc_debug_interval_secs
            .map(|s| (s as i64).saturating_mul(1000))
            .unwrap_or(86_400_000);

        let buckets_with_lc: Vec<(String, LifecycleConfiguration)> = {
            let cat = self.catalog.read().unwrap();
            cat.buckets
                .iter()
                .filter_map(|(name, b)| b.lifecycle.as_ref().map(|lc| (name.clone(), lc.clone())))
                .collect()
        };

        for (bname, lc) in buckets_with_lc {
            // 1. Current version Expiration (Days / Date)
            let expired_currents: Vec<(String, u64)> = {
                let cat = self.catalog.read().unwrap();
                let Some(b) = cat.buckets.get(&bname) else {
                    continue;
                };
                let mut out = Vec::new();
                for (key, chain) in &b.objects {
                    let Some(head) = chain.first() else { continue };
                    if head.is_delete_marker {
                        continue;
                    }
                    let is_exp = lc.rules.iter().any(|rule| {
                        if rule.status != LifecycleRuleStatus::Enabled {
                            return false;
                        }
                        let Some(exp) = &rule.expiration else {
                            return false;
                        };
                        if !rule.matches_object(key, head.total_size, &head.tags) {
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
                        out.push((key.clone(), head.seq));
                    }
                }
                out
            };

            for (key, exp_head_seq) in expired_currents {
                let _kl = self.key_stripe(&bname, &key).lock().await;
                let action_opt = {
                    let cat = self.catalog.read().unwrap();
                    cat.buckets.get(&bname).and_then(|b| {
                        let head = b.objects.get(&key)?.first()?;
                        if head.seq != exp_head_seq || head.is_delete_marker {
                            return None;
                        }
                        Some((
                            b.versioning,
                            b.owner.clone(),
                            head.retention,
                            head.legal_hold,
                        ))
                    })
                };
                let Some((versioning, b_owner, retention, legal_hold)) = action_opt else {
                    continue;
                };

                match versioning {
                    VersioningStatus::Unversioned => {
                        if check_worm_version_delete(retention, legal_hold, false, false, now_ms)
                            .is_err()
                        {
                            continue;
                        }
                        let _cg = self
                            .commit_wal(WalOp::DeleteVersionBySeq {
                                bucket: bname.clone(),
                                key: key.clone(),
                                seq: exp_head_seq,
                            })
                            .await?;
                        let mut reclaimed = Vec::new();
                        {
                            let mut cat = self.catalog.write().unwrap();
                            if let Some(b) = cat.buckets.get_mut(&bname)
                                && let Some(chain) = b.objects.get_mut(&key)
                            {
                                chain.retain(|v| {
                                    if v.seq == exp_head_seq {
                                        reclaimed.extend(v.extents.iter().copied());
                                        false
                                    } else {
                                        true
                                    }
                                });
                                if chain.is_empty() {
                                    b.objects.remove(&key);
                                }
                            }
                        }
                        if !reclaimed.is_empty() {
                            self.adjust_live_bytes(&[], &reclaimed);
                        }
                        drop(_cg);
                    }
                    VersioningStatus::Enabled | VersioningStatus::Suspended => {
                        let seq = self.alloc_seq();
                        let vid = if versioning == VersioningStatus::Suspended {
                            "null".to_string()
                        } else {
                            format!("v{seq:016x}")
                        };
                        let dummy_csum = ChecksumState {
                            algorithm: ChecksumAlgorithm::Crc64Nvme,
                            checksum_type: ChecksumType::FullObject,
                            value_b64: String::new(),
                            client_requested: false,
                        };
                        let dm_acl = AccessControlPolicy::new_private(b_owner.clone());
                        let _cg = self
                            .commit_wal(WalOp::PutVersion {
                                bucket: bname.clone(),
                                key: key.clone(),
                                seq,
                                version_id: Some(vid.clone()),
                                is_delete_marker: true,
                                total_size: 0,
                                etag: String::new(),
                                checksum: dummy_csum.clone(),
                                sys_meta: SystemMeta::default(),
                                user_meta: Vec::new(),
                                owner: b_owner.clone(),
                                acl: dm_acl.clone(),
                                tags: BTreeMap::new(),
                                last_modified_ms: now_ms,
                                extents: Vec::new(),
                                parts: None,
                                sse: SseStoredMeta::None,
                                retention: None,
                                legal_hold: None,
                            })
                            .await?;
                        let mut reclaimed = Vec::new();
                        {
                            let mut cat = self.catalog.write().unwrap();
                            if seq > cat.next_seq {
                                cat.next_seq = seq;
                            }
                            if let Some(b) = cat.buckets.get_mut(&bname)
                                && let Some(chain) = b.objects.get_mut(&key)
                            {
                                if b.versioning == VersioningStatus::Suspended {
                                    chain.retain(|old| {
                                        if old.version_id.as_deref().unwrap_or("null") == "null" {
                                            reclaimed.extend(old.extents.iter().copied());
                                            false
                                        } else {
                                            true
                                        }
                                    });
                                }
                                chain.insert(
                                    0,
                                    ObjectVersionEntry {
                                        seq,
                                        version_id: Some(vid),
                                        is_delete_marker: true,
                                        total_size: 0,
                                        etag: String::new(),
                                        checksum: dummy_csum,
                                        sys_meta: Arc::new(SystemMeta::default()),
                                        user_meta: Vec::new(),
                                        owner: Arc::new(b_owner),
                                        acl: Arc::new(dm_acl),
                                        tags: BTreeMap::new(),
                                        last_modified_ms: now_ms,
                                        extents: Arc::new([]),
                                        parts: None,
                                        sse: SseStoredMeta::None,
                                        retention: None,
                                        legal_hold: None,
                                    },
                                );
                            }
                        }
                        if !reclaimed.is_empty() {
                            self.adjust_live_bytes(&[], &reclaimed);
                        }
                        drop(_cg);
                    }
                }
            }

            // 2. NoncurrentVersionExpiration
            let expired_noncurrents: Vec<(String, u64)> = {
                let cat = self.catalog.read().unwrap();
                let Some(b) = cat.buckets.get(&bname) else {
                    continue;
                };
                let mut out = Vec::new();
                for (key, chain) in &b.objects {
                    if chain.len() < 2 {
                        continue;
                    }
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
                        let should_del = lc.rules.iter().any(|rule| {
                            if rule.status != LifecycleRuleStatus::Enabled {
                                return false;
                            }
                            let Some(nc) = &rule.noncurrent_version_expiration else {
                                return false;
                            };
                            if !rule.matches_object(key, ver.total_size, &ver.tags) {
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
                            out.push((key.clone(), ver.seq));
                        }
                    }
                }
                out
            };

            for (key, del_seq) in expired_noncurrents {
                let _kl = self.key_stripe(&bname, &key).lock().await;
                let still_eligible = {
                    let cat = self.catalog.read().unwrap();
                    cat.buckets
                        .get(&bname)
                        .and_then(|b| b.objects.get(&key))
                        .and_then(|c| c.iter().skip(1).find(|v| v.seq == del_seq))
                        .is_some_and(|v| {
                            !v.is_delete_marker
                                && check_worm_version_delete(
                                    v.retention,
                                    v.legal_hold,
                                    false,
                                    false,
                                    now_ms,
                                )
                                .is_ok()
                        })
                };
                if !still_eligible {
                    continue;
                }
                let _cg = self
                    .commit_wal(WalOp::DeleteVersionBySeq {
                        bucket: bname.clone(),
                        key: key.clone(),
                        seq: del_seq,
                    })
                    .await?;
                let mut reclaimed = Vec::new();
                {
                    let mut cat = self.catalog.write().unwrap();
                    if let Some(b) = cat.buckets.get_mut(&bname)
                        && let Some(chain) = b.objects.get_mut(&key)
                    {
                        chain.retain(|v| {
                            if v.seq == del_seq {
                                reclaimed.extend(v.extents.iter().copied());
                                false
                            } else {
                                true
                            }
                        });
                        if chain.is_empty() {
                            b.objects.remove(&key);
                        }
                    }
                }
                if !reclaimed.is_empty() {
                    self.adjust_live_bytes(&[], &reclaimed);
                }
                drop(_cg);
            }

            // 3. ExpiredObjectDeleteMarker (runs after NoncurrentVersionExpiration in the same tick!)
            let expired_sole_dms: Vec<(String, u64)> = {
                let cat = self.catalog.read().unwrap();
                let Some(b) = cat.buckets.get(&bname) else {
                    continue;
                };
                let mut out = Vec::new();
                for (key, chain) in &b.objects {
                    if chain.len() == 1 && chain[0].is_delete_marker {
                        let remove_dm = lc.rules.iter().any(|rule| {
                            rule.status == LifecycleRuleStatus::Enabled
                                && rule
                                    .expiration
                                    .is_some_and(|e| e.expired_object_delete_marker == Some(true))
                                && rule.matches_key_without_tags_or_size(key)
                        });
                        if remove_dm {
                            out.push((key.clone(), chain[0].seq));
                        }
                    }
                }
                out
            };

            for (key, dm_seq) in expired_sole_dms {
                let _kl = self.key_stripe(&bname, &key).lock().await;
                let still_sole_dm = {
                    let cat = self.catalog.read().unwrap();
                    cat.buckets
                        .get(&bname)
                        .and_then(|b| b.objects.get(&key))
                        .is_some_and(|c| {
                            c.len() == 1 && c[0].is_delete_marker && c[0].seq == dm_seq
                        })
                };
                if !still_sole_dm {
                    continue;
                }
                let _cg = self
                    .commit_wal(WalOp::DeleteVersionBySeq {
                        bucket: bname.clone(),
                        key: key.clone(),
                        seq: dm_seq,
                    })
                    .await?;
                {
                    let mut cat = self.catalog.write().unwrap();
                    if let Some(b) = cat.buckets.get_mut(&bname)
                        && let Some(chain) = b.objects.get_mut(&key)
                    {
                        chain.retain(|v| v.seq != dm_seq);
                        if chain.is_empty() {
                            b.objects.remove(&key);
                        }
                    }
                }
                drop(_cg);
            }

            // 4. AbortIncompleteMultipartUpload
            let expired_uploads: Vec<(String, String)> = {
                let cat = self.catalog.read().unwrap();
                let Some(b) = cat.buckets.get(&bname) else {
                    continue;
                };
                b.uploads
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
                    .collect()
            };

            for (key, uid) in expired_uploads {
                let _kl = self.key_stripe(&bname, &key).lock().await;
                let still_open = {
                    let cat = self.catalog.read().unwrap();
                    cat.buckets
                        .get(&bname)
                        .is_some_and(|b| b.uploads.contains_key(&(key.clone(), uid.clone())))
                };
                if !still_open {
                    continue;
                }
                let _cg = self
                    .commit_wal(WalOp::AbortMultipartUpload {
                        bucket: bname.clone(),
                        key: key.clone(),
                        upload_id: uid.clone(),
                    })
                    .await?;
                let mut reclaimed = Vec::new();
                {
                    let mut cat = self.catalog.write().unwrap();
                    if let Some(b) = cat.buckets.get_mut(&bname)
                        && let Some(removed_up) = b.uploads.remove(&(key, uid))
                    {
                        for p in removed_up.parts.into_values() {
                            reclaimed.extend(p.extents.iter().copied());
                        }
                    }
                }
                if !reclaimed.is_empty() {
                    self.adjust_live_bytes(&[], &reclaimed);
                }
                drop(_cg);
            }
        }
        Ok(())
    }
}

// ---- Offline Integrity Checker (`s3d fsck`, NFR-13) ----

#[derive(Debug, Serialize)]
pub struct FsckReport {
    pub status: String,
    pub instance_uuid: String,
    pub checked_lsn: u64,
    pub buckets: usize,
    pub object_versions: usize,
    pub open_uploads: usize,
    pub segments_checked: usize,
    pub bytes_verified: u64,
    pub errors: Vec<String>,
}

pub fn run_fsck<D: Disk>(disk: D) -> FsckReport {
    let mut errors = Vec::new();
    let engine = match Engine::open(disk.clone(), EngineConfig::default()) {
        Ok(e) => e,
        Err(e) => {
            errors.push(format!("recovery/open failed: {e}"));
            return FsckReport {
                status: "corrupted".into(),
                instance_uuid: String::new(),
                checked_lsn: 0,
                buckets: 0,
                object_versions: 0,
                open_uploads: 0,
                segments_checked: 0,
                bytes_verified: 0,
                errors,
            };
        }
    };

    let instance_uuid = hex::encode(engine.format.instance_uuid);
    let sse_s3_cipher = Aes256Cipher::new(&derive_sse_s3_master_key(&engine.format.instance_uuid));

    // Verify ALL checkpoint files in `ckpt/` (including older ones if any exist)
    if let Ok(entries) = disk.read_dir("ckpt") {
        for name in entries {
            if let Some(hex_str) = name.strip_prefix("ckpt-")
                && hex_str.len() == 16
                    && let Ok(exp_lsn) = u64::from_str_radix(hex_str, 16) {
                        let rel = format!("ckpt/{name}");
                        match disk.open(&rel, OpenOpts::read_only()) {
                            Ok(f) => {
                                if let Err(msg) = read_checkpoint_from_file(
                                    &f,
                                    Some(exp_lsn),
                                    Some(engine.format.uuid_lo()),
                                ) {
                                    errors.push(format!("checkpoint {rel} corrupt: {msg}"));
                                }
                            }
                            Err(e) => errors.push(format!("checkpoint {rel} open failed: {e}")),
                        }
                    }
        }
    }

    let checked_lsn = engine.wal.lock().unwrap().synced_lsn;
    let segments_checked = engine.seg_mgr.lock().unwrap().segments.len();
    let mut object_versions = 0usize;
    let mut open_uploads = 0usize;
    let mut bytes_verified = 0u64;
    let mut seen_extents: BTreeSet<(u32, u64)> = BTreeSet::new();

    let cat = engine.catalog.read().unwrap();
    let buckets = cat.buckets.len();
    let mgr = engine.seg_mgr.lock().unwrap();

    for (bname, b) in &cat.buckets {
        open_uploads += b.uploads.len();
        for (key, chain) in &b.objects {
            for v in chain {
                object_versions += 1;
                if v.is_delete_marker {
                    continue;
                }

                // 1. Physical block verification (header + CRC32C + extent uniqueness + size)
                let mut actual_size = 0u64;
                let mut read_ok = true;
                for ext in v.extents.iter() {
                    if !seen_extents.insert((ext.seg_id, ext.offset)) {
                        errors.push(format!(
                            "{bname}/{key}: duplicate extent ownership seg {} off {}",
                            ext.seg_id, ext.offset
                        ));
                    }
                    let Some(slot) = mgr.segments.get(&ext.seg_id) else {
                        errors.push(format!("{bname}/{key}: missing segment {}", ext.seg_id));
                        read_ok = false;
                        continue;
                    };
                    let mut raw = vec![0u8; ext.physical_bytes() as usize];
                    if let Err(e) = slot.file.read_exact_at(ext.offset, &mut raw) {
                        errors.push(format!(
                            "{bname}/{key}: read error seg {} off {}: {e}",
                            ext.seg_id, ext.offset
                        ));
                        read_ok = false;
                        continue;
                    }
                    let hdr: [u8; 12] = raw[0..12].try_into().unwrap();
                    match decode_block_header(&hdr) {
                        Ok((len, crc)) => {
                            let payload = &raw[12..];
                            let calc = crc32c::crc32c(payload);
                            if len != ext.len || crc != ext.crc32c || calc != ext.crc32c {
                                errors.push(format!(
                                    "{bname}/{key}: block CRC mismatch seg {} off {}",
                                    ext.seg_id, ext.offset
                                ));
                                read_ok = false;
                            }
                            actual_size += payload.len() as u64;
                            bytes_verified += payload.len() as u64;
                        }
                        Err(msg) => {
                            errors.push(format!("{bname}/{key}: {msg}"));
                            read_ok = false;
                        }
                    }
                }
                if actual_size != v.total_size {
                    errors.push(format!(
                        "{bname}/{key}: size mismatch expected {}, got {}",
                        v.total_size, actual_size
                    ));
                    read_ok = false;
                }
                if let Some(parts) = &v.parts {
                    let parts_sum: u64 = parts.iter().map(|p| p.size).sum();
                    if parts_sum != v.total_size {
                        errors.push(format!(
                            "{bname}/{key}: multipart part sizes sum {parts_sum} != {}",
                            v.total_size
                        ));
                        read_ok = false;
                    }
                }

                // 2. Plaintext MD5 / ETag / Checksum verification
                // (SSE-C raw customer keys are NEVER stored on disk, so SSE-C skips plaintext hashing
                //  except composite checksum combination from stored per-part checksums.)
                let can_decrypt_plaintext = match v.sse {
                    SseStoredMeta::None | SseStoredMeta::SseS3 { .. } => true,
                    SseStoredMeta::SseC { .. } => false,
                };
                if read_ok && !can_decrypt_plaintext {
                    if !v.checksum.value_b64.is_empty()
                        && v.checksum.checksum_type == ChecksumType::Composite
                        && let Some(parts) = &v.parts
                    {
                        let part_b64s: Vec<String> = parts
                            .iter()
                            .filter_map(|p| p.checksum.as_ref().map(|(_, b64)| b64.clone()))
                            .collect();
                        match compute_composite_checksum_b64(v.checksum.algorithm, &part_b64s) {
                            Ok(calc_b64) if calc_b64 != v.checksum.value_b64 => {
                                errors.push(format!(
                                    "{bname}/{key}: composite {} checksum mismatch expected {}, got {}",
                                    v.checksum.algorithm.as_aws_str(),
                                    v.checksum.value_b64,
                                    calc_b64
                                ));
                            }
                            Err(e) => errors.push(format!(
                                "{bname}/{key}: composite checksum compute failed: {e}"
                            )),
                            Ok(_) => {}
                        }
                    }
                    continue;
                }

                if !read_ok {
                    continue;
                }

                let ver_iv_opt = match v.sse {
                    SseStoredMeta::None => None,
                    SseStoredMeta::SseS3 { iv } => Some(iv),
                    SseStoredMeta::SseC { .. } => unreachable!(),
                };
                let slices = build_extent_read_slices(
                    &v.extents,
                    v.parts.as_deref(),
                    ver_iv_opt,
                    0,
                    v.total_size,
                );

                let mut md5_h = Md5::new();
                let mut full_csum_h = ActiveHasher::new(v.checksum.algorithm);

                let mut mp_part_idx = 0usize;
                let mut mp_part_rem = v
                    .parts
                    .as_ref()
                    .and_then(|ps| ps.first())
                    .map(|p| p.size)
                    .unwrap_or(0);
                let mut mp_part_md5 = Md5::new();
                let mut mp_md5_concat: Vec<u8> = Vec::new();
                let mut mp_part_csum_h = v
                    .parts
                    .as_ref()
                    .and_then(|ps| ps.first())
                    .and_then(|p| p.checksum.as_ref())
                    .map(|(alg, _)| ActiveHasher::new(*alg));
                let mut mp_part_csum_b64s: Vec<String> = Vec::new();

                if let Some(parts) = &v.parts {
                    while mp_part_idx < parts.len() && mp_part_rem == 0 {
                        let p = &parts[mp_part_idx];
                        let d: [u8; 16] = std::mem::take(&mut mp_part_md5).finalize().into();
                        mp_md5_concat.extend_from_slice(&d);
                        if let Some((alg, ref exp_b64)) = p.checksum {
                            let calc_b64 = mp_part_csum_h
                                .take()
                                .unwrap_or_else(|| ActiveHasher::new(alg))
                                .finalize_b64();
                            if &calc_b64 != exp_b64 {
                                errors.push(format!(
                                    "{bname}/{key}: part {} checksum mismatch expected {exp_b64}, got {calc_b64}",
                                    p.part_number
                                ));
                            }
                            mp_part_csum_b64s.push(calc_b64);
                        }
                        mp_part_idx += 1;
                        if mp_part_idx < parts.len() {
                            mp_part_rem = parts[mp_part_idx].size;
                            mp_part_csum_h = parts[mp_part_idx]
                                .checksum
                                .as_ref()
                                .map(|(alg, _)| ActiveHasher::new(*alg));
                        }
                    }
                }

                let mut cached_ext: Option<(u32, u64)> = None;
                let mut raw_buf: Vec<u8> = Vec::new();
                let mut dec_buf: Vec<u8> = Vec::new();

                for rs in slices {
                    let ext = rs.ext;
                    if cached_ext != Some((ext.seg_id, ext.offset)) {
                        let slot = mgr.segments.get(&ext.seg_id).unwrap();
                        raw_buf.resize(ext.physical_bytes() as usize, 0);
                        slot.file.read_exact_at(ext.offset, &mut raw_buf).unwrap();
                        cached_ext = Some((ext.seg_id, ext.offset));
                    }
                    dec_buf.clear();
                    dec_buf.extend_from_slice(&raw_buf[(12 + rs.rel_s)..(12 + rs.rel_e)]);
                    if let Some((iv, ctr_off)) = rs.ctr {
                        aes256_ctr_xor_with_cipher(&sse_s3_cipher, &iv, ctr_off, &mut dec_buf);
                    }
                    let payload: &[u8] = &dec_buf;
                    md5_h.update(payload);
                    full_csum_h.update(payload);

                    if let Some(parts) = &v.parts {
                        let mut rem_slice = payload;
                        while !rem_slice.is_empty() && mp_part_idx < parts.len() {
                            let take = (mp_part_rem as usize).min(rem_slice.len());
                            let chunk = &rem_slice[..take];
                            rem_slice = &rem_slice[take..];
                            mp_part_md5.update(chunk);
                            if let Some(h) = &mut mp_part_csum_h {
                                h.update(chunk);
                            }
                            mp_part_rem -= take as u64;
                            while mp_part_idx < parts.len() && mp_part_rem == 0 {
                                let p = &parts[mp_part_idx];
                                let d: [u8; 16] =
                                    std::mem::take(&mut mp_part_md5).finalize().into();
                                mp_md5_concat.extend_from_slice(&d);
                                if let Some((alg, ref exp_b64)) = p.checksum {
                                    let calc_b64 = mp_part_csum_h
                                        .take()
                                        .unwrap_or_else(|| ActiveHasher::new(alg))
                                        .finalize_b64();
                                    if &calc_b64 != exp_b64 {
                                        errors.push(format!(
                                            "{bname}/{key}: part {} checksum mismatch expected {exp_b64}, got {calc_b64}",
                                            p.part_number
                                        ));
                                    }
                                    mp_part_csum_b64s.push(calc_b64);
                                }
                                mp_part_idx += 1;
                                if mp_part_idx < parts.len() {
                                    mp_part_rem = parts[mp_part_idx].size;
                                    mp_part_csum_h = parts[mp_part_idx]
                                        .checksum
                                        .as_ref()
                                        .map(|(alg, _)| ActiveHasher::new(*alg));
                                }
                            }
                        }
                    }
                }

                if let Some(parts) = &v.parts {
                    let outer_md5: [u8; 16] = Md5::digest(&mp_md5_concat).into();
                    let expected_etag = format!("\"{}-{}\"", hex::encode(outer_md5), parts.len());
                    if expected_etag != v.etag {
                        errors.push(format!(
                            "{bname}/{key}: multipart ETag mismatch expected {}, got {}",
                            v.etag, expected_etag
                        ));
                    }
                } else {
                    let expected_etag = format!("\"{}\"", hex::encode(md5_h.finalize()));
                    if expected_etag != v.etag {
                        errors.push(format!(
                            "{bname}/{key}: ETag mismatch expected {}, got {}",
                            v.etag, expected_etag
                        ));
                    }
                }

                if !v.checksum.value_b64.is_empty() {
                    match v.checksum.checksum_type {
                        ChecksumType::FullObject => {
                            let calc_b64 = full_csum_h.finalize_b64();
                            if calc_b64 != v.checksum.value_b64 {
                                errors.push(format!(
                                    "{bname}/{key}: full-object {} checksum mismatch expected {}, got {}",
                                    v.checksum.algorithm.as_aws_str(),
                                    v.checksum.value_b64,
                                    calc_b64
                                ));
                            }
                        }
                        ChecksumType::Composite => {
                            match compute_composite_checksum_b64(
                                v.checksum.algorithm,
                                &mp_part_csum_b64s,
                            ) {
                                Ok(calc_b64) if calc_b64 != v.checksum.value_b64 => {
                                    errors.push(format!(
                                        "{bname}/{key}: composite {} checksum mismatch expected {}, got {}",
                                        v.checksum.algorithm.as_aws_str(),
                                        v.checksum.value_b64,
                                        calc_b64
                                    ));
                                }
                                Err(e) => errors.push(format!(
                                    "{bname}/{key}: composite checksum compute failed: {e}"
                                )),
                                Ok(_) => {}
                            }
                        }
                    }
                }
            }
        }

        for ((key, uid), up) in &b.uploads {
            for p in up.parts.values() {
                let mut part_bytes = 0u64;
                let mut part_md5 = Md5::new();
                let mut part_csum_h = p.checksum.as_ref().map(|(alg, _)| ActiveHasher::new(*alg));
                let mut read_ok = true;
                let part_sse_s3_iv = match up.sse {
                    SseStoredMeta::SseS3 { iv } => Some(p.sse_iv.unwrap_or(iv)),
                    _ => None,
                };
                let can_verify_plain = !matches!(up.sse, SseStoredMeta::SseC { .. });
                let mut plain_off = 0u64;

                for ext in p.extents.iter() {
                    if !seen_extents.insert((ext.seg_id, ext.offset)) {
                        errors.push(format!(
                            "{bname}/{key} upload {uid} part {}: duplicate extent seg {} off {}",
                            p.part_number, ext.seg_id, ext.offset
                        ));
                    }
                    let Some(slot) = mgr.segments.get(&ext.seg_id) else {
                        errors.push(format!(
                            "{bname}/{key} upload {uid} part {}: missing segment {}",
                            p.part_number, ext.seg_id
                        ));
                        read_ok = false;
                        continue;
                    };
                    let mut raw = vec![0u8; ext.physical_bytes() as usize];
                    if let Err(e) = slot.file.read_exact_at(ext.offset, &mut raw) {
                        errors.push(format!(
                            "{bname}/{key} upload {uid} part {}: read error: {e}",
                            p.part_number
                        ));
                        read_ok = false;
                        continue;
                    }
                    let hdr: [u8; 12] = raw[0..12].try_into().unwrap();
                    match decode_block_header(&hdr) {
                        Ok((len, crc)) => {
                            let payload = &mut raw[12..];
                            if len != ext.len
                                || crc != ext.crc32c
                                || crc32c::crc32c(payload) != ext.crc32c
                            {
                                errors.push(format!(
                                    "{bname}/{key} upload {uid} part {}: block CRC mismatch",
                                    p.part_number
                                ));
                                read_ok = false;
                            }
                            if can_verify_plain {
                                if let Some(piv) = part_sse_s3_iv {
                                    aes256_ctr_xor_with_cipher(
                                        &sse_s3_cipher,
                                        &piv,
                                        plain_off,
                                        payload,
                                    );
                                }
                                part_md5.update(&*payload);
                                if let Some(h) = &mut part_csum_h {
                                    h.update(&*payload);
                                }
                            }
                            plain_off += payload.len() as u64;
                            part_bytes += payload.len() as u64;
                            bytes_verified += payload.len() as u64;
                        }
                        Err(msg) => {
                            errors.push(format!(
                                "{bname}/{key} upload {uid} part {}: {msg}",
                                p.part_number
                            ));
                            read_ok = false;
                        }
                    }
                }
                if part_bytes != p.size {
                    errors.push(format!(
                        "{bname}/{key} upload {uid} part {}: size mismatch expected {}, got {part_bytes}",
                        p.part_number, p.size
                    ));
                } else if read_ok && can_verify_plain {
                    let md5_arr: [u8; 16] = part_md5.finalize().into();
                    if md5_arr != p.md5 {
                        errors.push(format!(
                            "{bname}/{key} upload {uid} part {}: MD5 mismatch",
                            p.part_number
                        ));
                    }
                    if let Some((_, ref exp_b64)) = p.checksum
                        && let Some(h) = part_csum_h {
                            let calc = h.finalize_b64();
                            if &calc != exp_b64 {
                                errors.push(format!(
                                    "{bname}/{key} upload {uid} part {}: checksum mismatch expected {exp_b64}, got {calc}",
                                    p.part_number
                                ));
                            }
                        }
                }
            }
        }
    }

    FsckReport {
        status: if errors.is_empty() {
            "ok".into()
        } else {
            "corrupted".into()
        },
        instance_uuid,
        checked_lsn,
        buckets,
        object_versions,
        open_uploads,
        segments_checked,
        bytes_verified,
        errors,
    }
}
