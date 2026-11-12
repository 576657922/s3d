//! Crash-safe log-structured object storage engine (`s3d-engine`).

pub mod catalog;
mod checksum_util;
pub mod format;

use std::collections::{BTreeMap, BTreeSet};
use std::future::poll_fn;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use bytes::BytesMut;
use md5::{Digest as _, Md5};
use rand::RngCore;
use serde::Serialize;
use s3d_disk::{Disk, DiskError, DiskFile, OpenOpts};
use s3d_types::*;
use thiserror::Error;
use tracing::{error, warn};

use crate::catalog::{
    BucketEntry, EngineByteReader, MemoryCatalog, MultipartUploadEntry, ObjectVersionEntry,
    SegmentPin, SegmentSlot, UploadPartEntry, SEG_STATE_ACTIVE, SEG_STATE_PENDING_DELETE,
    SEG_STATE_SEALED,
};
use crate::checksum_util::{
    combine_crc32, combine_crc32c, combine_crc64_nvme, compute_composite_checksum_b64,
    decode_u32_be_b64, encode_u32_be_b64, encode_u64_be_b64, ActiveHasher,
};
use crate::format::*;

const KEY_LOCK_STRIPES: usize = 256;

#[derive(Debug, Clone)]
pub struct EngineConfig {
    pub region: String,
    pub segment_size: u64,
    pub wal_file_size: u64,
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
}

#[derive(Default)]
struct GroupCommitQueue {
    leader_active: bool,
    pending: Vec<(WalOp, tokio::sync::oneshot::Sender<StoreResult<u64>>)>,
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
    _lock_guard: Box<dyn Send + Sync>,
    read_only_poisoned: AtomicBool,
    next_seq: AtomicU64,
    catalog: RwLock<MemoryCatalog>,
    seg_mgr: Mutex<SegmentManager<D>>,
    wal: Mutex<WalWriterState<D>>,
    group_commit_queue: Mutex<GroupCommitQueue>,
    key_locks: Vec<tokio::sync::Mutex<()>>,
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

        // 4. Replay WAL files in ascending order
        let mut wal_files: Vec<(u32, String)> = Vec::new();
        for name in disk.read_dir("wal")? {
            if let Some(stem) = name.strip_suffix(".log") {
                if let Ok(seq) = stem.parse::<u32>() {
                    wal_files.push((seq, format!("wal/{name}")));
                }
            }
        }
        wal_files.sort_by_key(|(seq, _)| *seq);

        let mut catalog = MemoryCatalog::default();
        let mut expected_lsn = 1u64;
        let mut deleted_segments: BTreeSet<u32> = BTreeSet::new();
        let mut created_segments: BTreeSet<u32> = BTreeSet::new();
        let mut last_wal_state: Option<(u32, u64)> = None;

        let total_wals = wal_files.len();
        for (idx, (wal_seq, rel_path)) in wal_files.into_iter().enumerate() {
            let is_last_wal = idx + 1 == total_wals;
            let f = disk.open(&rel_path, OpenOpts::open_rw())?;
            let file_len = f.len()?;
            if file_len < WAL_HEADER_LEN {
                if is_last_wal {
                    // Unfinished rollover at tail: discard empty/torn new WAL file
                    drop(f);
                    disk.remove_file(&rel_path)?;
                    disk.sync_dir("wal")?;
                    break;
                } else {
                    return Err(EngineOpenError::Corrupt(format!(
                        "{rel_path} truncated header in non-final WAL"
                    )));
                }
            }

            let mut raw = vec![0u8; file_len as usize];
            f.read_exact_at(0, &mut raw)?;
            let hdr: [u8; 32] = raw[0..32].try_into().unwrap();
            let first_lsn = match decode_wal_header(&hdr, wal_seq, format.uuid_lo()) {
                Ok(lsn) => lsn,
                Err(msg) => {
                    if is_last_wal && idx > 0 {
                        drop(f);
                        disk.remove_file(&rel_path)?;
                        disk.sync_dir("wal")?;
                        break;
                    }
                    return Err(EngineOpenError::Corrupt(msg));
                }
            };

            if first_lsn != expected_lsn {
                return Err(EngineOpenError::Corrupt(format!(
                    "{rel_path}: expected first_lsn {expected_lsn}, got {first_lsn}"
                )));
            }

            let mut pos = WAL_HEADER_LEN as usize;
            while pos < raw.len() {
                match decode_wal_record(&raw[pos..]) {
                    Ok(rec) => {
                        if rec.lsn != expected_lsn {
                            if is_last_wal
                                && !has_later_committed_record(&raw[pos..], expected_lsn)
                            {
                                warn!(
                                    rel_path,
                                    pos,
                                    expected_lsn,
                                    got_lsn = rec.lsn,
                                    "truncating out-of-order un-synced WAL tail (ST-6)"
                                );
                                f.set_len(pos as u64)?;
                                f.sync_data()?;
                                break;
                            }
                            return Err(EngineOpenError::Corrupt(format!(
                                "{rel_path}@{pos}: LSN gap expected {expected_lsn}, got {}",
                                rec.lsn
                            )));
                        }
                        apply_wal_op(
                            &mut catalog,
                            &mut created_segments,
                            &mut deleted_segments,
                            rec.op,
                        );
                        expected_lsn += 1;
                        pos += rec.total_frame_bytes;
                    }
                    Err(_err) => {
                        // [ST-6] Distinguish torn tail vs mid-WAL corruption!
                        if is_last_wal && !has_later_committed_record(&raw[pos..], expected_lsn) {
                            warn!(
                                rel_path,
                                pos,
                                expected_lsn,
                                "truncating torn WAL tail at un-synced boundary (ST-6)"
                            );
                            f.set_len(pos as u64)?;
                            f.sync_data()?;
                            break;
                        } else {
                            return Err(EngineOpenError::Corrupt(format!(
                                "{rel_path}@{pos}: mid-WAL corruption detected at LSN {expected_lsn}"
                            )));
                        }
                    }
                }
            }
            last_wal_state = Some((wal_seq, pos as u64));
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
                }
            }
            None => {
                let wal_seq = 1u32;
                let path = format!("wal/{wal_seq:08}.log");
                let f = disk.open(&path, OpenOpts::create_truncate_rw())?;
                let hdr = encode_wal_header(wal_seq, 1, format.uuid_lo());
                f.write_all_at(0, &hdr)?;
                f.sync_data()?;
                disk.sync_dir("wal")?;
                WalWriterState {
                    wal_seq,
                    file: f,
                    write_pos: WAL_HEADER_LEN,
                    next_lsn: 1,
                    synced_lsn: 0,
                }
            }
        };

        // 5. Reconcile segment files & verify referenced extents (both objects AND active uploads!)
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
        let mut max_seg_id = 0u32;

        for name in disk.read_dir("seg")? {
            if let Some(stem) = name.strip_suffix(".seg") {
                if let Ok(seg_id) = stem.parse::<u32>() {
                    if deleted_segments.contains(&seg_id) {
                        // [ST-7] Finish interrupted segment deletion recorded in WAL
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
                            active_readers: AtomicUsize::new(0),
                            state: AtomicU8::new(SEG_STATE_SEALED),
                        }),
                    );
                }
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
            let seg_id = 1u32;
            let slot = create_segment_slot(&disk, seg_id, format.uuid_lo())?;
            max_seg_id = seg_id;
            segments.insert(seg_id, slot);
            seg_id
        };

        let key_locks = (0..KEY_LOCK_STRIPES)
            .map(|_| tokio::sync::Mutex::new(()))
            .collect();

        let initial_next_seq = catalog.next_seq + 1;

        Ok(Arc::new(Self {
            disk,
            cfg,
            format,
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
            key_locks,
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

    /// Write a single framed data block (`<= max_block_payload`) into the active segment.
    fn write_data_block(&self, payload: &[u8]) -> StoreResult<(Extent, Arc<SegmentSlot<D>>)> {
        let payload_len = payload.len() as u32;
        let payload_crc = crc32c::crc32c(payload);
        let hdr = encode_block_header(payload_len, payload_crc);
        let frame_len = BLOCK_HEADER_LEN + payload_len as u64;

        let (slot, offset) = {
            let mut mgr = self.seg_mgr.lock().unwrap();
            let cur_id = mgr.active_seg_id;
            let cur_slot = Arc::clone(mgr.segments.get(&cur_id).unwrap());
            let cur_pos = cur_slot.write_pos.load(Ordering::SeqCst);

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
            }
        };

        let mut frame = Vec::with_capacity(frame_len as usize);
        frame.extend_from_slice(&hdr);
        frame.extend_from_slice(payload);
        slot.file.write_all_at(offset, &frame).map_err(|e| {
            error!(seg_id = slot.seg_id, offset, ?e, "segment write failed");
            S3Error::new(S3ErrorCode::InternalError, "Disk write error")
        })?;

        Ok((
            Extent {
                seg_id: slot.seg_id,
                offset,
                len: payload_len,
                crc32c: payload_crc,
            },
            slot,
        ))
    }

    /// Flush a batch of WAL operations in a single `write_all_at` + `sync_data` (`fdatasync`).
    /// On `EIO`, immediately poisons read-only WITHOUT updating `synced_lsn` or catalog (§10).
    fn flush_wal_batch(&self, ops: &[WalOp]) -> Vec<StoreResult<u64>> {
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
        let mut wal = self.wal.lock().unwrap();
        if self.is_read_only_poisoned() {
            let err = S3Error::new(
                S3ErrorCode::InternalError,
                "Storage engine is in read-only failed state.",
            );
            return vec![Err(err); ops.len()];
        }

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
        if let Err(e) = wal.file.sync_data() {
            let err = self.poison_read_only("wal_fdatasync", e);
            return vec![Err(err); ops.len()];
        }

        let last_lsn = *lsns.last().unwrap();
        wal.write_pos += encoded.len() as u64;
        wal.next_lsn = last_lsn + 1;
        wal.synced_lsn = last_lsn;
        lsns.into_iter().map(Ok).collect()
    }

    fn drain_pending_group_commits_sync(&self) {
        let max_batch = self.cfg.group_commit_max_batch.max(1);
        loop {
            let chunk: Vec<(WalOp, tokio::sync::oneshot::Sender<StoreResult<u64>>)> = {
                let mut q = self.group_commit_queue.lock().unwrap();
                if q.pending.is_empty() {
                    q.leader_active = false;
                    return;
                }
                let take = q.pending.len().min(max_batch);
                q.pending.drain(..take).collect()
            };
            let ops: Vec<WalOp> = chunk.iter().map(|(op, _)| op.clone()).collect();
            let results = self.flush_wal_batch(&ops);
            for ((_, tx), res) in chunk.into_iter().zip(results) {
                let _ = tx.send(res);
            }
        }
    }

    /// Group-Commit WAL append + `fdatasync` (§8.3). Concurrent callers batch into a single `fdatasync`.
    async fn commit_wal(&self, op: WalOp) -> StoreResult<u64> {
        if self.is_read_only_poisoned() {
            return Err(S3Error::new(
                S3ErrorCode::InternalError,
                "Storage engine is in read-only failed state.",
            ));
        }

        let follower_rx = {
            let mut q = self.group_commit_queue.lock().unwrap();
            if q.leader_active {
                let (tx, rx) = tokio::sync::oneshot::channel();
                q.pending.push((op.clone(), tx));
                Some(rx)
            } else {
                q.leader_active = true;
                None
            }
        };

        if let Some(rx) = follower_rx {
            return rx.await.unwrap_or_else(|_| {
                Err(S3Error::new(
                    S3ErrorCode::InternalError,
                    "Group commit channel closed",
                ))
            });
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

        if self.cfg.group_commit_window_ms > 0 {
            tokio::time::sleep(Duration::from_millis(self.cfg.group_commit_window_ms)).await;
        } else {
            tokio::task::yield_now().await;
        }

        let max_followers = self.cfg.group_commit_max_batch.max(1).saturating_sub(1);
        let followers: Vec<(WalOp, tokio::sync::oneshot::Sender<StoreResult<u64>>)> = {
            let mut q = self.group_commit_queue.lock().unwrap();
            let take = q.pending.len().min(max_followers);
            q.pending.drain(..take).collect()
        };

        let mut batch_ops = Vec::with_capacity(1 + followers.len());
        batch_ops.push(op);
        for (fop, _) in &followers {
            batch_ops.push(fop.clone());
        }

        let mut results = self.flush_wal_batch(&batch_ops);
        let my_res = results.remove(0);
        for ((_, tx), res) in followers.into_iter().zip(results) {
            let _ = tx.send(res);
        }

        self.drain_pending_group_commits_sync();
        guard.disarmed = true;
        my_res
    }

    /// Trigger online segment compaction / GC (`s3d compact`, §8.5).
    pub async fn compact(&self) -> StoreResult<usize> {
        self.check_writable(false)?;
        let candidates: Vec<Arc<SegmentSlot<D>>> = {
            let mgr = self.seg_mgr.lock().unwrap();
            mgr.segments
                .values()
                .filter(|s| {
                    if s.state.load(Ordering::Acquire) != SEG_STATE_SEALED {
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

            let mut touched_new_slots: BTreeMap<u32, Arc<SegmentSlot<D>>> = BTreeMap::new();
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
                let (new_ext, new_slot) = self.write_data_block(payload)?;
                touched_new_slots.insert(new_slot.seg_id, new_slot);
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
                let (new_ext, new_slot) = self.write_data_block(payload)?;
                touched_new_slots.insert(new_slot.seg_id, new_slot);
                copied_part.push((bname, key, uid, pn, pseq, eidx, ext, new_ext));
            }

            for slot in touched_new_slots.values() {
                slot.file
                    .sync_data()
                    .map_err(|e| self.poison_read_only("gc_seg_sync", e))?;
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
                    self.commit_wal(WalOp::RelocateExtents {
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
                        ns.live_bytes
                            .fetch_add(new_ext.physical_bytes(), Ordering::AcqRel);
                    }
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
                    self.commit_wal(WalOp::RelocateExtents {
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
                        ns.live_bytes
                            .fetch_add(new_ext.physical_bytes(), Ordering::AcqRel);
                    }
                }
            }

            if old_slot.live_bytes.load(Ordering::Acquire) == 0 {
                // [ST-7] Record deletion intent in WAL BEFORE unlinking file!
                self.commit_wal(WalOp::DeleteSegment { seg_id: old_id })
                    .await?;
                old_slot
                    .state
                    .store(SEG_STATE_PENDING_DELETE, Ordering::Release);
                {
                    let mut mgr = self.seg_mgr.lock().unwrap();
                    mgr.segments.remove(&old_id);
                }
                old_slot.try_reclaim_if_unpinned();
                compacted += 1;
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
        active_readers: std::sync::atomic::AtomicUsize::new(0),
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
        } => {
            catalog.buckets.insert(
                name.clone(),
                BucketEntry {
                    name,
                    owner,
                    acl,
                    region,
                    created_ms,
                    versioning: VersioningStatus::Unversioned,
                    explicit_ownership,
                    tags: BTreeMap::new(),
                    cors: None,
                    policy: None,
                    public_access_block: None,
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
                    sys_meta,
                    user_meta,
                    owner,
                    acl,
                    tags,
                    last_modified_ms,
                    extents: extents.into(),
                    parts: parts.map(Into::into),
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
                v.acl = acl;
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
                    sys_meta,
                    user_meta,
                    owner,
                    acl,
                    tags,
                    last_modified_ms: completed_ms,
                    extents: extents.into(),
                    parts: Some(parts.into()),
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
                {
                    if let Some(cur) = v.extents.get(item.extent_idx) {
                        if cur.seg_id == item.old_seg_id && cur.offset == item.old_offset {
                            let mut exts = v.extents.to_vec();
                            exts[item.extent_idx] = item.new_extent;
                            v.extents = exts.into();
                        }
                    }
                }
            }
            for pitem in part_items {
                if let Some(p) = catalog
                    .buckets
                    .get_mut(&pitem.bucket)
                    .and_then(|b| b.uploads.get_mut(&(pitem.key, pitem.upload_id)))
                    .and_then(|up| up.parts.get_mut(&pitem.part_number))
                    .filter(|p| p.part_seq == pitem.part_seq)
                {
                    if let Some(cur) = p.extents.get(pitem.extent_idx) {
                        if cur.seg_id == pitem.old_seg_id && cur.offset == pitem.old_offset {
                            let mut exts = p.extents.to_vec();
                            exts[pitem.extent_idx] = pitem.new_extent;
                            p.extents = exts.into();
                        }
                    }
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
    if let Some(expected) = &ctx.expected_bucket_owner {
        if expected != &b.owner.user_id {
            return Err(S3Error::new(S3ErrorCode::AccessDenied, "Access Denied")
                .with_bucket(bucket_name));
        }
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
    if req_tags.is_some_and(|t| !t.is_empty()) {
        if let Some(pol) = view.policy {
            let arn = format!("arn:aws:s3:::{bucket_name}/{key}");
            if pol.evaluate(ctx, &[S3Action::PutObjectTagging], &arn, &extra)
                == PolicyDecision::ExplicitDeny
            {
                return Err(S3Error::new(S3ErrorCode::AccessDenied, "Access Denied")
                    .with_key(bucket_name, key));
            }
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

fn encode_token(bucket: &str, key: &str) -> String {
    let raw = format!("v1:{bucket}:{key}");
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw.as_bytes())
}

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

enum MergedItem<'a> {
    Object(&'a String, &'a ObjectVersionEntry),
    CommonPrefix(String),
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

fn strip_etag_quotes(s: &str) -> &str {
    s.trim().trim_matches('"')
}

impl<D: Disk> ObjectStore for Engine<D> {
    type Reader = EngineByteReader<D>;

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

        if let Some(loc) = &req.location_constraint {
            if !loc.is_empty() && loc != &self.cfg.region {
                return Err(S3Error::new(
                    S3ErrorCode::InvalidLocationConstraint,
                    "The specified location-constraint is not valid",
                )
                .with_bucket(&req.bucket));
            }
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
            if let Some(spec) = &req.acl {
                if !matches!(spec, AclSpec::Canned(CannedAcl::Private)) {
                    return Err(S3Error::new(
                        S3ErrorCode::InvalidBucketAclWithObjectOwnership,
                        "Bucket cannot have ACLs set with ObjectOwnership's BucketOwnerEnforced setting",
                    )
                    .with_bucket(&req.bucket));
                }
            }
            AccessControlPolicy::new_private(caller.clone())
        } else {
            match &req.acl {
                None => AccessControlPolicy::new_private(caller.clone()),
                Some(spec) => resolve_target_acl(&caller, Some(&caller), spec)?,
            }
        };

        let op = WalOp::CreateBucket {
            name: req.bucket.clone(),
            owner: caller.clone(),
            acl: acl.clone(),
            region: self.cfg.region.clone(),
            created_ms: req.ctx.request_time_ms,
            explicit_ownership,
        };
        self.commit_wal(op).await?;

        let mut cat = self.catalog.write().unwrap();
        cat.buckets.insert(
            req.bucket.clone(),
            BucketEntry {
                name: req.bucket.clone(),
                owner: caller.clone(),
                acl,
                region: self.cfg.region.clone(),
                created_ms: req.ctx.request_time_ms,
                versioning: VersioningStatus::Unversioned,
                explicit_ownership,
                tags: BTreeMap::new(),
                cors: None,
                policy: None,
                public_access_block: None,
                objects: BTreeMap::new(),
                uploads: BTreeMap::new(),
                completed_uploads: BTreeMap::new(),
            },
        );

        Ok(BucketMetaSnapshot {
            name: req.bucket,
            owner: caller,
            region: self.cfg.region.clone(),
            created_ms: req.ctx.request_time_ms,
            versioning: VersioningStatus::Unversioned,
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
        self.commit_wal(WalOp::DeleteBucket {
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
            let _ = check_bucket_action(
                &cat,
                self.cfg.default_object_ownership,
                &req.ctx,
                &req.bucket,
                &[S3Action::PutBucketVersioning],
                None,
                &PolicyEvalExtra::default(),
            )?;
        }
        self.commit_wal(WalOp::UpdateBucketVersioning {
            name: req.bucket.clone(),
            versioning: req.status,
        })
        .await?;
        let mut cat = self.catalog.write().unwrap();
        if let Some(b) = cat.buckets.get_mut(&req.bucket) {
            b.versioning = req.status;
        }
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
        self.commit_wal(WalOp::UpdateBucketAcl {
            name: req.bucket.clone(),
            acl: new_acl.clone(),
        })
        .await?;
        let mut cat = self.catalog.write().unwrap();
        if let Some(b) = cat.buckets.get_mut(&req.bucket) {
            b.acl = new_acl;
        }
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
            policy: ver.acl.clone(),
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

        self.commit_wal(WalOp::UpdateObjectAcl {
            bucket: req.bucket.clone(),
            key: req.key.clone(),
            seq: target_seq,
            acl: new_acl.clone(),
        })
        .await?;

        let mut cat = self.catalog.write().unwrap();
        if let Some(v) = cat
            .buckets
            .get_mut(&req.bucket)
            .and_then(|b| b.objects.get_mut(&req.key))
            .and_then(|c| c.iter_mut().find(|v| v.seq == target_seq))
        {
            v.acl = new_acl;
        }
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
        self.commit_wal(WalOp::UpdateBucketOwnershipControls {
            name: req.bucket.clone(),
            ownership: Some(req.ownership),
        })
        .await?;
        let mut cat = self.catalog.write().unwrap();
        if let Some(b) = cat.buckets.get_mut(&req.bucket) {
            b.explicit_ownership = Some(req.ownership);
        }
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
        self.commit_wal(WalOp::UpdateBucketOwnershipControls {
            name: req.bucket.clone(),
            ownership: None,
        })
        .await?;
        let mut cat = self.catalog.write().unwrap();
        if let Some(b) = cat.buckets.get_mut(&req.bucket) {
            b.explicit_ownership = None;
        }
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
        self.commit_wal(WalOp::UpdateBucketTagging {
            name: req.bucket.clone(),
            tags: req.tags.clone(),
        })
        .await?;
        let mut cat = self.catalog.write().unwrap();
        if let Some(b) = cat.buckets.get_mut(&req.bucket) {
            b.tags = req.tags;
        }
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
        self.commit_wal(WalOp::UpdateBucketTagging {
            name: req.bucket.clone(),
            tags: BTreeMap::new(),
        })
        .await?;
        let mut cat = self.catalog.write().unwrap();
        if let Some(b) = cat.buckets.get_mut(&req.bucket) {
            b.tags.clear();
        }
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
        self.commit_wal(WalOp::UpdateObjectTagging {
            bucket: req.bucket.clone(),
            key: req.key.clone(),
            seq: target_seq,
            tags: req.tags.clone(),
        })
        .await?;
        let mut cat = self.catalog.write().unwrap();
        if let Some(v) = cat
            .buckets
            .get_mut(&req.bucket)
            .and_then(|b| b.objects.get_mut(&req.key))
            .and_then(|c| c.iter_mut().find(|v| v.seq == target_seq))
        {
            v.tags = req.tags;
        }
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
        self.commit_wal(WalOp::UpdateObjectTagging {
            bucket: req.bucket.clone(),
            key: req.key.clone(),
            seq: target_seq,
            tags: BTreeMap::new(),
        })
        .await?;
        let mut cat = self.catalog.write().unwrap();
        if let Some(v) = cat
            .buckets
            .get_mut(&req.bucket)
            .and_then(|b| b.objects.get_mut(&req.key))
            .and_then(|c| c.iter_mut().find(|v| v.seq == target_seq))
        {
            v.tags.clear();
        }
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
        self.commit_wal(WalOp::UpdateBucketCors {
            name: req.bucket.clone(),
            cors: Some(req.cors.clone()),
        })
        .await?;
        let mut cat = self.catalog.write().unwrap();
        if let Some(b) = cat.buckets.get_mut(&req.bucket) {
            b.cors = Some(req.cors);
        }
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
        self.commit_wal(WalOp::UpdateBucketCors {
            name: req.bucket.clone(),
            cors: None,
        })
        .await?;
        let mut cat = self.catalog.write().unwrap();
        if let Some(b) = cat.buckets.get_mut(&req.bucket) {
            b.cors = None;
        }
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
        self.commit_wal(WalOp::UpdateBucketPolicy {
            name: req.bucket.clone(),
            policy_json: Some(req.policy_json),
        })
        .await?;
        let mut cat = self.catalog.write().unwrap();
        if let Some(b) = cat.buckets.get_mut(&req.bucket) {
            b.policy = Some(doc);
        }
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
        self.commit_wal(WalOp::UpdateBucketPolicy {
            name: req.bucket.clone(),
            policy_json: None,
        })
        .await?;
        let mut cat = self.catalog.write().unwrap();
        if let Some(b) = cat.buckets.get_mut(&req.bucket) {
            b.policy = None;
        }
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
        self.commit_wal(WalOp::UpdatePublicAccessBlock {
            name: req.bucket.clone(),
            config: Some(req.config),
        })
        .await?;
        let mut cat = self.catalog.write().unwrap();
        if let Some(b) = cat.buckets.get_mut(&req.bucket) {
            b.public_access_block = Some(req.config);
        }
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
        self.commit_wal(WalOp::UpdatePublicAccessBlock {
            name: req.bucket.clone(),
            config: None,
        })
        .await?;
        let mut cat = self.catalog.write().unwrap();
        if let Some(b) = cat.buckets.get_mut(&req.bucket) {
            b.public_access_block = None;
        }
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

        {
            let cat = self.catalog.read().unwrap();
            let b = check_bucket_write_object(
                &cat,
                self.cfg.default_object_ownership,
                &req.ctx,
                &req.bucket,
                &req.key,
                req.tags.as_ref(),
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
        }

        // 1. Stream data into segment blocks (<= max_block_payload) while computing digests
        let mut block_buf = BytesMut::with_capacity(self.cfg.max_block_payload.min(64 * 1024));
        let mut extents: Vec<Extent> = Vec::new();
        let mut touched_slots: BTreeMap<u32, Arc<SegmentSlot<D>>> = BTreeMap::new();
        let mut seen_bytes = 0u64;

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
                let space = self.cfg.max_block_payload - block_buf.len();
                let take = space.min(slice.len());
                block_buf.extend_from_slice(&slice[..take]);
                slice = &slice[take..];
                if block_buf.len() == self.cfg.max_block_payload {
                    let (ext, slot) = self.write_data_block(&block_buf)?;
                    touched_slots.insert(slot.seg_id, slot);
                    extents.push(ext);
                    block_buf.clear();
                }
            }
        }
        if !block_buf.is_empty() {
            let (ext, slot) = self.write_data_block(&block_buf)?;
            touched_slots.insert(slot.seg_id, slot);
            extents.push(ext);
            block_buf.clear();
        }

        // 2. Verify SHA-256 / Content-MD5 / Checksum BEFORE syncing or writing WAL! (PR-21)
        let digests = body.finish().map_err(map_body_err)?;

        // 3. fdatasync touched data segments BEFORE writing WAL commit record (ST-1, 8.3)
        for slot in touched_slots.values() {
            slot.file
                .sync_data()
                .map_err(|e| self.poison_read_only("put_seg_fdatasync", e))?;
        }

        // 4. Acquire KeyLock, re-evaluate preconditions & ACL at commit point (FR-17), write & sync WAL
        let _kl = self.key_stripe(&req.bucket, &req.key).lock().await;
        let (versioning, obj_owner, obj_acl) = {
            let cat = self.catalog.read().unwrap();
            let b = check_bucket_write_object(
                &cat,
                self.cfg.default_object_ownership,
                &req.ctx,
                &req.bucket,
                &req.key,
                req.tags.as_ref(),
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
            (b.versioning, owner, acl)
        };
        let seq = self.alloc_seq();

        let etag = format!("\"{}\"", hex::encode(digests.md5));
        let version_id = match versioning {
            VersioningStatus::Unversioned => None,
            VersioningStatus::Suspended => Some("null".to_string()),
            VersioningStatus::Enabled => Some(format!("v{seq:016x}")),
        };
        let obj_tags = req.tags.unwrap_or_default();

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
        };
        self.commit_wal(op).await?;

        // 5. Commit to in-memory catalog & update live_bytes accounting
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
                    sys_meta: req.sys_meta,
                    user_meta: req.user_meta,
                    owner: obj_owner,
                    acl: obj_acl,
                    tags: obj_tags,
                    last_modified_ms: req.ctx.request_time_ms,
                    extents: extents.clone().into(),
                    parts: None,
                };
                insert_version_chain(b.versioning, chain, entry, &mut reclaimed_extents);
            }
        }

        self.adjust_live_bytes(&extents, &reclaimed_extents);

        Ok(PutObjectResp {
            etag,
            version_id,
            checksum: digests.checksum,
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
            let dm_owner = req.ctx.caller.clone().unwrap_or_else(|| b.owner.clone());
            let head = head_state_of(b.objects.get(&req.key));
            evaluate_delete_preconditions(req.if_match.as_deref(), &req.bucket, &req.key, head)?;
            (b.versioning, dm_owner)
        };
        let seq = self.alloc_seq();

        if let Some(vid) = &req.version_id {
            self.commit_wal(WalOp::DeleteVersion {
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
                if let Some(b) = cat.buckets.get_mut(&req.bucket) {
                    if let Some(chain) = b.objects.get_mut(&req.key) {
                        if let Some(pos) = chain.iter().position(|v| {
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
                }
            }
            self.adjust_live_bytes(&[], &reclaimed);
            return Ok(out_resp);
        }

        match versioning {
            VersioningStatus::Unversioned => {
                self.commit_wal(WalOp::DeleteVersion {
                    bucket: req.bucket.clone(),
                    key: req.key.clone(),
                    version_id: None,
                })
                .await?;
                let mut reclaimed = Vec::new();
                {
                    let mut cat = self.catalog.write().unwrap();
                    if let Some(b) = cat.buckets.get_mut(&req.bucket) {
                        if let Some(removed_chain) = b.objects.remove(&req.key) {
                            for v in removed_chain {
                                reclaimed.extend(v.extents.iter().copied());
                            }
                        }
                    }
                }
                self.adjust_live_bytes(&[], &reclaimed);
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
                self.commit_wal(WalOp::PutVersion {
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
                                sys_meta: SystemMeta::default(),
                                user_meta: Vec::new(),
                                owner: dm_owner,
                                acl: dm_acl,
                                tags: BTreeMap::new(),
                                last_modified_ms: req.ctx.request_time_ms,
                                extents: Arc::new([]),
                                parts: None,
                            },
                        );
                    }
                }
                self.adjust_live_bytes(&[], &reclaimed);
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
            && req.acl.is_none()
            && req.tagging_directive == TaggingDirective::Copy
        {
            return Err(S3Error::new(
                S3ErrorCode::InvalidRequest,
                "This copy request is illegal because it is trying to copy an object to itself without changing the object's metadata.",
            ));
        }
        self.check_writable(true)?;

        // 1. Lock-free snapshot read of source metadata & pin its segments
        let (src_ver, src_pins, dst_tags) = {
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
            (found, pins, dst_tags)
        };

        // 2. Copy blocks sequentially into active segment (maintaining strict 1-to-1 block ownership!)
        let mut new_extents = Vec::with_capacity(src_ver.extents.len());
        let mut touched_slots: BTreeMap<u32, Arc<SegmentSlot<D>>> = BTreeMap::new();
        let mut md5_hasher = Md5::new();
        let mut csum_hasher = ActiveHasher::new(src_ver.checksum.algorithm);

        for ext in src_ver.extents.iter() {
            let Some(pin) = src_pins.get(&ext.seg_id) else {
                return Err(S3Error::new(S3ErrorCode::InternalError, "Missing source segment"));
            };
            let mut raw = vec![0u8; ext.physical_bytes() as usize];
            pin.slot()
                .file
                .read_exact_at(ext.offset, &mut raw)
                .map_err(|_| S3Error::new(S3ErrorCode::InternalError, "Source read failed"))?;
            let payload = &raw[12..];
            if crc32c::crc32c(payload) != ext.crc32c {
                return Err(S3Error::new(
                    S3ErrorCode::InternalError,
                    "Source block CRC32C mismatch",
                ));
            }
            md5_hasher.update(payload);
            csum_hasher.update(payload);
            let (new_ext, slot) = self.write_data_block(payload)?;
            touched_slots.insert(slot.seg_id, slot);
            new_extents.push(new_ext);
        }
        drop(src_pins);

        for slot in touched_slots.values() {
            slot.file
                .sync_data()
                .map_err(|e| self.poison_read_only("copy_seg_sync", e))?;
        }

        // 3. Commit under destination key lock
        let _kl = self.key_stripe(&req.dst_bucket, &req.dst_key).lock().await;
        let req_tags_for_auth = match req.tagging_directive {
            TaggingDirective::Copy => (!src_ver.tags.is_empty()).then_some(&dst_tags),
            TaggingDirective::Replace => req.tags.as_ref(),
        };
        let (dst_versioning, dst_owner, dst_acl) = {
            let cat = self.catalog.read().unwrap();
            let dst_b = check_bucket_write_object(
                &cat,
                self.cfg.default_object_ownership,
                &req.ctx,
                &req.dst_bucket,
                &req.dst_key,
                req_tags_for_auth,
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
            (dst_b.versioning, owner, acl)
        };
        let seq = self.alloc_seq();

        let dst_vid = match dst_versioning {
            VersioningStatus::Unversioned => None,
            VersioningStatus::Suspended => Some("null".to_string()),
            VersioningStatus::Enabled => Some(format!("v{seq:016x}")),
        };
        let (sys_meta, user_meta) = if req.replace_metadata {
            (req.sys_meta, req.user_meta)
        } else {
            (src_ver.sys_meta.clone(), src_ver.user_meta.clone())
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
            sys_meta: sys_meta.clone(),
            user_meta: user_meta.clone(),
            owner: dst_owner.clone(),
            acl: dst_acl.clone(),
            tags: dst_tags.clone(),
            last_modified_ms: req.ctx.request_time_ms,
            extents: new_extents.clone(),
            parts: None,
        };
        self.commit_wal(op).await?;

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
                    sys_meta,
                    user_meta,
                    owner: dst_owner,
                    acl: dst_acl,
                    tags: dst_tags,
                    last_modified_ms: req.ctx.request_time_ms,
                    extents: new_extents.clone().into(),
                    parts: None,
                };
                insert_version_chain(dst_versioning, chain, entry, &mut reclaimed);
            }
        }
        self.adjust_live_bytes(&new_extents, &reclaimed);

        Ok(CopyObjectResp {
            etag,
            last_modified_ms: req.ctx.request_time_ms,
            src_version_id: src_ver.version_id,
            dst_version_id: dst_vid,
            checksum: dst_csum.client_requested.then_some(dst_csum),
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
        let (initiator, obj_owner, obj_acl) = {
            let cat = self.catalog.read().unwrap();
            let b = check_bucket_write_object(
                &cat,
                self.cfg.default_object_ownership,
                &req.ctx,
                &req.bucket,
                &req.key,
                req.tags.as_ref(),
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
            (initiator, obj_owner, obj_acl)
        };

        let seq = self.alloc_seq();
        let mut entropy = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut entropy);
        // [FR-24] >= 128-bit random entropy UploadId
        let upload_id = format!("mp{seq:016x}{}", hex::encode(entropy));
        let up_tags = req.tags.unwrap_or_default();

        self.commit_wal(WalOp::CreateMultipartUpload {
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
                        parts: BTreeMap::new(),
                    },
                );
            }
        }

        Ok(CreateMultipartUploadResp {
            bucket: req.bucket,
            key: req.key,
            upload_id,
            checksum_algorithm: req.checksum_algorithm,
            checksum_type: resolved_type,
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

        let up_alg = {
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
            up.checksum_algorithm
        };

        let mut block_buf = BytesMut::with_capacity(self.cfg.max_block_payload.min(64 * 1024));
        let mut extents: Vec<Extent> = Vec::new();
        let mut touched_slots: BTreeMap<u32, Arc<SegmentSlot<D>>> = BTreeMap::new();
        let mut seen_bytes = 0u64;
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
                let space = self.cfg.max_block_payload - block_buf.len();
                let take = space.min(slice.len());
                block_buf.extend_from_slice(&slice[..take]);
                slice = &slice[take..];
                if block_buf.len() == self.cfg.max_block_payload {
                    let (ext, slot) = self.write_data_block(&block_buf)?;
                    touched_slots.insert(slot.seg_id, slot);
                    extents.push(ext);
                    block_buf.clear();
                }
            }
        }
        if !block_buf.is_empty() {
            let (ext, slot) = self.write_data_block(&block_buf)?;
            touched_slots.insert(slot.seg_id, slot);
            extents.push(ext);
            block_buf.clear();
        }

        let digests = body.finish().map_err(map_body_err)?;
        if let Some(alg) = up_alg {
            if digests.checksum.client_requested && digests.checksum.algorithm != alg {
                return Err(S3Error::new(
                    S3ErrorCode::InvalidRequest,
                    format!(
                        "Checksum algorithm mismatch: upload expects {}",
                        alg.as_aws_str()
                    ),
                ));
            }
        }

        for slot in touched_slots.values() {
            slot.file
                .sync_data()
                .map_err(|e| self.poison_read_only("upload_part_seg_fdatasync", e))?;
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

        self.commit_wal(WalOp::PutUploadPart {
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
        })
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
            {
                if let Some(old_part) = up.parts.insert(
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
                    },
                ) {
                    reclaimed.extend(old_part.extents.iter().copied());
                }
            }
        }
        self.adjust_live_bytes(&extents, &reclaimed);

        Ok(UploadPartResp {
            etag,
            checksum: resp_csum,
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

        let (src_ver, src_pins, up_alg, slice_start, slice_end_excl) = {
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

            let found = self
                .lookup_version_for_copy_checked(
                    src_b,
                    &req.ctx,
                    &req.src_bucket,
                    &req.src_key,
                    req.src_version_id.as_deref(),
                )?
                .clone();

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
            (found, pins, up_alg, s, e_excl)
        };

        let mut block_buf = BytesMut::with_capacity(self.cfg.max_block_payload.min(64 * 1024));
        let mut extents: Vec<Extent> = Vec::new();
        let mut touched_slots: BTreeMap<u32, Arc<SegmentSlot<D>>> = BTreeMap::new();
        let mut md5_hasher = Md5::new();
        let mut crc64_hasher = crc64fast_nvme::Digest::new();
        let mut up_csum_hasher = up_alg.map(ActiveHasher::new);

        if slice_start < slice_end_excl {
            let mut logical_pos = 0u64;
            for ext in src_ver.extents.iter() {
                let ext_len = ext.len as u64;
                if ext_len == 0 {
                    continue;
                }
                let ext_start = logical_pos;
                let ext_end_excl = logical_pos + ext_len;
                logical_pos = ext_end_excl;

                if ext_end_excl <= slice_start {
                    continue;
                }
                if ext_start >= slice_end_excl {
                    break;
                }

                let Some(pin) = src_pins.get(&ext.seg_id) else {
                    return Err(S3Error::new(S3ErrorCode::InternalError, "Missing source segment"));
                };
                let mut raw = vec![0u8; ext.physical_bytes() as usize];
                pin.slot()
                    .file
                    .read_exact_at(ext.offset, &mut raw)
                    .map_err(|_| S3Error::new(S3ErrorCode::InternalError, "Source read failed"))?;
                let payload = &raw[12..];
                if crc32c::crc32c(payload) != ext.crc32c {
                    return Err(S3Error::new(
                        S3ErrorCode::InternalError,
                        "Source block CRC32C mismatch",
                    ));
                }

                let rel_s = slice_start.saturating_sub(ext_start) as usize;
                let rel_e = (slice_end_excl.min(ext_end_excl) - ext_start) as usize;
                let mut slice = &payload[rel_s..rel_e];
                md5_hasher.update(slice);
                crc64_hasher.write(slice);
                if let Some(h) = &mut up_csum_hasher {
                    h.update(slice);
                }

                while !slice.is_empty() {
                    let space = self.cfg.max_block_payload - block_buf.len();
                    let take = space.min(slice.len());
                    block_buf.extend_from_slice(&slice[..take]);
                    slice = &slice[take..];
                    if block_buf.len() == self.cfg.max_block_payload {
                        let (new_ext, slot) = self.write_data_block(&block_buf)?;
                        touched_slots.insert(slot.seg_id, slot);
                        extents.push(new_ext);
                        block_buf.clear();
                    }
                }
            }
            if !block_buf.is_empty() {
                let (new_ext, slot) = self.write_data_block(&block_buf)?;
                touched_slots.insert(slot.seg_id, slot);
                extents.push(new_ext);
                block_buf.clear();
            }
        }
        drop(src_pins);

        for slot in touched_slots.values() {
            slot.file
                .sync_data()
                .map_err(|e| self.poison_read_only("upload_part_copy_seg_sync", e))?;
        }

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

        self.commit_wal(WalOp::PutUploadPart {
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
        })
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
            {
                if let Some(old_part) = up.parts.insert(
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
                    },
                ) {
                    reclaimed.extend(old_part.extents.iter().copied());
                }
            }
        }
        self.adjust_live_bytes(&extents, &reclaimed);

        Ok(UploadPartCopyResp {
            etag,
            last_modified_ms: req.ctx.request_time_ms,
            src_version_id: src_ver.version_id,
            checksum: resp_csum,
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
        let (up, versioning) = {
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
            (up, b.versioning)
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
                        ChecksumAlgorithm::Sha1 | ChecksumAlgorithm::Sha256 => {}
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
            });
        }

        if total_size > self.cfg.max_object_size {
            return Err(S3Error::new(
                S3ErrorCode::EntityTooLarge,
                "Your proposed upload exceeds the maximum allowed size",
            ));
        }
        if let Some(exp_size) = req.expected_object_size {
            if exp_size != total_size {
                return Err(S3Error::new(
                    S3ErrorCode::PreconditionFailed,
                    "Object size does not match x-amz-mp-object-size.",
                ));
            }
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

        if let Some((exp_alg, exp_val)) = &req.expected_checksum {
            if !final_checksum.client_requested
                || *exp_alg != final_checksum.algorithm
                || exp_val.trim() != final_checksum.value_b64
            {
                return Err(S3Error::new(
                    S3ErrorCode::BadDigest,
                    "The digest you specified did not match the calculated digest.",
                ));
            }
        }

        // [FR-15, FR-17] Evaluate destination preconditions at commit point
        {
            let cat = self.catalog.read().unwrap();
            let b = lookup_bucket_checked(&cat, &req.ctx, &req.bucket)?;
            let head = head_state_of(b.objects.get(&req.key));
            evaluate_write_preconditions(&req.preconditions, &req.bucket, &req.key, head)?;
        }

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
        };

        self.commit_wal(WalOp::CompleteMultipartUpload {
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
                    sys_meta: up.sys_meta,
                    user_meta: up.user_meta,
                    owner: up.owner,
                    acl: up.acl,
                    tags: up.tags,
                    last_modified_ms: req.ctx.request_time_ms,
                    extents: combined_extents.into(),
                    parts: Some(boundaries.into()),
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

        self.commit_wal(WalOp::AbortMultipartUpload {
            bucket: req.bucket.clone(),
            key: req.key.clone(),
            upload_id: req.upload_id.clone(),
        })
        .await?;

        let mut reclaimed = Vec::new();
        {
            let mut cat = self.catalog.write().unwrap();
            if let Some(b) = cat.buckets.get_mut(&req.bucket) {
                if let Some(removed_up) = b.uploads.remove(&(req.key, req.upload_id)) {
                    for p in removed_up.parts.into_values() {
                        reclaimed.extend(p.extents.iter().copied());
                    }
                }
            }
        }
        if !reclaimed.is_empty() {
            self.adjust_live_bytes(&[], &reclaimed);
        }
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
                if let Some(delim) = req.delimiter.as_deref().filter(|d| !d.is_empty()) {
                    if let Some(pos) = rest.find(delim) {
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
                    size: v.total_size,
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
            if !pins.contains_key(&ext.seg_id) {
                let slot = mgr.segments.get(&ext.seg_id).ok_or_else(|| {
                    S3Error::new(
                        S3ErrorCode::InternalError,
                        "Referenced segment missing from segment table",
                    )
                })?;
                pins.insert(ext.seg_id, SegmentPin::acquire(slot));
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
        let (ver, pins) = {
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

            let pins = if need_reader {
                self.pin_extents(&found.extents)?
            } else {
                BTreeMap::new()
            };
            (found, pins)
        };

        let last_mod_http = httpdate::fmt_http_date(
            UNIX_EPOCH + std::time::Duration::from_millis(ver.last_modified_ms.max(0) as u64),
        );
        evaluate_read_preconditions(
            &req.preconditions,
            &ver.etag,
            ver.last_modified_ms,
            &last_mod_http,
        )?;

        let total_size = ver.total_size;
        let mut part_specific_csum: Option<ChecksumState> = None;

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
            EngineByteReader::new(pins, &ver.extents, start, end)
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
            owner: ver.owner,
            sys_meta: ver.sys_meta,
            user_meta: ver.user_meta,
            checksum,
            parts_count,
            tags_count: ver.tags.len(),
        };
        Ok((meta, reader))
    }
}

// ---- Offline Integrity Checker (`s3d fsck`, NFR-13) ----

#[derive(Debug, Serialize)]
pub struct FsckReport {
    pub status: String,
    pub checked_lsn: u64,
    pub buckets: usize,
    pub object_versions: usize,
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
                checked_lsn: 0,
                buckets: 0,
                object_versions: 0,
                segments_checked: 0,
                bytes_verified: 0,
                errors,
            };
        }
    };

    let checked_lsn = engine.wal.lock().unwrap().synced_lsn;
    let segments_checked = engine.seg_mgr.lock().unwrap().segments.len();
    let mut object_versions = 0usize;
    let mut bytes_verified = 0u64;

    let cat = engine.catalog.read().unwrap();
    let buckets = cat.buckets.len();
    let mgr = engine.seg_mgr.lock().unwrap();

    for (bname, b) in &cat.buckets {
        for (key, chain) in &b.objects {
            for v in chain {
                object_versions += 1;
                if v.is_delete_marker {
                    continue;
                }
                let mut md5_h = Md5::new();
                let mut actual_size = 0u64;
                for ext in v.extents.iter() {
                    let Some(slot) = mgr.segments.get(&ext.seg_id) else {
                        errors.push(format!("{bname}/{key}: missing segment {}", ext.seg_id));
                        continue;
                    };
                    let mut raw = vec![0u8; ext.physical_bytes() as usize];
                    if let Err(e) = slot.file.read_exact_at(ext.offset, &mut raw) {
                        errors.push(format!(
                            "{bname}/{key}: read error seg {} off {}: {e}",
                            ext.seg_id, ext.offset
                        ));
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
                            }
                            md5_h.update(payload);
                            actual_size += payload.len() as u64;
                            bytes_verified += payload.len() as u64;
                        }
                        Err(msg) => errors.push(format!("{bname}/{key}: {msg}")),
                    }
                }
                if actual_size != v.total_size {
                    errors.push(format!(
                        "{bname}/{key}: size mismatch expected {}, got {}",
                        v.total_size, actual_size
                    ));
                }
                if let Some(parts) = &v.parts {
                    let parts_sum: u64 = parts.iter().map(|p| p.size).sum();
                    if parts_sum != v.total_size {
                        errors.push(format!(
                            "{bname}/{key}: multipart part sizes sum {parts_sum} != {}",
                            v.total_size
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
            }
        }

        for ((key, uid), up) in &b.uploads {
            for p in up.parts.values() {
                let mut part_bytes = 0u64;
                for ext in p.extents.iter() {
                    let Some(slot) = mgr.segments.get(&ext.seg_id) else {
                        errors.push(format!(
                            "{bname}/{key} upload {uid} part {}: missing segment {}",
                            p.part_number, ext.seg_id
                        ));
                        continue;
                    };
                    let mut raw = vec![0u8; ext.physical_bytes() as usize];
                    if let Err(e) = slot.file.read_exact_at(ext.offset, &mut raw) {
                        errors.push(format!(
                            "{bname}/{key} upload {uid} part {}: read error: {e}",
                            p.part_number
                        ));
                        continue;
                    }
                    let hdr: [u8; 12] = raw[0..12].try_into().unwrap();
                    match decode_block_header(&hdr) {
                        Ok((len, crc)) => {
                            let payload = &raw[12..];
                            if len != ext.len
                                || crc != ext.crc32c
                                || crc32c::crc32c(payload) != ext.crc32c
                            {
                                errors.push(format!(
                                    "{bname}/{key} upload {uid} part {}: block CRC mismatch",
                                    p.part_number
                                ));
                            }
                            part_bytes += payload.len() as u64;
                            bytes_verified += payload.len() as u64;
                        }
                        Err(msg) => errors.push(format!(
                            "{bname}/{key} upload {uid} part {}: {msg}",
                            p.part_number
                        )),
                    }
                }
                if part_bytes != p.size {
                    errors.push(format!(
                        "{bname}/{key} upload {uid} part {}: size mismatch expected {}, got {part_bytes}",
                        p.part_number, p.size
                    ));
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
        checked_lsn,
        buckets,
        object_versions,
        segments_checked,
        bytes_verified,
        errors,
    }
}
