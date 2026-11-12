//! Crash-safe log-structured object storage engine (`s3d-engine`).

pub mod catalog;
pub mod format;

use std::collections::{BTreeMap, BTreeSet};
use std::future::poll_fn;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

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
    BucketEntry, EngineByteReader, MemoryCatalog, ObjectVersionEntry, SegmentPin, SegmentSlot,
    SEG_STATE_ACTIVE, SEG_STATE_PENDING_DELETE, SEG_STATE_SEALED,
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
    pub default_object_ownership: ObjectOwnership,
    pub gc_live_ratio: f64,
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
            default_object_ownership: ObjectOwnership::BucketOwnerEnforced,
            gc_live_ratio: 0.5,
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
    catalog: RwLock<MemoryCatalog>,
    seg_mgr: Mutex<SegmentManager<D>>,
    wal: Mutex<WalWriterState<D>>,
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

        // 5. Reconcile segment files & verify referenced extents
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

        Ok(Arc::new(Self {
            disk,
            cfg,
            format,
            _lock_guard: lock_guard,
            read_only_poisoned: AtomicBool::new(false),
            catalog: RwLock::new(catalog),
            seg_mgr: Mutex::new(SegmentManager {
                active_seg_id,
                next_seg_id: max_seg_id + 1,
                segments,
            }),
            wal: Mutex::new(wal_state),
            key_locks,
        }))
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

    /// Persist a WAL operation (`fdatasync`ing WAL; on `EIO`, immediately poisons read-only WITHOUT
    /// touching in-memory catalog per §10 hard rule!).
    fn append_and_sync_wal(&self, op: &WalOp) -> StoreResult<u64> {
        if self.is_read_only_poisoned() {
            return Err(S3Error::new(
                S3ErrorCode::InternalError,
                "Storage engine is in read-only failed state.",
            ));
        }
        let mut wal = self.wal.lock().unwrap();
        if self.is_read_only_poisoned() {
            return Err(S3Error::new(
                S3ErrorCode::InternalError,
                "Storage engine is in read-only failed state.",
            ));
        }

        let mut encoded = Vec::with_capacity(256);
        let lsn = wal.next_lsn;
        encode_wal_record(lsn, wal.synced_lsn, op, &mut encoded);

        // Roll WAL file if current file exceeds wal_file_size
        if wal.write_pos > WAL_HEADER_LEN
            && wal.write_pos + encoded.len() as u64 > self.cfg.wal_file_size
        {
            let new_seq = wal.wal_seq + 1;
            let rel_path = format!("wal/{new_seq:08}.log");
            let new_file = self
                .disk
                .open(&rel_path, OpenOpts::create_truncate_rw())
                .map_err(|e| self.poison_read_only("wal_roll_open", e))?;
            let hdr = encode_wal_header(new_seq, lsn, self.format.uuid_lo());
            new_file
                .write_all_at(0, &hdr)
                .map_err(|e| self.poison_read_only("wal_roll_hdr_write", e))?;
            new_file
                .sync_data()
                .map_err(|e| self.poison_read_only("wal_roll_hdr_sync", e))?;
            self.disk
                .sync_dir("wal")
                .map_err(|e| self.poison_read_only("wal_roll_dir_sync", e))?;

            wal.wal_seq = new_seq;
            wal.file = new_file;
            wal.write_pos = WAL_HEADER_LEN;
        }

        let offset = wal.write_pos;
        wal.file
            .write_all_at(offset, &encoded)
            .map_err(|e| self.poison_read_only("wal_write", e))?;
        wal.file
            .sync_data()
            .map_err(|e| self.poison_read_only("wal_fdatasync", e))?;

        wal.write_pos += encoded.len() as u64;
        wal.next_lsn = lsn + 1;
        wal.synced_lsn = lsn;
        Ok(lsn)
    }

    /// Trigger online segment compaction / GC (`s3d compact`, §8.5).
    pub async fn compact(&self) -> StoreResult< usize > {
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
            // Collect live references pointing to `old_id`
            let mut to_move = Vec::new();
            {
                let cat = self.catalog.read().unwrap();
                for (bname, b) in &cat.buckets {
                    for (key, chain) in &b.objects {
                        for v in chain {
                            for (eidx, ext) in v.extents.iter().enumerate() {
                                if ext.seg_id == old_id {
                                    to_move.push((bname.clone(), key.clone(), v.seq, eidx, *ext));
                                }
                            }
                        }
                    }
                }
            }

            let mut touched_new_slots: BTreeMap<u32, Arc<SegmentSlot<D>>> = BTreeMap::new();
            let mut copied = Vec::with_capacity(to_move.len());

            for (bname, key, seq, eidx, ext) in to_move {
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
                copied.push((bname, key, seq, eidx, ext, new_ext));
            }

            for slot in touched_new_slots.values() {
                slot.file
                    .sync_data()
                    .map_err(|e| self.poison_read_only("gc_seg_sync", e))?;
            }

            // Re-verify under key stripe lock / catalog write lock and relocate still-live extents
            let mut relocated_ops = Vec::new();
            for (bname, key, seq, eidx, old_ext, new_ext) in copied {
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
                    self.append_and_sync_wal(&WalOp::RelocateExtents {
                        items: vec![rel.clone()],
                    })?;
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
                    relocated_ops.push(rel);
                }
            }

            if old_slot.live_bytes.load(Ordering::Acquire) == 0 {
                // [ST-7] Record deletion intent in WAL BEFORE unlinking file!
                self.append_and_sync_wal(&WalOp::DeleteSegment { seg_id: old_id })?;
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
            region,
            created_ms,
            ownership,
        } => {
            catalog.buckets.insert(
                name.clone(),
                BucketEntry {
                    name,
                    owner,
                    region,
                    created_ms,
                    versioning: VersioningStatus::Unversioned,
                    ownership,
                    objects: BTreeMap::new(),
                },
            );
        }
        WalOp::UpdateBucketVersioning { name, versioning } => {
            if let Some(b) = catalog.buckets.get_mut(&name) {
                b.versioning = versioning;
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
            last_modified_ms,
            extents,
            part_sizes,
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
                    last_modified_ms,
                    extents: extents.into(),
                    part_sizes: part_sizes.map(Into::into),
                };
                let chain = b.objects.entry(key).or_default();
                match b.versioning {
                    VersioningStatus::Unversioned => {
                        chain.clear();
                        chain.push(entry);
                    }
                    VersioningStatus::Suspended => {
                        chain.retain(|v| v.version_id.as_deref() != Some("null"));
                        chain.insert(0, entry);
                    }
                    VersioningStatus::Enabled => {
                        chain.insert(0, entry);
                    }
                }
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
        WalOp::CreateSegment { seg_id } => {
            created_segments.insert(seg_id);
        }
        WalOp::RelocateExtents { items } => {
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

fn check_bucket_access<'a>(
    cat: &'a MemoryCatalog,
    ctx: &CallerContext,
    bucket_name: &str,
) -> StoreResult<&'a BucketEntry> {
    let b = cat.buckets.get(bucket_name).ok_or_else(|| {
        S3Error::new(S3ErrorCode::NoSuchBucket, "The specified bucket does not exist")
            .with_bucket(bucket_name)
    })?;
    let caller = require_authenticated(ctx)?;
    if let Some(expected) = &ctx.expected_bucket_owner {
        if expected != &b.owner.user_id {
            return Err(S3Error::new(S3ErrorCode::AccessDenied, "Access Denied")
                .with_bucket(bucket_name));
        }
    }
    if caller.user_id != b.owner.user_id {
        return Err(
            S3Error::new(S3ErrorCode::AccessDenied, "Access Denied").with_bucket(bucket_name)
        );
    }
    Ok(b)
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
            Some(tok) => Some(decode_token("__buckets__", tok)?),
            None => None,
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
        let op = WalOp::CreateBucket {
            name: req.bucket.clone(),
            owner: caller.clone(),
            region: self.cfg.region.clone(),
            created_ms: req.ctx.request_time_ms,
            ownership,
        };
        self.append_and_sync_wal(&op)?;

        let mut cat = self.catalog.write().unwrap();
        cat.buckets.insert(
            req.bucket.clone(),
            BucketEntry {
                name: req.bucket.clone(),
                owner: caller.clone(),
                region: self.cfg.region.clone(),
                created_ms: req.ctx.request_time_ms,
                versioning: VersioningStatus::Unversioned,
                ownership,
                objects: BTreeMap::new(),
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
        let b = check_bucket_access(&cat, &req.ctx, &req.bucket)?;
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
        self.check_writable(false)?;
        let _kl = self.key_stripe(&req.bucket, "").lock().await;
        {
            let cat = self.catalog.read().unwrap();
            let b = check_bucket_access(&cat, &req.ctx, &req.bucket)?;
            if b.objects.values().any(|c| !c.is_empty()) {
                return Err(S3Error::new(
                    S3ErrorCode::BucketNotEmpty,
                    "The bucket you tried to delete is not empty",
                )
                .with_bucket(&req.bucket));
            }
        }
        self.append_and_sync_wal(&WalOp::DeleteBucket {
            name: req.bucket.clone(),
        })?;
        let mut cat = self.catalog.write().unwrap();
        cat.buckets.remove(&req.bucket);
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

        let caller = {
            let cat = self.catalog.read().unwrap();
            let _ = check_bucket_access(&cat, &req.ctx, &req.bucket)?;
            require_authenticated(&req.ctx)?.clone()
        };

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

        // 4. Acquire KeyLock, re-evaluate preconditions at commit point (FR-17), write & sync WAL
        let _kl = self.key_stripe(&req.bucket, &req.key).lock().await;
        let (seq, versioning) = {
            let cat = self.catalog.read().unwrap();
            let b = check_bucket_access(&cat, &req.ctx, &req.bucket)?;
            let head = head_state_of(b.objects.get(&req.key));
            evaluate_write_preconditions(&req.preconditions, &req.bucket, &req.key, head)?;
            (cat.next_seq + 1, b.versioning)
        };

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
            owner: caller.clone(),
            last_modified_ms: req.ctx.request_time_ms,
            extents: extents.clone(),
            part_sizes: None,
        };
        self.append_and_sync_wal(&op)?;

        // 5. Commit to in-memory catalog & update live_bytes accounting
        let mut reclaimed_extents: Vec<Extent> = Vec::new();
        {
            let mut cat = self.catalog.write().unwrap();
            if seq > cat.next_seq {
                cat.next_seq = seq;
            }
            if let Some(b) = cat.buckets.get_mut(&req.bucket) {
                let chain = b.objects.entry(req.key).or_default();
                match b.versioning {
                    VersioningStatus::Unversioned => {
                        for old in chain.drain(..) {
                            reclaimed_extents.extend(old.extents.iter().copied());
                        }
                        chain.push(ObjectVersionEntry {
                            seq,
                            version_id: version_id.clone(),
                            is_delete_marker: false,
                            total_size: digests.total_bytes,
                            etag: etag.clone(),
                            checksum: digests.checksum.clone(),
                            sys_meta: req.sys_meta,
                            user_meta: req.user_meta,
                            owner: caller,
                            last_modified_ms: req.ctx.request_time_ms,
                            extents: extents.clone().into(),
                            part_sizes: None,
                        });
                    }
                    VersioningStatus::Suspended => {
                        chain.retain(|old| {
                            if old.version_id.as_deref() == Some("null") {
                                reclaimed_extents.extend(old.extents.iter().copied());
                                false
                            } else {
                                true
                            }
                        });
                        chain.insert(
                            0,
                            ObjectVersionEntry {
                                seq,
                                version_id: version_id.clone(),
                                is_delete_marker: false,
                                total_size: digests.total_bytes,
                                etag: etag.clone(),
                                checksum: digests.checksum.clone(),
                                sys_meta: req.sys_meta,
                                user_meta: req.user_meta,
                                owner: caller,
                                last_modified_ms: req.ctx.request_time_ms,
                                extents: extents.clone().into(),
                                part_sizes: None,
                            },
                        );
                    }
                    VersioningStatus::Enabled => {
                        chain.insert(
                            0,
                            ObjectVersionEntry {
                                seq,
                                version_id: version_id.clone(),
                                is_delete_marker: false,
                                total_size: digests.total_bytes,
                                etag: etag.clone(),
                                checksum: digests.checksum.clone(),
                                sys_meta: req.sys_meta,
                                user_meta: req.user_meta,
                                owner: caller,
                                last_modified_ms: req.ctx.request_time_ms,
                                extents: extents.clone().into(),
                                part_sizes: None,
                            },
                        );
                    }
                }
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

    async fn delete_object(&self, req: DeleteObjectReq) -> StoreResult<DeleteObjectResp> {
        validate_object_key(&req.bucket, &req.key)?;
        self.check_writable(false)?;

        let _kl = self.key_stripe(&req.bucket, &req.key).lock().await;
        let (seq, versioning, caller) = {
            let cat = self.catalog.read().unwrap();
            let b = check_bucket_access(&cat, &req.ctx, &req.bucket)?;
            let caller = require_authenticated(&req.ctx)?.clone();
            let head = head_state_of(b.objects.get(&req.key));
            evaluate_delete_preconditions(req.if_match.as_deref(), &req.bucket, &req.key, head)?;
            (cat.next_seq + 1, b.versioning, caller)
        };

        if let Some(vid) = &req.version_id {
            self.append_and_sync_wal(&WalOp::DeleteVersion {
                bucket: req.bucket.clone(),
                key: req.key.clone(),
                version_id: Some(vid.clone()),
            })?;
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
                self.append_and_sync_wal(&WalOp::DeleteVersion {
                    bucket: req.bucket.clone(),
                    key: req.key.clone(),
                    version_id: None,
                })?;
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
                self.append_and_sync_wal(&WalOp::PutVersion {
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
                    owner: caller.clone(),
                    last_modified_ms: req.ctx.request_time_ms,
                    extents: Vec::new(),
                    part_sizes: None,
                })?;

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
                                if old.version_id.as_deref() == Some("null") {
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
                                owner: caller,
                                last_modified_ms: req.ctx.request_time_ms,
                                extents: Arc::new([]),
                                part_sizes: None,
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
            let _ = check_bucket_access(&cat, &req.ctx, &req.bucket)?;
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
            return Err(S3Error::new(
                S3ErrorCode::InvalidRequest,
                "This copy request is illegal because it is trying to copy an object to itself without changing the object's metadata.",
            ));
        }
        self.check_writable(true)?;

        // 1. Lock-free snapshot read of source metadata & pin its segments
        let (src_ver, src_pins) = {
            let cat = self.catalog.read().unwrap();
            let src_b = check_bucket_access(&cat, &req.ctx, &req.src_bucket)?;
            let _ = check_bucket_access(&cat, &req.ctx, &req.dst_bucket)?;
            let found = match &req.src_version_id {
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

            if found.is_delete_marker {
                return Err(S3Error::new(
                    S3ErrorCode::InvalidRequest,
                    "The source of a copy request may not specifically refer to a delete marker by version id.",
                ));
            }
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
            (found, pins)
        };

        // 2. Copy blocks sequentially into active segment (maintaining strict 1-to-1 block ownership!)
        let mut new_extents = Vec::with_capacity(src_ver.extents.len());
        let mut touched_slots: BTreeMap<u32, Arc<SegmentSlot<D>>> = BTreeMap::new();
        let mut md5_hasher = Md5::new();

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
        let (seq, dst_versioning, caller) = {
            let cat = self.catalog.read().unwrap();
            let dst_b = check_bucket_access(&cat, &req.ctx, &req.dst_bucket)?;
            let caller = require_authenticated(&req.ctx)?.clone();
            let dst_head = head_state_of(dst_b.objects.get(&req.dst_key));
            evaluate_write_preconditions(
                &req.dst_preconditions,
                &req.dst_bucket,
                &req.dst_key,
                dst_head,
            )?;
            (cat.next_seq + 1, dst_b.versioning, caller)
        };

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

        let op = WalOp::PutVersion {
            bucket: req.dst_bucket.clone(),
            key: req.dst_key.clone(),
            seq,
            version_id: dst_vid.clone(),
            is_delete_marker: false,
            total_size: src_ver.total_size,
            etag: etag.clone(),
            checksum: src_ver.checksum.clone(),
            sys_meta: sys_meta.clone(),
            user_meta: user_meta.clone(),
            owner: caller.clone(),
            last_modified_ms: req.ctx.request_time_ms,
            extents: new_extents.clone(),
            part_sizes: None,
        };
        self.append_and_sync_wal(&op)?;

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
                    checksum: src_ver.checksum.clone(),
                    sys_meta,
                    user_meta,
                    owner: caller,
                    last_modified_ms: req.ctx.request_time_ms,
                    extents: new_extents.clone().into(),
                    part_sizes: None,
                };
                match dst_versioning {
                    VersioningStatus::Unversioned => {
                        for old in chain.drain(..) {
                            reclaimed.extend(old.extents.iter().copied());
                        }
                        chain.push(entry);
                    }
                    VersioningStatus::Suspended => {
                        chain.retain(|old| {
                            if old.version_id.as_deref() == Some("null") {
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
        }
        self.adjust_live_bytes(&new_extents, &reclaimed);

        Ok(CopyObjectResp {
            etag,
            last_modified_ms: req.ctx.request_time_ms,
            src_version_id: src_ver.version_id,
            dst_version_id: dst_vid,
            checksum: Some(src_ver.checksum),
        })
    }

    async fn list_objects_v1(&self, req: ListObjectsV1Req) -> StoreResult<ListObjectsV1Resp> {
        let cat = self.catalog.read().unwrap();
        let b = check_bucket_access(&cat, &req.ctx, &req.bucket)?;
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
        let b = check_bucket_access(&cat, &req.ctx, &req.bucket)?;
        let max_keys = req.max_keys.min(1000);
        let token_after = match &req.continuation_token {
            Some(tok) => Some(decode_token(&req.bucket, tok)?),
            None => None,
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
        let b = check_bucket_access(&cat, &req.ctx, &req.bucket)?;
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
        let (ver, pins) = {
            let cat = self.catalog.read().unwrap();
            let b = check_bucket_access(&cat, &req.ctx, &req.bucket)?;
            let found = match &req.version_id {
                None => {
                    let Some(head) = b.objects.get(&req.key).and_then(|c| c.first()) else {
                        return Err(S3Error::new(
                            S3ErrorCode::NoSuchKey,
                            "The specified key does not exist.",
                        )
                        .with_key(&req.bucket, &req.key));
                    };
                    if head.is_delete_marker {
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
                    head.clone()
                }
                Some(vid) => {
                    let Some(v) = b.objects.get(&req.key).and_then(|c| {
                        c.iter()
                            .find(|v| v.version_id.as_deref().unwrap_or("null") == vid.as_str())
                    }) else {
                        return Err(S3Error::new(
                            S3ErrorCode::NoSuchVersion,
                            "The specified version does not exist.",
                        )
                        .with_key(&req.bucket, &req.key));
                    };
                    if v.is_delete_marker {
                        return Err(S3Error::new(
                            S3ErrorCode::MethodNotAllowed,
                            "The specified method is not allowed against this resource.",
                        )
                        .with_header("x-amz-delete-marker", "true")
                        .with_header("Allow", "DELETE"));
                    }
                    v.clone()
                }
            };

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
        let (start, end, is_partial, parts_count) = if let Some(pn) = req.part_number {
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

        let is_full = content_len == total_size;
        let checksum = if req.checksum_mode_enabled && is_full {
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
                if v.part_sizes.is_none() {
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
