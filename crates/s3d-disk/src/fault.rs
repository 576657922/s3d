use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use rand::seq::SliceRandom;
use rand::Rng;

use crate::{Disk, DiskError, DiskFile, DiskResult, OpenOpts};

pub const SECTOR_SIZE: usize = 4096;

#[derive(Debug, Clone)]
struct DirtySectorWrite {
    inode_id: u64,
    sector_idx: usize,
    offset_in_sector: usize,
    data: Vec<u8>,
}

#[derive(Debug, Clone)]
enum PendingDirOp {
    Link { name: String, inode_id: u64 },
    Unlink { name: String },
    Rename {
        from_dir: String,
        from_name: String,
        to_name: String,
        inode_id: u64,
    },
}

#[derive(Debug, Clone, Default)]
struct FileState {
    durable: Vec<u8>,
    live: Vec<u8>,
    pending_sectors: Vec<DirtySectorWrite>,
    pending_set_len: Option<u64>,
}

#[derive(Debug)]
struct InnerState {
    next_inode: u64,
    files: BTreeMap<u64, FileState>,
    durable_dirs: BTreeMap<String, BTreeMap<String, u64>>,
    live_dirs: BTreeMap<String, BTreeMap<String, u64>>,
    pending_dir_ops: BTreeMap<String, Vec<PendingDirOp>>,
    locked: bool,
    fail_sync_at: Option<usize>,
    sync_calls: usize,
    always_fail_sync: bool,
}

impl Default for InnerState {
    fn default() -> Self {
        let mut durable_dirs = BTreeMap::new();
        durable_dirs.insert(String::new(), BTreeMap::new());
        let live_dirs = durable_dirs.clone();
        Self {
            next_inode: 1,
            files: BTreeMap::new(),
            durable_dirs,
            live_dirs,
            pending_dir_ops: BTreeMap::new(),
            locked: false,
            fail_sync_at: None,
            sync_calls: 0,
            always_fail_sync: false,
        }
    }
}

/// Adversarial crash-consistency simulator implementing weakest filesystem assumptions (VR-3).
#[derive(Clone)]
pub struct FaultDisk {
    inner: Arc<Mutex<InnerState>>,
    available: Arc<AtomicU64>,
    poison_sync: Arc<AtomicBool>,
}

impl Default for FaultDisk {
    fn default() -> Self {
        Self::new()
    }
}

impl FaultDisk {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(InnerState::default())),
            available: Arc::new(AtomicU64::new(30 * 1024 * 1024 * 1024)), // 30 GiB default
            poison_sync: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn set_available_bytes(&self, bytes: u64) {
        self.available.store(bytes, Ordering::SeqCst);
    }

    /// Force every subsequent `sync_data` / `sync_dir` to return `DiskError::IoError`.
    pub fn set_fail_all_syncs(&self, fail: bool) {
        self.poison_sync.store(fail, Ordering::SeqCst);
    }

    /// Fail specifically on the `nth` (1-based) sync operation and all subsequent syncs.
    pub fn fail_sync_after(&self, nth: usize) {
        let mut guard = self.inner.lock().unwrap();
        guard.sync_calls = 0;
        guard.fail_sync_at = Some(nth);
        guard.always_fail_sync = false;
        self.poison_sync.store(false, Ordering::SeqCst);
    }

    /// Simulate sudden power loss:
    /// - Un-`sync_dir`'d directory entries may randomly drop.
    /// - Un-`sync_data`'d file writes are split into 4 KiB sectors, shuffled across all files,
    ///   partially applied, and individual 4 KiB sectors may suffer prefix tearing.
    pub fn power_cut(&self, rng: &mut impl Rng) -> Self {
        let guard = self.inner.lock().unwrap();

        let mut crashed_dirs = guard.durable_dirs.clone();
        let mut crashed_files: BTreeMap<u64, FileState> = guard
            .files
            .iter()
            .map(|(&id, f)| {
                (
                    id,
                    FileState {
                        durable: f.durable.clone(),
                        live: f.durable.clone(),
                        pending_sectors: Vec::new(),
                        pending_set_len: None,
                    },
                )
            })
            .collect();

        // 1. Apply a random subset of un-fsynced directory metadata changes
        for (dir, ops) in &guard.pending_dir_ops {
            for op in ops {
                if rng.gen_bool(0.5) {
                    match op {
                        PendingDirOp::Link { name, inode_id } => {
                            crashed_dirs
                                .entry(dir.clone())
                                .or_default()
                                .insert(name.clone(), *inode_id);
                        }
                        PendingDirOp::Unlink { name } => {
                            if let Some(entries) = crashed_dirs.get_mut(dir) {
                                entries.remove(name);
                            }
                        }
                        PendingDirOp::Rename {
                            from_dir,
                            from_name,
                            to_name,
                            inode_id,
                        } => {
                            if let Some(src_entries) = crashed_dirs.get_mut(from_dir) {
                                src_entries.remove(from_name);
                            }
                            crashed_dirs
                                .entry(dir.clone())
                                .or_default()
                                .insert(to_name.clone(), *inode_id);
                        }
                    }
                }
            }
        }

        // 2. Collect all un-fsynced 4 KiB sector writes across ALL files and shuffle (cross-file reorder)
        let mut all_dirty: Vec<DirtySectorWrite> = guard
            .files
            .values()
            .flat_map(|f| f.pending_sectors.iter().cloned())
            .collect();
        all_dirty.shuffle(rng);

        for write in all_dirty {
            if rng.gen_bool(0.5) {
                if let Some(f) = crashed_files.get_mut(&write.inode_id) {
                    let take_len = if write.data.len() > 1 && rng.gen_bool(0.25) {
                        // Sector prefix tear!
                        rng.gen_range(1..write.data.len())
                    } else {
                        write.data.len()
                    };
                    let start = write.sector_idx * SECTOR_SIZE + write.offset_in_sector;
                    let end = start + take_len;
                    if f.durable.len() < end {
                        f.durable.resize(end, 0);
                    }
                    f.durable[start..end].copy_from_slice(&write.data[..take_len]);
                }
            }
        }

        // 3. Apply or drop pending un-fsynced set_len
        for (&id, orig) in &guard.files {
            if let Some(new_len) = orig.pending_set_len {
                if rng.gen_bool(0.5) {
                    if let Some(cf) = crashed_files.get_mut(&id) {
                        cf.durable.resize(new_len as usize, 0);
                    }
                }
            }
        }

        // Sync live = durable in recovered image, garbage-collect unreachable unlinked inodes
        let referenced: BTreeSet<u64> = crashed_dirs
            .values()
            .flat_map(|m| m.values().copied())
            .collect();
        crashed_files.retain(|id, f| {
            f.live = f.durable.clone();
            referenced.contains(id)
        });

        let live_dirs = crashed_dirs.clone();
        Self {
            inner: Arc::new(Mutex::new(InnerState {
                next_inode: guard.next_inode,
                files: crashed_files,
                durable_dirs: crashed_dirs,
                live_dirs,
                pending_dir_ops: BTreeMap::new(),
                locked: false,
                fail_sync_at: None,
                sync_calls: 0,
                always_fail_sync: false,
            })),
            available: Arc::new(AtomicU64::new(self.available.load(Ordering::SeqCst))),
            poison_sync: Arc::new(AtomicBool::new(false)),
        }
    }

    fn check_sync_fault(&self, guard: &mut InnerState) -> DiskResult<()> {
        if self.poison_sync.load(Ordering::SeqCst) || guard.always_fail_sync {
            return Err(DiskError::IoError);
        }
        guard.sync_calls += 1;
        if let Some(limit) = guard.fail_sync_at {
            if guard.sync_calls >= limit {
                guard.always_fail_sync = true;
                return Err(DiskError::IoError);
            }
        }
        Ok(())
    }
}

fn split_dir_file(rel: &str) -> DiskResult<(String, String)> {
    let trimmed = rel.trim_matches('/');
    if trimmed.is_empty() || trimmed.contains("..") {
        return Err(DiskError::InvalidInput);
    }
    match trimmed.rsplit_once('/') {
        Some((dir, name)) => {
            if name.is_empty() {
                return Err(DiskError::InvalidInput);
            }
            Ok((dir.to_string(), name.to_string()))
        }
        None => Ok((String::new(), trimmed.to_string())),
    }
}

fn normalize_dir(rel_dir: &str) -> DiskResult<String> {
    let trimmed = rel_dir.trim_matches('/');
    if trimmed == "." || trimmed.is_empty() {
        return Ok(String::new());
    }
    if trimmed.contains("..") {
        return Err(DiskError::InvalidInput);
    }
    Ok(trimmed.to_string())
}

pub struct FaultFile {
    disk: FaultDisk,
    inode_id: u64,
    readable: bool,
    writable: bool,
}

impl DiskFile for FaultFile {
    fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> DiskResult<()> {
        if !self.readable {
            return Err(DiskError::InvalidInput);
        }
        let guard = self.disk.inner.lock().unwrap();
        let file = guard.files.get(&self.inode_id).ok_or(DiskError::IoError)?;
        let start = offset as usize;
        let end = start.checked_add(buf.len()).ok_or(DiskError::InvalidInput)?;
        if end > file.live.len() {
            return Err(DiskError::UnexpectedEof);
        }
        buf.copy_from_slice(&file.live[start..end]);
        Ok(())
    }

    fn write_all_at(&self, offset: u64, buf: &[u8]) -> DiskResult<()> {
        if !self.writable {
            return Err(DiskError::InvalidInput);
        }
        if buf.is_empty() {
            return Ok(());
        }
        let mut guard = self.disk.inner.lock().unwrap();
        let file = guard
            .files
            .get_mut(&self.inode_id)
            .ok_or(DiskError::IoError)?;
        let start = offset as usize;
        let end = start.checked_add(buf.len()).ok_or(DiskError::InvalidInput)?;
        if file.live.len() < end {
            file.live.resize(end, 0);
        }
        file.live[start..end].copy_from_slice(buf);

        // Split write into 4 KiB sector chunks for adversarial crash modeling
        let mut cursor = 0usize;
        while cursor < buf.len() {
            let abs = start + cursor;
            let sector_idx = abs / SECTOR_SIZE;
            let offset_in_sector = abs % SECTOR_SIZE;
            let chunk_len = (SECTOR_SIZE - offset_in_sector).min(buf.len() - cursor);
            file.pending_sectors.push(DirtySectorWrite {
                inode_id: self.inode_id,
                sector_idx,
                offset_in_sector,
                data: buf[cursor..cursor + chunk_len].to_vec(),
            });
            cursor += chunk_len;
        }
        Ok(())
    }

    fn set_len(&self, size: u64) -> DiskResult<()> {
        if !self.writable {
            return Err(DiskError::InvalidInput);
        }
        let mut guard = self.disk.inner.lock().unwrap();
        let file = guard
            .files
            .get_mut(&self.inode_id)
            .ok_or(DiskError::IoError)?;
        file.live.resize(size as usize, 0);
        file.pending_set_len = Some(size);
        Ok(())
    }

    fn len(&self) -> DiskResult<u64> {
        let guard = self.disk.inner.lock().unwrap();
        let file = guard.files.get(&self.inode_id).ok_or(DiskError::IoError)?;
        Ok(file.live.len() as u64)
    }

    fn sync_data(&self) -> DiskResult<()> {
        let mut guard = self.disk.inner.lock().unwrap();
        self.disk.check_sync_fault(&mut guard)?;
        let file = guard
            .files
            .get_mut(&self.inode_id)
            .ok_or(DiskError::IoError)?;
        file.durable = file.live.clone();
        file.pending_sectors.clear();
        file.pending_set_len = None;
        Ok(())
    }
}

struct FaultLockGuard {
    inner: Arc<Mutex<InnerState>>,
}

impl Drop for FaultLockGuard {
    fn drop(&mut self) {
        if let Ok(mut guard) = self.inner.lock() {
            guard.locked = false;
        }
    }
}

impl Disk for FaultDisk {
    type File = FaultFile;

    fn open(&self, rel_path: &str, opts: OpenOpts) -> DiskResult<Self::File> {
        let (dir, name) = split_dir_file(rel_path)?;
        let mut guard = self.inner.lock().unwrap();
        if !guard.live_dirs.contains_key(&dir) {
            return Err(DiskError::NotFound);
        }
        let existing = guard.live_dirs.get(&dir).and_then(|d| d.get(&name)).copied();
        let inode_id = match existing {
            Some(_) if opts.create_new => return Err(DiskError::AlreadyExists),
            Some(id) => {
                if opts.truncate {
                    if !opts.write {
                        return Err(DiskError::InvalidInput);
                    }
                    if let Some(f) = guard.files.get_mut(&id) {
                        f.live.clear();
                        f.pending_set_len = Some(0);
                    }
                }
                id
            }
            None => {
                if !(opts.create || opts.create_new) {
                    return Err(DiskError::NotFound);
                }
                let id = guard.next_inode;
                guard.next_inode += 1;
                guard.files.insert(id, FileState::default());
                guard
                    .live_dirs
                    .get_mut(&dir)
                    .unwrap()
                    .insert(name.clone(), id);
                guard
                    .pending_dir_ops
                    .entry(dir)
                    .or_default()
                    .push(PendingDirOp::Link {
                        name,
                        inode_id: id,
                    });
                id
            }
        };

        Ok(FaultFile {
            disk: self.clone(),
            inode_id,
            readable: opts.read,
            writable: opts.write,
        })
    }

    fn rename(&self, from: &str, to: &str) -> DiskResult<()> {
        let (from_dir, from_name) = split_dir_file(from)?;
        let (to_dir, to_name) = split_dir_file(to)?;
        let mut guard = self.inner.lock().unwrap();
        if !guard.live_dirs.contains_key(&to_dir) {
            return Err(DiskError::NotFound);
        }
        let inode_id = guard
            .live_dirs
            .get_mut(&from_dir)
            .and_then(|d| d.remove(&from_name))
            .ok_or(DiskError::NotFound)?;
        guard
            .live_dirs
            .get_mut(&to_dir)
            .unwrap()
            .insert(to_name.clone(), inode_id);
        guard
            .pending_dir_ops
            .entry(to_dir)
            .or_default()
            .push(PendingDirOp::Rename {
                from_dir,
                from_name,
                to_name,
                inode_id,
            });
        Ok(())
    }

    fn remove_file(&self, rel_path: &str) -> DiskResult<()> {
        let (dir, name) = split_dir_file(rel_path)?;
        let mut guard = self.inner.lock().unwrap();
        let removed = guard
            .live_dirs
            .get_mut(&dir)
            .and_then(|d| d.remove(&name));
        if removed.is_none() {
            return Err(DiskError::NotFound);
        }
        guard
            .pending_dir_ops
            .entry(dir)
            .or_default()
            .push(PendingDirOp::Unlink { name });
        Ok(())
    }

    fn exists(&self, rel_path: &str) -> DiskResult<bool> {
        let (dir, name) = split_dir_file(rel_path)?;
        let guard = self.inner.lock().unwrap();
        Ok(guard
            .live_dirs
            .get(&dir)
            .is_some_and(|d| d.contains_key(&name)))
    }

    fn read_dir(&self, rel_dir: &str) -> DiskResult<Vec<String>> {
        let dir = normalize_dir(rel_dir)?;
        let guard = self.inner.lock().unwrap();
        let entries = guard.live_dirs.get(&dir).ok_or(DiskError::NotFound)?;
        Ok(entries.keys().cloned().collect())
    }

    fn create_dir_all(&self, rel_dir: &str) -> DiskResult<()> {
        let dir = normalize_dir(rel_dir)?;
        let mut guard = self.inner.lock().unwrap();
        if dir.is_empty() {
            return Ok(());
        }
        let mut cur = String::new();
        for part in dir.split('/') {
            if !cur.is_empty() {
                cur.push('/');
            }
            cur.push_str(part);
            guard.live_dirs.entry(cur.clone()).or_default();
            guard.durable_dirs.entry(cur.clone()).or_default();
        }
        Ok(())
    }

    fn sync_dir(&self, rel_dir: &str) -> DiskResult<()> {
        let dir = normalize_dir(rel_dir)?;
        let mut guard = self.inner.lock().unwrap();
        self.check_sync_fault(&mut guard)?;
        if !guard.live_dirs.contains_key(&dir) {
            return Err(DiskError::NotFound);
        }
        if let Some(ops) = guard.pending_dir_ops.remove(&dir) {
            for op in ops {
                if let PendingDirOp::Rename {
                    from_dir,
                    from_name,
                    ..
                } = op
                {
                    if let Some(src) = guard.durable_dirs.get_mut(&from_dir) {
                        src.remove(&from_name);
                    }
                }
            }
        }
        let snapshot = guard.live_dirs.get(&dir).cloned().unwrap_or_default();
        guard.durable_dirs.insert(dir, snapshot);
        Ok(())
    }

    fn available_bytes(&self) -> DiskResult<u64> {
        Ok(self.available.load(Ordering::SeqCst))
    }

    fn try_lock_exclusive(&self) -> DiskResult<Box<dyn Send + Sync>> {
        let mut guard = self.inner.lock().unwrap();
        if guard.locked {
            return Err(DiskError::Locked);
        }
        guard.locked = true;
        Ok(Box::new(FaultLockGuard {
            inner: Arc::clone(&self.inner),
        }))
    }
}
