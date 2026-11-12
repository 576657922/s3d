use std::ffi::CString;
use std::fs::{self, File, OpenOptions as StdOpenOptions};
use std::io::ErrorKind;
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::FileExt;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

use crate::{Disk, DiskError, DiskFile, DiskResult, OpenOpts};

#[derive(Clone)]
pub struct OsDisk {
    root: Arc<PathBuf>,
}

impl OsDisk {
    pub fn new(root: impl AsRef<Path>) -> DiskResult<Self> {
        let root = root.as_ref().to_path_buf();
        fs::create_dir_all(&root).map_err(map_io_err)?;
        Ok(Self {
            root: Arc::new(root),
        })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Open a file with OS page-cache bypass enabled where supported (`F_NOCACHE` on macOS,
    /// matching `fio --direct=1` for `VR-9` sequential disk bandwidth baselines).
    pub fn open_uncached(&self, rel_path: &str, opts: OpenOpts) -> DiskResult<OsFile> {
        let f = self.open(rel_path, opts)?;
        set_fd_nocache(&f.file)?;
        Ok(f)
    }

    fn resolve(&self, rel: &str) -> DiskResult<PathBuf> {
        if rel.is_empty() || rel == "." {
            return Ok((*self.root).clone());
        }
        let p = Path::new(rel);
        for comp in p.components() {
            match comp {
                Component::Normal(_) | Component::CurDir => {}
                Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                    return Err(DiskError::InvalidInput);
                }
            }
        }
        Ok(self.root.join(p))
    }
}

pub struct OsFile {
    file: File,
}

impl DiskFile for OsFile {
    fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> DiskResult<()> {
        self.file.read_exact_at(buf, offset).map_err(map_io_err)
    }

    fn write_all_at(&self, offset: u64, buf: &[u8]) -> DiskResult<()> {
        self.file.write_all_at(buf, offset).map_err(map_io_err)
    }

    fn set_len(&self, size: u64) -> DiskResult<()> {
        self.file.set_len(size).map_err(map_io_err)
    }

    fn len(&self) -> DiskResult<u64> {
        Ok(self.file.metadata().map_err(map_io_err)?.len())
    }

    fn sync_data(&self) -> DiskResult<()> {
        self.file.sync_data().map_err(map_io_err)
    }
}

struct LockGuard {
    _file: File,
}

impl Disk for OsDisk {
    type File = OsFile;

    fn open(&self, rel_path: &str, opts: OpenOpts) -> DiskResult<Self::File> {
        let full = self.resolve(rel_path)?;
        let mut std_opts = StdOpenOptions::new();
        std_opts
            .read(opts.read)
            .write(opts.write)
            .create(opts.create)
            .create_new(opts.create_new)
            .truncate(opts.truncate);
        let file = std_opts.open(full).map_err(map_io_err)?;
        Ok(OsFile { file })
    }

    fn rename(&self, from: &str, to: &str) -> DiskResult<()> {
        let src = self.resolve(from)?;
        let dst = self.resolve(to)?;
        fs::rename(src, dst).map_err(map_io_err)
    }

    fn remove_file(&self, rel_path: &str) -> DiskResult<()> {
        let full = self.resolve(rel_path)?;
        fs::remove_file(full).map_err(map_io_err)
    }

    fn exists(&self, rel_path: &str) -> DiskResult<bool> {
        let full = self.resolve(rel_path)?;
        Ok(full.exists())
    }

    fn read_dir(&self, rel_dir: &str) -> DiskResult<Vec<String>> {
        let full = self.resolve(rel_dir)?;
        let mut entries = Vec::new();
        for entry in fs::read_dir(full).map_err(map_io_err)? {
            let entry = entry.map_err(map_io_err)?;
            if let Some(name) = entry.file_name().to_str() {
                entries.push(name.to_string());
            }
        }
        entries.sort();
        Ok(entries)
    }

    fn create_dir_all(&self, rel_dir: &str) -> DiskResult<()> {
        let full = self.resolve(rel_dir)?;
        fs::create_dir_all(full).map_err(map_io_err)
    }

    fn sync_dir(&self, rel_dir: &str) -> DiskResult<()> {
        let full = self.resolve(rel_dir)?;
        let dir_file = File::open(full).map_err(map_io_err)?;
        dir_file.sync_all().map_err(map_io_err)
    }

    fn available_bytes(&self) -> DiskResult<u64> {
        statvfs_available_bytes(&self.root)
    }

    fn try_lock_exclusive(&self) -> DiskResult<Box<dyn Send + Sync>> {
        let lock_path = self.resolve("LOCK")?;
        let file = StdOpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(lock_path)
            .map_err(map_io_err)?;
        file.try_lock().map_err(|_| DiskError::Locked)?;
        Ok(Box::new(LockGuard { _file: file }))
    }
}

fn map_io_err(err: std::io::Error) -> DiskError {
    match err.kind() {
        ErrorKind::NotFound => DiskError::NotFound,
        ErrorKind::AlreadyExists => DiskError::AlreadyExists,
        ErrorKind::UnexpectedEof => DiskError::UnexpectedEof,
        ErrorKind::InvalidInput => DiskError::InvalidInput,
        ErrorKind::StorageFull => DiskError::NoSpace,
        _ => match err.raw_os_error() {
            Some(libc::ENOSPC) => DiskError::NoSpace,
            _ => DiskError::IoError,
        },
    }
}

/// Isolated FFI wrapper around POSIX `statvfs` (reviewed per `VR-10`).
#[allow(unsafe_code)]
fn statvfs_available_bytes(path: &Path) -> DiskResult<u64> {
    let c_path =
        CString::new(path.as_os_str().as_bytes()).map_err(|_| DiskError::InvalidInput)?;
    // SAFETY: `statvfs` is a plain C struct of POD integer fields (`u64`/`u32`/`c_ulong`)
    // with no non-zero niche invariants; zero-initializing it before passing a valid mutable
    // pointer and NUL-terminated `c_path.as_ptr()` to `libc::statvfs` is sound.
    let mut stat: libc::statvfs = unsafe { std::mem::zeroed() };
    // SAFETY: `c_path` is alive and NUL-terminated for the duration of the call, and `&mut stat`
    // points to a valid writable `libc::statvfs` on the stack.
    let rc = unsafe { libc::statvfs(c_path.as_ptr(), &mut stat) };
    if rc != 0 {
        return Err(DiskError::IoError);
    }
    let frsize = if stat.f_frsize > 0 {
        stat.f_frsize as u64
    } else {
        stat.f_bsize as u64
    };
    Ok((stat.f_bavail as u64).saturating_mul(frsize))
}

/// Isolated FFI wrapper enabling `F_NOCACHE` on macOS (`VR-10` audited).
#[allow(unsafe_code)]
fn set_fd_nocache(file: &File) -> DiskResult<()> {
    #[cfg(target_os = "macos")]
    {
        let fd = file.as_raw_fd();
        // SAFETY: `file` is an open `std::fs::File` whose raw file descriptor `fd` remains valid
        // for the duration of this call; `F_NOCACHE` takes a single `c_int` (`1`) argument and
        // does not alias or mutate any Rust memory.
        let rc = unsafe { libc::fcntl(fd, libc::F_NOCACHE, 1 as libc::c_int) };
        if rc == -1 {
            return Err(DiskError::IoError);
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = file;
    }
    Ok(())
}
