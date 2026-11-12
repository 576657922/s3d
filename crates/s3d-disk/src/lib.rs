pub mod fault;
pub mod os;

pub use fault::{FaultDisk, FaultFile, SECTOR_SIZE};
pub use os::{OsDisk, OsFile};

use thiserror::Error;

pub type DiskResult<T> = Result<T, DiskError>;

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum DiskError {
    #[error("file or directory not found")]
    NotFound,
    #[error("file already exists")]
    AlreadyExists,
    #[error("disk I/O failure (EIO)")]
    IoError,
    #[error("no space left on device (ENOSPC)")]
    NoSpace,
    #[error("unexpected EOF during positioned read")]
    UnexpectedEof,
    #[error("invalid path or argument")]
    InvalidInput,
    #[error("data directory is already locked by another process")]
    Locked,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct OpenOpts {
    pub read: bool,
    pub write: bool,
    pub create: bool,
    pub create_new: bool,
    pub truncate: bool,
}

impl OpenOpts {
    pub const fn read_only() -> Self {
        Self {
            read: true,
            write: false,
            create: false,
            create_new: false,
            truncate: false,
        }
    }

    pub const fn create_new_rw() -> Self {
        Self {
            read: true,
            write: true,
            create: true,
            create_new: true,
            truncate: false,
        }
    }

    pub const fn open_rw() -> Self {
        Self {
            read: true,
            write: true,
            create: false,
            create_new: false,
            truncate: false,
        }
    }

    pub const fn create_truncate_rw() -> Self {
        Self {
            read: true,
            write: true,
            create: true,
            create_new: false,
            truncate: true,
        }
    }
}

pub trait DiskFile: Send + Sync + 'static {
    fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> DiskResult<()>;
    fn write_all_at(&self, offset: u64, buf: &[u8]) -> DiskResult<()>;
    fn set_len(&self, size: u64) -> DiskResult<()>;
    fn len(&self) -> DiskResult<u64>;
    fn sync_data(&self) -> DiskResult<()>;
}

pub trait Disk: Clone + Send + Sync + 'static {
    type File: DiskFile;

    fn open(&self, rel_path: &str, opts: OpenOpts) -> DiskResult<Self::File>;
    fn rename(&self, from: &str, to: &str) -> DiskResult<()>;
    fn remove_file(&self, rel_path: &str) -> DiskResult<()>;
    fn exists(&self, rel_path: &str) -> DiskResult<bool>;
    fn read_dir(&self, rel_dir: &str) -> DiskResult<Vec<String>>;
    fn create_dir_all(&self, rel_dir: &str) -> DiskResult<()>;
    fn sync_dir(&self, rel_dir: &str) -> DiskResult<()>;
    fn available_bytes(&self) -> DiskResult<u64>;
    fn try_lock_exclusive(&self) -> DiskResult<Box<dyn Send + Sync>>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;

    fn run_disk_contract<D: Disk>(disk: &D) {
        let guard = disk.try_lock_exclusive().unwrap();
        assert_eq!(disk.try_lock_exclusive().err(), Some(DiskError::Locked));
        drop(guard);
        let _guard2 = disk.try_lock_exclusive().unwrap();

        assert!(disk.available_bytes().unwrap() > 0);
        assert_eq!(disk.open("../escape", OpenOpts::read_only()).err(), Some(DiskError::InvalidInput));

        disk.create_dir_all("wal").unwrap();
        disk.create_dir_all("tmp").unwrap();

        let f = disk.open("tmp/a.tmp", OpenOpts::create_new_rw()).unwrap();
        assert_eq!(disk.open("tmp/a.tmp", OpenOpts::create_new_rw()).err(), Some(DiskError::AlreadyExists));

        f.write_all_at(0, b"hello ").unwrap();
        f.write_all_at(6, b"world").unwrap();
        assert_eq!(f.len().unwrap(), 11);
        f.sync_data().unwrap();
        drop(f);

        disk.rename("tmp/a.tmp", "wal/00000001.log").unwrap();
        disk.sync_dir("wal").unwrap();
        assert!(!disk.exists("tmp/a.tmp").unwrap());
        assert!(disk.exists("wal/00000001.log").unwrap());
        assert_eq!(disk.read_dir("wal").unwrap(), vec!["00000001.log".to_string()]);

        let r = disk.open("wal/00000001.log", OpenOpts::open_rw()).unwrap();
        let mut buf = [0u8; 11];
        r.read_exact_at(0, &mut buf).unwrap();
        assert_eq!(&buf, b"hello world");

        r.set_len(5).unwrap();
        r.sync_data().unwrap();
        assert_eq!(r.len().unwrap(), 5);
        assert_eq!(r.read_exact_at(0, &mut buf).err(), Some(DiskError::UnexpectedEof));
        drop(r);

        disk.remove_file("wal/00000001.log").unwrap();
        disk.sync_dir("wal").unwrap();
        assert!(!disk.exists("wal/00000001.log").unwrap());
    }

    #[test]
    fn os_disk_contract() {
        let dir = tempfile::tempdir().unwrap();
        let disk = OsDisk::new(dir.path()).unwrap();
        run_disk_contract(&disk);
    }

    #[test]
    fn fault_disk_contract_and_power_cut() {
        let disk = FaultDisk::new();
        run_disk_contract(&disk);

        // Verify synced data survives power cut while unsynced writes can tear/drop
        disk.create_dir_all("seg").unwrap();
        let f = disk.open("seg/00000001.seg", OpenOpts::create_new_rw()).unwrap();
        f.write_all_at(0, &[0xAA; 8192]).unwrap();
        f.sync_data().unwrap();
        disk.sync_dir("seg").unwrap();

        // Unsynced write on top
        f.write_all_at(8192, &[0xBB; 8192]).unwrap();

        let mut rng = rand::rngs::StdRng::seed_from_u64(42);
        let crashed = disk.power_cut(&mut rng);
        let rf = crashed.open("seg/00000001.seg", OpenOpts::read_only()).unwrap();
        let mut head = [0u8; 8192];
        rf.read_exact_at(0, &mut head).unwrap();
        assert_eq!(head, [0xAA; 8192]);

        // Verify sync EIO injection
        crashed.fail_sync_after(1);
        let wf = crashed.open("seg/00000001.seg", OpenOpts::open_rw()).unwrap();
        wf.write_all_at(0, b"x").unwrap();
        assert_eq!(wf.sync_data().err(), Some(DiskError::IoError));
        assert_eq!(wf.sync_data().err(), Some(DiskError::IoError));
    }
}
