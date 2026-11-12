use serde::{Deserialize, Serialize};
use s3d_types::{
    ChecksumState, ObjectOwnership, OwnerInfo, SystemMeta, VersioningStatus,
};

pub const FORMAT_MAGIC: &[u8; 8] = b"S3DFMT01";
pub const FORMAT_VERSION: u32 = 1;
pub const FORMAT_FILE_LEN: usize = 48;

pub const SEG_HEADER_MAGIC: &[u8; 8] = b"S3DSEG01";
pub const SEG_HEADER_LEN: u64 = 32;
pub const BLOCK_MAGIC: u32 = 0x5333_424B; // "S3BK"
pub const BLOCK_HEADER_LEN: u64 = 12;
pub const DEFAULT_MAX_BLOCK_PAYLOAD: usize = 1024 * 1024; // 1 MiB

pub const WAL_HEADER_MAGIC: &[u8; 8] = b"S3DWAL01";
pub const WAL_HEADER_LEN: u64 = 32;
pub const MAX_WAL_RECORD_LEN: u32 = 16 * 1024 * 1024; // 16 MiB

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FormatFile {
    pub format_ver: u32,
    pub flags: u32,
    pub instance_uuid: [u8; 16],
    pub created_ms: i64,
}

impl FormatFile {
    pub fn encode(&self) -> [u8; FORMAT_FILE_LEN] {
        let mut buf = [0u8; FORMAT_FILE_LEN];
        buf[0..8].copy_from_slice(FORMAT_MAGIC);
        buf[8..12].copy_from_slice(&self.format_ver.to_le_bytes());
        buf[12..16].copy_from_slice(&self.flags.to_le_bytes());
        buf[16..32].copy_from_slice(&self.instance_uuid);
        buf[32..40].copy_from_slice(&self.created_ms.to_le_bytes());
        buf[40..44].copy_from_slice(&0u32.to_le_bytes());
        let crc = crc32c::crc32c(&buf[0..44]);
        buf[44..48].copy_from_slice(&crc.to_le_bytes());
        buf
    }

    pub fn decode(buf: &[u8; FORMAT_FILE_LEN]) -> Result<Self, String> {
        if &buf[0..8] != FORMAT_MAGIC {
            return Err("invalid FORMAT magic".into());
        }
        let expected_crc = u32::from_le_bytes(buf[44..48].try_into().unwrap());
        let actual_crc = crc32c::crc32c(&buf[0..44]);
        if expected_crc != actual_crc {
            return Err("FORMAT checksum mismatch".into());
        }
        let format_ver = u32::from_le_bytes(buf[8..12].try_into().unwrap());
        if format_ver != FORMAT_VERSION {
            return Err(format!("unsupported FORMAT version {format_ver}"));
        }
        let flags = u32::from_le_bytes(buf[12..16].try_into().unwrap());
        let mut instance_uuid = [0u8; 16];
        instance_uuid.copy_from_slice(&buf[16..32]);
        let created_ms = i64::from_le_bytes(buf[32..40].try_into().unwrap());
        Ok(Self {
            format_ver,
            flags,
            instance_uuid,
            created_ms,
        })
    }

    pub fn uuid_lo(&self) -> u64 {
        u64::from_le_bytes(self.instance_uuid[0..8].try_into().unwrap())
    }
}

pub fn encode_seg_header(seg_id: u32, uuid_lo: u64, created_sec: u32) -> [u8; 32] {
    let mut buf = [0u8; 32];
    buf[0..8].copy_from_slice(SEG_HEADER_MAGIC);
    buf[8..12].copy_from_slice(&seg_id.to_le_bytes());
    buf[12..16].copy_from_slice(&FORMAT_VERSION.to_le_bytes());
    buf[16..24].copy_from_slice(&uuid_lo.to_le_bytes());
    buf[24..28].copy_from_slice(&created_sec.to_le_bytes());
    let crc = crc32c::crc32c(&buf[0..28]);
    buf[28..32].copy_from_slice(&crc.to_le_bytes());
    buf
}

pub fn verify_seg_header(buf: &[u8; 32], expected_seg_id: u32, uuid_lo: u64) -> Result<(), String> {
    if &buf[0..8] != SEG_HEADER_MAGIC {
        return Err(format!("segment {expected_seg_id}: invalid magic"));
    }
    let expected_crc = u32::from_le_bytes(buf[28..32].try_into().unwrap());
    if crc32c::crc32c(&buf[0..28]) != expected_crc {
        return Err(format!("segment {expected_seg_id}: header CRC mismatch"));
    }
    let seg_id = u32::from_le_bytes(buf[8..12].try_into().unwrap());
    let ver = u32::from_le_bytes(buf[12..16].try_into().unwrap());
    let inst = u64::from_le_bytes(buf[16..24].try_into().unwrap());
    if seg_id != expected_seg_id || ver != FORMAT_VERSION || inst != uuid_lo {
        return Err(format!("segment {expected_seg_id}: header metadata mismatch"));
    }
    Ok(())
}

pub fn encode_block_header(payload_len: u32, payload_crc32c: u32) -> [u8; 12] {
    let mut hdr = [0u8; 12];
    hdr[0..4].copy_from_slice(&BLOCK_MAGIC.to_le_bytes());
    hdr[4..8].copy_from_slice(&payload_len.to_le_bytes());
    hdr[8..12].copy_from_slice(&payload_crc32c.to_le_bytes());
    hdr
}

pub fn decode_block_header(hdr: &[u8; 12]) -> Result<(u32, u32), String> {
    let magic = u32::from_le_bytes(hdr[0..4].try_into().unwrap());
    if magic != BLOCK_MAGIC {
        return Err(format!("corrupt block magic 0x{magic:08x}"));
    }
    let len = u32::from_le_bytes(hdr[4..8].try_into().unwrap());
    let crc = u32::from_le_bytes(hdr[8..12].try_into().unwrap());
    Ok((len, crc))
}

pub fn encode_wal_header(wal_seq: u32, first_lsn: u64, uuid_lo: u64) -> [u8; 32] {
    let mut buf = [0u8; 32];
    buf[0..8].copy_from_slice(WAL_HEADER_MAGIC);
    buf[8..12].copy_from_slice(&wal_seq.to_le_bytes());
    // [12..16] = header_crc32c computed over [0..12] + [16..32]
    buf[16..24].copy_from_slice(&first_lsn.to_le_bytes());
    buf[24..32].copy_from_slice(&uuid_lo.to_le_bytes());
    let mut crc = crc32c::crc32c(&buf[0..12]);
    crc = crc32c::crc32c_append(crc, &buf[16..32]);
    buf[12..16].copy_from_slice(&crc.to_le_bytes());
    buf
}

pub fn decode_wal_header(
    buf: &[u8; 32],
    expected_wal_seq: u32,
    uuid_lo: u64,
) -> Result<u64, String> {
    if &buf[0..8] != WAL_HEADER_MAGIC {
        return Err(format!("wal {expected_wal_seq}: invalid magic"));
    }
    let expected_crc = u32::from_le_bytes(buf[12..16].try_into().unwrap());
    let mut crc = crc32c::crc32c(&buf[0..12]);
    crc = crc32c::crc32c_append(crc, &buf[16..32]);
    if crc != expected_crc {
        return Err(format!("wal {expected_wal_seq}: header CRC mismatch"));
    }
    let seq = u32::from_le_bytes(buf[8..12].try_into().unwrap());
    let first_lsn = u64::from_le_bytes(buf[16..24].try_into().unwrap());
    let inst = u64::from_le_bytes(buf[24..32].try_into().unwrap());
    if seq != expected_wal_seq || inst != uuid_lo {
        return Err(format!("wal {expected_wal_seq}: metadata mismatch"));
    }
    Ok(first_lsn)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Extent {
    pub seg_id: u32,
    pub offset: u64,
    pub len: u32,
    pub crc32c: u32,
}

impl Extent {
    pub const fn physical_bytes(&self) -> u64 {
        BLOCK_HEADER_LEN + self.len as u64
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelocatedExtent {
    pub bucket: String,
    pub key: String,
    pub seq: u64,
    pub extent_idx: usize,
    pub old_seg_id: u32,
    pub old_offset: u64,
    pub new_extent: Extent,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WalOp {
    CreateBucket {
        name: String,
        owner: OwnerInfo,
        region: String,
        created_ms: i64,
        ownership: ObjectOwnership,
    },
    UpdateBucketVersioning {
        name: String,
        versioning: VersioningStatus,
    },
    DeleteBucket {
        name: String,
    },
    PutVersion {
        bucket: String,
        key: String,
        seq: u64,
        version_id: Option<String>,
        is_delete_marker: bool,
        total_size: u64,
        etag: String,
        checksum: ChecksumState,
        sys_meta: SystemMeta,
        user_meta: Vec<(String, String)>,
        owner: OwnerInfo,
        last_modified_ms: i64,
        extents: Vec<Extent>,
        part_sizes: Option<Vec<u64>>,
    },
    DeleteVersion {
        bucket: String,
        key: String,
        version_id: Option<String>,
    },
    CreateSegment {
        seg_id: u32,
    },
    RelocateExtents {
        items: Vec<RelocatedExtent>,
    },
    DeleteSegment {
        seg_id: u32,
    },
}

impl WalOp {
    pub const fn op_type_code(&self) -> u8 {
        match self {
            Self::CreateBucket { .. } => 0x10,
            Self::UpdateBucketVersioning { .. } => 0x11,
            Self::DeleteBucket { .. } => 0x12,
            Self::PutVersion { .. } => 0x20,
            Self::DeleteVersion { .. } => 0x21,
            Self::CreateSegment { .. } => 0x40,
            Self::RelocateExtents { .. } => 0x41,
            Self::DeleteSegment { .. } => 0x42,
        }
    }
}

pub const WAL_RECORD_MAGIC: u32 = 0x5333_5752; // "S3WR" framing sentinel for synced_lsn scan

/// Encode a WAL record:
/// `record_magic:u32 | body_len:u32 | crc32c:u32 | lsn:u64 | synced_lsn:u64 | type:u8 | ver:u8 | payload`
/// `body_len` = `8 (lsn) + 8 (synced_lsn) + 1 (type) + 1 (ver) + payload.len()`.
/// `crc32c` covers `record_magic (4B) + body_len (4B) + body (body_len B)`.
pub fn encode_wal_record(lsn: u64, synced_lsn: u64, op: &WalOp, out: &mut Vec<u8>) {
    let payload = serde_json::to_vec(op).expect("WalOp serialization cannot fail");
    let body_len = (18 + payload.len()) as u32;
    let start_pos = out.len();

    out.extend_from_slice(&WAL_RECORD_MAGIC.to_le_bytes());
    out.extend_from_slice(&body_len.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes()); // crc placeholder at start_pos + 8
    out.extend_from_slice(&lsn.to_le_bytes());
    out.extend_from_slice(&synced_lsn.to_le_bytes());
    out.push(op.op_type_code());
    out.push(1u8); // schema_ver = 1
    out.extend_from_slice(&payload);

    let mut crc = crc32c::crc32c(&out[start_pos..start_pos + 8]);
    crc = crc32c::crc32c_append(crc, &out[start_pos + 12..]);
    out[start_pos + 8..start_pos + 12].copy_from_slice(&crc.to_le_bytes());
}

#[derive(Debug)]
pub struct DecodedWalRecord {
    pub lsn: u64,
    pub synced_lsn: u64,
    pub op: WalOp,
    pub total_frame_bytes: usize,
}

#[derive(Debug, PartialEq, Eq)]
pub enum WalDecodeError {
    Truncated,
    Corrupt,
}

pub fn decode_wal_record(buf: &[u8]) -> Result<DecodedWalRecord, WalDecodeError> {
    if buf.len() < 12 {
        return Err(WalDecodeError::Truncated);
    }
    let magic = u32::from_le_bytes(buf[0..4].try_into().unwrap());
    if magic != WAL_RECORD_MAGIC {
        return Err(WalDecodeError::Corrupt);
    }
    let body_len = u32::from_le_bytes(buf[4..8].try_into().unwrap());
    if !(18..=MAX_WAL_RECORD_LEN).contains(&body_len) {
        return Err(WalDecodeError::Corrupt);
    }
    let total_frame_bytes = 12 + body_len as usize;
    if buf.len() < total_frame_bytes {
        return Err(WalDecodeError::Truncated);
    }

    let expected_crc = u32::from_le_bytes(buf[8..12].try_into().unwrap());
    let mut crc = crc32c::crc32c(&buf[0..8]);
    crc = crc32c::crc32c_append(crc, &buf[12..total_frame_bytes]);
    if crc != expected_crc {
        return Err(WalDecodeError::Corrupt);
    }

    let lsn = u64::from_le_bytes(buf[12..20].try_into().unwrap());
    let synced_lsn = u64::from_le_bytes(buf[20..28].try_into().unwrap());
    let _op_type = buf[28];
    let ver = buf[29];
    if ver != 1 {
        return Err(WalDecodeError::Corrupt);
    }
    let op: WalOp =
        serde_json::from_slice(&buf[30..total_frame_bytes]).map_err(|_| WalDecodeError::Corrupt)?;

    Ok(DecodedWalRecord {
        lsn,
        synced_lsn,
        op,
        total_frame_bytes,
    })
}

/// Look ahead after a corrupt/truncated byte offset in the last WAL file to check if ANY valid
/// subsequent record exists with `synced_lsn >= failed_expected_lsn` (proving `failed_expected_lsn`
/// was already committed before a later `fdatasync`, i.e., mid-WAL corruption per ST-6!).
pub fn has_later_committed_record(tail: &[u8], failed_expected_lsn: u64) -> bool {
    let magic_bytes = WAL_RECORD_MAGIC.to_le_bytes();
    let mut i = 1usize;
    while i + 30 <= tail.len() {
        if tail[i..i + 4] == magic_bytes {
            if let Ok(rec) = decode_wal_record(&tail[i..]) {
                if rec.lsn > failed_expected_lsn && rec.synced_lsn >= failed_expected_lsn {
                    return true;
                }
            }
        }
        i += 1;
    }
    false
}
