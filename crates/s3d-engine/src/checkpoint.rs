use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::Arc;

use s3d_disk::{DiskError, DiskFile};
use s3d_types::{
    AccessControlPolicy, AclGrant, AclPermission, BucketEncryptionConfig, BucketLoggingStatus,
    BucketPolicyDoc, ChecksumAlgorithm, ChecksumState, ChecksumType, CompleteMultipartUploadResp,
    CorsConfiguration, LegalHoldStatus, LifecycleConfiguration, ObjectLockConfiguration,
    ObjectOwnership, ObjectRetention, OwnerInfo, PublicAccessBlockConfig, SseStoredMeta,
    SystemMeta, VersioningStatus,
};

use crate::catalog::{
    BucketEntry, MemoryCatalog, MultipartUploadEntry, ObjectVersionEntry, UploadPartEntry,
};
use crate::format::{Extent, PartBoundaryInfo, FORMAT_VERSION};

pub const CKPT_HEADER_MAGIC: &[u8; 8] = b"S3DCKP01";
pub const CKPT_FOOTER_MAGIC: &[u8; 8] = b"S3DCKEND";
pub const CKPT_CHUNK_MAGIC: u32 = 0x5333_434B; // "S3CK"
pub const CKPT_HEADER_LEN: usize = 64;
pub const CKPT_FOOTER_LEN: usize = 32;
pub const CKPT_STREAM_CHUNK_TARGET: usize = 256 * 1024; // 256 KiB streaming chunk
pub const CKPT_MAX_CHUNK_LEN: usize = 4 * 1024 * 1024; // 4 MiB hard cap for fuzz/corruption safety

const VFLAG_HAS_VERSION_ID: u8 = 1 << 0;
const VFLAG_IS_DELETE_MARKER: u8 = 1 << 1;
const VFLAG_CSUM_CLIENT_REQ: u8 = 1 << 2;
const VFLAG_DEFAULT_OWNER_ACL: u8 = 1 << 3;
const VFLAG_HAS_USER_META: u8 = 1 << 4;
const VFLAG_HAS_TAGS: u8 = 1 << 5;
const VFLAG_HAS_PARTS: u8 = 1 << 6;

#[derive(Debug)]
pub struct LoadedCheckpoint {
    pub ckpt_lsn: u64,
    pub next_seg_id: u32,
    pub live_segments: BTreeSet<u32>,
    pub catalog: MemoryCatalog,
}

/// Write a full checkpoint snapshot directly to `file` in `256 KiB` CRC32C-framed chunks (`ST-8`).
pub fn write_checkpoint_to_file<F: DiskFile>(
    file: &F,
    uuid_lo: u64,
    ckpt_lsn: u64,
    next_seq: u64,
    next_seg_id: u32,
    live_segments: &BTreeSet<u32>,
    catalog: &MemoryCatalog,
) -> Result<u64, DiskError> {
    // 1. Collect interned owners across buckets, versions, and active uploads
    let mut owners: Vec<OwnerInfo> = Vec::new();
    let mut owner_map: HashMap<(String, String, String), u32> = HashMap::new();
    let mut intern_owner = |o: &OwnerInfo| -> u32 {
        let key = (
            o.user_id.clone(),
            o.display_name.clone(),
            o.email.clone(),
        );
        if let Some(&idx) = owner_map.get(&key) {
            idx
        } else {
            let idx = owners.len() as u32;
            owners.push(o.clone());
            owner_map.insert(key, idx);
            idx
        }
    };

    let mut version_count = 0u64;
    let mut upload_count = 0u32;
    for b in catalog.buckets.values() {
        let _ = intern_owner(&b.owner);
        for chain in b.objects.values() {
            version_count += chain.len() as u64;
            for v in chain {
                let _ = intern_owner(&v.owner);
            }
        }
        upload_count = upload_count.saturating_add(b.uploads.len() as u32);
        for up in b.uploads.values() {
            let _ = intern_owner(&up.initiator);
            let _ = intern_owner(&up.owner);
        }
    }

    // 2. Write 64-byte Header
    let mut hdr = [0u8; CKPT_HEADER_LEN];
    hdr[0..8].copy_from_slice(CKPT_HEADER_MAGIC);
    hdr[8..12].copy_from_slice(&FORMAT_VERSION.to_le_bytes());
    hdr[12..16].copy_from_slice(&0u32.to_le_bytes());
    hdr[16..24].copy_from_slice(&uuid_lo.to_le_bytes());
    hdr[24..32].copy_from_slice(&ckpt_lsn.to_le_bytes());
    hdr[32..40].copy_from_slice(&next_seq.to_le_bytes());
    hdr[40..44].copy_from_slice(&next_seg_id.to_le_bytes());
    hdr[44..48].copy_from_slice(&(catalog.buckets.len() as u32).to_le_bytes());
    hdr[48..56].copy_from_slice(&version_count.to_le_bytes());
    hdr[56..60].copy_from_slice(&upload_count.to_le_bytes());
    let hdr_crc = crc32c::crc32c(&hdr[0..60]);
    hdr[60..64].copy_from_slice(&hdr_crc.to_le_bytes());

    let mut writer = ChunkedCkptWriter::new(file);
    writer.write_raw(&hdr)?;

    // Section 1: Owner Intern Table
    writer.put_u32(owners.len() as u32)?;
    for o in &owners {
        writer.put_str(&o.user_id)?;
        writer.put_str(&o.display_name)?;
        writer.put_str(&o.email)?;
    }

    // Section 2: Live Segment IDs
    writer.put_u32(live_segments.len() as u32)?;
    for &seg_id in live_segments {
        writer.put_u32(seg_id)?;
    }

    // Section 3 & 4: Sorted Buckets, Sorted ObjectVersion Chains, and Multipart Uploads
    let lookup_owner = |o: &OwnerInfo| -> u32 {
        *owner_map
            .get(&(o.user_id.clone(), o.display_name.clone(), o.email.clone()))
            .expect("owner was interned in pass 1")
    };

    for b in catalog.buckets.values() {
        writer.put_str(&b.name)?;
        writer.put_u32(lookup_owner(&b.owner))?;
        encode_json_val(&mut writer, &b.acl)?;
        writer.put_str(&b.region)?;
        writer.put_i64(b.created_ms)?;
        writer.put_u8(encode_versioning(b.versioning))?;
        writer.put_u8(encode_opt_ownership(b.explicit_ownership))?;
        encode_tags(&mut writer, &b.tags)?;
        encode_opt_json(&mut writer, b.cors.as_ref())?;
        match &b.policy {
            None => writer.put_u8(0)?,
            Some(doc) => {
                writer.put_u8(1)?;
                writer.put_str(doc.raw_json())?;
            }
        }
        encode_opt_json(&mut writer, b.public_access_block.as_ref())?;
        writer.put_u8(u8::from(b.object_lock_enabled))?;
        encode_opt_json(&mut writer, b.object_lock_config.as_ref())?;
        encode_opt_json(&mut writer, b.lifecycle.as_ref())?;
        encode_opt_json(&mut writer, b.encryption.as_ref())?;
        encode_opt_json(&mut writer, b.logging.as_ref())?;

        // Object chains in ascending UTF-8 key order
        writer.put_u64(b.objects.len() as u64)?;
        for (key, chain) in &b.objects {
            writer.put_str(key)?;
            writer.put_u32(chain.len() as u32)?;
            for v in chain {
                let mut flags = 0u8;
                if v.version_id.is_some() {
                    flags |= VFLAG_HAS_VERSION_ID;
                }
                if v.is_delete_marker {
                    flags |= VFLAG_IS_DELETE_MARKER;
                }
                if v.checksum.client_requested {
                    flags |= VFLAG_CSUM_CLIENT_REQ;
                }
                let default_acl = v.acl.is_default_private_for(&v.owner);
                if default_acl {
                    flags |= VFLAG_DEFAULT_OWNER_ACL;
                }
                if !v.user_meta.is_empty() {
                    flags |= VFLAG_HAS_USER_META;
                }
                if !v.tags.is_empty() {
                    flags |= VFLAG_HAS_TAGS;
                }
                if v.parts.is_some() {
                    flags |= VFLAG_HAS_PARTS;
                }

                writer.put_u64(v.seq)?;
                writer.put_u8(flags)?;
                if let Some(vid) = &v.version_id {
                    writer.put_str(vid)?;
                }
                writer.put_u64(v.total_size)?;
                writer.put_i64(v.last_modified_ms)?;
                writer.put_str(&v.etag)?;
                writer.put_u8(encode_csum_alg(v.checksum.algorithm))?;
                writer.put_u8(encode_csum_type(v.checksum.checksum_type))?;
                writer.put_str(&v.checksum.value_b64)?;
                writer.put_u32(lookup_owner(&v.owner))?;
                if !default_acl {
                    encode_json_val(&mut writer, v.acl.as_ref())?;
                }
                encode_sys_meta(&mut writer, &v.sys_meta)?;
                if !v.user_meta.is_empty() {
                    writer.put_u32(v.user_meta.len() as u32)?;
                    for (mk, mv) in &v.user_meta {
                        writer.put_str(mk)?;
                        writer.put_str(mv)?;
                    }
                }
                if !v.tags.is_empty() {
                    encode_tags(&mut writer, &v.tags)?;
                }
                writer.put_u32(v.extents.len() as u32)?;
                for ext in v.extents.iter() {
                    writer.put_u32(ext.seg_id)?;
                    writer.put_u64(ext.offset)?;
                    writer.put_u32(ext.len)?;
                    writer.put_u32(ext.crc32c)?;
                }
                if let Some(parts) = &v.parts {
                    writer.put_u32(parts.len() as u32)?;
                    for p in parts.iter() {
                        writer.put_u32(p.part_number)?;
                        writer.put_u64(p.size)?;
                        match &p.checksum {
                            None => writer.put_u8(0)?,
                            Some((alg, val)) => {
                                writer.put_u8(1)?;
                                writer.put_u8(encode_csum_alg(*alg))?;
                                writer.put_str(val)?;
                            }
                        }
                        encode_opt_iv(&mut writer, p.sse_iv)?;
                    }
                }
                encode_sse_meta(&mut writer, &v.sse)?;
                encode_opt_json(&mut writer, v.retention.as_ref())?;
                encode_opt_legal_hold(&mut writer, v.legal_hold)?;
            }
        }

        // Active Multipart Uploads
        writer.put_u32(b.uploads.len() as u32)?;
        for up in b.uploads.values() {
            writer.put_str(&up.key)?;
            writer.put_str(&up.upload_id)?;
            writer.put_u32(lookup_owner(&up.initiator))?;
            writer.put_u32(lookup_owner(&up.owner))?;
            encode_json_val(&mut writer, &up.acl)?;
            encode_tags(&mut writer, &up.tags)?;
            writer.put_i64(up.initiated_ms)?;
            encode_sys_meta(&mut writer, &up.sys_meta)?;
            writer.put_u32(up.user_meta.len() as u32)?;
            for (mk, mv) in &up.user_meta {
                writer.put_str(mk)?;
                writer.put_str(mv)?;
            }
            match up.checksum_algorithm {
                None => writer.put_u8(0)?,
                Some(alg) => {
                    writer.put_u8(1)?;
                    writer.put_u8(encode_csum_alg(alg))?;
                }
            }
            match up.checksum_type {
                None => writer.put_u8(0)?,
                Some(ct) => {
                    writer.put_u8(1)?;
                    writer.put_u8(encode_csum_type(ct))?;
                }
            }
            encode_sse_meta(&mut writer, &up.sse)?;
            encode_opt_json(&mut writer, up.retention.as_ref())?;
            encode_opt_legal_hold(&mut writer, up.legal_hold)?;
            writer.put_u32(up.parts.len() as u32)?;
            for p in up.parts.values() {
                writer.put_u64(p.part_seq)?;
                writer.put_u32(p.part_number)?;
                writer.put_i64(p.last_modified_ms)?;
                writer.put_str(&p.etag)?;
                writer.put_u64(p.size)?;
                writer.put_bytes(&p.md5)?;
                writer.put_u64(p.crc64_nvme)?;
                match &p.checksum {
                    None => writer.put_u8(0)?,
                    Some((alg, val)) => {
                        writer.put_u8(1)?;
                        writer.put_u8(encode_csum_alg(*alg))?;
                        writer.put_str(val)?;
                    }
                }
                writer.put_u32(p.extents.len() as u32)?;
                for ext in p.extents.iter() {
                    writer.put_u32(ext.seg_id)?;
                    writer.put_u64(ext.offset)?;
                    writer.put_u32(ext.len)?;
                    writer.put_u32(ext.crc32c)?;
                }
                encode_opt_iv(&mut writer, p.sse_iv)?;
            }
        }

        // Completed uploads (24h retention cache)
        writer.put_u32(b.completed_uploads.len() as u32)?;
        for ((key, uid), (completed_ms, resp)) in &b.completed_uploads {
            writer.put_str(key)?;
            writer.put_str(uid)?;
            writer.put_i64(*completed_ms)?;
            encode_json_val(&mut writer, resp)?;
        }
    }

    writer.finish_chunks()?;
    writer.write_footer(ckpt_lsn)
}

/// Read and strictly validate a checkpoint file from disk (`ST-8`).
pub fn read_checkpoint_from_file<F: DiskFile>(
    file: &F,
    expected_lsn: Option<u64>,
    expected_uuid_lo: Option<u64>,
) -> Result<LoadedCheckpoint, String> {
    let file_len = file.len().map_err(|e| format!("checkpoint len error: {e}"))?;
    decode_checkpoint_reader(file, file_len, expected_lsn, expected_uuid_lo)
}

/// Fuzz-friendly byte-slice entry point validating header, CRC32C chunks, payload, and footer (`VR-7`).
pub fn decode_checkpoint_bytes(
    raw: &[u8],
    expected_uuid_lo: Option<u64>,
) -> Result<LoadedCheckpoint, String> {
    struct SliceReader<'a>(&'a [u8]);
    impl ReadAt for SliceReader<'_> {
        fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> Result<(), String> {
            let start = usize::try_from(offset).map_err(|_| "offset overflow".to_string())?;
            let end = start
                .checked_add(buf.len())
                .ok_or_else(|| "length overflow".to_string())?;
            if end > self.0.len() {
                return Err("unexpected EOF".into());
            }
            buf.copy_from_slice(&self.0[start..end]);
            Ok(())
        }
    }
    decode_checkpoint_reader(
        &SliceReader(raw),
        raw.len() as u64,
        None,
        expected_uuid_lo,
    )
}

trait ReadAt {
    fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> Result<(), String>;
}

impl<F: DiskFile> ReadAt for F {
    fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> Result<(), String> {
        DiskFile::read_exact_at(self, offset, buf).map_err(|e| format!("disk read error: {e}"))
    }
}

fn decode_checkpoint_reader<R: ReadAt>(
    reader: &R,
    file_len: u64,
    expected_lsn: Option<u64>,
    expected_uuid_lo: Option<u64>,
) -> Result<LoadedCheckpoint, String> {
    let min_len = (CKPT_HEADER_LEN + 12 + CKPT_FOOTER_LEN) as u64;
    if file_len < min_len {
        return Err(format!("checkpoint file too short ({file_len} bytes)"));
    }

    let mut hdr = [0u8; CKPT_HEADER_LEN];
    reader.read_exact_at(0, &mut hdr)?;
    if &hdr[0..8] != CKPT_HEADER_MAGIC {
        return Err("invalid checkpoint header magic".into());
    }
    let hdr_crc_expected = u32::from_le_bytes(hdr[60..64].try_into().unwrap());
    if crc32c::crc32c(&hdr[0..60]) != hdr_crc_expected {
        return Err("checkpoint header CRC32C mismatch".into());
    }

    let ver = u32::from_le_bytes(hdr[8..12].try_into().unwrap());
    if ver != FORMAT_VERSION {
        return Err(format!("unsupported checkpoint version {ver}"));
    }
    let uuid_lo = u64::from_le_bytes(hdr[16..24].try_into().unwrap());
    if let Some(exp_uuid) = expected_uuid_lo
        && uuid_lo != exp_uuid {
            return Err("checkpoint instance UUID mismatch".into());
        }
    let ckpt_lsn = u64::from_le_bytes(hdr[24..32].try_into().unwrap());
    if let Some(exp_lsn) = expected_lsn
        && ckpt_lsn != exp_lsn {
            return Err(format!(
                "checkpoint filename LSN {exp_lsn} != header LSN {ckpt_lsn}"
            ));
        }
    let next_seq = u64::from_le_bytes(hdr[32..40].try_into().unwrap());
    let next_seg_id = u32::from_le_bytes(hdr[40..44].try_into().unwrap());
    let bucket_count = u32::from_le_bytes(hdr[44..48].try_into().unwrap());

    let mut stream = ChunkedCkptReader::new(reader, file_len, &hdr);

    // Pre-allocated shared SystemMeta singletons for zero-alloc cold recovery (`NFR-6`)
    let sys_empty = Arc::new(SystemMeta {
        content_type: String::new(),
        ..SystemMeta::default()
    });
    let sys_binary_octet = Arc::new(SystemMeta {
        content_type: "binary/octet-stream".to_string(),
        ..SystemMeta::default()
    });
    let sys_app_octet = Arc::new(SystemMeta {
        content_type: "application/octet-stream".to_string(),
        ..SystemMeta::default()
    });

    // Section 1: Owner Intern Table
    let owner_count = stream.get_u32()? as usize;
    if owner_count > 1_000_000 {
        return Err("unreasonable owner table count".into());
    }
    let mut owners: Vec<(Arc<OwnerInfo>, Arc<AccessControlPolicy>)> =
        Vec::with_capacity(owner_count.min(1024));
    for _ in 0..owner_count {
        let user_id = stream.get_string(512)?;
        let display_name = stream.get_string(512)?;
        let email = stream.get_string(512)?;
        let o = OwnerInfo {
            user_id,
            display_name,
            email,
        };
        let default_acl = Arc::new(AccessControlPolicy {
            owner: o.clone(),
            grants: vec![AclGrant {
                grantee: s3d_types::AclGrantee::CanonicalUser(o.clone()),
                permission: AclPermission::FullControl,
            }],
        });
        owners.push((Arc::new(o), default_acl));
    }

    let get_owner = |idx: u32| -> Result<&(Arc<OwnerInfo>, Arc<AccessControlPolicy>), String> {
        owners
            .get(idx as usize)
            .ok_or_else(|| format!("invalid owner_idx {idx}"))
    };

    // Section 2: Live Segment IDs
    let seg_count = stream.get_u32()? as usize;
    if seg_count > 1_000_000 {
        return Err("unreasonable segment count".into());
    }
    let mut live_segments = BTreeSet::new();
    for _ in 0..seg_count {
        live_segments.insert(stream.get_u32()?);
    }

    // Section 3 & 4: Buckets, Versions, Uploads
    if bucket_count > 1_000_000 {
        return Err("unreasonable bucket count".into());
    }
    let mut buckets = BTreeMap::new();
    for _ in 0..bucket_count {
        let bname = stream.get_string(256)?;
        let bowner_idx = stream.get_u32()?;
        let bowner = (*get_owner(bowner_idx)?.0).clone();
        let bacl: AccessControlPolicy = decode_json_val(&mut stream, 256 * 1024)?;
        let region = stream.get_string(128)?;
        let created_ms = stream.get_i64()?;
        let versioning = decode_versioning(stream.get_u8()?)?;
        let explicit_ownership = decode_opt_ownership(stream.get_u8()?)?;
        let btags = decode_tags(&mut stream)?;
        let cors: Option<CorsConfiguration> = decode_opt_json(&mut stream, 512 * 1024)?;
        let policy = match stream.get_u8()? {
            0 => None,
            1 => {
                let raw_json = stream.get_string(64 * 1024)?;
                Some(
                    BucketPolicyDoc::parse_and_validate(&raw_json, &bname)
                        .map_err(|e| format!("corrupt bucket policy in checkpoint: {e}"))?,
                )
            }
            other => return Err(format!("invalid policy flag {other}")),
        };
        let public_access_block: Option<PublicAccessBlockConfig> =
            decode_opt_json(&mut stream, 8192)?;
        let object_lock_enabled = match stream.get_u8()? {
            0 => false,
            1 => true,
            other => return Err(format!("invalid object_lock_enabled byte {other}")),
        };
        let object_lock_config: Option<ObjectLockConfiguration> =
            decode_opt_json(&mut stream, 16 * 1024)?;
        let lifecycle: Option<LifecycleConfiguration> = decode_opt_json(&mut stream, 512 * 1024)?;
        let encryption: Option<BucketEncryptionConfig> = decode_opt_json(&mut stream, 16 * 1024)?;
        let logging: Option<BucketLoggingStatus> = decode_opt_json(&mut stream, 512 * 1024)?;

        let key_count = stream.get_u64()?;
        if key_count > 20_000_000 {
            return Err("unreasonable key count in checkpoint".into());
        }
        let mut objects: BTreeMap<String, Vec<ObjectVersionEntry>> = BTreeMap::new();
        for _ in 0..key_count {
            let key = stream.get_string(4096)?;
            let chain_len = stream.get_u32()? as usize;
            if chain_len == 0 || chain_len > 1_000_000 {
                return Err(format!("invalid version chain_len {chain_len}"));
            }
            let mut chain = Vec::with_capacity(chain_len.min(64));
            for _ in 0..chain_len {
                let seq = stream.get_u64()?;
                let flags = stream.get_u8()?;
                let version_id = if (flags & VFLAG_HAS_VERSION_ID) != 0 {
                    Some(stream.get_string(128)?)
                } else {
                    None
                };
                let is_delete_marker = (flags & VFLAG_IS_DELETE_MARKER) != 0;
                let total_size = stream.get_u64()?;
                let last_modified_ms = stream.get_i64()?;
                let etag = stream.get_string(128)?;
                let alg = decode_csum_alg(stream.get_u8()?)?;
                let ctype = decode_csum_type(stream.get_u8()?)?;
                let value_b64 = stream.get_string(128)?;
                let owner_idx = stream.get_u32()?;
                let (owner_arc, default_acl_arc) = get_owner(owner_idx)?;
                let acl = if (flags & VFLAG_DEFAULT_OWNER_ACL) != 0 {
                    Arc::clone(default_acl_arc)
                } else {
                    Arc::new(decode_json_val(&mut stream, 256 * 1024)?)
                };
                let sys_meta =
                    decode_sys_meta(&mut stream, &sys_empty, &sys_binary_octet, &sys_app_octet)?;
                let user_meta = if (flags & VFLAG_HAS_USER_META) != 0 {
                    let cnt = stream.get_u32()? as usize;
                    if cnt > 2048 {
                        return Err("too many user_meta entries".into());
                    }
                    let mut um = Vec::with_capacity(cnt.min(32));
                    for _ in 0..cnt {
                        let mk = stream.get_string(2048)?;
                        let mv = stream.get_string(2048)?;
                        um.push((mk, mv));
                    }
                    um
                } else {
                    Vec::new()
                };
                let tags = if (flags & VFLAG_HAS_TAGS) != 0 {
                    decode_tags(&mut stream)?
                } else {
                    BTreeMap::new()
                };
                let ext_cnt = stream.get_u32()? as usize;
                if ext_cnt > 100_000 {
                    return Err("unreasonable extent count".into());
                }
                let mut extents = Vec::with_capacity(ext_cnt.min(64));
                for _ in 0..ext_cnt {
                    extents.push(Extent {
                        seg_id: stream.get_u32()?,
                        offset: stream.get_u64()?,
                        len: stream.get_u32()?,
                        crc32c: stream.get_u32()?,
                    });
                }
                let parts = if (flags & VFLAG_HAS_PARTS) != 0 {
                    let pcnt = stream.get_u32()? as usize;
                    if pcnt > 10_000 {
                        return Err("part count > 10000".into());
                    }
                    let mut pv = Vec::with_capacity(pcnt.min(64));
                    for _ in 0..pcnt {
                        let pn = stream.get_u32()?;
                        let psize = stream.get_u64()?;
                        let pcsum = match stream.get_u8()? {
                            0 => None,
                            1 => {
                                let palg = decode_csum_alg(stream.get_u8()?)?;
                                let pval = stream.get_string(128)?;
                                Some((palg, pval))
                            }
                            other => return Err(format!("invalid part csum tag {other}")),
                        };
                        let psse_iv = decode_opt_iv(&mut stream)?;
                        pv.push(PartBoundaryInfo {
                            part_number: pn,
                            size: psize,
                            checksum: pcsum,
                            sse_iv: psse_iv,
                        });
                    }
                    Some(pv.into())
                } else {
                    None
                };
                let sse = decode_sse_meta(&mut stream)?;
                let retention: Option<ObjectRetention> = decode_opt_json(&mut stream, 4096)?;
                let legal_hold = decode_opt_legal_hold(&mut stream)?;

                chain.push(ObjectVersionEntry {
                    seq,
                    version_id,
                    is_delete_marker,
                    total_size,
                    etag,
                    checksum: ChecksumState {
                        algorithm: alg,
                        checksum_type: ctype,
                        value_b64,
                        client_requested: (flags & VFLAG_CSUM_CLIENT_REQ) != 0,
                    },
                    sys_meta,
                    user_meta,
                    owner: Arc::clone(owner_arc),
                    acl,
                    tags,
                    last_modified_ms,
                    extents: extents.into(),
                    parts,
                    sse,
                    retention,
                    legal_hold,
                });
            }
            objects.insert(key, chain);
        }

        // Active Uploads
        let up_cnt = stream.get_u32()? as usize;
        if up_cnt > 1_000_000 {
            return Err("unreasonable upload count".into());
        }
        let mut uploads = BTreeMap::new();
        for _ in 0..up_cnt {
            let key = stream.get_string(4096)?;
            let upload_id = stream.get_string(256)?;
            let init_idx = stream.get_u32()?;
            let own_idx = stream.get_u32()?;
            let initiator = (*get_owner(init_idx)?.0).clone();
            let owner = (*get_owner(own_idx)?.0).clone();
            let acl: AccessControlPolicy = decode_json_val(&mut stream, 256 * 1024)?;
            let tags = decode_tags(&mut stream)?;
            let initiated_ms = stream.get_i64()?;
            let sys_meta =
                (*decode_sys_meta(&mut stream, &sys_empty, &sys_binary_octet, &sys_app_octet)?)
                    .clone();
            let um_cnt = stream.get_u32()? as usize;
            if um_cnt > 2048 {
                return Err("too many upload user_meta".into());
            }
            let mut user_meta = Vec::with_capacity(um_cnt.min(32));
            for _ in 0..um_cnt {
                user_meta.push((stream.get_string(2048)?, stream.get_string(2048)?));
            }
            let checksum_algorithm = match stream.get_u8()? {
                0 => None,
                1 => Some(decode_csum_alg(stream.get_u8()?)?),
                other => return Err(format!("invalid upload csum alg flag {other}")),
            };
            let checksum_type = match stream.get_u8()? {
                0 => None,
                1 => Some(decode_csum_type(stream.get_u8()?)?),
                other => return Err(format!("invalid upload csum type flag {other}")),
            };
            let up_sse = decode_sse_meta(&mut stream)?;
            let up_retention: Option<ObjectRetention> = decode_opt_json(&mut stream, 4096)?;
            let up_legal_hold = decode_opt_legal_hold(&mut stream)?;
            let pcnt = stream.get_u32()? as usize;
            if pcnt > 10_000 {
                return Err("too many upload parts".into());
            }
            let mut parts = BTreeMap::new();
            for _ in 0..pcnt {
                let part_seq = stream.get_u64()?;
                let part_number = stream.get_u32()?;
                let last_modified_ms = stream.get_i64()?;
                let etag = stream.get_string(128)?;
                let size = stream.get_u64()?;
                let mut md5 = [0u8; 16];
                stream.get_exact(&mut md5)?;
                let crc64_nvme = stream.get_u64()?;
                let checksum = match stream.get_u8()? {
                    0 => None,
                    1 => {
                        let palg = decode_csum_alg(stream.get_u8()?)?;
                        let pval = stream.get_string(128)?;
                        Some((palg, pval))
                    }
                    other => return Err(format!("invalid upload part csum flag {other}")),
                };
                let ecnt = stream.get_u32()? as usize;
                if ecnt > 100_000 {
                    return Err("unreasonable part extent count".into());
                }
                let mut extents = Vec::with_capacity(ecnt.min(64));
                for _ in 0..ecnt {
                    extents.push(Extent {
                        seg_id: stream.get_u32()?,
                        offset: stream.get_u64()?,
                        len: stream.get_u32()?,
                        crc32c: stream.get_u32()?,
                    });
                }
                let sse_iv = decode_opt_iv(&mut stream)?;
                parts.insert(
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
            uploads.insert(
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
                    sse: up_sse,
                    retention: up_retention,
                    legal_hold: up_legal_hold,
                    parts,
                },
            );
        }

        // Completed Uploads
        let comp_cnt = stream.get_u32()? as usize;
        if comp_cnt > 1_000_000 {
            return Err("unreasonable completed_uploads count".into());
        }
        let mut completed_uploads = BTreeMap::new();
        for _ in 0..comp_cnt {
            let key = stream.get_string(4096)?;
            let uid = stream.get_string(256)?;
            let cms = stream.get_i64()?;
            let resp: CompleteMultipartUploadResp = decode_json_val(&mut stream, 16 * 1024)?;
            completed_uploads.insert((key, uid), (cms, resp));
        }

        buckets.insert(
            bname.clone(),
            BucketEntry {
                name: bname,
                owner: bowner,
                acl: bacl,
                region,
                created_ms,
                versioning,
                explicit_ownership,
                tags: btags,
                cors,
                policy,
                public_access_block,
                object_lock_enabled,
                object_lock_config,
                lifecycle,
                encryption,
                logging,
                objects,
                uploads,
                completed_uploads,
            },
        );
    }

    stream.verify_end_and_footer(ckpt_lsn)?;

    Ok(LoadedCheckpoint {
        ckpt_lsn,
        next_seg_id,
        live_segments,
        catalog: MemoryCatalog {
            next_seq: next_seq.saturating_sub(1),
            buckets,
        },
    })
}

// ---- Chunked Streaming Writer & Reader ----

struct ChunkedCkptWriter<'a, F: DiskFile> {
    file: &'a F,
    file_pos: u64,
    total_crc: u32,
    buf: Vec<u8>,
}

impl<'a, F: DiskFile> ChunkedCkptWriter<'a, F> {
    fn new(file: &'a F) -> Self {
        Self {
            file,
            file_pos: 0,
            total_crc: 0,
            buf: Vec::with_capacity(CKPT_STREAM_CHUNK_TARGET + 4096),
        }
    }

    fn write_raw(&mut self, bytes: &[u8]) -> Result<(), DiskError> {
        self.file.write_all_at(self.file_pos, bytes)?;
        self.file_pos += bytes.len() as u64;
        self.total_crc = crc32c::crc32c_append(self.total_crc, bytes);
        Ok(())
    }

    fn flush_chunk(&mut self) -> Result<(), DiskError> {
        while !self.buf.is_empty() {
            let take = self.buf.len().min(CKPT_MAX_CHUNK_LEN);
            let payload = &self.buf[..take];
            let mut frame_hdr = [0u8; 12];
            frame_hdr[0..4].copy_from_slice(&CKPT_CHUNK_MAGIC.to_le_bytes());
            frame_hdr[4..8].copy_from_slice(&(take as u32).to_le_bytes());
            let mut ccrc = crc32c::crc32c(&frame_hdr[0..8]);
            ccrc = crc32c::crc32c_append(ccrc, payload);
            frame_hdr[8..12].copy_from_slice(&ccrc.to_le_bytes());

            self.file.write_all_at(self.file_pos, &frame_hdr)?;
            self.file_pos += 12;
            self.total_crc = crc32c::crc32c_append(self.total_crc, &frame_hdr);

            self.file.write_all_at(self.file_pos, payload)?;
            self.file_pos += take as u64;
            self.total_crc = crc32c::crc32c_append(self.total_crc, payload);

            self.buf.drain(..take);
        }
        Ok(())
    }

    fn finish_chunks(&mut self) -> Result<(), DiskError> {
        self.flush_chunk()?;
        // Write 0-length sentinel chunk
        let mut eof_hdr = [0u8; 12];
        eof_hdr[0..4].copy_from_slice(&CKPT_CHUNK_MAGIC.to_le_bytes());
        eof_hdr[4..8].copy_from_slice(&0u32.to_le_bytes());
        let ccrc = crc32c::crc32c(&eof_hdr[0..8]);
        eof_hdr[8..12].copy_from_slice(&ccrc.to_le_bytes());
        self.write_raw(&eof_hdr)
    }

    fn write_footer(mut self, ckpt_lsn: u64) -> Result<u64, DiskError> {
        let final_file_len = self.file_pos + CKPT_FOOTER_LEN as u64;
        let mut ftr = [0u8; CKPT_FOOTER_LEN];
        ftr[0..8].copy_from_slice(CKPT_FOOTER_MAGIC);
        ftr[8..16].copy_from_slice(&ckpt_lsn.to_le_bytes());
        ftr[16..24].copy_from_slice(&final_file_len.to_le_bytes());
        let ftr_hdr_crc = crc32c::crc32c(&ftr[0..24]);
        ftr[24..28].copy_from_slice(&ftr_hdr_crc.to_le_bytes());
        let rolling = crc32c::crc32c_append(self.total_crc, &ftr[0..28]);
        ftr[28..32].copy_from_slice(&rolling.to_le_bytes());
        self.file.write_all_at(self.file_pos, &ftr)?;
        self.file_pos += CKPT_FOOTER_LEN as u64;
        Ok(self.file_pos)
    }

    fn put_bytes(&mut self, b: &[u8]) -> Result<(), DiskError> {
        self.buf.extend_from_slice(b);
        if self.buf.len() >= CKPT_STREAM_CHUNK_TARGET {
            self.flush_chunk()?;
        }
        Ok(())
    }

    fn put_u8(&mut self, v: u8) -> Result<(), DiskError> {
        self.put_bytes(&[v])
    }

    fn put_u32(&mut self, v: u32) -> Result<(), DiskError> {
        self.put_bytes(&v.to_le_bytes())
    }

    fn put_u64(&mut self, v: u64) -> Result<(), DiskError> {
        self.put_bytes(&v.to_le_bytes())
    }

    fn put_i64(&mut self, v: i64) -> Result<(), DiskError> {
        self.put_bytes(&v.to_le_bytes())
    }

    fn put_str(&mut self, s: &str) -> Result<(), DiskError> {
        self.put_u32(s.len() as u32)?;
        self.put_bytes(s.as_bytes())
    }
}

struct ChunkedCkptReader<'a, R: ReadAt> {
    reader: &'a R,
    file_len: u64,
    file_pos: u64,
    total_crc: u32,
    buf: Vec<u8>,
    buf_pos: usize,
    reached_sentinel: bool,
}

impl<'a, R: ReadAt> ChunkedCkptReader<'a, R> {
    fn new(reader: &'a R, file_len: u64, hdr_bytes: &[u8; CKPT_HEADER_LEN]) -> Self {
        Self {
            reader,
            file_len,
            file_pos: CKPT_HEADER_LEN as u64,
            total_crc: crc32c::crc32c(hdr_bytes),
            buf: Vec::new(),
            buf_pos: 0,
            reached_sentinel: false,
        }
    }

    fn pull_next_chunk(&mut self) -> Result<bool, String> {
        if self.reached_sentinel {
            return Ok(false);
        }
        let footer_start = self
            .file_len
            .checked_sub(CKPT_FOOTER_LEN as u64)
            .ok_or_else(|| "checkpoint truncated before footer".to_string())?;
        if self.file_pos + 12 > footer_start {
            return Err("checkpoint chunk header overlaps footer".into());
        }
        let mut chdr = [0u8; 12];
        self.reader.read_exact_at(self.file_pos, &mut chdr)?;
        self.file_pos += 12;
        self.total_crc = crc32c::crc32c_append(self.total_crc, &chdr);

        let magic = u32::from_le_bytes(chdr[0..4].try_into().unwrap());
        if magic != CKPT_CHUNK_MAGIC {
            return Err(format!("invalid checkpoint chunk magic 0x{magic:08x}"));
        }
        let clen = u32::from_le_bytes(chdr[4..8].try_into().unwrap()) as usize;
        let expected_crc = u32::from_le_bytes(chdr[8..12].try_into().unwrap());
        if clen > CKPT_MAX_CHUNK_LEN {
            return Err(format!("checkpoint chunk len {clen} exceeds max"));
        }
        if self.file_pos + (clen as u64) > footer_start {
            return Err("checkpoint chunk payload overlaps footer".into());
        }

        if clen == 0 {
            let calc = crc32c::crc32c(&chdr[0..8]);
            if calc != expected_crc {
                return Err("checkpoint sentinel chunk CRC mismatch".into());
            }
            self.reached_sentinel = true;
            return Ok(false);
        }

        self.buf.resize(clen, 0);
        self.buf_pos = 0;
        self.reader.read_exact_at(self.file_pos, &mut self.buf)?;
        self.file_pos += clen as u64;

        let mut calc = crc32c::crc32c(&chdr[0..8]);
        calc = crc32c::crc32c_append(calc, &self.buf);
        if calc != expected_crc {
            return Err("checkpoint data chunk CRC32C mismatch".into());
        }
        self.total_crc = crc32c::crc32c_append(self.total_crc, &self.buf);
        Ok(true)
    }

    fn get_exact(&mut self, out: &mut [u8]) -> Result<(), String> {
        let mut written = 0usize;
        while written < out.len() {
            let avail = self.buf.len() - self.buf_pos;
            if avail > 0 {
                let take = avail.min(out.len() - written);
                out[written..written + take]
                    .copy_from_slice(&self.buf[self.buf_pos..self.buf_pos + take]);
                self.buf_pos += take;
                written += take;
            } else if !self.pull_next_chunk()? {
                return Err("unexpected end of checkpoint stream".into());
            }
        }
        Ok(())
    }

    fn get_u8(&mut self) -> Result<u8, String> {
        let mut b = [0u8; 1];
        self.get_exact(&mut b)?;
        Ok(b[0])
    }

    fn get_u32(&mut self) -> Result<u32, String> {
        let mut b = [0u8; 4];
        self.get_exact(&mut b)?;
        Ok(u32::from_le_bytes(b))
    }

    fn get_u64(&mut self) -> Result<u64, String> {
        let mut b = [0u8; 8];
        self.get_exact(&mut b)?;
        Ok(u64::from_le_bytes(b))
    }

    fn get_i64(&mut self) -> Result<i64, String> {
        let mut b = [0u8; 8];
        self.get_exact(&mut b)?;
        Ok(i64::from_le_bytes(b))
    }

    fn get_vec(&mut self, max_len: usize) -> Result<Vec<u8>, String> {
        let len = self.get_u32()? as usize;
        if len > max_len {
            return Err(format!("field length {len} exceeds max {max_len}"));
        }
        let mut v = vec![0u8; len];
        self.get_exact(&mut v)?;
        Ok(v)
    }

    fn get_string(&mut self, max_len: usize) -> Result<String, String> {
        let v = self.get_vec(max_len)?;
        String::from_utf8(v).map_err(|_| "invalid UTF-8 string in checkpoint".into())
    }

    fn verify_end_and_footer(mut self, expected_lsn: u64) -> Result<(), String> {
        if self.buf_pos != self.buf.len() {
            return Err("trailing unconsumed bytes in checkpoint chunk".into());
        }
        if !self.reached_sentinel
            && self.pull_next_chunk()? {
                return Err("unexpected extra chunk before sentinel".into());
            }
        if self.file_pos + CKPT_FOOTER_LEN as u64 != self.file_len {
            return Err("checkpoint sentinel does not align with footer".into());
        }
        let mut ftr = [0u8; CKPT_FOOTER_LEN];
        self.reader.read_exact_at(self.file_pos, &mut ftr)?;
        if &ftr[0..8] != CKPT_FOOTER_MAGIC {
            return Err("invalid checkpoint footer magic".into());
        }
        let ftr_hdr_crc = u32::from_le_bytes(ftr[24..28].try_into().unwrap());
        if crc32c::crc32c(&ftr[0..24]) != ftr_hdr_crc {
            return Err("checkpoint footer header CRC mismatch".into());
        }
        let ftr_lsn = u64::from_le_bytes(ftr[8..16].try_into().unwrap());
        let ftr_file_len = u64::from_le_bytes(ftr[16..24].try_into().unwrap());
        if ftr_lsn != expected_lsn {
            return Err(format!(
                "checkpoint footer LSN {ftr_lsn} != header LSN {expected_lsn}"
            ));
        }
        if ftr_file_len != self.file_len {
            return Err(format!(
                "checkpoint footer file_len {ftr_file_len} != actual {}",
                self.file_len
            ));
        }
        let expected_total_crc = u32::from_le_bytes(ftr[28..32].try_into().unwrap());
        let actual_total_crc = crc32c::crc32c_append(self.total_crc, &ftr[0..28]);
        if actual_total_crc != expected_total_crc {
            return Err("checkpoint whole-file rolling CRC32C mismatch".into());
        }
        Ok(())
    }
}

// ---- Field Encoding Helpers ----

fn encode_versioning(v: VersioningStatus) -> u8 {
    match v {
        VersioningStatus::Unversioned => 0,
        VersioningStatus::Enabled => 1,
        VersioningStatus::Suspended => 2,
    }
}

fn decode_versioning(b: u8) -> Result<VersioningStatus, String> {
    match b {
        0 => Ok(VersioningStatus::Unversioned),
        1 => Ok(VersioningStatus::Enabled),
        2 => Ok(VersioningStatus::Suspended),
        other => Err(format!("invalid versioning byte {other}")),
    }
}

fn encode_opt_ownership(o: Option<ObjectOwnership>) -> u8 {
    match o {
        None => 0,
        Some(ObjectOwnership::BucketOwnerEnforced) => 1,
        Some(ObjectOwnership::ObjectWriter) => 2,
        Some(ObjectOwnership::BucketOwnerPreferred) => 3,
    }
}

fn decode_opt_ownership(b: u8) -> Result<Option<ObjectOwnership>, String> {
    match b {
        0 => Ok(None),
        1 => Ok(Some(ObjectOwnership::BucketOwnerEnforced)),
        2 => Ok(Some(ObjectOwnership::ObjectWriter)),
        3 => Ok(Some(ObjectOwnership::BucketOwnerPreferred)),
        other => Err(format!("invalid ownership byte {other}")),
    }
}

fn encode_csum_alg(a: ChecksumAlgorithm) -> u8 {
    match a {
        ChecksumAlgorithm::Crc32 => 0,
        ChecksumAlgorithm::Crc32c => 1,
        ChecksumAlgorithm::Crc64Nvme => 2,
        ChecksumAlgorithm::Sha1 => 3,
        ChecksumAlgorithm::Sha256 => 4,
        ChecksumAlgorithm::Md5 => 5,
        ChecksumAlgorithm::Sha512 => 6,
        ChecksumAlgorithm::XxHash64 => 7,
        ChecksumAlgorithm::XxHash3 => 8,
        ChecksumAlgorithm::XxHash128 => 9,
    }
}

fn decode_csum_alg(b: u8) -> Result<ChecksumAlgorithm, String> {
    match b {
        0 => Ok(ChecksumAlgorithm::Crc32),
        1 => Ok(ChecksumAlgorithm::Crc32c),
        2 => Ok(ChecksumAlgorithm::Crc64Nvme),
        3 => Ok(ChecksumAlgorithm::Sha1),
        4 => Ok(ChecksumAlgorithm::Sha256),
        5 => Ok(ChecksumAlgorithm::Md5),
        6 => Ok(ChecksumAlgorithm::Sha512),
        7 => Ok(ChecksumAlgorithm::XxHash64),
        8 => Ok(ChecksumAlgorithm::XxHash3),
        9 => Ok(ChecksumAlgorithm::XxHash128),
        other => Err(format!("invalid checksum algorithm {other}")),
    }
}

fn encode_csum_type(t: ChecksumType) -> u8 {
    match t {
        ChecksumType::FullObject => 0,
        ChecksumType::Composite => 1,
    }
}

fn decode_csum_type(b: u8) -> Result<ChecksumType, String> {
    match b {
        0 => Ok(ChecksumType::FullObject),
        1 => Ok(ChecksumType::Composite),
        other => Err(format!("invalid checksum type {other}")),
    }
}

fn encode_sys_meta<F: DiskFile>(
    w: &mut ChunkedCkptWriter<'_, F>,
    sm: &SystemMeta,
) -> Result<(), DiskError> {
    let other_none = sm.cache_control.is_none()
        && sm.content_disposition.is_none()
        && sm.content_encoding.is_none()
        && sm.content_language.is_none()
        && sm.expires.is_none();
    if other_none {
        match sm.content_type.as_str() {
            "" => return w.put_u8(0),
            "binary/octet-stream" => return w.put_u8(1),
            "application/octet-stream" => return w.put_u8(2),
            _ => {}
        }
    }
    w.put_u8(3)?;
    w.put_str(&sm.content_type)?;
    encode_opt_str(w, sm.cache_control.as_deref())?;
    encode_opt_str(w, sm.content_disposition.as_deref())?;
    encode_opt_str(w, sm.content_encoding.as_deref())?;
    encode_opt_str(w, sm.content_language.as_deref())?;
    encode_opt_str(w, sm.expires.as_deref())
}

fn decode_sys_meta<R: ReadAt>(
    r: &mut ChunkedCkptReader<'_, R>,
    sys_empty: &Arc<SystemMeta>,
    sys_bin: &Arc<SystemMeta>,
    sys_app: &Arc<SystemMeta>,
) -> Result<Arc<SystemMeta>, String> {
    match r.get_u8()? {
        0 => Ok(Arc::clone(sys_empty)),
        1 => Ok(Arc::clone(sys_bin)),
        2 => Ok(Arc::clone(sys_app)),
        3 => Ok(Arc::new(SystemMeta {
            content_type: r.get_string(1024)?,
            cache_control: decode_opt_str(r, 1024)?,
            content_disposition: decode_opt_str(r, 2048)?,
            content_encoding: decode_opt_str(r, 1024)?,
            content_language: decode_opt_str(r, 1024)?,
            expires: decode_opt_str(r, 1024)?,
        })),
        other => Err(format!("invalid sys_meta tag {other}")),
    }
}

fn encode_opt_str<F: DiskFile>(
    w: &mut ChunkedCkptWriter<'_, F>,
    s: Option<&str>,
) -> Result<(), DiskError> {
    match s {
        None => w.put_u8(0),
        Some(v) => {
            w.put_u8(1)?;
            w.put_str(v)
        }
    }
}

fn decode_opt_str<R: ReadAt>(
    r: &mut ChunkedCkptReader<'_, R>,
    max_len: usize,
) -> Result<Option<String>, String> {
    match r.get_u8()? {
        0 => Ok(None),
        1 => Ok(Some(r.get_string(max_len)?)),
        other => Err(format!("invalid opt_str tag {other}")),
    }
}

fn encode_tags<F: DiskFile>(
    w: &mut ChunkedCkptWriter<'_, F>,
    tags: &BTreeMap<String, String>,
) -> Result<(), DiskError> {
    w.put_u32(tags.len() as u32)?;
    for (k, v) in tags {
        w.put_str(k)?;
        w.put_str(v)?;
    }
    Ok(())
}

fn decode_tags<R: ReadAt>(r: &mut ChunkedCkptReader<'_, R>) -> Result<BTreeMap<String, String>, String> {
    let cnt = r.get_u32()? as usize;
    if cnt > 256 {
        return Err(format!("too many tags {cnt}"));
    }
    let mut out = BTreeMap::new();
    for _ in 0..cnt {
        let k = r.get_string(512)?;
        let v = r.get_string(1024)?;
        out.insert(k, v);
    }
    Ok(out)
}

fn encode_json_val<F: DiskFile, T: serde::Serialize>(
    w: &mut ChunkedCkptWriter<'_, F>,
    val: &T,
) -> Result<(), DiskError> {
    let raw = serde_json::to_vec(val).expect("checkpoint JSON serialization cannot fail");
    w.put_u32(raw.len() as u32)?;
    w.put_bytes(&raw)
}

fn decode_json_val<R: ReadAt, T: serde::de::DeserializeOwned>(
    r: &mut ChunkedCkptReader<'_, R>,
    max_len: usize,
) -> Result<T, String> {
    let raw = r.get_vec(max_len)?;
    serde_json::from_slice(&raw).map_err(|e| format!("checkpoint JSON decode error: {e}"))
}

fn encode_opt_json<F: DiskFile, T: serde::Serialize>(
    w: &mut ChunkedCkptWriter<'_, F>,
    val: Option<&T>,
) -> Result<(), DiskError> {
    match val {
        None => w.put_u8(0),
        Some(v) => {
            w.put_u8(1)?;
            encode_json_val(w, v)
        }
    }
}

fn decode_opt_json<R: ReadAt, T: serde::de::DeserializeOwned>(
    r: &mut ChunkedCkptReader<'_, R>,
    max_len: usize,
) -> Result<Option<T>, String> {
    match r.get_u8()? {
        0 => Ok(None),
        1 => Ok(Some(decode_json_val(r, max_len)?)),
        other => Err(format!("invalid opt_json tag {other}")),
    }
}

fn encode_opt_iv<F: DiskFile>(
    w: &mut ChunkedCkptWriter<'_, F>,
    iv: Option<[u8; 16]>,
) -> Result<(), DiskError> {
    match iv {
        None => w.put_u8(0),
        Some(bytes) => {
            w.put_u8(1)?;
            w.put_bytes(&bytes)
        }
    }
}

fn decode_opt_iv<R: ReadAt>(r: &mut ChunkedCkptReader<'_, R>) -> Result<Option<[u8; 16]>, String> {
    match r.get_u8()? {
        0 => Ok(None),
        1 => {
            let mut iv = [0u8; 16];
            r.get_exact(&mut iv)?;
            Ok(Some(iv))
        }
        other => Err(format!("invalid opt_iv tag {other}")),
    }
}

fn encode_sse_meta<F: DiskFile>(
    w: &mut ChunkedCkptWriter<'_, F>,
    sse: &SseStoredMeta,
) -> Result<(), DiskError> {
    match sse {
        SseStoredMeta::None => w.put_u8(0),
        SseStoredMeta::SseS3 { iv } => {
            w.put_u8(1)?;
            w.put_bytes(iv)
        }
        SseStoredMeta::SseC { key_md5, iv } => {
            w.put_u8(2)?;
            w.put_bytes(key_md5)?;
            w.put_bytes(iv)
        }
    }
}

fn decode_sse_meta<R: ReadAt>(r: &mut ChunkedCkptReader<'_, R>) -> Result<SseStoredMeta, String> {
    match r.get_u8()? {
        0 => Ok(SseStoredMeta::None),
        1 => {
            let mut iv = [0u8; 16];
            r.get_exact(&mut iv)?;
            Ok(SseStoredMeta::SseS3 { iv })
        }
        2 => {
            let mut key_md5 = [0u8; 16];
            let mut iv = [0u8; 16];
            r.get_exact(&mut key_md5)?;
            r.get_exact(&mut iv)?;
            Ok(SseStoredMeta::SseC { key_md5, iv })
        }
        other => Err(format!("invalid sse_meta tag {other}")),
    }
}

fn encode_opt_legal_hold<F: DiskFile>(
    w: &mut ChunkedCkptWriter<'_, F>,
    lh: Option<LegalHoldStatus>,
) -> Result<(), DiskError> {
    match lh {
        None => w.put_u8(0),
        Some(LegalHoldStatus::On) => w.put_u8(1),
        Some(LegalHoldStatus::Off) => w.put_u8(2),
    }
}

fn decode_opt_legal_hold<R: ReadAt>(
    r: &mut ChunkedCkptReader<'_, R>,
) -> Result<Option<LegalHoldStatus>, String> {
    match r.get_u8()? {
        0 => Ok(None),
        1 => Ok(Some(LegalHoldStatus::On)),
        2 => Ok(Some(LegalHoldStatus::Off)),
        other => Err(format!("invalid opt_legal_hold tag {other}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use s3d_disk::{Disk, FaultDisk, OpenOpts};

    #[test]
    fn checkpoint_roundtrip_and_corruption_detection_st8() {
        let disk = FaultDisk::new();
        disk.create_dir_all("ckpt").unwrap();

        let owner = OwnerInfo {
            user_id: "0123456789abcdef".into(),
            display_name: "main".into(),
            email: "main@example.com".into(),
        };
        let acl = AccessControlPolicy {
            owner: owner.clone(),
            grants: vec![AclGrant {
                grantee: s3d_types::AclGrantee::CanonicalUser(owner.clone()),
                permission: AclPermission::FullControl,
            }],
        };

        let mut objects = BTreeMap::new();
        objects.insert(
            "dir/k1".to_string(),
            vec![ObjectVersionEntry {
                seq: 7,
                version_id: Some("v0000000000000007".into()),
                is_delete_marker: false,
                total_size: 4096,
                etag: "\"00112233445566778899aabbccddeeff\"".into(),
                checksum: ChecksumState {
                    algorithm: ChecksumAlgorithm::Crc64Nvme,
                    checksum_type: ChecksumType::FullObject,
                    value_b64: "AAAAAAAAAAA=".into(),
                    client_requested: false,
                },
                sys_meta: Arc::new(SystemMeta {
                    content_type: "binary/octet-stream".into(),
                    ..Default::default()
                }),
                user_meta: vec![("env".into(), "prod".into())],
                owner: Arc::new(owner.clone()),
                acl: Arc::new(acl.clone()),
                tags: BTreeMap::from([("t1".into(), "v1".into())]),
                last_modified_ms: 1_700_000_000_000,
                extents: vec![Extent {
                    seg_id: 2,
                    offset: 32,
                    len: 4096,
                    crc32c: 0x1234_5678,
                }]
                .into(),
                parts: None,
                sse: SseStoredMeta::SseS3 { iv: [0x42; 16] },
                retention: None,
                legal_hold: Some(LegalHoldStatus::On),
            }],
        );

        let mut catalog = MemoryCatalog {
            next_seq: 7,
            buckets: BTreeMap::new(),
        };
        catalog.buckets.insert(
            "b1".into(),
            BucketEntry {
                name: "b1".into(),
                owner,
                acl,
                region: "us-east-1".into(),
                created_ms: 1_700_000_000_000,
                versioning: VersioningStatus::Enabled,
                explicit_ownership: Some(ObjectOwnership::ObjectWriter),
                tags: BTreeMap::new(),
                cors: None,
                policy: None,
                public_access_block: None,
                object_lock_enabled: true,
                object_lock_config: Some(ObjectLockConfiguration::default()),
                lifecycle: None,
                encryption: Some(BucketEncryptionConfig {
                    sse_algorithm: "AES256".into(),
                    bucket_key_enabled: None,
                }),
                logging: None,
                objects,
                uploads: BTreeMap::new(),
                completed_uploads: BTreeMap::new(),
            },
        );

        let live_segs = BTreeSet::from([2u32, 3u32]);
        let f = disk
            .open("ckpt/ckpt-000000000000002a", OpenOpts::create_truncate_rw())
            .unwrap();
        let written =
            write_checkpoint_to_file(&f, 0xCAFE_BABE_1234_5678, 42, 8, 4, &live_segs, &catalog)
                .unwrap();
        assert_eq!(written, f.len().unwrap());

        let loaded =
            read_checkpoint_from_file(&f, Some(42), Some(0xCAFE_BABE_1234_5678)).unwrap();
        assert_eq!(loaded.ckpt_lsn, 42);
        assert_eq!(loaded.next_seg_id, 4);
        assert_eq!(loaded.live_segments, live_segs);
        assert_eq!(loaded.catalog.next_seq, 7);
        let v = &loaded.catalog.buckets["b1"].objects["dir/k1"][0];
        assert_eq!(v.seq, 7);
        assert_eq!(v.total_size, 4096);
        assert_eq!(v.user_meta, vec![("env".into(), "prod".into())]);

        // Verify wrong UUID rejected
        assert!(read_checkpoint_from_file(&f, Some(42), Some(0xDEAD)).is_err());
        // Verify wrong expected LSN rejected
        assert!(read_checkpoint_from_file(&f, Some(43), Some(0xCAFE_BABE_1234_5678)).is_err());

        // Read raw bytes and test bit-flip detection anywhere in header, chunk, or footer
        let mut raw = vec![0u8; written as usize];
        DiskFile::read_exact_at(&f, 0, &mut raw).unwrap();
        assert!(decode_checkpoint_bytes(&raw, Some(0xCAFE_BABE_1234_5678)).is_ok());

        for flip_idx in [0, 30, 62, 70, raw.len() / 2, raw.len() - 20, raw.len() - 1] {
            let mut corrupted = raw.clone();
            corrupted[flip_idx] ^= 0x01;
            assert!(
                decode_checkpoint_bytes(&corrupted, Some(0xCAFE_BABE_1234_5678)).is_err(),
                "bit flip at {flip_idx} was not detected!"
            );
        }

        // Truncated file rejected
        assert!(decode_checkpoint_bytes(&raw[..raw.len() - 4], None).is_err());
    }
}
