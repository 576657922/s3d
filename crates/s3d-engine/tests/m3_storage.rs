//! Milestone M3 storage hardening tests:
//! - Checkpoints (`ST-8`), WAL rollover & old WAL pruning, post-checkpoint WAL tail replay,
//!   GC deleted-segment reconciliation across crash & checkpoint.
//! - Corrupt checkpoint startup refusal (`ST-8`: never silently fall back to older checkpoint).
//! - Offline `run_fsck` (`NFR-13`) corruption injection across segment blocks, checkpoints,
//!   mid-WAL records, missing segments, and multipart composite/full-object checksums.
//! - Low disk space `503 SlowDown` (`NFR-16`) while reads, deletes, and GC continue operating.

use std::collections::BTreeMap;
use std::future::poll_fn;
use std::pin::Pin;

use bytes::{Bytes, BytesMut};
use rand::rngs::StdRng;
use rand::SeedableRng;
use s3d_disk::{Disk, DiskFile, FaultDisk, OpenOpts};
use s3d_engine::{run_fsck, Engine, EngineConfig, EngineOpenError};
use s3d_model::InMemoryVerifiedStream;
use s3d_types::*;

fn caller(time_ms: i64) -> CallerContext {
    CallerContext {
        caller: Some(OwnerInfo {
            user_id: "0123456789abcdef".into(),
            display_name: "tester".into(),
            email: "tester@example.com".into(),
        }),
        request_time_ms: time_ms,
        expected_bucket_owner: None,
        is_authenticated: true,
        policy_ctx: RequestPolicyContext::default(),
    }
}

async fn read_all<R: AsyncByteReader>(mut reader: R) -> StoreResult<Bytes> {
    let mut out = BytesMut::new();
    while let Some(chunk) = poll_fn(|cx| Pin::new(&mut reader).poll_read_chunk(cx)).await? {
        out.extend_from_slice(&chunk);
    }
    Ok(out.freeze())
}

#[tokio::test]
async fn checkpoint_wal_pruning_gc_and_crash_recovery() {
    let disk = FaultDisk::new();
    let cfg = EngineConfig {
        segment_size: 8 * 1024, // force frequent segment sealing
        wal_file_size: 4 * 1024, // force frequent WAL rollover
        checkpoint_wal_bytes: 8 * 1024,
        max_block_payload: 2048,
        gc_live_ratio: 0.8,
        ..EngineConfig::default()
    };

    let engine = Engine::open(disk.clone(), cfg.clone()).unwrap();
    engine
        .create_bucket(CreateBucketReq {
            ctx: caller(1_000),
            bucket: "m3-bkt".into(),
            location_constraint: None,
            object_ownership: None,
            acl: None,
            object_lock_enabled: false,
        })
        .await
        .unwrap();
    engine
        .put_bucket_versioning(PutBucketVersioningReq {
            ctx: caller(1_001),
            bucket: "m3-bkt".into(),
            status: VersioningStatus::Enabled,
        })
        .await
        .unwrap();

    // Write 40 objects across multiple WALs and segments, overwriting several keys
    for i in 0..40u32 {
        let key = format!("dir/key-{:02}", i % 15);
        let payload = vec![(i & 0xFF) as u8; 1500];
        engine
            .put_object(
                PutObjectReq {
                    ctx: caller(2_000 + i as i64),
                    bucket: "m3-bkt".into(),
                    key,
                    sys_meta: SystemMeta {
                        content_type: "application/octet-stream".into(),
                        ..Default::default()
                    },
                    user_meta: vec![("seq".into(), i.to_string())],
                    acl: None,
                    tags: Some(BTreeMap::from([("k".into(), "v".into())])),
                    preconditions: Preconditions::default(),
                    max_bytes_limit: MAX_SINGLE_PUT_BYTES,
                    raw_sse: RawSseHeaders::default(),
                    raw_lock: RawUploadObjectLockHeaders::default(),
                },
                InMemoryVerifiedStream::from_bytes(
                    Bytes::from(payload),
                    Some(ChecksumAlgorithm::Crc32c),
                ),
            )
            .await
            .unwrap();
    }

    let wal_files_before = disk.read_dir("wal").unwrap();
    assert!(
        wal_files_before.len() >= 3,
        "expected multiple rolled WAL files, got {wal_files_before:?}"
    );
    assert!(engine.should_checkpoint());

    // Delete older versions on some keys & run compaction before checkpoint
    let vers = engine
        .list_object_versions(ListObjectVersionsReq {
            ctx: caller(3_000),
            bucket: "m3-bkt".into(),
            prefix: String::new(),
            delimiter: None,
            key_marker: None,
            version_id_marker: None,
            max_keys: 1000,
        })
        .await
        .unwrap();
    for entry in vers.entries.iter().filter(|e| !e.is_latest) {
        engine
            .delete_object(DeleteObjectReq {
                ctx: caller(3_100),
                bucket: "m3-bkt".into(),
                key: entry.key.clone(),
                version_id: Some(entry.version_id.clone()),
                if_match: None,
                bypass_governance: false,
            })
            .await
            .unwrap();
    }

    let compacted = engine.compact().await.unwrap();
    assert!(compacted >= 1, "expected GC to compact at least 1 dead segment");

    let ckpt_lsn = engine.write_checkpoint().await.unwrap();
    assert!(ckpt_lsn > 40);

    let wal_files_after = disk.read_dir("wal").unwrap();
    assert!(
        wal_files_after.len() < wal_files_before.len(),
        "expected covered sealed WALs to be pruned: before={wal_files_before:?}, after={wal_files_after:?}"
    );

    // Also add post-checkpoint WAL tail mutations + an open multipart upload + a completed multipart upload
    let mp = engine
        .create_multipart_upload(CreateMultipartUploadReq {
            ctx: caller(4_000),
            bucket: "m3-bkt".into(),
            key: "mp-composite".into(),
            sys_meta: SystemMeta::default(),
            user_meta: Vec::new(),
            acl: None,
            tags: None,
            checksum_algorithm: Some(ChecksumAlgorithm::Crc32),
            checksum_type: Some(ChecksumType::Composite),
            raw_sse: RawSseHeaders::default(),
            raw_lock: RawUploadObjectLockHeaders::default(),
        })
        .await
        .unwrap();
    let p1 = engine
        .upload_part(
            UploadPartReq {
                ctx: caller(4_001),
                bucket: "m3-bkt".into(),
                key: "mp-composite".into(),
                upload_id: mp.upload_id.clone(),
                part_number: 1,
                max_bytes_limit: MAX_PART_SIZE_BYTES,
                raw_sse: RawSseHeaders::default(),
            },
            InMemoryVerifiedStream::from_bytes(
                Bytes::from(vec![0xAB; 5 * 1024 * 1024]),
                Some(ChecksumAlgorithm::Crc32),
            ),
        )
        .await
        .unwrap();
    let p2 = engine
        .upload_part(
            UploadPartReq {
                ctx: caller(4_002),
                bucket: "m3-bkt".into(),
                key: "mp-composite".into(),
                upload_id: mp.upload_id.clone(),
                part_number: 2,
                max_bytes_limit: MAX_PART_SIZE_BYTES,
                raw_sse: RawSseHeaders::default(),
            },
            InMemoryVerifiedStream::from_bytes(
                Bytes::from(vec![0xCD; 1234]),
                Some(ChecksumAlgorithm::Crc32),
            ),
        )
        .await
        .unwrap();
    let comp_resp = engine
        .complete_multipart_upload(CompleteMultipartUploadReq {
            ctx: caller(4_003),
            bucket: "m3-bkt".into(),
            key: "mp-composite".into(),
            upload_id: mp.upload_id.clone(),
            parts: vec![
                CompletePartSpec {
                    part_number: 1,
                    etag: p1.etag,
                    checksum: p1.checksum.map(|c| (c.algorithm, c.value_b64)),
                },
                CompletePartSpec {
                    part_number: 2,
                    etag: p2.etag,
                    checksum: p2.checksum.map(|c| (c.algorithm, c.value_b64)),
                },
            ],
            preconditions: Preconditions::default(),
            expected_object_size: None,
            expected_checksum: None,
            raw_sse: RawSseHeaders::default(),
        })
        .await
        .unwrap();

    // Open multipart upload with 1 part
    let open_mp = engine
        .create_multipart_upload(CreateMultipartUploadReq {
            ctx: caller(4_010),
            bucket: "m3-bkt".into(),
            key: "mp-open".into(),
            sys_meta: SystemMeta::default(),
            user_meta: Vec::new(),
            acl: None,
            tags: None,
            checksum_algorithm: Some(ChecksumAlgorithm::Sha256),
            checksum_type: Some(ChecksumType::Composite),
            raw_sse: RawSseHeaders::default(),
            raw_lock: RawUploadObjectLockHeaders::default(),
        })
        .await
        .unwrap();
    engine
        .upload_part(
            UploadPartReq {
                ctx: caller(4_011),
                bucket: "m3-bkt".into(),
                key: "mp-open".into(),
                upload_id: open_mp.upload_id.clone(),
                part_number: 1,
                max_bytes_limit: MAX_PART_SIZE_BYTES,
                raw_sse: RawSseHeaders::default(),
            },
            InMemoryVerifiedStream::from_bytes(
                Bytes::from(vec![0x55; 4096]),
                Some(ChecksumAlgorithm::Sha256),
            ),
        )
        .await
        .unwrap();

    let metrics = engine.metrics_snapshot();
    assert_eq!(metrics.checkpoints_total, 1);
    assert_eq!(metrics.last_checkpoint_lsn, ckpt_lsn);
    assert_eq!(metrics.catalog_buckets, 1);
    assert_eq!(metrics.catalog_open_uploads, 1);

    drop(engine);

    // Simulate sudden power cut and recover from checkpoint + WAL tail!
    let mut rng = StdRng::seed_from_u64(2026);
    let crashed = disk.power_cut(&mut rng);
    let report = run_fsck(crashed.clone());
    assert_eq!(report.status, "ok", "fsck failed: {:?}", report.errors);
    assert_eq!(report.open_uploads, 1);
    assert!(report.errors.is_empty());

    let recovered = Engine::open(crashed, cfg).unwrap();
    let got = recovered
        .get_object(GetObjectReq {
            ctx: caller(5_000),
            bucket: "m3-bkt".into(),
            key: "mp-composite".into(),
            version_id: None,
            range: None,
            part_number: None,
            preconditions: Preconditions::default(),
            checksum_mode_enabled: true,
            raw_sse: RawSseHeaders::default(),
        })
        .await
        .unwrap();
    assert_eq!(got.meta.etag, comp_resp.etag);
    assert_eq!(got.meta.checksum, comp_resp.checksum);
    let bytes = read_all(got.reader).await.unwrap();
    assert_eq!(bytes.len(), 5 * 1024 * 1024 + 1234);
    assert_eq!(&bytes[..16], &[0xAB; 16]);
    assert_eq!(&bytes[5 * 1024 * 1024..], &[0xCD; 1234]);
}

#[tokio::test]
async fn corrupt_latest_checkpoint_refuses_startup_st8() {
    let disk = FaultDisk::new();
    let engine = Engine::open(disk.clone(), EngineConfig::default()).unwrap();
    engine
        .create_bucket(CreateBucketReq {
            ctx: caller(1_000),
            bucket: "st8-bkt".into(),
            location_constraint: None,
            object_ownership: None,
            acl: None,
            object_lock_enabled: false,
        })
        .await
        .unwrap();
    let lsn1 = engine.write_checkpoint().await.unwrap();

    // Keep an older valid checkpoint copy on disk to prove Engine::open NEVER silently falls back!
    let ckpt1_name = format!("ckpt/ckpt-{lsn1:016x}");
    let old_raw = {
        let f = disk.open(&ckpt1_name, OpenOpts::read_only()).unwrap();
        let mut v = vec![0u8; f.len().unwrap() as usize];
        f.read_exact_at(0, &mut v).unwrap();
        v
    };

    engine
        .put_object(
            PutObjectReq {
                ctx: caller(2_000),
                bucket: "st8-bkt".into(),
                key: "k1".into(),
                sys_meta: SystemMeta::default(),
                user_meta: Vec::new(),
                acl: None,
                tags: None,
                preconditions: Preconditions::default(),
                max_bytes_limit: MAX_SINGLE_PUT_BYTES,
                raw_sse: RawSseHeaders::default(),
                raw_lock: RawUploadObjectLockHeaders::default(),
            },
            InMemoryVerifiedStream::from_bytes(Bytes::from_static(b"hello-st8"), None),
        )
        .await
        .unwrap();
    let lsn2 = engine.write_checkpoint().await.unwrap();
    assert!(lsn2 > lsn1);
    drop(engine);

    // Re-materialize older ckpt1 alongside ckpt2, then flip 1 bit in ckpt2
    {
        let f1 = disk.open(&ckpt1_name, OpenOpts::create_truncate_rw()).unwrap();
        f1.write_all_at(0, &old_raw).unwrap();
        f1.sync_data().unwrap();

        let ckpt2_name = format!("ckpt/ckpt-{lsn2:016x}");
        let f2 = disk.open(&ckpt2_name, OpenOpts::open_rw()).unwrap();
        let len = f2.len().unwrap();
        let mut b = [0u8; 1];
        f2.read_exact_at(len / 2, &mut b).unwrap();
        b[0] ^= 0x04;
        f2.write_all_at(len / 2, &b).unwrap();
        f2.sync_data().unwrap();
        disk.sync_dir("ckpt").unwrap();
    }

    // Engine::open MUST refuse startup with EngineOpenError::Corrupt (ST-8)!
    let err = match Engine::open(disk.clone(), EngineConfig::default()) {
        Ok(_) => panic!("Engine::open silently fell back or accepted corrupt checkpoint!"),
        Err(e) => e,
    };
    assert!(matches!(err, EngineOpenError::Corrupt(_)), "unexpected err: {err:?}");

    let report = run_fsck(disk);
    assert_eq!(report.status, "corrupted");
    assert!(!report.errors.is_empty());
}

#[tokio::test]
async fn fsck_detects_segment_wal_and_missing_file_corruptions_nfr13() {
    let disk = FaultDisk::new();
    let engine = Engine::open(disk.clone(), EngineConfig::default()).unwrap();
    engine
        .create_bucket(CreateBucketReq {
            ctx: caller(1_000),
            bucket: "fsck-bkt".into(),
            location_constraint: None,
            object_ownership: None,
            acl: None,
            object_lock_enabled: false,
        })
        .await
        .unwrap();
    for k in ["obj-a", "obj-b"] {
        engine
            .put_object(
                PutObjectReq {
                    ctx: caller(1_500),
                    bucket: "fsck-bkt".into(),
                    key: k.into(),
                    sys_meta: SystemMeta::default(),
                    user_meta: Vec::new(),
                    acl: None,
                    tags: None,
                    preconditions: Preconditions::default(),
                    max_bytes_limit: MAX_SINGLE_PUT_BYTES,
                    raw_sse: RawSseHeaders::default(),
                    raw_lock: RawUploadObjectLockHeaders::default(),
                },
                InMemoryVerifiedStream::from_bytes(
                    Bytes::from(vec![0x42; 1024]),
                    Some(ChecksumAlgorithm::Sha256),
                ),
            )
            .await
            .unwrap();
    }
    drop(engine);

    let mut rng = StdRng::seed_from_u64(99);

    // Baseline clean fsck
    let base = run_fsck(disk.clone());
    assert_eq!(base.status, "ok");

    // Case A: Flip a payload byte inside `seg/00000001.seg`
    {
        let d = disk.power_cut(&mut rng);
        let f = d.open("seg/00000001.seg", OpenOpts::open_rw()).unwrap();
        let mut b = [0u8; 1];
        f.read_exact_at(64, &mut b).unwrap();
        b[0] ^= 0x80;
        f.write_all_at(64, &b).unwrap();
        f.sync_data().unwrap();
        let rep = run_fsck(d);
        assert_eq!(rep.status, "corrupted");
        assert!(
            rep.errors.iter().any(|e| e.contains("CRC mismatch")),
            "expected CRC mismatch in {:?}",
            rep.errors
        );
    }

    // Case B: Flip a byte in a mid-WAL record (not the final tail record!)
    {
        let d = disk.power_cut(&mut rng);
        let f = d.open("wal/00000001.log", OpenOpts::open_rw()).unwrap();
        let mut b = [0u8; 1];
        // Offset 40 is inside the very first WAL record (`CreateBucket`, followed by two `PutVersion` records)
        f.read_exact_at(40, &mut b).unwrap();
        b[0] ^= 0x01;
        f.write_all_at(40, &b).unwrap();
        f.sync_data().unwrap();
        let rep = run_fsck(d);
        assert_eq!(rep.status, "corrupted");
        assert!(!rep.errors.is_empty());
    }

    // Case C: Remove referenced segment file `seg/00000001.seg`
    {
        let d = disk.power_cut(&mut rng);
        d.remove_file("seg/00000001.seg").unwrap();
        d.sync_dir("seg").unwrap();
        let rep = run_fsck(d);
        assert_eq!(rep.status, "corrupted");
        assert!(
            rep.errors.iter().any(|e| e.contains("missing segment")),
            "expected missing segment error in {:?}",
            rep.errors
        );
    }
}

#[tokio::test]
async fn low_disk_space_returns_503_slowdown_while_reads_deletes_and_gc_succeed_nfr16() {
    let disk = FaultDisk::new();
    let cfg = EngineConfig {
        segment_size: 4096,
        max_block_payload: 1024,
        reserved_disk_bytes: 2 * 1024 * 1024 * 1024, // 2 GiB
        gc_live_ratio: 0.9,
        ..EngineConfig::default()
    };
    let engine = Engine::open(disk.clone(), cfg).unwrap();
    engine
        .create_bucket(CreateBucketReq {
            ctx: caller(1_000),
            bucket: "nfr16-bkt".into(),
            location_constraint: None,
            object_ownership: None,
            acl: None,
            object_lock_enabled: false,
        })
        .await
        .unwrap();

    for i in 0..6 {
        engine
            .put_object(
                PutObjectReq {
                    ctx: caller(1_100 + i),
                    bucket: "nfr16-bkt".into(),
                    key: format!("k-{i}"),
                    sys_meta: SystemMeta::default(),
                    user_meta: Vec::new(),
                    acl: None,
                    tags: None,
                    preconditions: Preconditions::default(),
                    max_bytes_limit: MAX_SINGLE_PUT_BYTES,
                    raw_sse: RawSseHeaders::default(),
                    raw_lock: RawUploadObjectLockHeaders::default(),
                },
                InMemoryVerifiedStream::from_bytes(Bytes::from(vec![0x33; 1500]), None),
            )
            .await
            .unwrap();
    }

    // Drop available space below 2 GiB reserved threshold!
    disk.set_available_bytes(512 * 1024 * 1024); // 512 MiB < 2 GiB

    // 1. New writes MUST be rejected with 503 SlowDown
    let put_err = engine
        .put_object(
            PutObjectReq {
                ctx: caller(2_000),
                bucket: "nfr16-bkt".into(),
                key: "blocked".into(),
                sys_meta: SystemMeta::default(),
                user_meta: Vec::new(),
                acl: None,
                tags: None,
                preconditions: Preconditions::default(),
                max_bytes_limit: MAX_SINGLE_PUT_BYTES,
                raw_sse: RawSseHeaders::default(),
                raw_lock: RawUploadObjectLockHeaders::default(),
            },
            InMemoryVerifiedStream::from_bytes(Bytes::from_static(b"nope"), None),
        )
        .await
        .err()
        .unwrap();
    assert_eq!(put_err.code, S3ErrorCode::SlowDown);
    assert_eq!(put_err.code.status_code(), 503);

    let cb_err = engine
        .create_bucket(CreateBucketReq {
            ctx: caller(2_001),
            bucket: "blocked-bkt".into(),
            location_constraint: None,
            object_ownership: None,
            acl: None,
            object_lock_enabled: false,
        })
        .await
        .err()
        .unwrap();
    assert_eq!(cb_err.code, S3ErrorCode::SlowDown);

    // 2. Reads, HEAD, ListObjectsV2 MUST succeed
    let got = engine
        .get_object(GetObjectReq {
            ctx: caller(2_010),
            bucket: "nfr16-bkt".into(),
            key: "k-0".into(),
            version_id: None,
            range: None,
            part_number: None,
            preconditions: Preconditions::default(),
            checksum_mode_enabled: false,
            raw_sse: RawSseHeaders::default(),
        })
        .await
        .unwrap();
    assert_eq!(read_all(got.reader).await.unwrap().len(), 1500);

    let listed = engine
        .list_objects_v2(ListObjectsV2Req {
            ctx: caller(2_011),
            bucket: "nfr16-bkt".into(),
            prefix: String::new(),
            delimiter: None,
            max_keys: 1000,
            continuation_token: None,
            start_after: None,
            fetch_owner: false,
        })
        .await
        .unwrap();
    assert_eq!(listed.contents.len(), 6);

    // 3. DeleteObject, DeleteObjects, and compact() MUST succeed under low disk space!
    engine
        .delete_object(DeleteObjectReq {
            ctx: caller(2_020),
            bucket: "nfr16-bkt".into(),
            key: "k-0".into(),
            version_id: None,
            if_match: None,
            bypass_governance: false,
        })
        .await
        .unwrap();
    let del_multi = engine
        .delete_objects(DeleteObjectsReq {
            ctx: caller(2_021),
            bucket: "nfr16-bkt".into(),
            quiet: false,
            items: vec![
                DeleteObjectsItem {
                    key: "k-1".into(),
                    version_id: None,
                    etag_if_match: None,
                },
                DeleteObjectsItem {
                    key: "k-2".into(),
                    version_id: None,
                    etag_if_match: None,
                },
            ],
            bypass_governance: false,
        })
        .await
        .unwrap();
    assert_eq!(del_multi.errors.len(), 0);
    assert_eq!(del_multi.deleted.len(), 2);

    let compacted = engine.compact().await.unwrap();
    assert!(compacted >= 1, "expected GC to reclaim segments even under low disk space");

    // Restore disk space -> writes resume!
    disk.set_available_bytes(10 * 1024 * 1024 * 1024);
    engine
        .put_object(
            PutObjectReq {
                ctx: caller(3_000),
                bucket: "nfr16-bkt".into(),
                key: "resumed".into(),
                sys_meta: SystemMeta::default(),
                user_meta: Vec::new(),
                acl: None,
                tags: None,
                preconditions: Preconditions::default(),
                max_bytes_limit: MAX_SINGLE_PUT_BYTES,
                raw_sse: RawSseHeaders::default(),
                raw_lock: RawUploadObjectLockHeaders::default(),
            },
            InMemoryVerifiedStream::from_bytes(Bytes::from_static(b"ok"), None),
        )
        .await
        .unwrap();
}
