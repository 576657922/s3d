use std::collections::BTreeMap;
use std::future::poll_fn;
use std::pin::Pin;

use bytes::{Bytes, BytesMut};
use proptest::prelude::*;
use rand::rngs::StdRng;
use rand::seq::SliceRandom;
use rand::{Rng, SeedableRng};
use s3d_disk::{Disk, DiskFile, FaultDisk, OpenOpts};
use s3d_engine::{run_fsck, Engine, EngineConfig};
use s3d_model::{InMemoryVerifiedStream, ModelConfig, ModelStore};
use s3d_types::*;

async fn read_all<R: AsyncByteReader>(mut reader: R) -> StoreResult<Bytes> {
    let mut out = BytesMut::new();
    while let Some(chunk) = poll_fn(|cx| Pin::new(&mut reader).poll_read_chunk(cx)).await? {
        out.extend_from_slice(&chunk);
    }
    Ok(out.freeze())
}

fn test_caller(time_ms: i64) -> CallerContext {
    CallerContext {
        caller: Some(OwnerInfo {
            user_id: "0123456789abcdef".into(),
            display_name: "tester".into(),
            email: "tester@example.com".into(),
        }),
        request_time_ms: time_ms,
        expected_bucket_owner: None,
        is_authenticated: true,
    }
}

#[derive(Debug, Clone)]
enum ModelOp {
    CreateBucket(u8),
    DeleteBucket(u8),
    Put {
        b: u8,
        k: u8,
        size: usize,
        seed: u8,
        bad_digest: bool,
        if_none_match_star: bool,
    },
    Get {
        b: u8,
        k: u8,
        range: Option<ByteRangeSpec>,
    },
    Head {
        b: u8,
        k: u8,
    },
    Delete {
        b: u8,
        k: u8,
        if_match_star: bool,
    },
    Copy {
        sb: u8,
        sk: u8,
        db: u8,
        dk: u8,
        replace_meta: bool,
    },
    ListV1 {
        b: u8,
        prefix_idx: u8,
        delim: bool,
        max_keys: usize,
    },
    ListV2 {
        b: u8,
        prefix_idx: u8,
        delim: bool,
        max_keys: usize,
    },
    Compact,
}

const BUCKET_POOL: &[&str] = &["alpha-bkt", "beta-bkt", "ab"]; // includes invalid "ab"
const KEY_POOL: &[&str] = &[
    "k1",
    "k2",
    "dir/a",
    "dir/b",
    "dir//nested/../weird+key",
    "unicode-键名/测试",
];
const PREFIX_POOL: &[&str] = &["", "dir/", "k", "nonexistent/"];

fn op_strategy() -> impl Strategy<Value = ModelOp> {
    prop_oneof![
        2 => (0u8..3).prop_map(ModelOp::CreateBucket),
        1 => (0u8..3).prop_map(ModelOp::DeleteBucket),
        6 => (
            0u8..3,
            0u8..6,
            prop_oneof![Just(0usize), Just(1), Just(4095), Just(4096), Just(8192), Just(20_000)],
            any::<u8>(),
            prop::bool::weighted(0.15),
            prop::bool::weighted(0.25),
        )
            .prop_map(|(b, k, size, seed, bad_digest, if_none_match_star)| ModelOp::Put {
                b,
                k,
                size,
                seed,
                bad_digest,
                if_none_match_star,
            }),
        5 => (
            0u8..3,
            0u8..6,
            prop_oneof![
                Just(None),
                Just(Some(ByteRangeSpec::FromTo { start: 0, end: 10 })),
                Just(Some(ByteRangeSpec::From { start: 4096 })),
                Just(Some(ByteRangeSpec::Suffix { len: 128 })),
            ],
        )
            .prop_map(|(b, k, range)| ModelOp::Get { b, k, range }),
        2 => (0u8..3, 0u8..6).prop_map(|(b, k)| ModelOp::Head { b, k }),
        3 => (0u8..3, 0u8..6, prop::bool::weighted(0.3))
            .prop_map(|(b, k, if_match_star)| ModelOp::Delete { b, k, if_match_star }),
        2 => (0u8..2, 0u8..4, 0u8..2, 0u8..4, any::<bool>())
            .prop_map(|(sb, sk, db, dk, replace_meta)| ModelOp::Copy {
                sb,
                sk,
                db,
                dk,
                replace_meta,
            }),
        2 => (0u8..2, 0u8..4, any::<bool>(), 0usize..=4)
            .prop_map(|(b, prefix_idx, delim, max_keys)| ModelOp::ListV1 {
                b,
                prefix_idx,
                delim,
                max_keys,
            }),
        2 => (0u8..2, 0u8..4, any::<bool>(), 0usize..=4)
            .prop_map(|(b, prefix_idx, delim, max_keys)| ModelOp::ListV2 {
                b,
                prefix_idx,
                delim,
                max_keys,
            }),
        1 => Just(ModelOp::Compact),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(250))] // 250 cases * 45 ops = >11,000 op steps!
    #[test]
    fn vr2_differential_engine_vs_model(ops in prop::collection::vec(op_strategy(), 1..45)) {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        rt.block_on(async move {
            let disk = FaultDisk::new();
            let eng_cfg = EngineConfig {
                segment_size: 32 * 1024, // small segment size to force frequent rolls & GC!
                wal_file_size: 16 * 1024,
                max_block_payload: 8 * 1024, // 8 KiB blocks to force multi-block extents!
                ..EngineConfig::default()
            };
            let engine = Engine::open(disk.clone(), eng_cfg).unwrap();
            let model = ModelStore::new(ModelConfig::default());

            let mut clock_ms = 1_762_900_000_000i64;

            for op in ops {
                clock_ms += 1000;
                let ctx = test_caller(clock_ms);

                match op {
                    ModelOp::CreateBucket(bi) => {
                        let req = CreateBucketReq {
                            ctx,
                            bucket: BUCKET_POOL[bi as usize].to_string(),
                            location_constraint: None,
                            object_ownership: None,
                        };
                        let re = engine.create_bucket(req.clone()).await.map(|r| r.name);
                        let rm = model.create_bucket(req).await.map(|r| r.name);
                        assert_eq!(re.map_err(|e| e.code), rm.map_err(|e| e.code));
                    }
                    ModelOp::DeleteBucket(bi) => {
                        let req = BucketRef {
                            ctx,
                            bucket: BUCKET_POOL[bi as usize].to_string(),
                        };
                        let re = engine.delete_bucket(req.clone()).await;
                        let rm = model.delete_bucket(req).await;
                        assert_eq!(re.map_err(|e| e.code), rm.map_err(|e| e.code));
                    }
                    ModelOp::Put { b, k, size, seed, bad_digest, if_none_match_star } => {
                        let payload: Vec<u8> = (0..size).map(|i| seed.wrapping_add(i as u8)).collect();
                        let cond = if if_none_match_star {
                            Preconditions {
                                if_none_match: Some(vec!["*".into()]),
                                ..Default::default()
                            }
                        } else {
                            Preconditions::default()
                        };
                        let req = PutObjectReq {
                            ctx,
                            bucket: BUCKET_POOL[b as usize].to_string(),
                            key: KEY_POOL[k as usize].to_string(),
                            sys_meta: SystemMeta::default(),
                            user_meta: vec![("k".into(), format!("v{seed}"))],
                            preconditions: cond,
                            max_bytes_limit: MAX_SINGLE_PUT_BYTES,
                        };
                        let make_stream = || {
                            let s = InMemoryVerifiedStream::from_bytes(
                                Bytes::from(payload.clone()),
                                Some(ChecksumAlgorithm::Crc32c),
                            );
                            if bad_digest {
                                s.with_injected_error(BodyStreamError::BadDigest)
                            } else {
                                s
                            }
                        };
                        let re = engine.put_object(req.clone(), make_stream()).await;
                        let rm = model.put_object(req, make_stream()).await;
                        match (re, rm) {
                            (Ok(ae), Ok(am)) => {
                                assert_eq!(ae.etag, am.etag);
                                assert_eq!(ae.checksum, am.checksum);
                            }
                            (Err(ee), Err(em)) => assert_eq!(ee.code, em.code),
                            (l, r) => panic!("Put mismatch: engine={l:?}, model={r:?}"),
                        }
                    }
                    ModelOp::Get { b, k, range } => {
                        let req = GetObjectReq {
                            ctx,
                            bucket: BUCKET_POOL[b as usize].to_string(),
                            key: KEY_POOL[k as usize].to_string(),
                            version_id: None,
                            range,
                            part_number: None,
                            preconditions: Preconditions::default(),
                            checksum_mode_enabled: true,
                        };
                        let re = engine.get_object(req.clone()).await;
                        let rm = model.get_object(req).await;
                        match (re, rm) {
                            (Ok(ge), Ok(gm)) => {
                                assert_eq!(ge.meta.etag, gm.meta.etag);
                                assert_eq!(ge.meta.content_length, gm.meta.content_length);
                                assert_eq!(ge.meta.content_range, gm.meta.content_range);
                                assert_eq!(ge.meta.checksum, gm.meta.checksum);
                                let be = read_all(ge.reader).await.unwrap();
                                let bm = read_all(gm.reader).await.unwrap();
                                assert_eq!(be, bm);
                            }
                            (Err(ee), Err(em)) => assert_eq!(ee.code, em.code),
                            (l, r) => panic!(
                                "Get mismatch: engine={:?}, model={:?}",
                                l.map(|x| x.meta).map_err(|e| e.code),
                                r.map(|x| x.meta).map_err(|e| e.code)
                            ),
                        }
                    }
                    ModelOp::Head { b, k } => {
                        let req = GetObjectReq {
                            ctx,
                            bucket: BUCKET_POOL[b as usize].to_string(),
                            key: KEY_POOL[k as usize].to_string(),
                            version_id: None,
                            range: None,
                            part_number: None,
                            preconditions: Preconditions::default(),
                            checksum_mode_enabled: true,
                        };
                        let re = engine.head_object(req.clone()).await;
                        let rm = model.head_object(req).await;
                        match (re, rm) {
                            (Ok(he), Ok(hm)) => {
                                assert_eq!(he.etag, hm.etag);
                                assert_eq!(he.content_length, hm.content_length);
                                assert_eq!(he.user_meta, hm.user_meta);
                            }
                            (Err(ee), Err(em)) => assert_eq!(ee.code, em.code),
                            (l, r) => panic!("Head mismatch: engine={l:?}, model={r:?}"),
                        }
                    }
                    ModelOp::Delete { b, k, if_match_star } => {
                        let req = DeleteObjectReq {
                            ctx,
                            bucket: BUCKET_POOL[b as usize].to_string(),
                            key: KEY_POOL[k as usize].to_string(),
                            version_id: None,
                            if_match: if if_match_star {
                                Some(vec!["*".into()])
                            } else {
                                None
                            },
                        };
                        let re = engine.delete_object(req.clone()).await;
                        let rm = model.delete_object(req).await;
                        assert_eq!(
                            re.map(|r| r.is_delete_marker).map_err(|e| e.code),
                            rm.map(|r| r.is_delete_marker).map_err(|e| e.code)
                        );
                    }
                    ModelOp::Copy { sb, sk, db, dk, replace_meta } => {
                        let req = CopyObjectReq {
                            ctx,
                            src_bucket: BUCKET_POOL[sb as usize].to_string(),
                            src_key: KEY_POOL[sk as usize].to_string(),
                            src_version_id: None,
                            dst_bucket: BUCKET_POOL[db as usize].to_string(),
                            dst_key: KEY_POOL[dk as usize].to_string(),
                            replace_metadata: replace_meta,
                            sys_meta: SystemMeta::default(),
                            user_meta: vec![("copied".into(), "true".into())],
                            src_preconditions: Preconditions::default(),
                            dst_preconditions: Preconditions::default(),
                        };
                        let re = engine.copy_object(req.clone()).await;
                        let rm = model.copy_object(req).await;
                        assert_eq!(
                            re.map(|r| r.etag).map_err(|e| e.code),
                            rm.map(|r| r.etag).map_err(|e| e.code)
                        );
                    }
                    ModelOp::ListV1 { b, prefix_idx, delim, max_keys } => {
                        let req = ListObjectsV1Req {
                            ctx,
                            bucket: BUCKET_POOL[b as usize].to_string(),
                            prefix: PREFIX_POOL[prefix_idx as usize].to_string(),
                            delimiter: if delim { Some("/".into()) } else { None },
                            marker: None,
                            max_keys,
                        };
                        let re = engine.list_objects_v1(req.clone()).await;
                        let rm = model.list_objects_v1(req).await;
                        match (re, rm) {
                            (Ok(le), Ok(lm)) => {
                                let ke: Vec<_> = le.contents.iter().map(|c| (&c.key, c.size, &c.etag)).collect();
                                let km: Vec<_> = lm.contents.iter().map(|c| (&c.key, c.size, &c.etag)).collect();
                                assert_eq!(ke, km);
                                assert_eq!(le.common_prefixes, lm.common_prefixes);
                                assert_eq!(le.is_truncated, lm.is_truncated);
                                assert_eq!(le.next_marker, lm.next_marker);
                            }
                            (Err(ee), Err(em)) => assert_eq!(ee.code, em.code),
                            (l, r) => panic!("ListV1 mismatch: {l:?} vs {r:?}"),
                        }
                    }
                    ModelOp::ListV2 { b, prefix_idx, delim, max_keys } => {
                        let req = ListObjectsV2Req {
                            ctx,
                            bucket: BUCKET_POOL[b as usize].to_string(),
                            prefix: PREFIX_POOL[prefix_idx as usize].to_string(),
                            delimiter: if delim { Some("/".into()) } else { None },
                            start_after: None,
                            continuation_token: None,
                            max_keys,
                            fetch_owner: true,
                        };
                        let re = engine.list_objects_v2(req.clone()).await;
                        let rm = model.list_objects_v2(req).await;
                        match (re, rm) {
                            (Ok(le), Ok(lm)) => {
                                let ke: Vec<_> = le.contents.iter().map(|c| (&c.key, c.size, &c.etag)).collect();
                                let km: Vec<_> = lm.contents.iter().map(|c| (&c.key, c.size, &c.etag)).collect();
                                assert_eq!(ke, km);
                                assert_eq!(le.common_prefixes, lm.common_prefixes);
                                assert_eq!(le.is_truncated, lm.is_truncated);
                                assert_eq!(le.key_count, lm.key_count);
                            }
                            (Err(ee), Err(em)) => assert_eq!(ee.code, em.code),
                            (l, r) => panic!("ListV2 mismatch: {l:?} vs {r:?}"),
                        }
                    }
                    ModelOp::Compact => {
                        engine.compact().await.unwrap();
                    }
                }
            }

            drop(engine);
            let report = run_fsck(disk);
            assert_eq!(report.status, "ok", "fsck errors: {:?}", report.errors);
        });
    }
}

/// VR-3: 1,000 random power-cut cycles with un-fsynced torn writes, segment rollovers, and GC!
/// Verifies ST-1 (confirmed writes survive), ST-2 (byte-exact), ST-3 (no half objects),
/// ST-4 (no deleted/overwritten resurrection), and clean post-recovery fsck & continued writes.
#[tokio::test]
async fn vr3_1000_random_power_cuts_zero_violations() {
    let mut rng = StdRng::seed_from_u64(0x5333_2026);
    let mut disk = FaultDisk::new();
    let cfg = EngineConfig {
        segment_size: 24 * 1024,
        wal_file_size: 12 * 1024,
        max_block_payload: 4 * 1024,
        ..EngineConfig::default()
    };

    // Confirmed ground truth: key -> Option<Vec<u8>> (None = confirmed deleted)
    let mut confirmed: BTreeMap<String, Option<Vec<u8>>> = BTreeMap::new();
    let mut bucket_created = false;

    for round in 0..1000usize {
        let engine = Engine::open(disk.clone(), cfg.clone())
            .unwrap_or_else(|e| panic!("round {round} recovery failed: {e}"));
        let ctx = test_caller(1_762_900_000_000 + round as i64 * 1000);

        if !bucket_created {
            engine
                .create_bucket(CreateBucketReq {
                    ctx: ctx.clone(),
                    bucket: "crash-bkt".into(),
                    location_constraint: None,
                    object_ownership: None,
                })
                .await
                .unwrap();
            bucket_created = true;
        }

        // Verify ST-1, ST-2, ST-4 against confirmed state right after recovery!
        for (k, expected) in &confirmed {
            let res = engine
                .get_object(GetObjectReq {
                    ctx: ctx.clone(),
                    bucket: "crash-bkt".into(),
                    key: k.clone(),
                    version_id: None,
                    range: None,
                    part_number: None,
                    preconditions: Preconditions::default(),
                    checksum_mode_enabled: true,
                })
                .await;
            match (expected, res) {
                (None, Err(e)) => assert_eq!(e.code, S3ErrorCode::NoSuchKey, "round {round} key {k}"),
                (None, Ok(_)) => panic!("round {round}: deleted key {k} resurrected! (ST-4)"),
                (Some(exp_bytes), Ok(got)) => {
                    let actual = read_all(got.reader).await.unwrap();
                    assert_eq!(&actual[..], &exp_bytes[..], "round {round}: corrupt bytes on {k} (ST-2)");
                }
                (Some(_), Err(e)) => {
                    panic!("round {round}: confirmed key {k} lost after crash: {e} (ST-1)")
                }
            }
        }

        // Execute 1..=4 confirmed operations (puts, overwrites, deletes, occasional GC)
        let steps = rng.gen_range(1..=3);
        for _ in 0..steps {
            let key = format!("k{}", rng.gen_range(0..6));
            if rng.gen_bool(0.7) {
                let len = *[0usize, 17, 4096, 9000].choose(&mut rng).unwrap();
                let mut data = vec![0u8; len];
                rng.fill(&mut data[..]);
                engine
                    .put_object(
                        PutObjectReq {
                            ctx: ctx.clone(),
                            bucket: "crash-bkt".into(),
                            key: key.clone(),
                            sys_meta: SystemMeta::default(),
                            user_meta: Vec::new(),
                            preconditions: Preconditions::default(),
                            max_bytes_limit: MAX_SINGLE_PUT_BYTES,
                        },
                        InMemoryVerifiedStream::from_bytes(Bytes::from(data.clone()), None),
                    )
                    .await
                    .unwrap();
                confirmed.insert(key, Some(data));
            } else {
                engine
                    .delete_object(DeleteObjectReq {
                        ctx: ctx.clone(),
                        bucket: "crash-bkt".into(),
                        key: key.clone(),
                        version_id: None,
                        if_match: None,
                    })
                    .await
                    .unwrap();
                confirmed.insert(key, None);
            }
        }

        if round % 20 == 0 {
            engine.compact().await.unwrap();
        }

        // Inject un-fsynced dirty tail writes onto active WAL and active segment right before power cut
        // to simulate an in-flight crashed write tearing across 4 KiB sectors! (ST-3, ST-6)
        if rng.gen_bool(0.6) {
            if let Ok(wal_files) = disk.read_dir("wal") {
                if let Some(last_wal) = wal_files.last() {
                    if let Ok(wf) = disk.open(&format!("wal/{last_wal}"), OpenOpts::open_rw()) {
                        let pos = wf.len().unwrap();
                        let mut junk = vec![0u8; rng.gen_range(5..6000)];
                        rng.fill(&mut junk[..]);
                        // Deliberately put valid WAL_RECORD_MAGIC with torn body or random bytes without sync!
                        junk[0..4].copy_from_slice(&s3d_engine::format::WAL_RECORD_MAGIC.to_le_bytes());
                        let _ = wf.write_all_at(pos, &junk);
                    }
                }
            }
        }

        drop(engine);
        disk = disk.power_cut(&mut rng);
    }

    let report = run_fsck(disk);
    assert_eq!(report.status, "ok", "final fsck errors: {:?}", report.errors);
}

#[tokio::test]
async fn fsync_eio_triggers_immediate_read_only_circuit_breaker() {
    let disk = FaultDisk::new();
    let engine = Engine::open(disk.clone(), EngineConfig::default()).unwrap();
    let ctx = test_caller(1_762_900_000_000);

    engine
        .create_bucket(CreateBucketReq {
            ctx: ctx.clone(),
            bucket: "eio-bkt".into(),
            location_constraint: None,
            object_ownership: None,
        })
        .await
        .unwrap();

    engine
        .put_object(
            PutObjectReq {
                ctx: ctx.clone(),
                bucket: "eio-bkt".into(),
                key: "good".into(),
                sys_meta: SystemMeta::default(),
                user_meta: Vec::new(),
                preconditions: Preconditions::default(),
                max_bytes_limit: MAX_SINGLE_PUT_BYTES,
            },
            InMemoryVerifiedStream::from_bytes(Bytes::from_static(b"durable-v1"), None),
        )
        .await
        .unwrap();

    // Inject EIO on the next fsync!
    disk.fail_sync_after(1);
    let err = engine
        .put_object(
            PutObjectReq {
                ctx: ctx.clone(),
                bucket: "eio-bkt".into(),
                key: "bad".into(),
                sys_meta: SystemMeta::default(),
                user_meta: Vec::new(),
                preconditions: Preconditions::default(),
                max_bytes_limit: MAX_SINGLE_PUT_BYTES,
            },
            InMemoryVerifiedStream::from_bytes(Bytes::from_static(b"uncommitted"), None),
        )
        .await
        .unwrap_err();
    assert_eq!(err.code, S3ErrorCode::InternalError);
    assert!(engine.is_read_only_poisoned());

    // Even if disk later stops failing syncs, poisoned engine MUST NOT accept new writes (§10 hard rule!)
    disk.set_fail_all_syncs(false);
    let err2 = engine
        .delete_object(DeleteObjectReq {
            ctx: ctx.clone(),
            bucket: "eio-bkt".into(),
            key: "good".into(),
            version_id: None,
            if_match: None,
        })
        .await
        .unwrap_err();
    assert_eq!(err2.code, S3ErrorCode::InternalError);

    // Uncommitted "bad" key MUST NOT be visible in RAM, while committed "good" remains readable!
    assert_eq!(
        engine
            .head_object(GetObjectReq {
                ctx: ctx.clone(),
                bucket: "eio-bkt".into(),
                key: "bad".into(),
                version_id: None,
                range: None,
                part_number: None,
                preconditions: Preconditions::default(),
                checksum_mode_enabled: false,
            })
            .await
            .unwrap_err()
            .code,
        S3ErrorCode::NoSuchKey
    );
    let good = engine
        .get_object(GetObjectReq {
            ctx,
            bucket: "eio-bkt".into(),
            key: "good".into(),
            version_id: None,
            range: None,
            part_number: None,
            preconditions: Preconditions::default(),
            checksum_mode_enabled: false,
        })
        .await
        .unwrap();
    assert_eq!(&read_all(good.reader).await.unwrap()[..], b"durable-v1");
}
