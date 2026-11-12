//! `VR-4` §3.2 `Shuttle` randomized concurrency schedule checks over `Engine<FaultDisk>`:
//! 1. `shuttle_gc_vs_rw`: 4 concurrent tasks overwriting/reading keys across small segments +
//!    1 task running `compact()` and `write_checkpoint()`.
//! 2. `shuttle_multipart_complete_vs_abort`: concurrent `UploadPart` overwrites on identical
//!    `partNumber` (`FR-25`) + concurrent `CompleteMultipartUpload` vs `AbortMultipartUpload` (`FR-28`).
//! 3. `shuttle_conditional_write_mutex`: 4 concurrent tasks racing `PutObject(If-None-Match: *)`
//!    and `PutObject(If-Match)` / `DeleteObject(If-Match)` on the same key (`FR-17`).
//!
//! Includes both fast CI smoke tests (1,000 schedules total) and `vr4_shuttle_10k_m3_gate`
//! (10,000 randomized schedules across the 3 scenarios).

use std::future::poll_fn;
use std::pin::Pin;
use std::sync::Arc;

use bytes::{Bytes, BytesMut};
use s3d_disk::FaultDisk;
use s3d_engine::{run_fsck, Engine, EngineConfig};
use s3d_model::InMemoryVerifiedStream;
use s3d_types::*;

fn caller(time_ms: i64) -> CallerContext {
    CallerContext {
        caller: Some(OwnerInfo {
            user_id: "0123456789abcdef".into(),
            display_name: "shuttle".into(),
            email: "shuttle@example.com".into(),
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

fn scenario_gc_vs_rw() {
    shuttle::future::block_on(async {
        let disk = FaultDisk::new();
        let cfg = EngineConfig {
            segment_size: 2048,
            wal_file_size: 8192,
            max_block_payload: 512,
            gc_live_ratio: 0.9,
            ..EngineConfig::default()
        };
        let engine = Engine::open(disk.clone(), cfg).unwrap();
        engine
            .create_bucket(CreateBucketReq {
                ctx: caller(1_000),
                bucket: "shuttle-gc".into(),
                location_constraint: None,
                object_ownership: None,
                acl: None,
            })
            .await
            .unwrap();

        for k in ["k0", "k1"] {
            engine
                .put_object(
                    PutObjectReq {
                        ctx: caller(1_010),
                        bucket: "shuttle-gc".into(),
                        key: k.into(),
                        sys_meta: SystemMeta::default(),
                        user_meta: Vec::new(),
                        acl: None,
                        tags: None,
                        preconditions: Preconditions::default(),
                        max_bytes_limit: MAX_SINGLE_PUT_BYTES,
                    },
                    InMemoryVerifiedStream::from_bytes(Bytes::from(vec![0x11; 900]), None),
                )
                .await
                .unwrap();
        }

        let mut tasks = Vec::new();
        for tid in 0..4u8 {
            let eng = Arc::clone(&engine);
            tasks.push(shuttle::future::spawn(async move {
                let key = if tid % 2 == 0 { "k0" } else { "k1" };
                let fill = 0x20u8.wrapping_add(tid);
                shuttle::future::yield_now().await;
                eng.put_object(
                    PutObjectReq {
                        ctx: caller(2_000 + tid as i64),
                        bucket: "shuttle-gc".into(),
                        key: key.into(),
                        sys_meta: SystemMeta::default(),
                        user_meta: Vec::new(),
                        acl: None,
                        tags: None,
                        preconditions: Preconditions::default(),
                        max_bytes_limit: MAX_SINGLE_PUT_BYTES,
                    },
                    InMemoryVerifiedStream::from_bytes(Bytes::from(vec![fill; 900]), None),
                )
                .await
                .unwrap();

                shuttle::future::yield_now().await;
                let got = eng
                    .get_object(GetObjectReq {
                        ctx: caller(2_100 + tid as i64),
                        bucket: "shuttle-gc".into(),
                        key: key.into(),
                        version_id: None,
                        range: None,
                        part_number: None,
                        preconditions: Preconditions::default(),
                        checksum_mode_enabled: false,
                    })
                    .await
                    .unwrap();
                shuttle::future::yield_now().await;
                let body = read_all(got.reader).await.unwrap();
                assert_eq!(body.len(), 900);
                // Every byte must match a single writer's uniform fill byte (no torn/corrupt reads!)
                assert!(body.iter().all(|&b| b == body[0]));
            }));
        }

        let eng_gc = Arc::clone(&engine);
        let gc_task = shuttle::future::spawn(async move {
            shuttle::future::yield_now().await;
            eng_gc.compact().await.unwrap();
            shuttle::future::yield_now().await;
            eng_gc.write_checkpoint().await.unwrap();
        });

        for t in tasks {
            t.await.unwrap();
        }
        gc_task.await.unwrap();
        drop(engine);

        let rep = run_fsck(disk);
        assert_eq!(rep.status, "ok", "fsck errors after GC vs RW: {:?}", rep.errors);
    });
}

fn scenario_multipart_complete_vs_abort() {
    shuttle::future::block_on(async {
        let disk = FaultDisk::new();
        let engine = Engine::open(disk.clone(), EngineConfig::default()).unwrap();
        engine
            .create_bucket(CreateBucketReq {
                ctx: caller(1_000),
                bucket: "shuttle-mp".into(),
                location_constraint: None,
                object_ownership: None,
                acl: None,
            })
            .await
            .unwrap();

        let init = engine
            .create_multipart_upload(CreateMultipartUploadReq {
                ctx: caller(1_010),
                bucket: "shuttle-mp".into(),
                key: "race-obj".into(),
                sys_meta: SystemMeta::default(),
                user_meta: Vec::new(),
                acl: None,
                tags: None,
                checksum_algorithm: None,
                checksum_type: None,
            })
            .await
            .unwrap();

        // Step 1: 2 concurrent UploadPart calls racing on identical part_number = 1 (FR-25)
        let uid = init.upload_id.clone();
        let e1 = Arc::clone(&engine);
        let u1 = uid.clone();
        let p_a = shuttle::future::spawn(async move {
            shuttle::future::yield_now().await;
            e1.upload_part(
                UploadPartReq {
                    ctx: caller(1_100),
                    bucket: "shuttle-mp".into(),
                    key: "race-obj".into(),
                    upload_id: u1,
                    part_number: 1,
                    max_bytes_limit: MAX_PART_SIZE_BYTES,
                },
                InMemoryVerifiedStream::from_bytes(Bytes::from(vec![0xAA; 1024]), None),
            )
            .await
            .unwrap()
        });

        let e2 = Arc::clone(&engine);
        let u2 = uid.clone();
        let p_b = shuttle::future::spawn(async move {
            shuttle::future::yield_now().await;
            e2.upload_part(
                UploadPartReq {
                    ctx: caller(1_101),
                    bucket: "shuttle-mp".into(),
                    key: "race-obj".into(),
                    upload_id: u2,
                    part_number: 1,
                    max_bytes_limit: MAX_PART_SIZE_BYTES,
                },
                InMemoryVerifiedStream::from_bytes(Bytes::from(vec![0xBB; 2048]), None),
            )
            .await
            .unwrap()
        });

        let _ra = p_a.await.unwrap();
        let _rb = p_b.await.unwrap();

        // Inspect winning part 1 ETag via ListParts
        let lp = engine
            .list_parts(ListPartsReq {
                ctx: caller(1_200),
                bucket: "shuttle-mp".into(),
                key: "race-obj".into(),
                upload_id: uid.clone(),
                max_parts: 10,
                part_number_marker: 0,
            })
            .await
            .unwrap();
        assert_eq!(lp.parts.len(), 1);
        let winning_etag = lp.parts[0].etag.clone();
        let winning_size = lp.parts[0].size;

        // Step 2: Concurrent CompleteMultipartUpload vs AbortMultipartUpload (FR-28)
        let ec = Arc::clone(&engine);
        let uc = uid.clone();
        let comp_task = shuttle::future::spawn(async move {
            shuttle::future::yield_now().await;
            ec.complete_multipart_upload(CompleteMultipartUploadReq {
                ctx: caller(1_300),
                bucket: "shuttle-mp".into(),
                key: "race-obj".into(),
                upload_id: uc,
                parts: vec![CompletePartSpec {
                    part_number: 1,
                    etag: winning_etag,
                    checksum: None,
                }],
                preconditions: Preconditions::default(),
                expected_object_size: None,
                expected_checksum: None,
            })
            .await
        });

        let ea = Arc::clone(&engine);
        let ua = uid.clone();
        let abort_task = shuttle::future::spawn(async move {
            shuttle::future::yield_now().await;
            ea.abort_multipart_upload(AbortMultipartUploadReq {
                ctx: caller(1_301),
                bucket: "shuttle-mp".into(),
                key: "race-obj".into(),
                upload_id: ua,
            })
            .await
        });

        let comp_res = comp_task.await.unwrap();
        let abort_res = abort_task.await.unwrap();

        let head_res = engine
            .head_object(GetObjectReq {
                ctx: caller(1_400),
                bucket: "shuttle-mp".into(),
                key: "race-obj".into(),
                version_id: None,
                range: None,
                part_number: None,
                preconditions: Preconditions::default(),
                checksum_mode_enabled: false,
            })
            .await;

        match (comp_res, abort_res) {
            (Ok(_), Err(e)) => {
                // Complete won first -> Abort saw NoSuchUpload -> object MUST exist with winning_size
                assert_eq!(e.code, S3ErrorCode::NoSuchUpload);
                assert_eq!(head_res.unwrap().total_object_size, winning_size);
            }
            (Err(e), Ok(())) => {
                // Abort won first -> Complete saw NoSuchUpload -> object MUST NOT exist
                assert_eq!(e.code, S3ErrorCode::NoSuchUpload);
                assert_eq!(head_res.unwrap_err().code, S3ErrorCode::NoSuchKey);
            }
            other => panic!("impossible Complete vs Abort outcome pair: {other:?}"),
        }

        drop(engine);
        let rep = run_fsck(disk);
        assert_eq!(rep.status, "ok", "fsck errors after MPU race: {:?}", rep.errors);
    });
}

fn scenario_conditional_write_mutex() {
    shuttle::future::block_on(async {
        let disk = FaultDisk::new();
        let engine = Engine::open(disk, EngineConfig::default()).unwrap();
        engine
            .create_bucket(CreateBucketReq {
                ctx: caller(1_000),
                bucket: "shuttle-cond".into(),
                location_constraint: None,
                object_ownership: None,
                acl: None,
            })
            .await
            .unwrap();

        // Phase 1: 4 tasks race `PutObject(If-None-Match: *)` -> strictly 1 succeeds, 3 get 412!
        let mut create_tasks = Vec::new();
        for tid in 0..4u8 {
            let eng = Arc::clone(&engine);
            create_tasks.push(shuttle::future::spawn(async move {
                shuttle::future::yield_now().await;
                eng.put_object(
                    PutObjectReq {
                        ctx: caller(1_100 + tid as i64),
                        bucket: "shuttle-cond".into(),
                        key: "mutex-key".into(),
                        sys_meta: SystemMeta::default(),
                        user_meta: Vec::new(),
                        acl: None,
                        tags: None,
                        preconditions: Preconditions {
                            if_none_match: Some(vec!["*".into()]),
                            ..Default::default()
                        },
                        max_bytes_limit: MAX_SINGLE_PUT_BYTES,
                    },
                    InMemoryVerifiedStream::from_bytes(Bytes::from(vec![tid; 64]), None),
                )
                .await
            }));
        }

        let mut winners = Vec::new();
        for t in create_tasks {
            match t.await.unwrap() {
                Ok(resp) => winners.push(resp.etag),
                Err(e) => assert_eq!(e.code, S3ErrorCode::PreconditionFailed),
            }
        }
        assert_eq!(
            winners.len(),
            1,
            "strictly 1 If-None-Match:* writer must win!"
        );
        let initial_etag = winners.pop().unwrap();

        // Phase 2: 2 CAS PutObject(If-Match: initial_etag) + 2 DeleteObject(If-Match: initial_etag)
        // Strictly 1 must succeed (`200` or `204`), the other 3 must get `412` or `404`!
        let mut cas_tasks = Vec::new();
        for tid in 0..2u8 {
            let eng = Arc::clone(&engine);
            let et = initial_etag.clone();
            cas_tasks.push(shuttle::future::spawn(async move {
                shuttle::future::yield_now().await;
                eng.put_object(
                    PutObjectReq {
                        ctx: caller(1_200 + tid as i64),
                        bucket: "shuttle-cond".into(),
                        key: "mutex-key".into(),
                        sys_meta: SystemMeta::default(),
                        user_meta: Vec::new(),
                        acl: None,
                        tags: None,
                        preconditions: Preconditions {
                            if_match: Some(vec![et]),
                            ..Default::default()
                        },
                        max_bytes_limit: MAX_SINGLE_PUT_BYTES,
                    },
                    InMemoryVerifiedStream::from_bytes(Bytes::from(vec![0x90 + tid; 64]), None),
                )
                .await
                .map(|_| ())
            }));
        }
        for tid in 0..2u8 {
            let eng = Arc::clone(&engine);
            let et = initial_etag.clone();
            cas_tasks.push(shuttle::future::spawn(async move {
                shuttle::future::yield_now().await;
                eng.delete_object(DeleteObjectReq {
                    ctx: caller(1_210 + tid as i64),
                    bucket: "shuttle-cond".into(),
                    key: "mutex-key".into(),
                    version_id: None,
                    if_match: Some(vec![et]),
                })
                .await
                .map(|_| ())
            }));
        }

        let mut cas_winners = 0usize;
        for t in cas_tasks {
            match t.await.unwrap() {
                Ok(()) => cas_winners += 1,
                Err(e) => assert!(
                    matches!(e.code, S3ErrorCode::PreconditionFailed | S3ErrorCode::NoSuchKey),
                    "unexpected CAS loser error: {e:?}"
                ),
            }
        }
        assert_eq!(cas_winners, 1, "strictly 1 If-Match CAS mutation must win!");
    });
}

#[test]
fn shuttle_regression_inflight_segment_rollover_vs_gc_seeds() {
    // Regression seeds discovered during M3 VR-4 that caught newly-sealed segments
    // being reclaimed by GC before in-flight writers completed catalog + live_bytes commit.
    shuttle::check_random_with_seed(scenario_gc_vs_rw, 13444799941140065528, 1);
    shuttle::check_random_with_seed(scenario_gc_vs_rw, 3189285914870582412, 1);
}

#[test]
fn shuttle_ci_1000_schedules() {
    shuttle::check_random(scenario_gc_vs_rw, 340);
    shuttle::check_random(scenario_multipart_complete_vs_abort, 330);
    shuttle::check_random(scenario_conditional_write_mutex, 330);
}

#[test]
#[ignore]
fn vr4_shuttle_10k_m3_gate() {
    let t0 = std::time::Instant::now();
    shuttle::check_random(scenario_gc_vs_rw, 3_400);
    shuttle::check_random(scenario_multipart_complete_vs_abort, 3_300);
    shuttle::check_random(scenario_conditional_write_mutex, 3_300);
    eprintln!(
        "VR-4 Shuttle M3 gate passed: 10,000 randomized concurrency schedules verified in {:.2}s, 0 failures.",
        t0.elapsed().as_secs_f64()
    );
}
