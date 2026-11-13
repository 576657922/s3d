use std::collections::{BTreeMap, HashMap};
use std::future::poll_fn;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use bytes::{Bytes, BytesMut};
use proptest::prelude::*;
use proptest::test_runner::{RngAlgorithm, TestRng, TestRunner};
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

fn test_caller(user_idx: u8, time_ms: i64) -> CallerContext {
    match user_idx {
        0 => CallerContext {
            caller: Some(OwnerInfo {
                user_id: "0123456789abcdef".into(),
                display_name: "tester".into(),
                email: "tester@example.com".into(),
            }),
            request_time_ms: time_ms,
            expected_bucket_owner: None,
            is_authenticated: true,
            policy_ctx: RequestPolicyContext::default(),
        },
        1 => CallerContext {
            caller: Some(OwnerInfo {
                user_id: "fedcba9876543210".into(),
                display_name: "altuser".into(),
                email: "alt@example.com".into(),
            }),
            request_time_ms: time_ms,
            expected_bucket_owner: None,
            is_authenticated: true,
            policy_ctx: RequestPolicyContext::default(),
        },
        _ => CallerContext {
            caller: None,
            request_time_ms: time_ms,
            expected_bucket_owner: None,
            is_authenticated: false,
            policy_ctx: RequestPolicyContext::default(),
        },
    }
}

fn sample_tags(tag_slot: Option<u8>) -> Option<BTreeMap<String, String>> {
    match tag_slot {
        None => None,
        Some(0) => Some(BTreeMap::new()),
        Some(1) => Some(BTreeMap::from([("env".to_string(), "prod".to_string())])),
        _ => Some(BTreeMap::from([
            ("a".to_string(), "".to_string()),
            ("env".to_string(), "stage".to_string()),
        ])),
    }
}

fn sample_policy_json(bucket: &str, variant: u8) -> String {
    match variant {
        0 => format!(
            r#"{{"Version":"2012-10-17","Statement":[{{"Effect":"Allow","Principal":"*","Action":["s3:GetObject","s3:ListBucket"],"Resource":["arn:aws:s3:::{bucket}","arn:aws:s3:::{bucket}/*"]}}]}}"#
        ),
        1 => format!(
            r#"{{"Version":"2012-10-17","Statement":[{{"Effect":"Allow","Principal":{{"AWS":"fedcba9876543210"}},"Action":"s3:*","Resource":["arn:aws:s3:::{bucket}","arn:aws:s3:::{bucket}/*"]}}]}}"#
        ),
        2 => format!(
            r#"{{"Version":"2012-10-17","Statement":[{{"Effect":"Deny","Principal":"*","Action":"s3:PutObjectTagging","Resource":"arn:aws:s3:::{bucket}/*"}}]}}"#
        ),
        _ => r#"{"Version":"2012-10-17","Statement":[]}"#.to_string(), // invalid (empty statement)
    }
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
const CSUM_POOL: &[Option<ChecksumAlgorithm>] = &[
    None,
    Some(ChecksumAlgorithm::Crc32),
    Some(ChecksumAlgorithm::Crc32c),
    Some(ChecksumAlgorithm::Crc64Nvme),
    Some(ChecksumAlgorithm::Sha1),
    Some(ChecksumAlgorithm::Sha256),
    Some(ChecksumAlgorithm::Md5),
    Some(ChecksumAlgorithm::Sha512),
    Some(ChecksumAlgorithm::XxHash64),
    Some(ChecksumAlgorithm::XxHash3),
    Some(ChecksumAlgorithm::XxHash128),
];

fn sample_upload_lock(lock_slot: u8) -> RawUploadObjectLockHeaders {
    match lock_slot {
        1 => RawUploadObjectLockHeaders {
            mode: Some("GOVERNANCE".into()),
            retain_until_date: Some("2030-01-01T00:00:00.000Z".into()),
            legal_hold: None,
        },
        2 => RawUploadObjectLockHeaders {
            mode: None,
            retain_until_date: None,
            legal_hold: Some("ON".into()),
        },
        3 => RawUploadObjectLockHeaders {
            mode: Some("COMPLIANCE".into()),
            retain_until_date: Some("2030-01-01T00:00:00.000Z".into()),
            legal_hold: Some("ON".into()),
        },
        4 => RawUploadObjectLockHeaders {
            // Past retain-until date -> tests 400 InvalidArgument differential branch
            mode: Some("GOVERNANCE".into()),
            retain_until_date: Some("2020-01-01T00:00:00.000Z".into()),
            legal_hold: None,
        },
        _ => RawUploadObjectLockHeaders::default(),
    }
}

fn make_patterned_payload(size: usize, seed: u8) -> Bytes {
    if size == 0 {
        return Bytes::new();
    }
    let mut buf = vec![seed; size];
    let step = if size > 65_536 { 257 } else { 1 };
    let mut i = 0usize;
    while i < size {
        buf[i] = seed.wrapping_add((i % 251) as u8);
        i += step;
    }
    buf[size - 1] = seed ^ 0x5A;
    Bytes::from(buf)
}
const CANNED_ACL_POOL: &[CannedAcl] = &[
    CannedAcl::Private,
    CannedAcl::PublicRead,
    CannedAcl::PublicReadWrite,
    CannedAcl::AuthenticatedRead,
    CannedAcl::BucketOwnerRead,
    CannedAcl::BucketOwnerFullControl,
];

#[derive(Debug, Clone)]
enum ModelOp {
    CreateBucket {
        u: u8,
        b: u8,
        ownership: Option<ObjectOwnership>,
        canned_acl: Option<u8>,
        object_lock_enabled: bool,
    },
    DeleteBucket {
        u: u8,
        b: u8,
    },
    SetVersioning {
        u: u8,
        b: u8,
        enabled: bool,
    },
    GetVersioning {
        u: u8,
        b: u8,
    },
    Put {
        u: u8,
        b: u8,
        k: u8,
        size: usize,
        seed: u8,
        csum_idx: u8,
        bad_digest: bool,
        if_none_match_star: bool,
        canned_acl: Option<u8>,
        tag_slot: Option<u8>,
        lock_slot: u8,
    },
    Get {
        u: u8,
        b: u8,
        k: u8,
        ver_slot: Option<u8>,
        range: Option<ByteRangeSpec>,
        part_num: Option<u32>,
    },
    Head {
        u: u8,
        b: u8,
        k: u8,
        ver_slot: Option<u8>,
    },
    GetAttrs {
        u: u8,
        b: u8,
        k: u8,
        ver_slot: Option<u8>,
    },
    Delete {
        u: u8,
        b: u8,
        k: u8,
        ver_slot: Option<u8>,
        if_match_star: bool,
        bypass_governance: bool,
    },
    DeleteMulti {
        u: u8,
        b: u8,
        keys: Vec<(u8, Option<u8>, bool)>,
        quiet: bool,
        bypass_governance: bool,
    },
    Copy {
        u: u8,
        sb: u8,
        sk: u8,
        ver_slot: Option<u8>,
        db: u8,
        dk: u8,
        replace_meta: bool,
        canned_acl: Option<u8>,
        replace_tags: bool,
        tag_slot: Option<u8>,
    },
    ListV1 {
        u: u8,
        b: u8,
        prefix_idx: u8,
        delim: bool,
        max_keys: usize,
    },
    ListV2 {
        u: u8,
        b: u8,
        prefix_idx: u8,
        delim: bool,
        max_keys: usize,
    },
    ListVersions {
        u: u8,
        b: u8,
        prefix_idx: u8,
        delim: bool,
        max_keys: usize,
    },
    MpuCreate {
        u: u8,
        b: u8,
        k: u8,
        csum_idx: u8,
        full_obj_csum: bool,
        tag_slot: Option<u8>,
        lock_slot: u8,
    },
    MpuPart {
        u: u8,
        up_slot: u8,
        part_num: u32,
        size: usize,
        seed: u8,
    },
    MpuPartCopy {
        u: u8,
        up_slot: u8,
        part_num: u32,
        sb: u8,
        sk: u8,
        src_range: Option<(u64, u64)>,
    },
    MpuListParts {
        u: u8,
        up_slot: u8,
        max_parts: usize,
        marker: u32,
    },
    MpuListUploads {
        u: u8,
        b: u8,
        prefix_idx: u8,
        delim: bool,
        max_uploads: usize,
    },
    MpuComplete {
        u: u8,
        up_slot: u8,
        duplicate_part: bool,
        wrong_order: bool,
        if_none_match_star: bool,
    },
    MpuAbort {
        u: u8,
        up_slot: u8,
    },
    BucketAcl {
        u: u8,
        b: u8,
        put_canned: Option<u8>,
    },
    ObjectAcl {
        u: u8,
        b: u8,
        k: u8,
        ver_slot: Option<u8>,
        put_canned: Option<u8>,
    },
    BucketOwnership {
        u: u8,
        b: u8,
        action: u8, // 0=get, 1=delete, 2..=4=put
    },
    BucketTagging {
        u: u8,
        b: u8,
        action: u8, // 0=get, 1=delete, 2..=4=put
    },
    ObjectTagging {
        u: u8,
        b: u8,
        k: u8,
        ver_slot: Option<u8>,
        action: u8, // 0=get, 1=delete, 2..=4=put
    },
    BucketCors {
        u: u8,
        b: u8,
        action: u8, // 0=get, 1=delete, 2=put
    },
    BucketPolicy {
        u: u8,
        b: u8,
        action: u8, // 0=get, 1=delete, 2=status, 3..=6=put(variant)
    },
    PublicAccessBlock {
        u: u8,
        b: u8,
        action: u8, // 0=get, 1=delete, 2=put
        bits: u8,
    },
    BucketEncryption {
        u: u8,
        b: u8,
        action: u8, // 0=get, 1=delete, 2=put
    },
    BucketLifecycle {
        u: u8,
        b: u8,
        action: u8, // 0=get, 1=delete, 2=put
    },
    LifecycleTick,
    BucketObjectLock {
        u: u8,
        b: u8,
        put: bool,
    },
    ObjectRetention {
        u: u8,
        b: u8,
        k: u8,
        ver_slot: Option<u8>,
        action: u8, // 0=get, 1=put_gov, 2=put_comp
        bypass: bool,
    },
    ObjectLegalHold {
        u: u8,
        b: u8,
        k: u8,
        ver_slot: Option<u8>,
        action: u8, // 0=get, 1=on, 2=off
    },
    BucketLogging {
        u: u8,
        b: u8,
        tb: u8,
        enable: Option<bool>, // None=get, Some(false)=disable, Some(true)=enable
    },
    SsePutGet {
        u: u8,
        b: u8,
        k: u8,
        sse_kind: u8, // 0=SSE-S3, 1=SSE-C keyA, 2=SSE-C keyB
        read_kind: u8, // 0=none, 1=SSE-C keyA, 2=SSE-C keyB
        size: usize,
    },
    Compact,
}

fn opt_tag_slot() -> impl Strategy<Value = Option<u8>> {
    prop_oneof![
        3 => Just(None),
        2 => (0u8..3).prop_map(Some),
    ]
}

fn user_strategy() -> impl Strategy<Value = u8> {
    prop_oneof![
        7 => Just(0u8),
        2 => Just(1u8),
        1 => Just(2u8),
    ]
}

fn opt_canned_strategy() -> impl Strategy<Value = Option<u8>> {
    prop_oneof![
        4 => Just(None),
        2 => (0u8..6).prop_map(Some),
    ]
}

fn opt_ver_slot() -> impl Strategy<Value = Option<u8>> {
    prop_oneof![
        3 => Just(None),
        2 => (0u8..5).prop_map(Some),
    ]
}

fn op_strategy() -> impl Strategy<Value = ModelOp> {
    prop_oneof![
        3 => (
            user_strategy(),
            0u8..3,
            prop_oneof![
                Just(None),
                Just(Some(ObjectOwnership::ObjectWriter)),
                Just(Some(ObjectOwnership::BucketOwnerPreferred)),
                Just(Some(ObjectOwnership::BucketOwnerEnforced)),
            ],
            opt_canned_strategy(),
            prop::bool::weighted(0.35),
        )
            .prop_map(
                |(u, b, ownership, canned_acl, object_lock_enabled)| ModelOp::CreateBucket {
                    u,
                    b,
                    ownership,
                    canned_acl,
                    object_lock_enabled,
                },
            ),
        1 => (user_strategy(), 0u8..3).prop_map(|(u, b)| ModelOp::DeleteBucket { u, b }),
        2 => (user_strategy(), 0u8..2, any::<bool>())
            .prop_map(|(u, b, enabled)| ModelOp::SetVersioning { u, b, enabled }),
        1 => (user_strategy(), 0u8..2).prop_map(|(u, b)| ModelOp::GetVersioning { u, b }),
        6 => (
            user_strategy(),
            0u8..3,
            0u8..6,
            prop_oneof![
                5 => Just(0usize),
                5 => Just(1),
                4 => Just(4095),
                4 => Just(4096),
                4 => Just(8192),
                4 => Just(17_000),
                1 => Just(5 * 1024 * 1024 - 1),
                1 => Just(5 * 1024 * 1024),
            ],
            any::<u8>(),
            0u8..11,
            prop::bool::weighted(0.1),
            prop::bool::weighted(0.2),
            opt_canned_strategy(),
            opt_tag_slot(),
            prop_oneof![6 => Just(0u8), 1 => Just(1u8), 1 => Just(2u8), 1 => Just(3u8), 1 => Just(4u8)],
        )
            .prop_map(
                |(
                    u,
                    b,
                    k,
                    size,
                    seed,
                    csum_idx,
                    bad_digest,
                    if_none_match_star,
                    canned_acl,
                    tag_slot,
                    lock_slot,
                )| {
                    ModelOp::Put {
                        u,
                        b,
                        k,
                        size,
                        seed,
                        csum_idx,
                        bad_digest,
                        if_none_match_star,
                        canned_acl,
                        tag_slot,
                        lock_slot,
                    }
                },
            ),
        4 => (
            user_strategy(),
            0u8..2,
            0u8..6,
            opt_ver_slot(),
            prop_oneof![
                Just(None),
                Just(Some(ByteRangeSpec::FromTo { start: 0, end: 10 })),
                Just(Some(ByteRangeSpec::From { start: 4096 })),
                Just(Some(ByteRangeSpec::Suffix { len: 128 })),
            ],
            prop_oneof![Just(None), Just(Some(1u32)), Just(Some(2u32))],
        )
            .prop_map(|(u, b, k, ver_slot, range, part_num)| ModelOp::Get {
                u,
                b,
                k,
                ver_slot,
                range,
                part_num,
            }),
        2 => (user_strategy(), 0u8..2, 0u8..6, opt_ver_slot())
            .prop_map(|(u, b, k, ver_slot)| ModelOp::Head { u, b, k, ver_slot }),
        2 => (user_strategy(), 0u8..2, 0u8..6, opt_ver_slot())
            .prop_map(|(u, b, k, ver_slot)| ModelOp::GetAttrs { u, b, k, ver_slot }),
        3 => (
            user_strategy(),
            0u8..2,
            0u8..6,
            opt_ver_slot(),
            prop::bool::weighted(0.25),
            any::<bool>(),
        )
            .prop_map(
                |(u, b, k, ver_slot, if_match_star, bypass_governance)| ModelOp::Delete {
                    u,
                    b,
                    k,
                    ver_slot,
                    if_match_star,
                    bypass_governance,
                },
            ),
        2 => (
            user_strategy(),
            0u8..2,
            prop::collection::vec((0u8..6, opt_ver_slot(), prop::bool::weighted(0.2)), 1..=4),
            any::<bool>(),
            any::<bool>(),
        )
            .prop_map(|(u, b, keys, quiet, bypass_governance)| ModelOp::DeleteMulti {
                u,
                b,
                keys,
                quiet,
                bypass_governance,
            }),
        2 => (
            user_strategy(),
            0u8..2,
            0u8..5,
            opt_ver_slot(),
            0u8..2,
            0u8..5,
            any::<bool>(),
            opt_canned_strategy(),
            any::<bool>(),
            opt_tag_slot(),
        )
            .prop_map(
                |(
                    u,
                    sb,
                    sk,
                    ver_slot,
                    db,
                    dk,
                    replace_meta,
                    canned_acl,
                    replace_tags,
                    tag_slot,
                )| ModelOp::Copy {
                    u,
                    sb,
                    sk,
                    ver_slot,
                    db,
                    dk,
                    replace_meta,
                    canned_acl,
                    replace_tags,
                    tag_slot,
                },
            ),
        2 => (user_strategy(), 0u8..2, 0u8..4, any::<bool>(), 0usize..=4)
            .prop_map(|(u, b, prefix_idx, delim, max_keys)| ModelOp::ListV1 {
                u,
                b,
                prefix_idx,
                delim,
                max_keys,
            }),
        2 => (user_strategy(), 0u8..2, 0u8..4, any::<bool>(), 0usize..=4)
            .prop_map(|(u, b, prefix_idx, delim, max_keys)| ModelOp::ListV2 {
                u,
                b,
                prefix_idx,
                delim,
                max_keys,
            }),
        2 => (user_strategy(), 0u8..2, 0u8..4, any::<bool>(), 0usize..=4)
            .prop_map(|(u, b, prefix_idx, delim, max_keys)| ModelOp::ListVersions {
                u,
                b,
                prefix_idx,
                delim,
                max_keys,
            }),
        3 => (
            user_strategy(),
            0u8..2,
            0u8..4,
            0u8..11,
            any::<bool>(),
            opt_tag_slot(),
            prop_oneof![6 => Just(0u8), 1 => Just(1u8), 1 => Just(2u8), 1 => Just(3u8), 1 => Just(4u8)],
        )
            .prop_map(
                |(u, b, k, csum_idx, full_obj_csum, tag_slot, lock_slot)| ModelOp::MpuCreate {
                    u,
                    b,
                    k,
                    csum_idx,
                    full_obj_csum,
                    tag_slot,
                    lock_slot,
                },
            ),
        4 => (
            user_strategy(),
            0u8..4,
            prop_oneof![Just(1u32), Just(2u32), Just(3u32), Just(0u32)],
            prop_oneof![
                6 => Just(0usize),
                6 => Just(64),
                6 => Just(4096),
                6 => Just(9000),
                1 => Just(5 * 1024 * 1024 - 1),
                1 => Just(5 * 1024 * 1024),
            ],
            any::<u8>(),
        )
            .prop_map(|(u, up_slot, part_num, size, seed)| ModelOp::MpuPart {
                u,
                up_slot,
                part_num,
                size,
                seed,
            }),
        2 => (
            user_strategy(),
            0u8..4,
            prop_oneof![Just(1u32), Just(2u32)],
            0u8..2,
            0u8..4,
            prop_oneof![Just(None), Just(Some((0u64, 15u64))), Just(Some((10u64, 5u64)))],
        )
            .prop_map(|(u, up_slot, part_num, sb, sk, src_range)| ModelOp::MpuPartCopy {
                u,
                up_slot,
                part_num,
                sb,
                sk,
                src_range,
            }),
        2 => (user_strategy(), 0u8..4, 0usize..=4, 0u32..=2)
            .prop_map(|(u, up_slot, max_parts, marker)| ModelOp::MpuListParts {
                u,
                up_slot,
                max_parts,
                marker,
            }),
        2 => (user_strategy(), 0u8..2, 0u8..4, any::<bool>(), 0usize..=4)
            .prop_map(|(u, b, prefix_idx, delim, max_uploads)| ModelOp::MpuListUploads {
                u,
                b,
                prefix_idx,
                delim,
                max_uploads,
            }),
        3 => (
            user_strategy(),
            0u8..4,
            prop::bool::weighted(0.25),
            prop::bool::weighted(0.15),
            prop::bool::weighted(0.2),
        )
            .prop_map(
                |(u, up_slot, duplicate_part, wrong_order, if_none_match_star)| {
                    ModelOp::MpuComplete {
                        u,
                        up_slot,
                        duplicate_part,
                        wrong_order,
                        if_none_match_star,
                    }
                }
            ),
        2 => (user_strategy(), 0u8..4).prop_map(|(u, up_slot)| ModelOp::MpuAbort { u, up_slot }),
        2 => (user_strategy(), 0u8..2, opt_canned_strategy())
            .prop_map(|(u, b, put_canned)| ModelOp::BucketAcl { u, b, put_canned }),
        2 => (user_strategy(), 0u8..2, 0u8..4, opt_ver_slot(), opt_canned_strategy())
            .prop_map(|(u, b, k, ver_slot, put_canned)| ModelOp::ObjectAcl {
                u,
                b,
                k,
                ver_slot,
                put_canned,
            }),
        2 => (user_strategy(), 0u8..2, 0u8..5)
            .prop_map(|(u, b, action)| ModelOp::BucketOwnership { u, b, action }),
        2 => (user_strategy(), 0u8..2, 0u8..5)
            .prop_map(|(u, b, action)| ModelOp::BucketTagging { u, b, action }),
        2 => (user_strategy(), 0u8..2, 0u8..4, opt_ver_slot(), 0u8..5)
            .prop_map(|(u, b, k, ver_slot, action)| ModelOp::ObjectTagging {
                u,
                b,
                k,
                ver_slot,
                action,
            }),
        2 => (user_strategy(), 0u8..2, 0u8..3)
            .prop_map(|(u, b, action)| ModelOp::BucketCors { u, b, action }),
        3 => (user_strategy(), 0u8..2, 0u8..7)
            .prop_map(|(u, b, action)| ModelOp::BucketPolicy { u, b, action }),
        2 => (user_strategy(), 0u8..2, 0u8..3, 0u8..16)
            .prop_map(|(u, b, action, bits)| ModelOp::PublicAccessBlock {
                u,
                b,
                action,
                bits,
            }),
        2 => (user_strategy(), 0u8..2, 0u8..3)
            .prop_map(|(u, b, action)| ModelOp::BucketEncryption { u, b, action }),
        2 => (user_strategy(), 0u8..2, 0u8..3)
            .prop_map(|(u, b, action)| ModelOp::BucketLifecycle { u, b, action }),
        1 => Just(ModelOp::LifecycleTick),
        2 => (user_strategy(), 0u8..2, any::<bool>())
            .prop_map(|(u, b, put)| ModelOp::BucketObjectLock { u, b, put }),
        2 => (
            user_strategy(),
            0u8..2,
            0u8..4,
            opt_ver_slot(),
            0u8..3,
            any::<bool>(),
        )
            .prop_map(|(u, b, k, ver_slot, action, bypass)| ModelOp::ObjectRetention {
                u,
                b,
                k,
                ver_slot,
                action,
                bypass,
            }),
        2 => (user_strategy(), 0u8..2, 0u8..4, opt_ver_slot(), 0u8..3)
            .prop_map(|(u, b, k, ver_slot, action)| ModelOp::ObjectLegalHold {
                u,
                b,
                k,
                ver_slot,
                action,
            }),
        2 => (
            user_strategy(),
            0u8..2,
            0u8..2,
            prop_oneof![Just(None), Just(Some(false)), Just(Some(true))],
        )
            .prop_map(|(u, b, tb, enable)| ModelOp::BucketLogging { u, b, tb, enable }),
        3 => (
            user_strategy(),
            0u8..2,
            0u8..4,
            0u8..3,
            0u8..3,
            prop_oneof![Just(0usize), Just(37), Just(4096), Just(9001)],
        )
            .prop_map(|(u, b, k, sse_kind, read_kind, size)| ModelOp::SsePutGet {
                u,
                b,
                k,
                sse_kind,
                read_kind,
                size,
            }),
        1 => Just(ModelOp::Compact),
    ]
}

#[derive(Default)]
struct TrackedUpload {
    bucket: String,
    key: String,
    e_uid: String,
    m_uid: String,
    parts: BTreeMap<u32, CompletePartSpec>,
}

#[derive(Default)]
struct IdBijection {
    m2e_ver: HashMap<String, String>,
    ver_ring: Vec<(String, String)>, // (e_vid, m_vid)
    m2e_uid: HashMap<String, String>,
    uploads: Vec<TrackedUpload>,
}

impl IdBijection {
    fn record_ver_pair(&mut self, ev: &Option<String>, mv: &Option<String>) {
        match (ev, mv) {
            (Some(e), Some(m)) => {
                if let Some(prev) = self.m2e_ver.insert(m.clone(), e.clone())
                    && m != "null" {
                        assert_eq!(&prev, e, "version bijection conflict for {m}");
                    }
                self.ver_ring.push((e.clone(), m.clone()));
                if self.ver_ring.len() > 16 {
                    self.ver_ring.remove(0);
                }
            }
            (None, None) => {}
            (l, r) => panic!("version_id presence mismatch: engine={l:?}, model={r:?}"),
        }
    }

    fn pick_ver(&self, slot: Option<u8>) -> (Option<String>, Option<String>) {
        let Some(idx) = slot else {
            return (None, None);
        };
        if idx == 4 || self.ver_ring.is_empty() {
            return (Some("bogus-vid".into()), Some("bogus-vid".into()));
        }
        let (ev, mv) = &self.ver_ring[(idx as usize) % self.ver_ring.len()];
        (Some(ev.clone()), Some(mv.clone()))
    }

    fn record_upload(&mut self, bucket: String, key: String, e_uid: String, m_uid: String) {
        self.m2e_uid.insert(m_uid.clone(), e_uid.clone());
        self.uploads.push(TrackedUpload {
            bucket,
            key,
            e_uid,
            m_uid,
            parts: BTreeMap::new(),
        });
        if self.uploads.len() > 8 {
            self.uploads.remove(0);
        }
    }

    fn pick_upload(&self, slot: u8) -> (String, String, String, String, Vec<CompletePartSpec>) {
        if self.uploads.is_empty() || slot >= 3 && (slot as usize) >= self.uploads.len() {
            return (
                BUCKET_POOL[0].into(),
                KEY_POOL[0].into(),
                "no-such-upload".into(),
                "no-such-upload".into(),
                vec![CompletePartSpec {
                    part_number: 1,
                    etag: "\"00000000000000000000000000000000\"".into(),
                    checksum: None,
                }],
            );
        }
        let up = &self.uploads[(slot as usize) % self.uploads.len()];
        let parts: Vec<CompletePartSpec> = up.parts.values().cloned().collect();
        (
            up.bucket.clone(),
            up.key.clone(),
            up.e_uid.clone(),
            up.m_uid.clone(),
            parts,
        )
    }
}

async fn run_differential_sequence(ops: Vec<ModelOp>) {
    let has_large_op = ops.iter().any(|op| match op {
        ModelOp::Put { size, .. } | ModelOp::MpuPart { size, .. } => *size >= 65_536,
        _ => false,
    });
    let disk = FaultDisk::new();
    let eng_cfg = if has_large_op {
        EngineConfig {
            segment_size: 2 * 1024 * 1024,
            wal_file_size: 64 * 1024,
            max_block_payload: 256 * 1024,
            default_object_ownership: ObjectOwnership::ObjectWriter,
            ..EngineConfig::default()
        }
    } else {
        EngineConfig {
            segment_size: 32 * 1024,
            wal_file_size: 16 * 1024,
            max_block_payload: 8 * 1024,
            default_object_ownership: ObjectOwnership::ObjectWriter,
            ..EngineConfig::default()
        }
    };
    let engine = Engine::open(disk.clone(), eng_cfg).unwrap();
    let model = ModelStore::new(ModelConfig {
        default_object_ownership: ObjectOwnership::ObjectWriter,
        ..ModelConfig::default()
    });

    let mut ids = IdBijection::default();
    let mut clock_ms = 1_762_900_000_000i64;

    for op in ops {
        clock_ms += 1000;
        match op {
            ModelOp::CreateBucket {
                u,
                b,
                ownership,
                canned_acl,
                object_lock_enabled,
            } => {
                let req = CreateBucketReq {
                    ctx: test_caller(u, clock_ms),
                    bucket: BUCKET_POOL[b as usize].to_string(),
                    location_constraint: None,
                    object_ownership: ownership,
                    acl: canned_acl.map(|i| AclSpec::Canned(CANNED_ACL_POOL[i as usize])),
                    object_lock_enabled,
                };
                let re = engine.create_bucket(req.clone()).await.map(|r| (r.name, r.ownership));
                let rm = model.create_bucket(req).await.map(|r| (r.name, r.ownership));
                assert_eq!(re.map_err(|e| e.code), rm.map_err(|e| e.code));
            }
            ModelOp::DeleteBucket { u, b } => {
                let req = BucketRef {
                    ctx: test_caller(u, clock_ms),
                    bucket: BUCKET_POOL[b as usize].to_string(),
                };
                let re = engine.delete_bucket(req.clone()).await;
                let rm = model.delete_bucket(req).await;
                assert_eq!(re.map_err(|e| e.code), rm.map_err(|e| e.code));
            }
            ModelOp::SetVersioning { u, b, enabled } => {
                let req = PutBucketVersioningReq {
                    ctx: test_caller(u, clock_ms),
                    bucket: BUCKET_POOL[b as usize].to_string(),
                    status: if enabled {
                        VersioningStatus::Enabled
                    } else {
                        VersioningStatus::Suspended
                    },
                };
                let re = engine.put_bucket_versioning(req.clone()).await;
                let rm = model.put_bucket_versioning(req).await;
                assert_eq!(re.map_err(|e| e.code), rm.map_err(|e| e.code));
            }
            ModelOp::GetVersioning { u, b } => {
                let req = BucketRef {
                    ctx: test_caller(u, clock_ms),
                    bucket: BUCKET_POOL[b as usize].to_string(),
                };
                let re = engine.get_bucket_versioning(req.clone()).await;
                let rm = model.get_bucket_versioning(req).await;
                assert_eq!(re.map_err(|e| e.code), rm.map_err(|e| e.code));
            }
            ModelOp::Put {
                u,
                b,
                k,
                size,
                seed,
                csum_idx,
                bad_digest,
                if_none_match_star,
                canned_acl,
                tag_slot,
                lock_slot,
            } => {
                let payload = make_patterned_payload(size, seed);
                let cond = if if_none_match_star {
                    Preconditions {
                        if_none_match: Some(vec!["*".into()]),
                        ..Default::default()
                    }
                } else {
                    Preconditions::default()
                };
                let alg = CSUM_POOL[csum_idx as usize];
                let req = PutObjectReq {
                    ctx: test_caller(u, clock_ms),
                    bucket: BUCKET_POOL[b as usize].to_string(),
                    key: KEY_POOL[k as usize].to_string(),
                    sys_meta: SystemMeta::default(),
                    user_meta: vec![("k".into(), format!("v{seed}"))],
                    acl: canned_acl.map(|i| AclSpec::Canned(CANNED_ACL_POOL[i as usize])),
                    tags: sample_tags(tag_slot),
                    preconditions: cond,
                    max_bytes_limit: MAX_SINGLE_PUT_BYTES,
                    raw_sse: RawSseHeaders::default(),
                    raw_lock: sample_upload_lock(lock_slot),
                };
                let make_stream = || {
                    let s = InMemoryVerifiedStream::from_bytes(payload.clone(), alg);
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
                        ids.record_ver_pair(&ae.version_id, &am.version_id);
                    }
                    (Err(ee), Err(em)) => assert_eq!(ee.code, em.code),
                    (l, r) => panic!("Put mismatch: engine={l:?}, model={r:?}"),
                }
            }
            ModelOp::Get {
                u,
                b,
                k,
                ver_slot,
                range,
                part_num,
            } => {
                let (ev, mv) = ids.pick_ver(ver_slot);
                let (range, part_num) = if part_num.is_some() {
                    (None, part_num)
                } else {
                    (range, None)
                };
                let ctx = test_caller(u, clock_ms);
                let re = engine
                    .get_object(GetObjectReq {
                        ctx: ctx.clone(),
                        bucket: BUCKET_POOL[b as usize].to_string(),
                        key: KEY_POOL[k as usize].to_string(),
                        version_id: ev,
                        range,
                        part_number: part_num,
                        preconditions: Preconditions::default(),
                        checksum_mode_enabled: true,
                        raw_sse: RawSseHeaders::default(),
                    })
                    .await;
                let rm = model
                    .get_object(GetObjectReq {
                        ctx,
                        bucket: BUCKET_POOL[b as usize].to_string(),
                        key: KEY_POOL[k as usize].to_string(),
                        version_id: mv,
                        range,
                        part_number: part_num,
                        preconditions: Preconditions::default(),
                        checksum_mode_enabled: true,
                        raw_sse: RawSseHeaders::default(),
                    })
                    .await;
                match (re, rm) {
                    (Ok(ge), Ok(gm)) => {
                        assert_eq!(ge.meta.etag, gm.meta.etag);
                        assert_eq!(ge.meta.content_length, gm.meta.content_length);
                        assert_eq!(ge.meta.content_range, gm.meta.content_range);
                        assert_eq!(ge.meta.checksum, gm.meta.checksum);
                        assert_eq!(ge.meta.parts_count, gm.meta.parts_count);
                        assert_eq!(ge.meta.tags_count, gm.meta.tags_count);
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
            ModelOp::Head { u, b, k, ver_slot } => {
                let (ev, mv) = ids.pick_ver(ver_slot);
                let ctx = test_caller(u, clock_ms);
                let re = engine
                    .head_object(GetObjectReq {
                        ctx: ctx.clone(),
                        bucket: BUCKET_POOL[b as usize].to_string(),
                        key: KEY_POOL[k as usize].to_string(),
                        version_id: ev,
                        range: None,
                        part_number: None,
                        preconditions: Preconditions::default(),
                        checksum_mode_enabled: true,
                        raw_sse: RawSseHeaders::default(),
                    })
                    .await;
                let rm = model
                    .head_object(GetObjectReq {
                        ctx,
                        bucket: BUCKET_POOL[b as usize].to_string(),
                        key: KEY_POOL[k as usize].to_string(),
                        version_id: mv,
                        range: None,
                        part_number: None,
                        preconditions: Preconditions::default(),
                        checksum_mode_enabled: true,
                        raw_sse: RawSseHeaders::default(),
                    })
                    .await;
                match (re, rm) {
                    (Ok(he), Ok(hm)) => {
                        assert_eq!(he.etag, hm.etag);
                        assert_eq!(he.content_length, hm.content_length);
                        assert_eq!(he.user_meta, hm.user_meta);
                        assert_eq!(he.owner, hm.owner);
                        assert_eq!(he.tags_count, hm.tags_count);
                    }
                    (Err(ee), Err(em)) => assert_eq!(ee.code, em.code),
                    (l, r) => panic!("Head mismatch: engine={l:?}, model={r:?}"),
                }
            }
            ModelOp::GetAttrs { u, b, k, ver_slot } => {
                let (ev, mv) = ids.pick_ver(ver_slot);
                let ctx = test_caller(u, clock_ms);
                let attrs = ObjectAttributesMask {
                    etag: true,
                    checksum: true,
                    object_parts: true,
                    storage_class: true,
                    object_size: true,
                };
                let re = engine
                    .get_object_attributes(GetObjectAttributesReq {
                        ctx: ctx.clone(),
                        bucket: BUCKET_POOL[b as usize].to_string(),
                        key: KEY_POOL[k as usize].to_string(),
                        version_id: ev,
                        attrs,
                        max_parts: 100,
                        part_number_marker: 0,
                        raw_sse: RawSseHeaders::default(),
                    })
                    .await;
                let rm = model
                    .get_object_attributes(GetObjectAttributesReq {
                        ctx,
                        bucket: BUCKET_POOL[b as usize].to_string(),
                        key: KEY_POOL[k as usize].to_string(),
                        version_id: mv,
                        attrs,
                        max_parts: 100,
                        part_number_marker: 0,
                        raw_sse: RawSseHeaders::default(),
                    })
                    .await;
                match (re, rm) {
                    (Ok(ae), Ok(am)) => {
                        assert_eq!(ae.etag, am.etag);
                        assert_eq!(ae.checksum, am.checksum);
                        assert_eq!(ae.object_size, am.object_size);
                        assert_eq!(
                            ae.object_parts.as_ref().map(|p| p.total_parts_count),
                            am.object_parts.as_ref().map(|p| p.total_parts_count)
                        );
                    }
                    (Err(ee), Err(em)) => assert_eq!(ee.code, em.code),
                    (l, r) => panic!("GetAttrs mismatch: engine={l:?}, model={r:?}"),
                }
            }
            ModelOp::Delete {
                u,
                b,
                k,
                ver_slot,
                if_match_star,
                bypass_governance,
            } => {
                let (ev, mv) = ids.pick_ver(ver_slot);
                let ctx = test_caller(u, clock_ms);
                let if_match = if_match_star.then(|| vec!["*".into()]);
                let re = engine
                    .delete_object(DeleteObjectReq {
                        ctx: ctx.clone(),
                        bucket: BUCKET_POOL[b as usize].to_string(),
                        key: KEY_POOL[k as usize].to_string(),
                        version_id: ev.clone(),
                        if_match: if_match.clone(),
                        bypass_governance,
                    })
                    .await;
                let rm = model
                    .delete_object(DeleteObjectReq {
                        ctx,
                        bucket: BUCKET_POOL[b as usize].to_string(),
                        key: KEY_POOL[k as usize].to_string(),
                        version_id: mv,
                        if_match,
                        bypass_governance,
                    })
                    .await;
                match (re, rm) {
                    (Ok(de), Ok(dm)) => {
                        assert_eq!(de.is_delete_marker, dm.is_delete_marker);
                        if ev.is_none() {
                            ids.record_ver_pair(&de.version_id, &dm.version_id);
                        }
                    }
                    (Err(ee), Err(em)) => assert_eq!(ee.code, em.code),
                    (l, r) => panic!("Delete mismatch: {l:?} vs {r:?}"),
                }
            }
            ModelOp::DeleteMulti {
                u,
                b,
                keys,
                quiet,
                bypass_governance,
            } => {
                let ctx = test_caller(u, clock_ms);
                let mut e_items = Vec::with_capacity(keys.len());
                let mut m_items = Vec::with_capacity(keys.len());
                for (ki, vs, ims) in &keys {
                    let (ev, mv) = ids.pick_ver(*vs);
                    let ifm = ims.then(|| vec!["*".into()]);
                    e_items.push(DeleteObjectsItem {
                        key: KEY_POOL[*ki as usize].to_string(),
                        version_id: ev,
                        etag_if_match: ifm.clone(),
                    });
                    m_items.push(DeleteObjectsItem {
                        key: KEY_POOL[*ki as usize].to_string(),
                        version_id: mv,
                        etag_if_match: ifm,
                    });
                }
                let re = engine
                    .delete_objects(DeleteObjectsReq {
                        ctx: ctx.clone(),
                        bucket: BUCKET_POOL[b as usize].to_string(),
                        quiet,
                        items: e_items,
                        bypass_governance,
                    })
                    .await;
                let rm = model
                    .delete_objects(DeleteObjectsReq {
                        ctx,
                        bucket: BUCKET_POOL[b as usize].to_string(),
                        quiet,
                        items: m_items,
                        bypass_governance,
                    })
                    .await;
                match (re, rm) {
                    (Ok(de), Ok(dm)) => {
                        assert_eq!(de.deleted.len(), dm.deleted.len());
                        assert_eq!(de.errors.len(), dm.errors.len());
                        for (le, lm) in de.deleted.iter().zip(dm.deleted.iter()) {
                            assert_eq!(le.key, lm.key);
                            assert_eq!(le.delete_marker, lm.delete_marker);
                            if le.delete_marker {
                                ids.record_ver_pair(
                                    &le.delete_marker_version_id,
                                    &lm.delete_marker_version_id,
                                );
                            }
                        }
                        for (ee, em) in de.errors.iter().zip(dm.errors.iter()) {
                            assert_eq!(ee.key, em.key);
                            assert_eq!(ee.code, em.code);
                        }
                    }
                    (Err(ee), Err(em)) => assert_eq!(ee.code, em.code),
                    (l, r) => panic!("DeleteObjects mismatch: {l:?} vs {r:?}"),
                }
            }
            ModelOp::Copy {
                u,
                sb,
                sk,
                ver_slot,
                db,
                dk,
                replace_meta,
                canned_acl,
                replace_tags,
                tag_slot,
            } => {
                let (ev, mv) = ids.pick_ver(ver_slot);
                let ctx = test_caller(u, clock_ms);
                let acl = canned_acl.map(|i| AclSpec::Canned(CANNED_ACL_POOL[i as usize]));
                let tagging_directive = if replace_tags {
                    TaggingDirective::Replace
                } else {
                    TaggingDirective::Copy
                };
                let tags = sample_tags(tag_slot);
                let re = engine
                    .copy_object(CopyObjectReq {
                        ctx: ctx.clone(),
                        src_bucket: BUCKET_POOL[sb as usize].to_string(),
                        src_key: KEY_POOL[sk as usize].to_string(),
                        src_version_id: ev,
                        dst_bucket: BUCKET_POOL[db as usize].to_string(),
                        dst_key: KEY_POOL[dk as usize].to_string(),
                        replace_metadata: replace_meta,
                        sys_meta: SystemMeta::default(),
                        user_meta: vec![("copied".into(), "true".into())],
                        acl: acl.clone(),
                        tagging_directive,
                        tags: tags.clone(),
                        src_preconditions: Preconditions::default(),
                        dst_preconditions: Preconditions::default(),
                        raw_copy_src_sse: RawCopySourceSseHeaders::default(),
                        raw_sse: RawSseHeaders::default(),
                        raw_lock: RawUploadObjectLockHeaders::default(),
                    })
                    .await;
                let rm = model
                    .copy_object(CopyObjectReq {
                        ctx,
                        src_bucket: BUCKET_POOL[sb as usize].to_string(),
                        src_key: KEY_POOL[sk as usize].to_string(),
                        src_version_id: mv,
                        dst_bucket: BUCKET_POOL[db as usize].to_string(),
                        dst_key: KEY_POOL[dk as usize].to_string(),
                        replace_metadata: replace_meta,
                        sys_meta: SystemMeta::default(),
                        user_meta: vec![("copied".into(), "true".into())],
                        acl,
                        tagging_directive,
                        tags,
                        src_preconditions: Preconditions::default(),
                        dst_preconditions: Preconditions::default(),
                        raw_copy_src_sse: RawCopySourceSseHeaders::default(),
                        raw_sse: RawSseHeaders::default(),
                        raw_lock: RawUploadObjectLockHeaders::default(),
                    })
                    .await;
                match (re, rm) {
                    (Ok(ce), Ok(cm)) => {
                        assert_eq!(ce.etag, cm.etag);
                        assert_eq!(ce.checksum, cm.checksum);
                        ids.record_ver_pair(&ce.dst_version_id, &cm.dst_version_id);
                    }
                    (Err(ee), Err(em)) => assert_eq!(ee.code, em.code),
                    (l, r) => panic!("Copy mismatch: {l:?} vs {r:?}"),
                }
            }
            ModelOp::ListV1 {
                u,
                b,
                prefix_idx,
                delim,
                max_keys,
            } => {
                let req = ListObjectsV1Req {
                    ctx: test_caller(u, clock_ms),
                    bucket: BUCKET_POOL[b as usize].to_string(),
                    prefix: PREFIX_POOL[prefix_idx as usize].to_string(),
                    delimiter: delim.then(|| "/".into()),
                    marker: None,
                    max_keys,
                };
                let re = engine.list_objects_v1(req.clone()).await;
                let rm = model.list_objects_v1(req).await;
                match (re, rm) {
                    (Ok(le), Ok(lm)) => {
                        let ke: Vec<_> = le
                            .contents
                            .iter()
                            .map(|c| (&c.key, c.size, &c.etag, c.checksum_alg))
                            .collect();
                        let km: Vec<_> = lm
                            .contents
                            .iter()
                            .map(|c| (&c.key, c.size, &c.etag, c.checksum_alg))
                            .collect();
                        assert_eq!(ke, km);
                        assert_eq!(le.common_prefixes, lm.common_prefixes);
                        assert_eq!(le.is_truncated, lm.is_truncated);
                        assert_eq!(le.next_marker, lm.next_marker);
                    }
                    (Err(ee), Err(em)) => assert_eq!(ee.code, em.code),
                    (l, r) => panic!("ListV1 mismatch: {l:?} vs {r:?}"),
                }
            }
            ModelOp::ListV2 {
                u,
                b,
                prefix_idx,
                delim,
                max_keys,
            } => {
                let req = ListObjectsV2Req {
                    ctx: test_caller(u, clock_ms),
                    bucket: BUCKET_POOL[b as usize].to_string(),
                    prefix: PREFIX_POOL[prefix_idx as usize].to_string(),
                    delimiter: delim.then(|| "/".into()),
                    start_after: None,
                    continuation_token: None,
                    max_keys,
                    fetch_owner: true,
                };
                let re = engine.list_objects_v2(req.clone()).await;
                let rm = model.list_objects_v2(req).await;
                match (re, rm) {
                    (Ok(le), Ok(lm)) => {
                        let ke: Vec<_> = le
                            .contents
                            .iter()
                            .map(|c| (&c.key, c.size, &c.etag, &c.owner))
                            .collect();
                        let km: Vec<_> = lm
                            .contents
                            .iter()
                            .map(|c| (&c.key, c.size, &c.etag, &c.owner))
                            .collect();
                        assert_eq!(ke, km);
                        assert_eq!(le.common_prefixes, lm.common_prefixes);
                        assert_eq!(le.is_truncated, lm.is_truncated);
                        assert_eq!(le.key_count, lm.key_count);
                    }
                    (Err(ee), Err(em)) => assert_eq!(ee.code, em.code),
                    (l, r) => panic!("ListV2 mismatch: {l:?} vs {r:?}"),
                }
            }
            ModelOp::ListVersions {
                u,
                b,
                prefix_idx,
                delim,
                max_keys,
            } => {
                let req = ListObjectVersionsReq {
                    ctx: test_caller(u, clock_ms),
                    bucket: BUCKET_POOL[b as usize].to_string(),
                    prefix: PREFIX_POOL[prefix_idx as usize].to_string(),
                    delimiter: delim.then(|| "/".into()),
                    key_marker: None,
                    version_id_marker: None,
                    max_keys,
                };
                let re = engine.list_object_versions(req.clone()).await;
                let rm = model.list_object_versions(req).await;
                match (re, rm) {
                    (Ok(le), Ok(lm)) => {
                        assert_eq!(le.entries.len(), lm.entries.len());
                        for (ve, vm) in le.entries.iter().zip(lm.entries.iter()) {
                            assert_eq!(ve.key, vm.key);
                            assert_eq!(ve.is_latest, vm.is_latest);
                            assert_eq!(ve.is_delete_marker, vm.is_delete_marker);
                            assert_eq!(ve.size, vm.size);
                            assert_eq!(ve.etag, vm.etag);
                            if vm.version_id == "null" {
                                assert_eq!(ve.version_id, "null");
                            } else if let Some(exp_ev) = ids.m2e_ver.get(&vm.version_id) {
                                assert_eq!(&ve.version_id, exp_ev);
                            }
                        }
                        assert_eq!(le.common_prefixes, lm.common_prefixes);
                        assert_eq!(le.is_truncated, lm.is_truncated);
                        assert_eq!(le.next_key_marker, lm.next_key_marker);
                    }
                    (Err(ee), Err(em)) => assert_eq!(ee.code, em.code),
                    (l, r) => panic!("ListVersions mismatch: {l:?} vs {r:?}"),
                }
            }
            ModelOp::MpuCreate {
                u,
                b,
                k,
                csum_idx,
                full_obj_csum,
                tag_slot,
                lock_slot,
            } => {
                let alg = CSUM_POOL[csum_idx as usize];
                let ctype = if full_obj_csum {
                    Some(ChecksumType::FullObject)
                } else {
                    None
                };
                let req = CreateMultipartUploadReq {
                    ctx: test_caller(u, clock_ms),
                    bucket: BUCKET_POOL[b as usize].to_string(),
                    key: KEY_POOL[k as usize].to_string(),
                    sys_meta: SystemMeta::default(),
                    user_meta: vec![("mpu".into(), "yes".into())],
                    acl: None,
                    tags: sample_tags(tag_slot),
                    checksum_algorithm: alg,
                    checksum_type: ctype,
                    raw_sse: RawSseHeaders::default(),
                    raw_lock: sample_upload_lock(lock_slot),
                };
                let re = engine.create_multipart_upload(req.clone()).await;
                let rm = model.create_multipart_upload(req).await;
                match (re, rm) {
                    (Ok(ce), Ok(cm)) => {
                        assert_eq!(ce.checksum_algorithm, cm.checksum_algorithm);
                        assert_eq!(ce.checksum_type, cm.checksum_type);
                        ids.record_upload(ce.bucket, ce.key, ce.upload_id, cm.upload_id);
                    }
                    (Err(ee), Err(em)) => assert_eq!(ee.code, em.code),
                    (l, r) => panic!("MpuCreate mismatch: {l:?} vs {r:?}"),
                }
            }
            ModelOp::MpuPart {
                u,
                up_slot,
                part_num,
                size,
                seed,
            } => {
                let (bkt, key, e_uid, m_uid, _) = ids.pick_upload(up_slot);
                let payload = make_patterned_payload(size, seed);
                let ctx = test_caller(u, clock_ms);
                let re = engine
                    .upload_part(
                        UploadPartReq {
                            ctx: ctx.clone(),
                            bucket: bkt.clone(),
                            key: key.clone(),
                            upload_id: e_uid.clone(),
                            part_number: part_num,
                            max_bytes_limit: MAX_PART_SIZE_BYTES,
                            raw_sse: RawSseHeaders::default(),
                        },
                        InMemoryVerifiedStream::from_bytes(payload.clone(), None),
                    )
                    .await;
                let rm = model
                    .upload_part(
                        UploadPartReq {
                            ctx,
                            bucket: bkt,
                            key,
                            upload_id: m_uid.clone(),
                            part_number: part_num,
                            max_bytes_limit: MAX_PART_SIZE_BYTES,
                            raw_sse: RawSseHeaders::default(),
                        },
                        InMemoryVerifiedStream::from_bytes(payload, None),
                    )
                    .await;
                match (re, rm) {
                    (Ok(pe), Ok(pm)) => {
                        assert_eq!(pe.etag, pm.etag);
                        assert_eq!(pe.checksum, pm.checksum);
                        if let Some(up) = ids.uploads.iter_mut().find(|x| x.e_uid == e_uid) {
                            up.parts.insert(
                                part_num,
                                CompletePartSpec {
                                    part_number: part_num,
                                    etag: pe.etag,
                                    checksum: pe.checksum.map(|c| (c.algorithm, c.value_b64)),
                                },
                            );
                        }
                    }
                    (Err(ee), Err(em)) => assert_eq!(ee.code, em.code),
                    (l, r) => panic!("UploadPart mismatch: {l:?} vs {r:?}"),
                }
            }
            ModelOp::MpuPartCopy {
                u,
                up_slot,
                part_num,
                sb,
                sk,
                src_range,
            } => {
                let (bkt, key, e_uid, m_uid, _) = ids.pick_upload(up_slot);
                let ctx = test_caller(u, clock_ms);
                let re = engine
                    .upload_part_copy(UploadPartCopyReq {
                        ctx: ctx.clone(),
                        src_bucket: BUCKET_POOL[sb as usize].to_string(),
                        src_key: KEY_POOL[sk as usize].to_string(),
                        src_version_id: None,
                        src_range,
                        src_preconditions: Preconditions::default(),
                        dst_bucket: bkt.clone(),
                        dst_key: key.clone(),
                        upload_id: e_uid.clone(),
                        part_number: part_num,
                        raw_copy_src_sse: RawCopySourceSseHeaders::default(),
                        raw_sse: RawSseHeaders::default(),
                    })
                    .await;
                let rm = model
                    .upload_part_copy(UploadPartCopyReq {
                        ctx,
                        src_bucket: BUCKET_POOL[sb as usize].to_string(),
                        src_key: KEY_POOL[sk as usize].to_string(),
                        src_version_id: None,
                        src_range,
                        src_preconditions: Preconditions::default(),
                        dst_bucket: bkt,
                        dst_key: key,
                        upload_id: m_uid,
                        part_number: part_num,
                        raw_copy_src_sse: RawCopySourceSseHeaders::default(),
                        raw_sse: RawSseHeaders::default(),
                    })
                    .await;
                match (re, rm) {
                    (Ok(pe), Ok(pm)) => {
                        assert_eq!(pe.etag, pm.etag);
                        assert_eq!(pe.checksum, pm.checksum);
                        if let Some(up) = ids.uploads.iter_mut().find(|x| x.e_uid == e_uid) {
                            up.parts.insert(
                                part_num,
                                CompletePartSpec {
                                    part_number: part_num,
                                    etag: pe.etag,
                                    checksum: pe.checksum.map(|c| (c.algorithm, c.value_b64)),
                                },
                            );
                        }
                    }
                    (Err(ee), Err(em)) => assert_eq!(ee.code, em.code),
                    (l, r) => panic!("UploadPartCopy mismatch: {l:?} vs {r:?}"),
                }
            }
            ModelOp::MpuListParts {
                u,
                up_slot,
                max_parts,
                marker,
            } => {
                let (bkt, key, e_uid, m_uid, _) = ids.pick_upload(up_slot);
                let ctx = test_caller(u, clock_ms);
                let re = engine
                    .list_parts(ListPartsReq {
                        ctx: ctx.clone(),
                        bucket: bkt.clone(),
                        key: key.clone(),
                        upload_id: e_uid,
                        max_parts,
                        part_number_marker: marker,
                    })
                    .await;
                let rm = model
                    .list_parts(ListPartsReq {
                        ctx,
                        bucket: bkt,
                        key,
                        upload_id: m_uid,
                        max_parts,
                        part_number_marker: marker,
                    })
                    .await;
                match (re, rm) {
                    (Ok(le), Ok(lm)) => {
                        assert_eq!(le.is_truncated, lm.is_truncated);
                        assert_eq!(le.next_part_number_marker, lm.next_part_number_marker);
                        let pe: Vec<_> = le
                            .parts
                            .iter()
                            .map(|p| (p.part_number, &p.etag, p.size, &p.checksum))
                            .collect();
                        let pm: Vec<_> = lm
                            .parts
                            .iter()
                            .map(|p| (p.part_number, &p.etag, p.size, &p.checksum))
                            .collect();
                        assert_eq!(pe, pm);
                    }
                    (Err(ee), Err(em)) => assert_eq!(ee.code, em.code),
                    (l, r) => panic!("ListParts mismatch: {l:?} vs {r:?}"),
                }
            }
            ModelOp::MpuListUploads {
                u,
                b,
                prefix_idx,
                delim,
                max_uploads,
            } => {
                let req = ListMultipartUploadsReq {
                    ctx: test_caller(u, clock_ms),
                    bucket: BUCKET_POOL[b as usize].to_string(),
                    prefix: PREFIX_POOL[prefix_idx as usize].to_string(),
                    delimiter: delim.then(|| "/".into()),
                    key_marker: None,
                    upload_id_marker: None,
                    max_uploads,
                };
                let re = engine.list_multipart_uploads(req.clone()).await;
                let rm = model.list_multipart_uploads(req).await;
                match (re, rm) {
                    (Ok(le), Ok(lm)) => {
                        assert_eq!(le.uploads.len(), lm.uploads.len());
                        assert_eq!(le.common_prefixes, lm.common_prefixes);
                        assert_eq!(le.is_truncated, lm.is_truncated);
                        for (ue, um) in le.uploads.iter().zip(lm.uploads.iter()) {
                            assert_eq!(ue.key, um.key);
                            if let Some(exp_eu) = ids.m2e_uid.get(&um.upload_id) {
                                assert_eq!(&ue.upload_id, exp_eu);
                            }
                        }
                    }
                    (Err(ee), Err(em)) => assert_eq!(ee.code, em.code),
                    (l, r) => panic!("ListMultipartUploads mismatch: {l:?} vs {r:?}"),
                }
            }
            ModelOp::MpuComplete {
                u,
                up_slot,
                duplicate_part,
                wrong_order,
                if_none_match_star,
            } => {
                let (bkt, key, e_uid, m_uid, mut parts) = ids.pick_upload(up_slot);
                if parts.is_empty() {
                    parts.push(CompletePartSpec {
                        part_number: 1,
                        etag: "\"00000000000000000000000000000000\"".into(),
                        checksum: None,
                    });
                }
                if duplicate_part {
                    let first = parts[0].clone();
                    parts.insert(0, first);
                }
                if wrong_order && parts.len() >= 2 {
                    parts.reverse();
                }
                let cond = if if_none_match_star {
                    Preconditions {
                        if_none_match: Some(vec!["*".into()]),
                        ..Default::default()
                    }
                } else {
                    Preconditions::default()
                };
                let ctx = test_caller(u, clock_ms);
                let re = engine
                    .complete_multipart_upload(CompleteMultipartUploadReq {
                        ctx: ctx.clone(),
                        bucket: bkt.clone(),
                        key: key.clone(),
                        upload_id: e_uid,
                        parts: parts.clone(),
                        expected_checksum: None,
                        expected_object_size: None,
                        preconditions: cond.clone(),
                        raw_sse: RawSseHeaders::default(),
                    })
                    .await;
                let rm = model
                    .complete_multipart_upload(CompleteMultipartUploadReq {
                        ctx,
                        bucket: bkt,
                        key,
                        upload_id: m_uid,
                        parts,
                        expected_checksum: None,
                        expected_object_size: None,
                        preconditions: cond,
                        raw_sse: RawSseHeaders::default(),
                    })
                    .await;
                match (re, rm) {
                    (Ok(ce), Ok(cm)) => {
                        assert_eq!(ce.etag, cm.etag);
                        assert_eq!(ce.checksum, cm.checksum);
                        ids.record_ver_pair(&ce.version_id, &cm.version_id);
                    }
                    (Err(ee), Err(em)) => assert_eq!(ee.code, em.code),
                    (l, r) => panic!("MpuComplete mismatch: {l:?} vs {r:?}"),
                }
            }
            ModelOp::MpuAbort { u, up_slot } => {
                let (bkt, key, e_uid, m_uid, _) = ids.pick_upload(up_slot);
                let ctx = test_caller(u, clock_ms);
                let re = engine
                    .abort_multipart_upload(AbortMultipartUploadReq {
                        ctx: ctx.clone(),
                        bucket: bkt.clone(),
                        key: key.clone(),
                        upload_id: e_uid,
                    })
                    .await;
                let rm = model
                    .abort_multipart_upload(AbortMultipartUploadReq {
                        ctx,
                        bucket: bkt,
                        key,
                        upload_id: m_uid,
                    })
                    .await;
                assert_eq!(re.map_err(|e| e.code), rm.map_err(|e| e.code));
            }
            ModelOp::BucketAcl { u, b, put_canned } => {
                let ctx = test_caller(u, clock_ms);
                let bkt = BUCKET_POOL[b as usize].to_string();
                if let Some(ci) = put_canned {
                    let req = PutBucketAclReq {
                        ctx,
                        bucket: bkt,
                        acl: AclSpec::Canned(CANNED_ACL_POOL[ci as usize]),
                    };
                    let re = engine.put_bucket_acl(req.clone()).await;
                    let rm = model.put_bucket_acl(req).await;
                    assert_eq!(re.map_err(|e| e.code), rm.map_err(|e| e.code));
                } else {
                    let req = BucketRef { ctx, bucket: bkt };
                    let re = engine.get_bucket_acl(req.clone()).await;
                    let rm = model.get_bucket_acl(req).await;
                    assert_eq!(re.map_err(|e| e.code), rm.map_err(|e| e.code));
                }
            }
            ModelOp::ObjectAcl {
                u,
                b,
                k,
                ver_slot,
                put_canned,
            } => {
                let (ev, mv) = ids.pick_ver(ver_slot);
                let ctx = test_caller(u, clock_ms);
                let bkt = BUCKET_POOL[b as usize].to_string();
                let key = KEY_POOL[k as usize].to_string();
                if let Some(ci) = put_canned {
                    let acl = AclSpec::Canned(CANNED_ACL_POOL[ci as usize]);
                    let re = engine
                        .put_object_acl(PutObjectAclReq {
                            ctx: ctx.clone(),
                            bucket: bkt.clone(),
                            key: key.clone(),
                            version_id: ev,
                            acl: acl.clone(),
                        })
                        .await;
                    let rm = model
                        .put_object_acl(PutObjectAclReq {
                            ctx,
                            bucket: bkt,
                            key,
                            version_id: mv,
                            acl,
                        })
                        .await;
                    assert_eq!(
                        re.map(|v| v.is_some()).map_err(|e| e.code),
                        rm.map(|v| v.is_some()).map_err(|e| e.code)
                    );
                } else {
                    let re = engine
                        .get_object_acl(GetObjectAclReq {
                            ctx: ctx.clone(),
                            bucket: bkt.clone(),
                            key: key.clone(),
                            version_id: ev,
                        })
                        .await;
                    let rm = model
                        .get_object_acl(GetObjectAclReq {
                            ctx,
                            bucket: bkt,
                            key,
                            version_id: mv,
                        })
                        .await;
                    assert_eq!(
                        re.map(|r| r.policy).map_err(|e| e.code),
                        rm.map(|r| r.policy).map_err(|e| e.code)
                    );
                }
            }
            ModelOp::BucketOwnership { u, b, action } => {
                let ctx = test_caller(u, clock_ms);
                let bucket = BUCKET_POOL[b as usize].to_string();
                match action {
                    0 => {
                        let req = BucketRef { ctx, bucket };
                        let re = engine.get_bucket_ownership_controls(req.clone()).await;
                        let rm = model.get_bucket_ownership_controls(req).await;
                        assert_eq!(re.map_err(|e| e.code), rm.map_err(|e| e.code));
                    }
                    1 => {
                        let req = BucketRef { ctx, bucket };
                        let re = engine.delete_bucket_ownership_controls(req.clone()).await;
                        let rm = model.delete_bucket_ownership_controls(req).await;
                        assert_eq!(re.map_err(|e| e.code), rm.map_err(|e| e.code));
                    }
                    _ => {
                        let ownership = match action {
                            2 => ObjectOwnership::ObjectWriter,
                            3 => ObjectOwnership::BucketOwnerPreferred,
                            _ => ObjectOwnership::BucketOwnerEnforced,
                        };
                        let req = PutBucketOwnershipControlsReq {
                            ctx,
                            bucket,
                            ownership,
                        };
                        let re = engine.put_bucket_ownership_controls(req.clone()).await;
                        let rm = model.put_bucket_ownership_controls(req).await;
                        assert_eq!(re.map_err(|e| e.code), rm.map_err(|e| e.code));
                    }
                }
            }
            ModelOp::BucketTagging { u, b, action } => {
                let ctx = test_caller(u, clock_ms);
                let bucket = BUCKET_POOL[b as usize].to_string();
                match action {
                    0 => {
                        let req = BucketRef { ctx, bucket };
                        let re = engine.get_bucket_tagging(req.clone()).await;
                        let rm = model.get_bucket_tagging(req).await;
                        assert_eq!(re.map_err(|e| e.code), rm.map_err(|e| e.code));
                    }
                    1 => {
                        let req = BucketRef { ctx, bucket };
                        let re = engine.delete_bucket_tagging(req.clone()).await;
                        let rm = model.delete_bucket_tagging(req).await;
                        assert_eq!(re.map_err(|e| e.code), rm.map_err(|e| e.code));
                    }
                    _ => {
                        let tags = sample_tags(Some(action - 2)).unwrap_or_default();
                        let req = PutBucketTaggingReq { ctx, bucket, tags };
                        let re = engine.put_bucket_tagging(req.clone()).await;
                        let rm = model.put_bucket_tagging(req).await;
                        assert_eq!(re.map_err(|e| e.code), rm.map_err(|e| e.code));
                    }
                }
            }
            ModelOp::ObjectTagging {
                u,
                b,
                k,
                ver_slot,
                action,
            } => {
                let (ev, mv) = ids.pick_ver(ver_slot);
                let ctx = test_caller(u, clock_ms);
                let bucket = BUCKET_POOL[b as usize].to_string();
                let key = KEY_POOL[k as usize].to_string();
                match action {
                    0 => {
                        let re = engine
                            .get_object_tagging(ObjectTaggingRef {
                                ctx: ctx.clone(),
                                bucket: bucket.clone(),
                                key: key.clone(),
                                version_id: ev,
                            })
                            .await;
                        let rm = model
                            .get_object_tagging(ObjectTaggingRef {
                                ctx,
                                bucket,
                                key,
                                version_id: mv,
                            })
                            .await;
                        assert_eq!(
                            re.map(|r| (r.version_id.is_some(), r.tags))
                                .map_err(|e| e.code),
                            rm.map(|r| (r.version_id.is_some(), r.tags))
                                .map_err(|e| e.code),
                        );
                    }
                    1 => {
                        let re = engine
                            .delete_object_tagging(ObjectTaggingRef {
                                ctx: ctx.clone(),
                                bucket: bucket.clone(),
                                key: key.clone(),
                                version_id: ev,
                            })
                            .await;
                        let rm = model
                            .delete_object_tagging(ObjectTaggingRef {
                                ctx,
                                bucket,
                                key,
                                version_id: mv,
                            })
                            .await;
                        assert_eq!(
                            re.map(|v| v.is_some()).map_err(|e| e.code),
                            rm.map(|v| v.is_some()).map_err(|e| e.code),
                        );
                    }
                    _ => {
                        let tags = sample_tags(Some(action - 2)).unwrap_or_default();
                        let re = engine
                            .put_object_tagging(PutObjectTaggingReq {
                                ctx: ctx.clone(),
                                bucket: bucket.clone(),
                                key: key.clone(),
                                version_id: ev,
                                tags: tags.clone(),
                            })
                            .await;
                        let rm = model
                            .put_object_tagging(PutObjectTaggingReq {
                                ctx,
                                bucket,
                                key,
                                version_id: mv,
                                tags,
                            })
                            .await;
                        assert_eq!(
                            re.map(|v| v.is_some()).map_err(|e| e.code),
                            rm.map(|v| v.is_some()).map_err(|e| e.code),
                        );
                    }
                }
            }
            ModelOp::BucketCors { u, b, action } => {
                let ctx = test_caller(u, clock_ms);
                let bucket = BUCKET_POOL[b as usize].to_string();
                match action {
                    0 => {
                        let req = BucketRef { ctx, bucket };
                        let re = engine.get_bucket_cors(req.clone()).await;
                        let rm = model.get_bucket_cors(req).await;
                        assert_eq!(re.map_err(|e| e.code), rm.map_err(|e| e.code));
                    }
                    1 => {
                        let req = BucketRef { ctx, bucket };
                        let re = engine.delete_bucket_cors(req.clone()).await;
                        let rm = model.delete_bucket_cors(req).await;
                        assert_eq!(re.map_err(|e| e.code), rm.map_err(|e| e.code));
                    }
                    _ => {
                        let cors = CorsConfiguration {
                            rules: vec![CorsRule {
                                id: Some("r1".into()),
                                allowed_origins: vec!["https://*.example.com".into()],
                                allowed_methods: vec!["GET".into(), "PUT".into()],
                                allowed_headers: vec!["*".into()],
                                expose_headers: vec!["ETag".into()],
                                max_age_seconds: Some(60),
                            }],
                        };
                        let req = PutBucketCorsReq { ctx, bucket, cors };
                        let re = engine.put_bucket_cors(req.clone()).await;
                        let rm = model.put_bucket_cors(req).await;
                        assert_eq!(re.map_err(|e| e.code), rm.map_err(|e| e.code));
                    }
                }
            }
            ModelOp::BucketPolicy { u, b, action } => {
                let ctx = test_caller(u, clock_ms);
                let bucket = BUCKET_POOL[b as usize].to_string();
                match action {
                    0 => {
                        let req = BucketRef { ctx, bucket };
                        let re = engine.get_bucket_policy(req.clone()).await;
                        let rm = model.get_bucket_policy(req).await;
                        assert_eq!(re.map_err(|e| e.code), rm.map_err(|e| e.code));
                    }
                    1 => {
                        let req = BucketRef { ctx, bucket };
                        let re = engine.delete_bucket_policy(req.clone()).await;
                        let rm = model.delete_bucket_policy(req).await;
                        assert_eq!(re.map_err(|e| e.code), rm.map_err(|e| e.code));
                    }
                    2 => {
                        let req = BucketRef { ctx, bucket };
                        let re = engine.get_bucket_policy_status(req.clone()).await;
                        let rm = model.get_bucket_policy_status(req).await;
                        assert_eq!(re.map_err(|e| e.code), rm.map_err(|e| e.code));
                    }
                    _ => {
                        let policy_json = sample_policy_json(&bucket, action - 3);
                        let req = PutBucketPolicyReq {
                            ctx,
                            bucket,
                            policy_json,
                        };
                        let re = engine.put_bucket_policy(req.clone()).await;
                        let rm = model.put_bucket_policy(req).await;
                        assert_eq!(re.map_err(|e| e.code), rm.map_err(|e| e.code));
                    }
                }
            }
            ModelOp::PublicAccessBlock { u, b, action, bits } => {
                let ctx = test_caller(u, clock_ms);
                let bucket = BUCKET_POOL[b as usize].to_string();
                match action {
                    0 => {
                        let req = BucketRef { ctx, bucket };
                        let re = engine.get_public_access_block(req.clone()).await;
                        let rm = model.get_public_access_block(req).await;
                        assert_eq!(re.map_err(|e| e.code), rm.map_err(|e| e.code));
                    }
                    1 => {
                        let req = BucketRef { ctx, bucket };
                        let re = engine.delete_public_access_block(req.clone()).await;
                        let rm = model.delete_public_access_block(req).await;
                        assert_eq!(re.map_err(|e| e.code), rm.map_err(|e| e.code));
                    }
                    _ => {
                        let config = PublicAccessBlockConfig {
                            block_public_acls: (bits & 1) != 0,
                            ignore_public_acls: (bits & 2) != 0,
                            block_public_policy: (bits & 4) != 0,
                            restrict_public_buckets: (bits & 8) != 0,
                        };
                        let req = PutPublicAccessBlockReq {
                            ctx,
                            bucket,
                            config,
                        };
                        let re = engine.put_public_access_block(req.clone()).await;
                        let rm = model.put_public_access_block(req).await;
                        assert_eq!(re.map_err(|e| e.code), rm.map_err(|e| e.code));
                    }
                }
            }
            ModelOp::BucketEncryption { u, b, action } => {
                let ctx = test_caller(u, clock_ms);
                let bucket = BUCKET_POOL[b as usize].to_string();
                match action {
                    0 => {
                        let req = BucketRef { ctx, bucket };
                        let re = engine.get_bucket_encryption(req.clone()).await;
                        let rm = model.get_bucket_encryption(req).await;
                        assert_eq!(re.map_err(|e| e.code), rm.map_err(|e| e.code));
                    }
                    1 => {
                        let req = BucketRef { ctx, bucket };
                        let re = engine.delete_bucket_encryption(req.clone()).await;
                        let rm = model.delete_bucket_encryption(req).await;
                        assert_eq!(re.map_err(|e| e.code), rm.map_err(|e| e.code));
                    }
                    _ => {
                        let req = PutBucketEncryptionReq {
                            ctx,
                            bucket,
                            config: BucketEncryptionConfig {
                                sse_algorithm: "AES256".into(),
                                bucket_key_enabled: Some(false),
                            },
                        };
                        let re = engine.put_bucket_encryption(req.clone()).await;
                        let rm = model.put_bucket_encryption(req).await;
                        assert_eq!(re.map_err(|e| e.code), rm.map_err(|e| e.code));
                    }
                }
            }
            ModelOp::BucketLifecycle { u, b, action } => {
                let ctx = test_caller(u, clock_ms);
                let bucket = BUCKET_POOL[b as usize].to_string();
                match action {
                    0 => {
                        let req = BucketRef { ctx, bucket };
                        let re = engine.get_bucket_lifecycle_configuration(req.clone()).await;
                        let rm = model.get_bucket_lifecycle_configuration(req).await;
                        assert_eq!(re.map_err(|e| e.code), rm.map_err(|e| e.code));
                    }
                    1 => {
                        let req = BucketRef { ctx, bucket };
                        let re = engine.delete_bucket_lifecycle(req.clone()).await;
                        let rm = model.delete_bucket_lifecycle(req).await;
                        assert_eq!(re.map_err(|e| e.code), rm.map_err(|e| e.code));
                    }
                    _ => {
                        let config = LifecycleConfiguration {
                            rules: vec![LifecycleRule {
                                id: "r-exp".into(),
                                status: LifecycleRuleStatus::Enabled,
                                scope: LifecycleRuleScope::Filter(LifecycleFilter::Prefix(
                                    "dir/".into(),
                                )),
                                expiration: Some(LifecycleExpiration {
                                    days: Some(1),
                                    date_us: None,
                                    expired_object_delete_marker: None,
                                }),
                                noncurrent_version_expiration: Some(NoncurrentVersionExpiration {
                                    noncurrent_days: 1,
                                    newer_noncurrent_versions: Some(1),
                                }),
                                abort_incomplete_multipart_upload: Some(
                                    AbortIncompleteMultipartUpload {
                                        days_after_initiation: 1,
                                    },
                                ),
                            }],
                        };
                        let req = PutBucketLifecycleReq {
                            ctx,
                            bucket,
                            config,
                        };
                        let re = engine
                            .put_bucket_lifecycle_configuration(req.clone())
                            .await;
                        let rm = model.put_bucket_lifecycle_configuration(req).await;
                        assert_eq!(re.map_err(|e| e.code), rm.map_err(|e| e.code));
                    }
                }
            }
            ModelOp::LifecycleTick => {
                clock_ms += 3_000;
                engine.run_lifecycle_tick(clock_ms, Some(2)).await.unwrap();
                model.run_lifecycle_tick(clock_ms, Some(2));
                // Sync any newly inserted delete marker version IDs into IdBijection
                for bname in &BUCKET_POOL[0..2] {
                    let ctx = test_caller(0, clock_ms);
                    let req = ListObjectVersionsReq {
                        ctx,
                        bucket: (*bname).to_string(),
                        prefix: String::new(),
                        delimiter: None,
                        key_marker: None,
                        version_id_marker: None,
                        max_keys: 1000,
                    };
                    if let (Ok(le), Ok(lm)) = (
                        engine.list_object_versions(req.clone()).await,
                        model.list_object_versions(req).await,
                    ) {
                        assert_eq!(le.entries.len(), lm.entries.len());
                        for (ve, vm) in le.entries.iter().zip(lm.entries.iter()) {
                            assert_eq!(ve.key, vm.key);
                            assert_eq!(ve.is_delete_marker, vm.is_delete_marker);
                            if vm.version_id != "null" && !ids.m2e_ver.contains_key(&vm.version_id) {
                                ids.record_ver_pair(
                                    &Some(ve.version_id.clone()),
                                    &Some(vm.version_id.clone()),
                                );
                            }
                        }
                    }
                }
            }
            ModelOp::BucketObjectLock { u, b, put } => {
                let ctx = test_caller(u, clock_ms);
                let bucket = BUCKET_POOL[b as usize].to_string();
                if put {
                    let req = PutObjectLockConfigurationReq {
                        ctx,
                        bucket,
                        config: ObjectLockConfiguration {
                            default_retention: Some(DefaultRetention {
                                mode: ObjectLockMode::Governance,
                                period: DefaultRetentionPeriod::Days(1),
                            }),
                        },
                    };
                    let re = engine.put_object_lock_configuration(req.clone()).await;
                    let rm = model.put_object_lock_configuration(req).await;
                    assert_eq!(re.map_err(|e| e.code), rm.map_err(|e| e.code));
                } else {
                    let req = BucketRef { ctx, bucket };
                    let re = engine.get_object_lock_configuration(req.clone()).await;
                    let rm = model.get_object_lock_configuration(req).await;
                    assert_eq!(re.map_err(|e| e.code), rm.map_err(|e| e.code));
                }
            }
            ModelOp::ObjectRetention {
                u,
                b,
                k,
                ver_slot,
                action,
                bypass,
            } => {
                let (ev, mv) = ids.pick_ver(ver_slot);
                let ctx = test_caller(u, clock_ms);
                let bucket = BUCKET_POOL[b as usize].to_string();
                let key = KEY_POOL[k as usize].to_string();
                if action == 0 {
                    let re = engine
                        .get_object_retention(ObjectLockRef {
                            ctx: ctx.clone(),
                            bucket: bucket.clone(),
                            key: key.clone(),
                            version_id: ev,
                        })
                        .await;
                    let rm = model
                        .get_object_retention(ObjectLockRef {
                            ctx,
                            bucket,
                            key,
                            version_id: mv,
                        })
                        .await;
                    assert_eq!(re.map_err(|e| e.code), rm.map_err(|e| e.code));
                } else {
                    let mode = if action == 1 {
                        ObjectLockMode::Governance
                    } else {
                        ObjectLockMode::Compliance
                    };
                    let retention = ObjectRetention {
                        mode,
                        retain_until_us: (clock_ms + 60_000) * 1000,
                    };
                    let re = engine
                        .put_object_retention(PutObjectRetentionReq {
                            ctx: ctx.clone(),
                            bucket: bucket.clone(),
                            key: key.clone(),
                            version_id: ev,
                            retention,
                            bypass_governance: bypass,
                        })
                        .await;
                    let rm = model
                        .put_object_retention(PutObjectRetentionReq {
                            ctx,
                            bucket,
                            key,
                            version_id: mv,
                            retention,
                            bypass_governance: bypass,
                        })
                        .await;
                    assert_eq!(re.map_err(|e| e.code), rm.map_err(|e| e.code));
                }
            }
            ModelOp::ObjectLegalHold {
                u,
                b,
                k,
                ver_slot,
                action,
            } => {
                let (ev, mv) = ids.pick_ver(ver_slot);
                let ctx = test_caller(u, clock_ms);
                let bucket = BUCKET_POOL[b as usize].to_string();
                let key = KEY_POOL[k as usize].to_string();
                if action == 0 {
                    let re = engine
                        .get_object_legal_hold(ObjectLockRef {
                            ctx: ctx.clone(),
                            bucket: bucket.clone(),
                            key: key.clone(),
                            version_id: ev,
                        })
                        .await;
                    let rm = model
                        .get_object_legal_hold(ObjectLockRef {
                            ctx,
                            bucket,
                            key,
                            version_id: mv,
                        })
                        .await;
                    assert_eq!(re.map_err(|e| e.code), rm.map_err(|e| e.code));
                } else {
                    let status = if action == 1 {
                        LegalHoldStatus::On
                    } else {
                        LegalHoldStatus::Off
                    };
                    let re = engine
                        .put_object_legal_hold(PutObjectLegalHoldReq {
                            ctx: ctx.clone(),
                            bucket: bucket.clone(),
                            key: key.clone(),
                            version_id: ev,
                            status,
                        })
                        .await;
                    let rm = model
                        .put_object_legal_hold(PutObjectLegalHoldReq {
                            ctx,
                            bucket,
                            key,
                            version_id: mv,
                            status,
                        })
                        .await;
                    assert_eq!(re.map_err(|e| e.code), rm.map_err(|e| e.code));
                }
            }
            ModelOp::BucketLogging { u, b, tb, enable } => {
                let ctx = test_caller(u, clock_ms);
                let bucket = BUCKET_POOL[b as usize].to_string();
                match enable {
                    None => {
                        let req = BucketRef { ctx, bucket };
                        let re = engine.get_bucket_logging(req.clone()).await;
                        let rm = model.get_bucket_logging(req).await;
                        assert_eq!(re.map_err(|e| e.code), rm.map_err(|e| e.code));
                    }
                    Some(en) => {
                        let status = if en {
                            BucketLoggingStatus {
                                logging_enabled: Some(LoggingEnabled {
                                    target_bucket: BUCKET_POOL[tb as usize].to_string(),
                                    target_prefix: "logs/".into(),
                                    target_grants: Vec::new(),
                                    target_object_key_format: None,
                                }),
                            }
                        } else {
                            BucketLoggingStatus::default()
                        };
                        let req = PutBucketLoggingReq {
                            ctx,
                            bucket,
                            status,
                        };
                        let re = engine.put_bucket_logging(req.clone()).await;
                        let rm = model.put_bucket_logging(req).await;
                        assert_eq!(re.map_err(|e| e.code), rm.map_err(|e| e.code));
                    }
                }
            }
            ModelOp::SsePutGet {
                u,
                b,
                k,
                sse_kind,
                read_kind,
                size,
            } => {
                let write_sse = match sse_kind {
                    0 => RawSseHeaders {
                        sse_algorithm: Some("AES256".into()),
                        ..Default::default()
                    },
                    1 => RawSseHeaders {
                        sse_customer_algorithm: Some("AES256".into()),
                        sse_customer_key_b64: Some(
                            "pO3upElrwuEXSoFwCfnZPdSsmt/xWeFa0N9KgDijwVs=".into(),
                        ),
                        sse_customer_key_md5_b64: Some("DWygnHRtgiJ77HCm+1rvHw==".into()),
                        ..Default::default()
                    },
                    _ => RawSseHeaders {
                        sse_customer_algorithm: Some("AES256".into()),
                        sse_customer_key_b64: Some(
                            "6b+WOZ1T3cqZMxgThRcXAQBrS5mXKdDUphvpxptl9/4=".into(),
                        ),
                        sse_customer_key_md5_b64: Some("arxBvwY2V4SiOne6yppVPQ==".into()),
                        ..Default::default()
                    },
                };
                let read_sse = match read_kind {
                    0 => RawSseHeaders::default(),
                    1 => RawSseHeaders {
                        sse_customer_algorithm: Some("AES256".into()),
                        sse_customer_key_b64: Some(
                            "pO3upElrwuEXSoFwCfnZPdSsmt/xWeFa0N9KgDijwVs=".into(),
                        ),
                        sse_customer_key_md5_b64: Some("DWygnHRtgiJ77HCm+1rvHw==".into()),
                        ..Default::default()
                    },
                    _ => RawSseHeaders {
                        sse_customer_algorithm: Some("AES256".into()),
                        sse_customer_key_b64: Some(
                            "6b+WOZ1T3cqZMxgThRcXAQBrS5mXKdDUphvpxptl9/4=".into(),
                        ),
                        sse_customer_key_md5_b64: Some("arxBvwY2V4SiOne6yppVPQ==".into()),
                        ..Default::default()
                    },
                };
                let mut put_ctx = test_caller(u, clock_ms);
                put_ctx.policy_ctx.x_amz_server_side_encryption =
                    write_sse.sse_algorithm.clone();
                put_ctx.policy_ctx.x_amz_sse_customer_algorithm =
                    write_sse.sse_customer_algorithm.clone();
                let payload: Vec<u8> = (0..size).map(|i| (i * 31 + 7) as u8).collect();
                let put_req = PutObjectReq {
                    ctx: put_ctx,
                    bucket: BUCKET_POOL[b as usize].to_string(),
                    key: KEY_POOL[k as usize].to_string(),
                    sys_meta: SystemMeta::default(),
                    user_meta: Vec::new(),
                    acl: None,
                    tags: None,
                    preconditions: Preconditions::default(),
                    max_bytes_limit: MAX_SINGLE_PUT_BYTES,
                    raw_sse: write_sse,
                    raw_lock: RawUploadObjectLockHeaders::default(),
                };
                let re = engine
                    .put_object(
                        put_req.clone(),
                        InMemoryVerifiedStream::from_bytes(Bytes::from(payload.clone()), None),
                    )
                    .await;
                let rm = model
                    .put_object(
                        put_req,
                        InMemoryVerifiedStream::from_bytes(Bytes::from(payload), None),
                    )
                    .await;
                match (re, rm) {
                    (Ok(ae), Ok(am)) => {
                        assert_eq!(ae.etag, am.etag);
                        assert_eq!(ae.sse, am.sse);
                        assert_eq!(ae.expiration_header, am.expiration_header);
                        ids.record_ver_pair(&ae.version_id, &am.version_id);

                        let mut get_ctx = test_caller(u, clock_ms + 1);
                        get_ctx.policy_ctx.x_amz_sse_customer_algorithm =
                            read_sse.sse_customer_algorithm.clone();
                        let ge = engine
                            .get_object(GetObjectReq {
                                ctx: get_ctx.clone(),
                                bucket: BUCKET_POOL[b as usize].to_string(),
                                key: KEY_POOL[k as usize].to_string(),
                                version_id: ae.version_id,
                                range: None,
                                part_number: None,
                                preconditions: Preconditions::default(),
                                checksum_mode_enabled: true,
                                raw_sse: read_sse.clone(),
                            })
                            .await;
                        let gm = model
                            .get_object(GetObjectReq {
                                ctx: get_ctx,
                                bucket: BUCKET_POOL[b as usize].to_string(),
                                key: KEY_POOL[k as usize].to_string(),
                                version_id: am.version_id,
                                range: None,
                                part_number: None,
                                preconditions: Preconditions::default(),
                                checksum_mode_enabled: true,
                                raw_sse: read_sse,
                            })
                            .await;
                        match (ge, gm) {
                            (Ok(oe), Ok(om)) => {
                                assert_eq!(oe.meta.sse, om.meta.sse);
                                assert_eq!(oe.meta.expiration_header, om.meta.expiration_header);
                                assert_eq!(
                                    read_all(oe.reader).await.unwrap(),
                                    read_all(om.reader).await.unwrap()
                                );
                            }
                            (Err(ee), Err(em)) => assert_eq!(ee.code, em.code),
                            (l, r) => panic!(
                                "SsePutGet read mismatch: {:?} vs {:?}",
                                l.map(|x| x.meta).map_err(|e| e.code),
                                r.map(|x| x.meta).map_err(|e| e.code)
                            ),
                        }
                    }
                    (Err(ee), Err(em)) => assert_eq!(ee.code, em.code),
                    (l, r) => panic!("SsePutGet write mismatch: {l:?} vs {r:?}"),
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
}

fn run_vr2_parallel(total_cases: usize, seed_base: u64, max_seq_len: usize) {
    let workers = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(8)
        .max(4);
    let completed = Arc::new(AtomicUsize::new(0));

    let mut handles = Vec::with_capacity(workers);
    for tid in 0..workers {
        let cases_for_worker = total_cases / workers + usize::from(tid < total_cases % workers);
        if cases_for_worker == 0 {
            continue;
        }
        let completed = Arc::clone(&completed);
        handles.push(std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            let mut seed = [0u8; 32];
            seed[0..8].copy_from_slice(&(seed_base + tid as u64).to_le_bytes());
            let rng = TestRng::from_seed(RngAlgorithm::ChaCha, &seed);
            let cfg = ProptestConfig {
                cases: cases_for_worker as u32,
                max_shrink_iters: 256,
                ..ProptestConfig::default()
            };
            let mut runner = TestRunner::new_with_rng(cfg, rng);
            let strategy = prop::collection::vec(op_strategy(), 1..max_seq_len);
            runner
                .run(&strategy, |ops| {
                    rt.block_on(run_differential_sequence(ops));
                    completed.fetch_add(1, Ordering::Relaxed);
                    Ok(())
                })
                .unwrap_or_else(|e| panic!("worker {tid} differential failure: {e}"));
        }));
    }

    for h in handles {
        h.join().unwrap();
    }
    let total = completed.load(Ordering::SeqCst);
    assert_eq!(total, total_cases);
}

/// Default CI `VR-2`: 10,000 proptest differential sequences in `--release` (`1,000` in debug).
#[test]
fn vr2_differential_engine_vs_model() {
    let cases = if cfg!(debug_assertions) { 1_000 } else { 10_000 };
    run_vr2_parallel(cases, 0x5333_2026_C100, 30);
}

/// Multi-part `>= 5 MiB` assembly differential test covering composite & full-object checksums,
/// `partNumber` ranged reads, and `GetObjectAttributes` `ObjectParts`.
#[tokio::test]
async fn vr2_multipart_5mib_boundary_differential() {
    let disk = FaultDisk::new();
    let engine = Engine::open(disk.clone(), EngineConfig::default()).unwrap();
    let model = ModelStore::new(ModelConfig::default());
    let ctx = test_caller(0, 1_762_900_000_000);

    for store_kind in 0..2 {
        let req_b = CreateBucketReq {
            ctx: ctx.clone(),
            bucket: "mpu5m-bkt".into(),
            location_constraint: None,
            object_ownership: None,
            acl: None,
            object_lock_enabled: false,
        };
        if store_kind == 0 {
            engine.create_bucket(req_b).await.unwrap();
        } else {
            model.create_bucket(req_b).await.unwrap();
        }
    }

    for (idx, (alg, ctype)) in [
        (ChecksumAlgorithm::Crc32c, ChecksumType::Composite),
        (ChecksumAlgorithm::Crc64Nvme, ChecksumType::FullObject),
    ]
    .into_iter()
    .enumerate()
    {
        let key = format!("obj-{idx}");
        let ce = engine
            .create_multipart_upload(CreateMultipartUploadReq {
                ctx: ctx.clone(),
                bucket: "mpu5m-bkt".into(),
                key: key.clone(),
                sys_meta: SystemMeta::default(),
                user_meta: Vec::new(),
                acl: None,
                tags: None,
                checksum_algorithm: Some(alg),
                checksum_type: Some(ctype),
                raw_sse: RawSseHeaders::default(),
                raw_lock: RawUploadObjectLockHeaders::default(),
            })
            .await
            .unwrap();
        let cm = model
            .create_multipart_upload(CreateMultipartUploadReq {
                ctx: ctx.clone(),
                bucket: "mpu5m-bkt".into(),
                key: key.clone(),
                sys_meta: SystemMeta::default(),
                user_meta: Vec::new(),
                acl: None,
                tags: None,
                checksum_algorithm: Some(alg),
                checksum_type: Some(ctype),
                raw_sse: RawSseHeaders::default(),
                raw_lock: RawUploadObjectLockHeaders::default(),
            })
            .await
            .unwrap();

        let p1 = Bytes::from(vec![0x5Au8; MIN_PART_SIZE_BYTES as usize]); // exact 5 MiB
        let p2 = Bytes::from(vec![0xA5u8; 321]); // < 5 MiB final part

        let mut e_specs = Vec::new();
        let mut m_specs = Vec::new();
        for (pn, data) in [(1u32, p1.clone()), (2u32, p2.clone())] {
            let pe = engine
                .upload_part(
                    UploadPartReq {
                        ctx: ctx.clone(),
                        bucket: "mpu5m-bkt".into(),
                        key: key.clone(),
                        upload_id: ce.upload_id.clone(),
                        part_number: pn,
                        max_bytes_limit: MAX_PART_SIZE_BYTES,
                        raw_sse: RawSseHeaders::default(),
                    },
                    InMemoryVerifiedStream::from_bytes(data.clone(), Some(alg)),
                )
                .await
                .unwrap();
            let pm = model
                .upload_part(
                    UploadPartReq {
                        ctx: ctx.clone(),
                        bucket: "mpu5m-bkt".into(),
                        key: key.clone(),
                        upload_id: cm.upload_id.clone(),
                        part_number: pn,
                        max_bytes_limit: MAX_PART_SIZE_BYTES,
                        raw_sse: RawSseHeaders::default(),
                    },
                    InMemoryVerifiedStream::from_bytes(data, Some(alg)),
                )
                .await
                .unwrap();
            assert_eq!(pe.etag, pm.etag);
            assert_eq!(pe.checksum, pm.checksum);
            e_specs.push(CompletePartSpec {
                part_number: pn,
                etag: pe.etag,
                checksum: pe.checksum.map(|c| (c.algorithm, c.value_b64)),
            });
            m_specs.push(CompletePartSpec {
                part_number: pn,
                etag: pm.etag,
                checksum: pm.checksum.map(|c| (c.algorithm, c.value_b64)),
            });
        }

        let fin_e = engine
            .complete_multipart_upload(CompleteMultipartUploadReq {
                ctx: ctx.clone(),
                bucket: "mpu5m-bkt".into(),
                key: key.clone(),
                upload_id: ce.upload_id,
                parts: e_specs,
                expected_checksum: None,
                expected_object_size: Some(MIN_PART_SIZE_BYTES + 321),
                preconditions: Preconditions::default(),
                raw_sse: RawSseHeaders::default(),
            })
            .await
            .unwrap();
        let fin_m = model
            .complete_multipart_upload(CompleteMultipartUploadReq {
                ctx: ctx.clone(),
                bucket: "mpu5m-bkt".into(),
                key: key.clone(),
                upload_id: cm.upload_id,
                parts: m_specs,
                expected_checksum: None,
                expected_object_size: Some(MIN_PART_SIZE_BYTES + 321),
                preconditions: Preconditions::default(),
                raw_sse: RawSseHeaders::default(),
            })
            .await
            .unwrap();
        assert_eq!(fin_e.etag, fin_m.etag);
        assert_eq!(fin_e.checksum, fin_m.checksum);

        // Verify partNumber=2 GET matches 1:1
        let g2e = engine
            .get_object(GetObjectReq {
                ctx: ctx.clone(),
                bucket: "mpu5m-bkt".into(),
                key: key.clone(),
                version_id: None,
                range: None,
                part_number: Some(2),
                preconditions: Preconditions::default(),
                checksum_mode_enabled: true,
                raw_sse: RawSseHeaders::default(),
            })
            .await
            .unwrap();
        let g2m = model
            .get_object(GetObjectReq {
                ctx: ctx.clone(),
                bucket: "mpu5m-bkt".into(),
                key: key.clone(),
                version_id: None,
                range: None,
                part_number: Some(2),
                preconditions: Preconditions::default(),
                checksum_mode_enabled: true,
                raw_sse: RawSseHeaders::default(),
            })
            .await
            .unwrap();
        assert_eq!(g2e.meta.parts_count, Some(2));
        assert_eq!(g2e.meta.content_range, g2m.meta.content_range);
        assert_eq!(
            read_all(g2e.reader).await.unwrap(),
            read_all(g2m.reader).await.unwrap()
        );
    }

    drop(engine);
    let report = run_fsck(disk);
    assert_eq!(report.status, "ok", "fsck errors: {:?}", report.errors);
}

/// M1 Full Gate (`VR-2`): 100,000 proptest differential sequences against `ModelStore` (`0` diffs).
#[test]
#[ignore]
fn vr2_100k_sequences_m1_gate() {
    const TOTAL_CASES: usize = 100_000;
    let t0 = std::time::Instant::now();
    run_vr2_parallel(TOTAL_CASES, 0x5333_2026_0000, 25);
    eprintln!(
        "VR-2 M1 gate passed: {TOTAL_CASES} proptest sequences executed in {:.2}s, 0 diffs.",
        t0.elapsed().as_secs_f64()
    );
}

/// Nightly Gate (`VR-2`): 1,000,000 proptest differential sequences against `ModelStore` (`0` diffs).
#[test]
#[ignore]
fn vr2_1m_sequences_nightly_gate() {
    const TOTAL_CASES: usize = 1_000_000;
    let t0 = std::time::Instant::now();
    run_vr2_parallel(TOTAL_CASES, 0x5333_2026_9900, 25);
    eprintln!(
        "VR-2 Nightly gate passed: {TOTAL_CASES} proptest sequences executed in {:.2}s, 0 diffs.",
        t0.elapsed().as_secs_f64()
    );
}

async fn run_power_cut_chain(seed: u64, rounds: usize) {
    let mut rng = StdRng::seed_from_u64(seed);
    let mut disk = FaultDisk::new();
    let cfg = EngineConfig {
        segment_size: 24 * 1024,
        wal_file_size: 12 * 1024,
        checkpoint_wal_bytes: 16 * 1024,
        max_block_payload: 4 * 1024,
        ..EngineConfig::default()
    };

    struct PendingAtomicKey {
        key: String,
        before: Option<Vec<u8>>,
        after: Option<Vec<u8>>,
    }

    // Unversioned ground truth: key -> Option<Vec<u8>>
    let mut confirmed_unver: BTreeMap<String, Option<Vec<u8>>> = BTreeMap::new();
    // Atomic candidate from an interrupted mid-syscall operation in the prior round:
    // recovery must yield EITHER `before` OR `after` (`ST-3`).
    let mut pending_atomic_unver: Option<PendingAtomicKey> = None;
    // Versioned ground truth: (key, version_id) -> Vec<u8>, plus current head Option<Vec<u8>>
    let mut confirmed_ver_by_id: BTreeMap<(String, String), Vec<u8>> = BTreeMap::new();
    let mut confirmed_ver_head: BTreeMap<String, Option<Vec<u8>>> = BTreeMap::new();
    let mut buckets_ready = false;

    for round in 0..rounds {
        let engine = Engine::open(disk.clone(), cfg.clone())
            .unwrap_or_else(|e| panic!("seed {seed:#x} round {round} recovery failed: {e}"));
        let ctx = test_caller(0, 1_762_900_000_000 + round as i64 * 1000);

        if !buckets_ready {
            engine
                .create_bucket(CreateBucketReq {
                    ctx: ctx.clone(),
                    bucket: "crash-bkt".into(),
                    location_constraint: None,
                    object_ownership: None,
                    acl: None,
                    object_lock_enabled: false,
                })
                .await
                .unwrap();
            engine
                .create_bucket(CreateBucketReq {
                    ctx: ctx.clone(),
                    bucket: "ver-bkt".into(),
                    location_constraint: None,
                    object_ownership: None,
                    acl: None,
                    object_lock_enabled: false,
                })
                .await
                .unwrap();
            engine
                .put_bucket_versioning(PutBucketVersioningReq {
                    ctx: ctx.clone(),
                    bucket: "ver-bkt".into(),
                    status: VersioningStatus::Enabled,
                })
                .await
                .unwrap();
            buckets_ready = true;
        }

        // Resolve & verify ST-3 crash atomicity on any key that suffered a mid-syscall power cut
        if let Some(PendingAtomicKey {
            key: akey,
            before: before_val,
            after: after_val,
        }) = pending_atomic_unver.take()
        {
            let res = engine
                .get_object(GetObjectReq {
                    ctx: ctx.clone(),
                    bucket: "crash-bkt".into(),
                    key: akey.clone(),
                    version_id: None,
                    range: None,
                    part_number: None,
                    preconditions: Preconditions::default(),
                    checksum_mode_enabled: true,
                    raw_sse: RawSseHeaders::default(),
                })
                .await;
            let resolved: Option<Vec<u8>> = match res {
                Ok(got) => Some(read_all(got.reader).await.unwrap().to_vec()),
                Err(e) if e.code == S3ErrorCode::NoSuchKey => None,
                Err(e) => panic!("round {round}: unexpected error reading atomic key {akey}: {e}"),
            };
            assert!(
                resolved == before_val || resolved == after_val,
                "round {round}: mid-syscall torn/corrupt state on {akey} (ST-3 violation)!"
            );
            confirmed_unver.insert(akey, resolved);
        }

        // Verify ST-1, ST-2, ST-4 on unversioned bucket
        for (k, expected) in &confirmed_unver {
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
                    raw_sse: RawSseHeaders::default(),
                })
                .await;
            match (expected, res) {
                (None, Err(e)) => assert_eq!(e.code, S3ErrorCode::NoSuchKey),
                (None, Ok(_)) => panic!("round {round}: deleted key {k} resurrected! (ST-4)"),
                (Some(exp_bytes), Ok(got)) => {
                    let actual = read_all(got.reader).await.unwrap();
                    assert_eq!(&actual[..], &exp_bytes[..], "corrupt bytes on {k} (ST-2)");
                }
                (Some(_), Err(e)) => panic!("confirmed key {k} lost after crash: {e} (ST-1)"),
            }
        }

        // Verify ST-1, ST-2, ST-4 on versioned bucket (both latest head and historical VersionIds)
        for (k, expected) in &confirmed_ver_head {
            let res = engine
                .get_object(GetObjectReq {
                    ctx: ctx.clone(),
                    bucket: "ver-bkt".into(),
                    key: k.clone(),
                    version_id: None,
                    range: None,
                    part_number: None,
                    preconditions: Preconditions::default(),
                    checksum_mode_enabled: true,
                    raw_sse: RawSseHeaders::default(),
                })
                .await;
            match (expected, res) {
                (None, Err(e)) => assert_eq!(e.code, S3ErrorCode::NoSuchKey),
                (None, Ok(_)) => panic!("versioned DeleteMarker lost on {k}! (ST-4)"),
                (Some(exp_bytes), Ok(got)) => {
                    let actual = read_all(got.reader).await.unwrap();
                    assert_eq!(&actual[..], &exp_bytes[..]);
                }
                (Some(_), Err(e)) => panic!("versioned head {k} lost: {e} (ST-1)"),
            }
        }
        for ((k, vid), exp_bytes) in &confirmed_ver_by_id {
            let got = engine
                .get_object(GetObjectReq {
                    ctx: ctx.clone(),
                    bucket: "ver-bkt".into(),
                    key: k.clone(),
                    version_id: Some(vid.clone()),
                    range: None,
                    part_number: None,
                    preconditions: Preconditions::default(),
                    checksum_mode_enabled: true,
                    raw_sse: RawSseHeaders::default(),
                })
                .await
                .unwrap_or_else(|e| panic!("confirmed version ({k}, {vid}) lost: {e}"));
            let actual = read_all(got.reader).await.unwrap();
            assert_eq!(&actual[..], &exp_bytes[..]);
        }

        // Execute 1..=3 confirmed operations (unversioned put/del, versioned put/del, 1-part MPU)
        let steps = rng.gen_range(1..=3);
        for _ in 0..steps {
            let roll = rng.gen_range(0..10u8);
            if roll < 5 {
                let key = format!("k{}", rng.gen_range(0..6));
                if rng.gen_bool(0.7) {
                    let len = *[0usize, 17, 4096, 8500].choose(&mut rng).unwrap();
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
                                acl: None,
                                tags: None,
                                preconditions: Preconditions::default(),
                                max_bytes_limit: MAX_SINGLE_PUT_BYTES,
                                raw_sse: RawSseHeaders::default(),
                                raw_lock: RawUploadObjectLockHeaders::default(),
                            },
                            InMemoryVerifiedStream::from_bytes(Bytes::from(data.clone()), None),
                        )
                        .await
                        .unwrap();
                    confirmed_unver.insert(key, Some(data));
                } else {
                    engine
                        .delete_object(DeleteObjectReq {
                            ctx: ctx.clone(),
                            bucket: "crash-bkt".into(),
                            key: key.clone(),
                            version_id: None,
                            if_match: None,
                            bypass_governance: false,
                        })
                        .await
                        .unwrap();
                    confirmed_unver.insert(key, None);
                }
            } else if roll < 8 {
                let key = format!("vk{}", rng.gen_range(0..3));
                if rng.gen_bool(0.7) {
                    let len = *[1usize, 512, 4200].choose(&mut rng).unwrap();
                    let mut data = vec![0u8; len];
                    rng.fill(&mut data[..]);
                    let resp = engine
                        .put_object(
                            PutObjectReq {
                                ctx: ctx.clone(),
                                bucket: "ver-bkt".into(),
                                key: key.clone(),
                                sys_meta: SystemMeta::default(),
                                user_meta: Vec::new(),
                                acl: None,
                                tags: None,
                                preconditions: Preconditions::default(),
                                max_bytes_limit: MAX_SINGLE_PUT_BYTES,
                                raw_sse: RawSseHeaders::default(),
                                raw_lock: RawUploadObjectLockHeaders::default(),
                            },
                            InMemoryVerifiedStream::from_bytes(Bytes::from(data.clone()), None),
                        )
                        .await
                        .unwrap();
                    let vid = resp.version_id.unwrap();
                    if confirmed_ver_by_id.len() < 12 {
                        confirmed_ver_by_id.insert((key.clone(), vid), data.clone());
                    }
                    confirmed_ver_head.insert(key, Some(data));
                } else {
                    engine
                        .delete_object(DeleteObjectReq {
                            ctx: ctx.clone(),
                            bucket: "ver-bkt".into(),
                            key: key.clone(),
                            version_id: None,
                            if_match: None,
                            bypass_governance: false,
                        })
                        .await
                        .unwrap();
                    confirmed_ver_head.insert(key, None);
                }
            } else {
                // 1-part Multipart Upload (either completed or left in-flight/aborted across crash!)
                let key = format!("mpu{}", rng.gen_range(0..3));
                let init = engine
                    .create_multipart_upload(CreateMultipartUploadReq {
                        ctx: ctx.clone(),
                        bucket: "crash-bkt".into(),
                        key: key.clone(),
                        sys_meta: SystemMeta::default(),
                        user_meta: Vec::new(),
                        acl: None,
                        tags: None,
                        checksum_algorithm: Some(ChecksumAlgorithm::Crc32c),
                        checksum_type: None,
                        raw_sse: RawSseHeaders::default(),
                        raw_lock: RawUploadObjectLockHeaders::default(),
                    })
                    .await
                    .unwrap();
                let mut pdata = vec![0u8; 2048];
                rng.fill(&mut pdata[..]);
                let pr = engine
                    .upload_part(
                        UploadPartReq {
                            ctx: ctx.clone(),
                            bucket: "crash-bkt".into(),
                            key: key.clone(),
                            upload_id: init.upload_id.clone(),
                            part_number: 1,
                            max_bytes_limit: MAX_PART_SIZE_BYTES,
                            raw_sse: RawSseHeaders::default(),
                        },
                        InMemoryVerifiedStream::from_bytes(
                            Bytes::from(pdata.clone()),
                            Some(ChecksumAlgorithm::Crc32c),
                        ),
                    )
                    .await
                    .unwrap();
                if rng.gen_bool(0.6) {
                    engine
                        .complete_multipart_upload(CompleteMultipartUploadReq {
                            ctx: ctx.clone(),
                            bucket: "crash-bkt".into(),
                            key: key.clone(),
                            upload_id: init.upload_id,
                            parts: vec![CompletePartSpec {
                                part_number: 1,
                                etag: pr.etag,
                                checksum: pr.checksum.map(|c| (c.algorithm, c.value_b64)),
                            }],
                            expected_checksum: None,
                            expected_object_size: None,
                            preconditions: Preconditions::default(),
                            raw_sse: RawSseHeaders::default(),
                        })
                        .await
                        .unwrap();
                    confirmed_unver.insert(key, Some(pdata));
                } else if rng.gen_bool(0.5) {
                    engine
                        .abort_multipart_upload(AbortMultipartUploadReq {
                            ctx: ctx.clone(),
                            bucket: "crash-bkt".into(),
                            key,
                            upload_id: init.upload_id,
                        })
                        .await
                        .unwrap();
                }
            }
        }

        if round % 20 == 0 {
            engine.compact().await.unwrap();
        }
        if round > 0 && round % 25 == 0 {
            engine.write_checkpoint().await.unwrap();
        }

        // True in-flight mid-syscall power-cut injection (`VR-3`):
        // Arm a sector-granular I/O countdown on `FaultDisk` and drive a real `Engine` operation
        // right into the power cut (tearing multi-block/SSE writes, deletes, MPUs, GC compaction,
        // or checkpoints mid-syscall!).
        match rng.gen_range(0..5u8) {
            0 | 1 => {
                // Multi-block / multi-segment PutObject (up to 64 KiB across 24 KiB segments, +/- SSE-S3)
                let key = format!("k{}", rng.gen_range(0..6));
                let prev = confirmed_unver.get(&key).cloned().unwrap_or(None);
                let len = *[1usize, 4096, 12_288, 28_000, 65_536]
                    .choose(&mut rng)
                    .unwrap();
                let mut data = vec![0u8; len];
                rng.fill(&mut data[..]);
                let raw_sse = if rng.gen_bool(0.4) {
                    RawSseHeaders {
                        sse_algorithm: Some("AES256".into()),
                        ..Default::default()
                    }
                } else {
                    RawSseHeaders::default()
                };
                disk.arm_mid_io_power_cut(rng.gen_range(0..26));
                let put_res = engine
                    .put_object(
                        PutObjectReq {
                            ctx: ctx.clone(),
                            bucket: "crash-bkt".into(),
                            key: key.clone(),
                            sys_meta: SystemMeta::default(),
                            user_meta: Vec::new(),
                            acl: None,
                            tags: None,
                            preconditions: Preconditions::default(),
                            max_bytes_limit: MAX_SINGLE_PUT_BYTES,
                            raw_sse,
                            raw_lock: RawUploadObjectLockHeaders::default(),
                        },
                        InMemoryVerifiedStream::from_bytes(Bytes::from(data.clone()), None),
                    )
                    .await;
                if put_res.is_ok() {
                    confirmed_unver.insert(key, Some(data));
                } else {
                    pending_atomic_unver = Some(PendingAtomicKey {
                        key,
                        before: prev,
                        after: Some(data),
                    });
                }
            }
            2 => {
                // Mid-syscall DeleteObject
                let key = format!("k{}", rng.gen_range(0..6));
                let prev = confirmed_unver.get(&key).cloned().unwrap_or(None);
                disk.arm_mid_io_power_cut(rng.gen_range(0..6));
                let del_res = engine
                    .delete_object(DeleteObjectReq {
                        ctx: ctx.clone(),
                        bucket: "crash-bkt".into(),
                        key: key.clone(),
                        version_id: None,
                        if_match: None,
                        bypass_governance: false,
                    })
                    .await;
                if del_res.is_ok() {
                    confirmed_unver.insert(key, None);
                } else {
                    pending_atomic_unver = Some(PendingAtomicKey {
                        key,
                        before: prev,
                        after: None,
                    });
                }
            }
            3 => {
                // Mid-syscall MultipartUpload (Create -> 16 KiB multi-block UploadPart -> Complete)
                let key = format!("mpu{}", rng.gen_range(0..3));
                let prev = confirmed_unver.get(&key).cloned().unwrap_or(None);
                let mut pdata = vec![0u8; 16_384];
                rng.fill(&mut pdata[..]);
                disk.arm_mid_io_power_cut(rng.gen_range(0..20));
                if let Ok(init) = engine
                    .create_multipart_upload(CreateMultipartUploadReq {
                        ctx: ctx.clone(),
                        bucket: "crash-bkt".into(),
                        key: key.clone(),
                        sys_meta: SystemMeta::default(),
                        user_meta: Vec::new(),
                        acl: None,
                        tags: None,
                        checksum_algorithm: Some(ChecksumAlgorithm::Crc64Nvme),
                        checksum_type: Some(ChecksumType::FullObject),
                        raw_sse: RawSseHeaders::default(),
                        raw_lock: RawUploadObjectLockHeaders::default(),
                    })
                    .await
                    && let Ok(pr) = engine
                        .upload_part(
                            UploadPartReq {
                                ctx: ctx.clone(),
                                bucket: "crash-bkt".into(),
                                key: key.clone(),
                                upload_id: init.upload_id.clone(),
                                part_number: 1,
                                max_bytes_limit: MAX_PART_SIZE_BYTES,
                                raw_sse: RawSseHeaders::default(),
                            },
                            InMemoryVerifiedStream::from_bytes(
                                Bytes::from(pdata.clone()),
                                Some(ChecksumAlgorithm::Crc64Nvme),
                            ),
                        )
                        .await
                {
                    let comp_res = engine
                        .complete_multipart_upload(CompleteMultipartUploadReq {
                            ctx: ctx.clone(),
                            bucket: "crash-bkt".into(),
                            key: key.clone(),
                            upload_id: init.upload_id,
                            parts: vec![CompletePartSpec {
                                part_number: 1,
                                etag: pr.etag,
                                checksum: pr.checksum.map(|c| (c.algorithm, c.value_b64)),
                            }],
                            expected_checksum: None,
                            expected_object_size: None,
                            preconditions: Preconditions::default(),
                            raw_sse: RawSseHeaders::default(),
                        })
                        .await;
                    if comp_res.is_ok() {
                        confirmed_unver.insert(key, Some(pdata));
                    } else {
                        pending_atomic_unver = Some(PendingAtomicKey {
                            key,
                            before: prev,
                            after: Some(pdata),
                        });
                    }
                }
            }
            _ => {
                // Mid-syscall GC compaction or checkpoint write (`ST-8` & Spec §5 VR-3)
                disk.arm_mid_io_power_cut(rng.gen_range(0..14));
                if rng.gen_bool(0.5) {
                    let _ = engine.compact().await;
                } else {
                    let _ = engine.write_checkpoint().await;
                }
            }
        }

        drop(engine);
        disk = disk.power_cut(&mut rng);
    }

    let report = run_fsck(disk);
    assert_eq!(report.status, "ok", "final fsck errors: {:?}", report.errors);
}

/// Default CI `VR-3`: 1,000 random power-cut cycles (2 chains * 500 rounds) with zero violations.
#[tokio::test]
async fn vr3_1000_random_power_cuts_zero_violations() {
    run_power_cut_chain(0x5333_2026, 500).await;
    run_power_cut_chain(0x5333_2027, 500).await;
}

/// M1 Full Gate (`VR-3`): 10,000 random power-cut cycles (20 chains * 500 rounds) with zero violations.
#[test]
#[ignore]
fn vr3_10k_random_power_cuts_m1_gate() {
    const CHAINS: usize = 20;
    const ROUNDS_PER_CHAIN: usize = 500;
    let workers = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(8)
        .min(CHAINS);
    let next_chain = Arc::new(AtomicUsize::new(0));
    let total_rounds = Arc::new(AtomicUsize::new(0));

    let mut handles = Vec::with_capacity(workers);
    for _ in 0..workers {
        let next_chain = Arc::clone(&next_chain);
        let total_rounds = Arc::clone(&total_rounds);
        handles.push(std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            loop {
                let cid = next_chain.fetch_add(1, Ordering::SeqCst);
                if cid >= CHAINS {
                    break;
                }
                rt.block_on(run_power_cut_chain(0xCAFE_0000 + cid as u64, ROUNDS_PER_CHAIN));
                total_rounds.fetch_add(ROUNDS_PER_CHAIN, Ordering::SeqCst);
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
    let done = total_rounds.load(Ordering::SeqCst);
    assert_eq!(done, CHAINS * ROUNDS_PER_CHAIN);
    eprintln!("VR-3 M1 gate passed: {done} random power-cut cycles executed, 0 violations.");
}

/// M3 Full Gate (`VR-3`): 100,000 random power-cut cycles (200 chains * 500 rounds)
/// with concurrent GC compaction, WAL rollover/pruning, and checkpoints — zero violations.
#[test]
#[ignore]
fn vr3_100k_random_power_cuts_m3_gate() {
    const CHAINS: usize = 200;
    const ROUNDS_PER_CHAIN: usize = 500;
    let workers = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(8)
        .min(CHAINS);
    let next_chain = Arc::new(AtomicUsize::new(0));
    let total_rounds = Arc::new(AtomicUsize::new(0));
    let t0 = std::time::Instant::now();

    let mut handles = Vec::with_capacity(workers);
    for _ in 0..workers {
        let next_chain = Arc::clone(&next_chain);
        let total_rounds = Arc::clone(&total_rounds);
        handles.push(std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            loop {
                let cid = next_chain.fetch_add(1, Ordering::SeqCst);
                if cid >= CHAINS {
                    break;
                }
                rt.block_on(run_power_cut_chain(0xD3AD_0000 + cid as u64, ROUNDS_PER_CHAIN));
                let cur = total_rounds.fetch_add(ROUNDS_PER_CHAIN, Ordering::SeqCst) + ROUNDS_PER_CHAIN;
                if cur.is_multiple_of(10_000) {
                    eprintln!("VR-3 M3 progress: {cur} / {} power-cuts verified", CHAINS * ROUNDS_PER_CHAIN);
                }
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
    let done = total_rounds.load(Ordering::SeqCst);
    assert_eq!(done, CHAINS * ROUNDS_PER_CHAIN);
    eprintln!(
        "VR-3 M3 gate passed: {done} random power-cut cycles executed in {:.2}s, 0 violations.",
        t0.elapsed().as_secs_f64()
    );
}

#[tokio::test]
async fn fsync_eio_triggers_immediate_read_only_circuit_breaker() {
    let disk = FaultDisk::new();
    let engine = Engine::open(disk.clone(), EngineConfig::default()).unwrap();
    let ctx = test_caller(0, 1_762_900_000_000);

    engine
        .create_bucket(CreateBucketReq {
            ctx: ctx.clone(),
            bucket: "eio-bkt".into(),
            location_constraint: None,
            object_ownership: None,
            acl: None,
            object_lock_enabled: false,
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
                acl: None,
                tags: None,
                preconditions: Preconditions::default(),
                max_bytes_limit: MAX_SINGLE_PUT_BYTES,
                raw_sse: RawSseHeaders::default(),
                raw_lock: RawUploadObjectLockHeaders::default(),
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
                acl: None,
                tags: None,
                preconditions: Preconditions::default(),
                max_bytes_limit: MAX_SINGLE_PUT_BYTES,
                raw_sse: RawSseHeaders::default(),
                raw_lock: RawUploadObjectLockHeaders::default(),
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
            bypass_governance: false,
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
                raw_sse: RawSseHeaders::default(),
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
            raw_sse: RawSseHeaders::default(),
        })
        .await
        .unwrap();
    assert_eq!(&read_all(good.reader).await.unwrap()[..], b"durable-v1");
}

/// Milestone M4 (`VR-2` + `VR-3` + `NFR-13`) end-to-end verification of all 4 P2 domains
/// across `Engine` vs `ModelStore` parity, `write_checkpoint()`, WAL tail replay, `power_cut()`,
/// zero-SSE-C-key-on-disk audit, and `run_fsck()`.
#[tokio::test]
async fn vr2_vr3_p2_encryption_lock_lifecycle_logging_checkpoint_crash() {
    use base64::Engine as _;

    let mut disk = FaultDisk::new();
    let cfg = EngineConfig {
        segment_size: 8 * 1024 * 1024,
        wal_file_size: 64 * 1024,
        max_block_payload: 64 * 1024,
        default_object_ownership: ObjectOwnership::ObjectWriter,
        ..EngineConfig::default()
    };
    let engine = Engine::open(disk.clone(), cfg.clone()).unwrap();
    let model = ModelStore::new(ModelConfig {
        default_object_ownership: ObjectOwnership::ObjectWriter,
        ..ModelConfig::default()
    });

    let t0 = 1_762_900_000_000i64;
    let ctx = test_caller(0, t0);

    // 1. Create Object-Lock-enabled source bucket + logging target bucket on both Engine & ModelStore
    for bkt_req in [
        CreateBucketReq {
            ctx: ctx.clone(),
            bucket: "p2-main".into(),
            location_constraint: None,
            object_ownership: None,
            acl: None,
            object_lock_enabled: true,
        },
        CreateBucketReq {
            ctx: ctx.clone(),
            bucket: "p2-logs".into(),
            location_constraint: None,
            object_ownership: None,
            acl: None,
            object_lock_enabled: false,
        },
    ] {
        engine.create_bucket(bkt_req.clone()).await.unwrap();
        model.create_bucket(bkt_req).await.unwrap();
    }

    // Object Lock automatically enables Versioning and blocks suspending Versioning (409 InvalidBucketState)
    assert_eq!(
        engine
            .get_bucket_versioning(BucketRef {
                ctx: ctx.clone(),
                bucket: "p2-main".into(),
            })
            .await
            .unwrap(),
        VersioningStatus::Enabled
    );
    let susp_req = PutBucketVersioningReq {
        ctx: ctx.clone(),
        bucket: "p2-main".into(),
        status: VersioningStatus::Suspended,
    };
    assert_eq!(
        engine.put_bucket_versioning(susp_req.clone()).await.unwrap_err().code,
        S3ErrorCode::InvalidBucketState
    );
    assert_eq!(
        model.put_bucket_versioning(susp_req).await.unwrap_err().code,
        S3ErrorCode::InvalidBucketState
    );

    // Configure default GOVERNANCE retention (1 day), bucket SSE-S3 encryption, Lifecycle, and Bucket Logging
    let lock_cfg_req = PutObjectLockConfigurationReq {
        ctx: ctx.clone(),
        bucket: "p2-main".into(),
        config: ObjectLockConfiguration {
            default_retention: Some(DefaultRetention {
                mode: ObjectLockMode::Governance,
                period: DefaultRetentionPeriod::Days(1),
            }),
        },
    };
    engine
        .put_object_lock_configuration(lock_cfg_req.clone())
        .await
        .unwrap();
    model.put_object_lock_configuration(lock_cfg_req).await.unwrap();

    let enc_req = PutBucketEncryptionReq {
        ctx: ctx.clone(),
        bucket: "p2-main".into(),
        config: BucketEncryptionConfig {
            sse_algorithm: "AES256".into(),
            bucket_key_enabled: Some(true),
        },
    };
    engine.put_bucket_encryption(enc_req.clone()).await.unwrap();
    model.put_bucket_encryption(enc_req).await.unwrap();

    let lc_req = PutBucketLifecycleReq {
        ctx: ctx.clone(),
        bucket: "p2-main".into(),
        config: LifecycleConfiguration {
            rules: vec![LifecycleRule {
                id: "exp-logs".into(),
                status: LifecycleRuleStatus::Enabled,
                scope: LifecycleRuleScope::Filter(LifecycleFilter::Prefix("lc/".into())),
                expiration: Some(LifecycleExpiration {
                    days: Some(1),
                    date_us: None,
                    expired_object_delete_marker: None,
                }),
                noncurrent_version_expiration: Some(NoncurrentVersionExpiration {
                    noncurrent_days: 1,
                    newer_noncurrent_versions: None,
                }),
                abort_incomplete_multipart_upload: Some(AbortIncompleteMultipartUpload {
                    days_after_initiation: 1,
                }),
            }],
        },
    };
    engine
        .put_bucket_lifecycle_configuration(lc_req.clone())
        .await
        .unwrap();
    model
        .put_bucket_lifecycle_configuration(lc_req)
        .await
        .unwrap();

    let log_policy = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"logging.s3.amazonaws.com"},"Action":"s3:PutObject","Resource":"arn:aws:s3:::p2-logs/access/*","Condition":{"ArnLike":{"aws:SourceArn":"arn:aws:s3:::p2-main"},"StringEquals":{"aws:SourceAccount":"0123456789abcdef"}}}]}"#;
    let pol_req = PutBucketPolicyReq {
        ctx: ctx.clone(),
        bucket: "p2-logs".into(),
        policy_json: log_policy.into(),
    };
    engine.put_bucket_policy(pol_req.clone()).await.unwrap();
    model.put_bucket_policy(pol_req).await.unwrap();

    let put_log_req = PutBucketLoggingReq {
        ctx: ctx.clone(),
        bucket: "p2-main".into(),
        status: BucketLoggingStatus {
            logging_enabled: Some(LoggingEnabled {
                target_bucket: "p2-logs".into(),
                target_prefix: "access/".into(),
                target_grants: Vec::new(),
                target_object_key_format: Some(TargetObjectKeyFormat::PartitionedPrefix(
                    PartitionDateSource::EventTime,
                )),
            }),
        },
    };
    engine.put_bucket_logging(put_log_req.clone()).await.unwrap();
    model.put_bucket_logging(put_log_req).await.unwrap();

    // 2. Upload unaligned SSE-C multipart object (part 1 = 5 MiB + 3 bytes, part 2 = 777 bytes)
    let raw_customer_key = [0xA7u8; 32];
    let ssec_key_b64 = base64::engine::general_purpose::STANDARD.encode(raw_customer_key);
    let ssec_md5_b64 = {
        use md5::{Digest as _, Md5};
        base64::engine::general_purpose::STANDARD.encode(Md5::digest(raw_customer_key))
    };
    let ssec_hdrs = RawSseHeaders {
        sse_customer_algorithm: Some("AES256".into()),
        sse_customer_key_b64: Some(ssec_key_b64.clone()),
        sse_customer_key_md5_b64: Some(ssec_md5_b64.clone()),
        ..Default::default()
    };

    let p1_len = MIN_PART_SIZE_BYTES as usize + 3;
    let p2_len = 777usize;
    let p1_data: Vec<u8> = (0..p1_len).map(|i| (i * 13 + 5) as u8).collect();
    let p2_data: Vec<u8> = (0..p2_len).map(|i| (i * 29 + 11) as u8).collect();
    let mut full_expected = p1_data.clone();
    full_expected.extend_from_slice(&p2_data);

    let init_e = engine
        .create_multipart_upload(CreateMultipartUploadReq {
            ctx: ctx.clone(),
            bucket: "p2-main".into(),
            key: "lc/ssec-mpu".into(),
            sys_meta: SystemMeta::default(),
            user_meta: Vec::new(),
            acl: None,
            tags: None,
            checksum_algorithm: Some(ChecksumAlgorithm::Crc32c),
            checksum_type: Some(ChecksumType::Composite),
            raw_sse: ssec_hdrs.clone(),
            raw_lock: RawUploadObjectLockHeaders {
                mode: Some("GOVERNANCE".into()),
                retain_until_date: Some("2099-01-01T00:00:00Z".into()),
                legal_hold: Some("ON".into()),
            },
        })
        .await
        .unwrap();
    let init_m = model
        .create_multipart_upload(CreateMultipartUploadReq {
            ctx: ctx.clone(),
            bucket: "p2-main".into(),
            key: "lc/ssec-mpu".into(),
            sys_meta: SystemMeta::default(),
            user_meta: Vec::new(),
            acl: None,
            tags: None,
            checksum_algorithm: Some(ChecksumAlgorithm::Crc32c),
            checksum_type: Some(ChecksumType::Composite),
            raw_sse: ssec_hdrs.clone(),
            raw_lock: RawUploadObjectLockHeaders {
                mode: Some("GOVERNANCE".into()),
                retain_until_date: Some("2099-01-01T00:00:00Z".into()),
                legal_hold: Some("ON".into()),
            },
        })
        .await
        .unwrap();

    let mut e_parts = Vec::new();
    let mut m_parts = Vec::new();
    for (pn, bytes) in [(1u32, p1_data), (2u32, p2_data)] {
        let pe = engine
            .upload_part(
                UploadPartReq {
                    ctx: ctx.clone(),
                    bucket: "p2-main".into(),
                    key: "lc/ssec-mpu".into(),
                    upload_id: init_e.upload_id.clone(),
                    part_number: pn,
                    max_bytes_limit: MAX_PART_SIZE_BYTES,
                    raw_sse: ssec_hdrs.clone(),
                },
                InMemoryVerifiedStream::from_bytes(Bytes::from(bytes.clone()), Some(ChecksumAlgorithm::Crc32c)),
            )
            .await
            .unwrap();
        let pm = model
            .upload_part(
                UploadPartReq {
                    ctx: ctx.clone(),
                    bucket: "p2-main".into(),
                    key: "lc/ssec-mpu".into(),
                    upload_id: init_m.upload_id.clone(),
                    part_number: pn,
                    max_bytes_limit: MAX_PART_SIZE_BYTES,
                    raw_sse: ssec_hdrs.clone(),
                },
                InMemoryVerifiedStream::from_bytes(Bytes::from(bytes), Some(ChecksumAlgorithm::Crc32c)),
            )
            .await
            .unwrap();
        assert_eq!(pe.etag, pm.etag);
        assert_eq!(pe.sse, pm.sse);
        e_parts.push(CompletePartSpec {
            part_number: pn,
            etag: pe.etag,
            checksum: pe.checksum.map(|c| (c.algorithm, c.value_b64)),
        });
        m_parts.push(CompletePartSpec {
            part_number: pn,
            etag: pm.etag,
            checksum: pm.checksum.map(|c| (c.algorithm, c.value_b64)),
        });
    }

    let comp_e = engine
        .complete_multipart_upload(CompleteMultipartUploadReq {
            ctx: ctx.clone(),
            bucket: "p2-main".into(),
            key: "lc/ssec-mpu".into(),
            upload_id: init_e.upload_id,
            parts: e_parts,
            expected_checksum: None,
            expected_object_size: None,
            preconditions: Preconditions::default(),
            raw_sse: ssec_hdrs.clone(),
        })
        .await
        .unwrap();
    let comp_m = model
        .complete_multipart_upload(CompleteMultipartUploadReq {
            ctx: ctx.clone(),
            bucket: "p2-main".into(),
            key: "lc/ssec-mpu".into(),
            upload_id: init_m.upload_id,
            parts: m_parts,
            expected_checksum: None,
            expected_object_size: None,
            preconditions: Preconditions::default(),
            raw_sse: ssec_hdrs.clone(),
        })
        .await
        .unwrap();
    assert_eq!(comp_e.etag, comp_m.etag);
    assert_eq!(comp_e.sse, comp_m.sse);
    assert_eq!(comp_e.expiration_header, comp_m.expiration_header);
    assert!(comp_e.expiration_header.as_deref().unwrap().contains("rule-id=\"exp-logs\""));

    // Also upload a default-encrypted SSE-S3 object before checkpoint + another after checkpoint
    engine
        .put_object(
            PutObjectReq {
                ctx: ctx.clone(),
                bucket: "p2-main".into(),
                key: "lc/default-sses3".into(),
                sys_meta: SystemMeta::default(),
                user_meta: Vec::new(),
                acl: None,
                tags: None,
                preconditions: Preconditions::default(),
                max_bytes_limit: MAX_SINGLE_PUT_BYTES,
                raw_sse: RawSseHeaders::default(),
                raw_lock: RawUploadObjectLockHeaders::default(),
            },
            InMemoryVerifiedStream::from_bytes(Bytes::from_static(b"secret-sse-s3-payload"), None),
        )
        .await
        .unwrap();
    model
        .put_object(
            PutObjectReq {
                ctx: ctx.clone(),
                bucket: "p2-main".into(),
                key: "lc/default-sses3".into(),
                sys_meta: SystemMeta::default(),
                user_meta: Vec::new(),
                acl: None,
                tags: None,
                preconditions: Preconditions::default(),
                max_bytes_limit: MAX_SINGLE_PUT_BYTES,
                raw_sse: RawSseHeaders::default(),
                raw_lock: RawUploadObjectLockHeaders::default(),
            },
            InMemoryVerifiedStream::from_bytes(Bytes::from_static(b"secret-sse-s3-payload"), None),
        )
        .await
        .unwrap();

    // Write checkpoint, then mutate LegalHold in post-checkpoint WAL tail, then simulate power loss!
    engine.write_checkpoint().await.unwrap();
    let ssec_vid_e = comp_e.version_id.clone().unwrap();
    let ssec_vid_m = comp_m.version_id.clone().unwrap();

    // WORM protection: deleting locked version with LegalHold::On fails even with bypass_governance = true!
    assert_eq!(
        engine
            .delete_object(DeleteObjectReq {
                ctx: ctx.clone(),
                bucket: "p2-main".into(),
                key: "lc/ssec-mpu".into(),
                version_id: Some(ssec_vid_e.clone()),
                if_match: None,
                bypass_governance: true,
            })
            .await
            .unwrap_err()
            .code,
        S3ErrorCode::AccessDenied
    );
    // Turn LegalHold OFF in post-checkpoint WAL tail
    engine
        .put_object_legal_hold(PutObjectLegalHoldReq {
            ctx: ctx.clone(),
            bucket: "p2-main".into(),
            key: "lc/ssec-mpu".into(),
            version_id: Some(ssec_vid_e.clone()),
            status: LegalHoldStatus::Off,
        })
        .await
        .unwrap();
    model
        .put_object_legal_hold(PutObjectLegalHoldReq {
            ctx: ctx.clone(),
            bucket: "p2-main".into(),
            key: "lc/ssec-mpu".into(),
            version_id: Some(ssec_vid_m.clone()),
            status: LegalHoldStatus::Off,
        })
        .await
        .unwrap();

    drop(engine);
    let mut rng = StdRng::seed_from_u64(0x4D34_2026);
    disk = disk.power_cut(&mut rng);

    // 3. Audit every file on disk: raw 32-byte SSE-C key AND plaintext `secret-sse-s3-payload` MUST NOT appear!
    for dir in ["wal", "ckpt", "seg"] {
        if let Ok(files) = disk.read_dir(dir) {
            for fname in files {
                let f = disk.open(&format!("{dir}/{fname}"), OpenOpts::read_only()).unwrap();
                let mut raw = vec![0u8; f.len().unwrap() as usize];
                f.read_exact_at(0, &mut raw).unwrap();
                assert!(
                    !raw.windows(32).any(|w| w == raw_customer_key),
                    "CRITICAL: raw SSE-C customer key leaked into {dir}/{fname}!"
                );
                assert!(
                    !raw.windows(b"secret-sse-s3-payload".len())
                        .any(|w| w == b"secret-sse-s3-payload"),
                    "CRITICAL: SSE-S3 plaintext was stored unencrypted in {dir}/{fname}!"
                );
            }
        }
    }

    let fsck_rep = run_fsck(disk.clone());
    assert_eq!(fsck_rep.status, "ok", "fsck errors: {:?}", fsck_rep.errors);

    // 4. Recover Engine from checkpoint + WAL tail and verify cross-part Range read, ?partNumber=2,
    //    Bucket Logging, Lifecycle tick parity, and GOVERNANCE bypass delete!
    let recovered = Engine::open(disk.clone(), cfg).unwrap();
    assert_eq!(
        recovered
            .get_bucket_logging(BucketRef {
                ctx: ctx.clone(),
                bucket: "p2-main".into(),
            })
            .await
            .unwrap()
            .logging_enabled
            .unwrap()
            .target_bucket,
        "p2-logs"
    );
    assert_eq!(
        recovered
            .get_object_legal_hold(ObjectLockRef {
                ctx: ctx.clone(),
                bucket: "p2-main".into(),
                key: "lc/ssec-mpu".into(),
                version_id: Some(ssec_vid_e.clone()),
            })
            .await
            .unwrap(),
        LegalHoldStatus::Off
    );

    // Cross-part unaligned Range read spanning part 1 -> part 2 boundary!
    let r_start = (p1_len - 37) as u64;
    let r_end = (p1_len + 49) as u64;
    let rng_got = recovered
        .get_object(GetObjectReq {
            ctx: ctx.clone(),
            bucket: "p2-main".into(),
            key: "lc/ssec-mpu".into(),
            version_id: Some(ssec_vid_e.clone()),
            range: Some(ByteRangeSpec::FromTo {
                start: r_start,
                end: r_end,
            }),
            part_number: None,
            preconditions: Preconditions::default(),
            checksum_mode_enabled: false,
            raw_sse: ssec_hdrs.clone(),
        })
        .await
        .unwrap();
    let rng_bytes = read_all(rng_got.reader).await.unwrap();
    assert_eq!(
        &rng_bytes[..],
        &full_expected[(r_start as usize)..=(r_end as usize)]
    );

    // Run lifecycle tick after 1 debug day (2s): current versions get DeleteMarkers, WORM-locked noncurrent versions survive!
    recovered.run_lifecycle_tick(t0 + 3_000, Some(2)).await.unwrap();
    model.run_lifecycle_tick(t0 + 3_000, Some(2));
    match recovered
        .get_object(GetObjectReq {
            ctx: ctx.clone(),
            bucket: "p2-main".into(),
            key: "lc/default-sses3".into(),
            version_id: None,
            range: None,
            part_number: None,
            preconditions: Preconditions::default(),
            checksum_mode_enabled: false,
            raw_sse: RawSseHeaders::default(),
        })
        .await
    {
        Err(e) => assert_eq!(e.code, S3ErrorCode::NoSuchKey),
        Ok(_) => panic!("expected NoSuchKey after lifecycle expiration inserted delete marker"),
    }

    // Delete GOVERNANCE-locked version without bypass -> 403 AccessDenied; WITH bypass -> 204!
    assert_eq!(
        recovered
            .delete_object(DeleteObjectReq {
                ctx: ctx.clone(),
                bucket: "p2-main".into(),
                key: "lc/ssec-mpu".into(),
                version_id: Some(ssec_vid_e.clone()),
                if_match: None,
                bypass_governance: false,
            })
            .await
            .unwrap_err()
            .code,
        S3ErrorCode::AccessDenied
    );
    recovered
        .delete_object(DeleteObjectReq {
            ctx: ctx.clone(),
            bucket: "p2-main".into(),
            key: "lc/ssec-mpu".into(),
            version_id: Some(ssec_vid_e),
            if_match: None,
            bypass_governance: true,
        })
        .await
        .unwrap();

    drop(recovered);
    let final_fsck = run_fsck(disk);
    assert_eq!(final_fsck.status, "ok", "final fsck errors: {:?}", final_fsck.errors);
}

/// `VR-3`: True mid-syscall sector-granular power cuts on multi-block & multi-MiB objects
/// (`128 KiB`, `1 MiB + 37 B`, `5 MiB + 19 B`), SSE-C streams, 2-part `5 MiB + 321 B`
/// `MultipartUpload`, `compact()`, and `write_checkpoint()`, differentially checked against
/// `ModelStore` (`model_before` / `model_after`) and `run_fsck`.
#[tokio::test]
async fn vr3_mid_syscall_multi_mib_power_cuts() {
    use base64::Engine as _;
    use md5::{Digest as _, Md5};

    let mut rng = StdRng::seed_from_u64(0x5333_D15C_2026);
    let mut disk = FaultDisk::new();
    let cfg = EngineConfig {
        segment_size: 512 * 1024, // 512 KiB -> 5 MiB object spans 11 segments!
        wal_file_size: 64 * 1024,
        checkpoint_wal_bytes: 64 * 1024,
        max_block_payload: 64 * 1024, // 64 KiB -> 16 x 4 KiB sectors per block
        ..EngineConfig::default()
    };

    let mut model = ModelStore::new(ModelConfig::default());
    let ctx = test_caller(0, 1_762_950_000_000);

    let raw_customer_key = [0x5Cu8; 32];
    let ssec_hdrs = RawSseHeaders {
        sse_customer_algorithm: Some("AES256".into()),
        sse_customer_key_b64: Some(
            base64::engine::general_purpose::STANDARD.encode(raw_customer_key),
        ),
        sse_customer_key_md5_b64: Some(
            base64::engine::general_purpose::STANDARD.encode(Md5::digest(raw_customer_key)),
        ),
        ..Default::default()
    };

    // Initialize bucket & baseline 1 MiB + 37 B object in both Engine and ModelStore
    {
        let engine = Engine::open(disk.clone(), cfg.clone()).unwrap();
        let req_b = CreateBucketReq {
            ctx: ctx.clone(),
            bucket: "mib-crash".into(),
            location_constraint: None,
            object_ownership: None,
            acl: None,
            object_lock_enabled: false,
        };
        engine.create_bucket(req_b.clone()).await.unwrap();
        model.create_bucket(req_b).await.unwrap();

        let base_1m = make_patterned_payload(1024 * 1024 + 37, 0x11);
        let put_base = PutObjectReq {
            ctx: ctx.clone(),
            bucket: "mib-crash".into(),
            key: "obj-1m".into(),
            sys_meta: SystemMeta::default(),
            user_meta: vec![("gen".into(), "0".into())],
            acl: None,
            tags: None,
            preconditions: Preconditions::default(),
            max_bytes_limit: MAX_SINGLE_PUT_BYTES,
            raw_sse: RawSseHeaders::default(),
            raw_lock: RawUploadObjectLockHeaders::default(),
        };
        engine
            .put_object(
                put_base.clone(),
                InMemoryVerifiedStream::from_bytes(
                    base_1m.clone(),
                    Some(ChecksumAlgorithm::XxHash128),
                ),
            )
            .await
            .unwrap();
        model
            .put_object(
                put_base,
                InMemoryVerifiedStream::from_bytes(base_1m, Some(ChecksumAlgorithm::XxHash128)),
            )
            .await
            .unwrap();
    }

    async fn read_model_obj(
        store: &ModelStore,
        ctx: &CallerContext,
        key: &str,
        raw_sse: &RawSseHeaders,
    ) -> Option<(String, Bytes)> {
        match store
            .get_object(GetObjectReq {
                ctx: ctx.clone(),
                bucket: "mib-crash".into(),
                key: key.into(),
                version_id: None,
                range: None,
                part_number: None,
                preconditions: Preconditions::default(),
                checksum_mode_enabled: true,
                raw_sse: raw_sse.clone(),
            })
            .await
        {
            Ok(resp) => Some((resp.meta.etag, read_all(resp.reader).await.unwrap())),
            Err(e) if e.code == S3ErrorCode::NoSuchKey => None,
            Err(e) => panic!("unexpected model read error on {key}: {e}"),
        }
    }

    // 1. Sweep mid-syscall cuts across 128 KiB, 1 MiB + 37 B, and 5 MiB + 19 B (SSE-C + SHA512),
    // ending each trial with a large countdown that allows full completion (`ST-1` durability).
    let put_trials: &[(usize, &str, bool, &[usize])] = &[
        (128 * 1024, "obj-128k", false, &[0, 3, 19, 33, 36, 120]),
        (1024 * 1024 + 37, "obj-1m", false, &[1, 17, 140, 275, 450]),
        (
            5 * 1024 * 1024 + 19,
            "obj-5m-ssec",
            true,
            &[0, 7, 135, 650, 1320, 1800],
        ),
    ];

    for (t_idx, &(size, key, use_ssec, countdowns)) in put_trials.iter().enumerate() {
        let last_cd = *countdowns.last().unwrap();
        for &cd in countdowns {
            let payload = make_patterned_payload(size, (t_idx as u8).wrapping_add(cd as u8));
            let sse = if use_ssec {
                ssec_hdrs.clone()
            } else {
                RawSseHeaders::default()
            };
            let put_req = PutObjectReq {
                ctx: ctx.clone(),
                bucket: "mib-crash".into(),
                key: key.into(),
                sys_meta: SystemMeta::default(),
                user_meta: vec![("cd".into(), cd.to_string())],
                acl: None,
                tags: None,
                preconditions: Preconditions::default(),
                max_bytes_limit: MAX_SINGLE_PUT_BYTES,
                raw_sse: sse.clone(),
                raw_lock: RawUploadObjectLockHeaders::default(),
            };

            let model_before = model.clone();
            let model_after = model.clone();
            model_after
                .put_object(
                    put_req.clone(),
                    InMemoryVerifiedStream::from_bytes(
                        payload.clone(),
                        Some(ChecksumAlgorithm::Sha512),
                    ),
                )
                .await
                .unwrap();

            let engine = Engine::open(disk.clone(), cfg.clone()).unwrap();
            disk.arm_mid_io_power_cut(cd);
            let eng_res = engine
                .put_object(
                    put_req,
                    InMemoryVerifiedStream::from_bytes(
                        payload.clone(),
                        Some(ChecksumAlgorithm::Sha512),
                    ),
                )
                .await;
            if cd == last_cd {
                assert!(
                    eng_res.is_ok(),
                    "expected final completion round on {key} cd={cd} to succeed, got {eng_res:?}"
                );
            } else {
                assert!(
                    disk.did_trip_power_cut(),
                    "expected mid-syscall cut to trip on {key} cd={cd}"
                );
            }
            drop(engine);
            disk = disk.power_cut(&mut rng);

            let report = run_fsck(disk.clone());
            assert_eq!(
                report.status, "ok",
                "fsck failed after mid-syscall cut key={key} cd={cd}: {:?}",
                report.errors
            );

            let recovered = Engine::open(disk.clone(), cfg.clone()).unwrap();
            let got_eng = match recovered
                .get_object(GetObjectReq {
                    ctx: ctx.clone(),
                    bucket: "mib-crash".into(),
                    key: key.into(),
                    version_id: None,
                    range: None,
                    part_number: None,
                    preconditions: Preconditions::default(),
                    checksum_mode_enabled: true,
                    raw_sse: sse.clone(),
                })
                .await
            {
                Ok(r) => Some((r.meta.etag, read_all(r.reader).await.unwrap())),
                Err(e) if e.code == S3ErrorCode::NoSuchKey => None,
                Err(e) => panic!("unexpected recovered read error on {key} cd={cd}: {e}"),
            };

            let exp_after = read_model_obj(&model_after, &ctx, key, &sse).await;
            let exp_before = read_model_obj(&model_before, &ctx, key, &sse).await;

            if eng_res.is_ok() {
                // ST-1: 200 OK write MUST equal model_after
                assert_eq!(got_eng, exp_after, "ST-1 violation on {key} cd={cd}");
                model = model_after;
            } else if got_eng == exp_after {
                model = model_after;
            } else {
                assert_eq!(
                    got_eng, exp_before,
                    "ST-3 atomicity violation (torn multi-MiB object!) on {key} cd={cd}"
                );
                model = model_before;
            }
            drop(recovered);
        }
    }

    // 2. Mid-syscall power cut during 2-part 5 MiB + 321 B MultipartUpload
    let p1 = make_patterned_payload(MIN_PART_SIZE_BYTES as usize, 0x71);
    let p2 = make_patterned_payload(321, 0x72);
    for cd in [12usize, 680, 1345, 1800] {
        let model_before = model.clone();
        let model_after = model.clone();
        {
            let m_init = model_after
                .create_multipart_upload(CreateMultipartUploadReq {
                    ctx: ctx.clone(),
                    bucket: "mib-crash".into(),
                    key: "mpu-5m".into(),
                    sys_meta: SystemMeta::default(),
                    user_meta: Vec::new(),
                    acl: None,
                    tags: None,
                    checksum_algorithm: Some(ChecksumAlgorithm::XxHash64),
                    checksum_type: Some(ChecksumType::Composite),
                    raw_sse: RawSseHeaders::default(),
                    raw_lock: RawUploadObjectLockHeaders::default(),
                })
                .await
                .unwrap();
            let mp1 = model_after
                .upload_part(
                    UploadPartReq {
                        ctx: ctx.clone(),
                        bucket: "mib-crash".into(),
                        key: "mpu-5m".into(),
                        upload_id: m_init.upload_id.clone(),
                        part_number: 1,
                        max_bytes_limit: MAX_PART_SIZE_BYTES,
                        raw_sse: RawSseHeaders::default(),
                    },
                    InMemoryVerifiedStream::from_bytes(p1.clone(), Some(ChecksumAlgorithm::XxHash64)),
                )
                .await
                .unwrap();
            let mp2 = model_after
                .upload_part(
                    UploadPartReq {
                        ctx: ctx.clone(),
                        bucket: "mib-crash".into(),
                        key: "mpu-5m".into(),
                        upload_id: m_init.upload_id.clone(),
                        part_number: 2,
                        max_bytes_limit: MAX_PART_SIZE_BYTES,
                        raw_sse: RawSseHeaders::default(),
                    },
                    InMemoryVerifiedStream::from_bytes(p2.clone(), Some(ChecksumAlgorithm::XxHash64)),
                )
                .await
                .unwrap();
            model_after
                .complete_multipart_upload(CompleteMultipartUploadReq {
                    ctx: ctx.clone(),
                    bucket: "mib-crash".into(),
                    key: "mpu-5m".into(),
                    upload_id: m_init.upload_id,
                    parts: vec![
                        CompletePartSpec {
                            part_number: 1,
                            etag: mp1.etag,
                            checksum: mp1.checksum.map(|c| (c.algorithm, c.value_b64)),
                        },
                        CompletePartSpec {
                            part_number: 2,
                            etag: mp2.etag,
                            checksum: mp2.checksum.map(|c| (c.algorithm, c.value_b64)),
                        },
                    ],
                    expected_checksum: None,
                    expected_object_size: None,
                    preconditions: Preconditions::default(),
                    raw_sse: RawSseHeaders::default(),
                })
                .await
                .unwrap();
        }

        let engine = Engine::open(disk.clone(), cfg.clone()).unwrap();
        disk.arm_mid_io_power_cut(cd);
        let mut completed_ok = false;
        if let Ok(e_init) = engine
            .create_multipart_upload(CreateMultipartUploadReq {
                ctx: ctx.clone(),
                bucket: "mib-crash".into(),
                key: "mpu-5m".into(),
                sys_meta: SystemMeta::default(),
                user_meta: Vec::new(),
                acl: None,
                tags: None,
                checksum_algorithm: Some(ChecksumAlgorithm::XxHash64),
                checksum_type: Some(ChecksumType::Composite),
                raw_sse: RawSseHeaders::default(),
                raw_lock: RawUploadObjectLockHeaders::default(),
            })
            .await
            && let Ok(ep1) = engine
                .upload_part(
                    UploadPartReq {
                        ctx: ctx.clone(),
                        bucket: "mib-crash".into(),
                        key: "mpu-5m".into(),
                        upload_id: e_init.upload_id.clone(),
                        part_number: 1,
                        max_bytes_limit: MAX_PART_SIZE_BYTES,
                        raw_sse: RawSseHeaders::default(),
                    },
                    InMemoryVerifiedStream::from_bytes(p1.clone(), Some(ChecksumAlgorithm::XxHash64)),
                )
                .await
            && let Ok(ep2) = engine
                .upload_part(
                    UploadPartReq {
                        ctx: ctx.clone(),
                        bucket: "mib-crash".into(),
                        key: "mpu-5m".into(),
                        upload_id: e_init.upload_id.clone(),
                        part_number: 2,
                        max_bytes_limit: MAX_PART_SIZE_BYTES,
                        raw_sse: RawSseHeaders::default(),
                    },
                    InMemoryVerifiedStream::from_bytes(p2.clone(), Some(ChecksumAlgorithm::XxHash64)),
                )
                .await
        {
            completed_ok = engine
                .complete_multipart_upload(CompleteMultipartUploadReq {
                    ctx: ctx.clone(),
                    bucket: "mib-crash".into(),
                    key: "mpu-5m".into(),
                    upload_id: e_init.upload_id,
                    parts: vec![
                        CompletePartSpec {
                            part_number: 1,
                            etag: ep1.etag,
                            checksum: ep1.checksum.map(|c| (c.algorithm, c.value_b64)),
                        },
                        CompletePartSpec {
                            part_number: 2,
                            etag: ep2.etag,
                            checksum: ep2.checksum.map(|c| (c.algorithm, c.value_b64)),
                        },
                    ],
                    expected_checksum: None,
                    expected_object_size: None,
                    preconditions: Preconditions::default(),
                    raw_sse: RawSseHeaders::default(),
                })
                .await
                .is_ok();
        }
        if cd == 1800 {
            assert!(completed_ok, "expected final mpu-5m round cd={cd} to complete");
        } else {
            assert!(disk.did_trip_power_cut(), "expected mid-syscall cut to trip on mpu-5m cd={cd}");
        }
        drop(engine);
        disk = disk.power_cut(&mut rng);

        let report = run_fsck(disk.clone());
        assert_eq!(report.status, "ok", "fsck errors on mpu-5m cd={cd}: {:?}", report.errors);

        let recovered = Engine::open(disk.clone(), cfg.clone()).unwrap();
        let got_eng = match recovered
            .get_object(GetObjectReq {
                ctx: ctx.clone(),
                bucket: "mib-crash".into(),
                key: "mpu-5m".into(),
                version_id: None,
                range: None,
                part_number: None,
                preconditions: Preconditions::default(),
                checksum_mode_enabled: true,
                raw_sse: RawSseHeaders::default(),
            })
            .await
        {
            Ok(r) => Some((r.meta.etag, read_all(r.reader).await.unwrap())),
            Err(e) if e.code == S3ErrorCode::NoSuchKey => None,
            Err(e) => panic!("unexpected mpu-5m read error cd={cd}: {e}"),
        };
        let exp_after = read_model_obj(&model_after, &ctx, "mpu-5m", &RawSseHeaders::default()).await;
        let exp_before = read_model_obj(&model_before, &ctx, "mpu-5m", &RawSseHeaders::default()).await;
        if completed_ok {
            assert_eq!(got_eng, exp_after);
            model = model_after;
        } else if got_eng == exp_after {
            model = model_after;
        } else {
            assert_eq!(got_eng, exp_before);
            model = model_before;
        }
        drop(recovered);
    }

    // 3. Overwrite obj-1m to create dead extents, then cut power mid-`compact()` and mid-`write_checkpoint()`!
    {
        let engine = Engine::open(disk.clone(), cfg.clone()).unwrap();
        let new_1m = make_patterned_payload(1024 * 1024 + 37, 0x99);
        let req_ow = PutObjectReq {
            ctx: ctx.clone(),
            bucket: "mib-crash".into(),
            key: "obj-1m".into(),
            sys_meta: SystemMeta::default(),
            user_meta: Vec::new(),
            acl: None,
            tags: None,
            preconditions: Preconditions::default(),
            max_bytes_limit: MAX_SINGLE_PUT_BYTES,
            raw_sse: RawSseHeaders::default(),
            raw_lock: RawUploadObjectLockHeaders::default(),
        };
        engine
            .put_object(req_ow.clone(), InMemoryVerifiedStream::from_bytes(new_1m.clone(), None))
            .await
            .unwrap();
        model
            .put_object(req_ow, InMemoryVerifiedStream::from_bytes(new_1m, None))
            .await
            .unwrap();
    }

    for (is_ckpt, cd) in [(false, 1usize), (false, 45), (true, 0), (true, 2), (true, 6)] {
        let engine = Engine::open(disk.clone(), cfg.clone()).unwrap();
        disk.arm_mid_io_power_cut(cd);
        if is_ckpt {
            let _ = engine.write_checkpoint().await;
        } else {
            let _ = engine.compact().await;
        }
        drop(engine);
        disk = disk.power_cut(&mut rng);

        let report = run_fsck(disk.clone());
        assert_eq!(
            report.status, "ok",
            "fsck failed after mid-{} cd={cd}: {:?}",
            if is_ckpt { "checkpoint" } else { "compact" },
            report.errors
        );

        let recovered = Engine::open(disk.clone(), cfg.clone()).unwrap();
        for (key, sse) in [
            ("obj-128k", RawSseHeaders::default()),
            ("obj-1m", RawSseHeaders::default()),
            ("obj-5m-ssec", ssec_hdrs.clone()),
            ("mpu-5m", RawSseHeaders::default()),
        ] {
            let exp = read_model_obj(&model, &ctx, key, &sse).await.unwrap();
            let got = recovered
                .get_object(GetObjectReq {
                    ctx: ctx.clone(),
                    bucket: "mib-crash".into(),
                    key: key.into(),
                    version_id: None,
                    range: None,
                    part_number: None,
                    preconditions: Preconditions::default(),
                    checksum_mode_enabled: true,
                    raw_sse: sse,
                })
                .await
                .unwrap();
            assert_eq!(got.meta.etag, exp.0, "etag mismatch on {key}");
            assert_eq!(read_all(got.reader).await.unwrap(), exp.1, "data mismatch on {key}");
        }
        drop(recovered);
    }
}

/// Non-ignored regression test for seed `0xD3AD_001F` (caught by `VR-3` 100k mid-syscall power-cut gate):
/// When power cuts during `write_checkpoint()`'s post-checkpoint WAL pruning before `sync_dir("wal")`,
/// POSIX/ext4 directory entry reordering may persist `unlink("wal/00000002.log")` while dropping
/// `unlink("wal/00000001.log")`. Because both `00000001.log` and `00000002.log` are strictly covered
/// by the already-durable checkpoint (`first_lsn_of_00000003 <= ckpt_lsn + 1`), recovery and `fsck`
/// must tolerate the pre-checkpoint gap and finish pruning the obsolete pre-checkpoint WAL file.
#[tokio::test]
async fn vr3_regression_seed_0xd3ad001f_interrupted_wal_prune_dir_reorder() {
    run_power_cut_chain(0xD3AD_001F, 50).await;
}
