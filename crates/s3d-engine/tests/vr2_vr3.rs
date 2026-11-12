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
];
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
    },
    DeleteMulti {
        u: u8,
        b: u8,
        keys: Vec<(u8, Option<u8>, bool)>,
        quiet: bool,
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
        )
            .prop_map(|(u, b, ownership, canned_acl)| ModelOp::CreateBucket {
                u,
                b,
                ownership,
                canned_acl,
            }),
        1 => (user_strategy(), 0u8..3).prop_map(|(u, b)| ModelOp::DeleteBucket { u, b }),
        2 => (user_strategy(), 0u8..2, any::<bool>())
            .prop_map(|(u, b, enabled)| ModelOp::SetVersioning { u, b, enabled }),
        1 => (user_strategy(), 0u8..2).prop_map(|(u, b)| ModelOp::GetVersioning { u, b }),
        6 => (
            user_strategy(),
            0u8..3,
            0u8..6,
            prop_oneof![Just(0usize), Just(1), Just(4095), Just(4096), Just(8192), Just(17_000)],
            any::<u8>(),
            0u8..6,
            prop::bool::weighted(0.1),
            prop::bool::weighted(0.2),
            opt_canned_strategy(),
            opt_tag_slot(),
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
        )
            .prop_map(|(u, b, k, ver_slot, if_match_star)| ModelOp::Delete {
                u,
                b,
                k,
                ver_slot,
                if_match_star,
            }),
        2 => (
            user_strategy(),
            0u8..2,
            prop::collection::vec((0u8..6, opt_ver_slot(), prop::bool::weighted(0.2)), 1..=4),
            any::<bool>(),
        )
            .prop_map(|(u, b, keys, quiet)| ModelOp::DeleteMulti { u, b, keys, quiet }),
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
            0u8..6,
            any::<bool>(),
            opt_tag_slot(),
        )
            .prop_map(
                |(u, b, k, csum_idx, full_obj_csum, tag_slot)| ModelOp::MpuCreate {
                    u,
                    b,
                    k,
                    csum_idx,
                    full_obj_csum,
                    tag_slot,
                },
            ),
        4 => (
            user_strategy(),
            0u8..4,
            prop_oneof![Just(1u32), Just(2u32), Just(3u32), Just(0u32)],
            prop_oneof![Just(0usize), Just(64), Just(4096), Just(9000)],
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
    let disk = FaultDisk::new();
    let eng_cfg = EngineConfig {
        segment_size: 32 * 1024,
        wal_file_size: 16 * 1024,
        max_block_payload: 8 * 1024,
        default_object_ownership: ObjectOwnership::ObjectWriter,
        ..EngineConfig::default()
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
            } => {
                let req = CreateBucketReq {
                    ctx: test_caller(u, clock_ms),
                    bucket: BUCKET_POOL[b as usize].to_string(),
                    location_constraint: None,
                    object_ownership: ownership,
                    acl: canned_acl.map(|i| AclSpec::Canned(CANNED_ACL_POOL[i as usize])),
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
            } => {
                let payload: Vec<u8> = (0..size).map(|i| seed.wrapping_add(i as u8)).collect();
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
                };
                let make_stream = || {
                    let s = InMemoryVerifiedStream::from_bytes(Bytes::from(payload.clone()), alg);
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
                    })
                    .await;
                let rm = model
                    .delete_object(DeleteObjectReq {
                        ctx,
                        bucket: BUCKET_POOL[b as usize].to_string(),
                        key: KEY_POOL[k as usize].to_string(),
                        version_id: mv,
                        if_match,
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
            ModelOp::DeleteMulti { u, b, keys, quiet } => {
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
                    })
                    .await;
                let rm = model
                    .delete_objects(DeleteObjectsReq {
                        ctx,
                        bucket: BUCKET_POOL[b as usize].to_string(),
                        quiet,
                        items: m_items,
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
                let payload: Vec<u8> = (0..size).map(|i| seed.wrapping_add(i as u8)).collect();
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
                        },
                        InMemoryVerifiedStream::from_bytes(Bytes::from(payload.clone()), None),
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
                        },
                        InMemoryVerifiedStream::from_bytes(Bytes::from(payload), None),
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
            ModelOp::Compact => {
                engine.compact().await.unwrap();
            }
        }
    }

    drop(engine);
    let report = run_fsck(disk);
    assert_eq!(report.status, "ok", "fsck errors: {:?}", report.errors);
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(250))]
    #[test]
    fn vr2_differential_engine_vs_model(ops in prop::collection::vec(op_strategy(), 1..40)) {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(run_differential_sequence(ops));
    }
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
    let workers = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(8)
        .max(4);
    let completed = Arc::new(AtomicUsize::new(0));

    let mut handles = Vec::with_capacity(workers);
    for tid in 0..workers {
        let cases_for_worker = TOTAL_CASES / workers + usize::from(tid < TOTAL_CASES % workers);
        let completed = Arc::clone(&completed);
        handles.push(std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            let mut seed = [0u8; 32];
            seed[0..8].copy_from_slice(&(0x5333_2026_0000u64 + tid as u64).to_le_bytes());
            let rng = TestRng::from_seed(RngAlgorithm::ChaCha, &seed);
            let cfg = ProptestConfig {
                cases: cases_for_worker as u32,
                max_shrink_iters: 256,
                ..ProptestConfig::default()
            };
            let mut runner = TestRunner::new_with_rng(cfg, rng);
            let strategy = prop::collection::vec(op_strategy(), 1..25);
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
    assert_eq!(total, TOTAL_CASES);
    eprintln!("VR-2 M1 gate passed: {total} proptest sequences executed, 0 diffs.");
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

    // Unversioned ground truth: key -> Option<Vec<u8>>
    let mut confirmed_unver: BTreeMap<String, Option<Vec<u8>>> = BTreeMap::new();
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

        // Simulate a crashed in-flight checkpoint write in `tmp/` (`ST-8`)
        if rng.gen_bool(0.3)
            && let Ok(tf) = disk.open("tmp/ckpt-inflight.tmp", OpenOpts::create_truncate_rw()) {
                let _ = tf.write_all_at(0, b"S3DCKP01-partial-uncommitted");
            }

        // Inject un-fsynced dirty tail writes onto active WAL and active segment right before power cut
        // to simulate an in-flight crashed write tearing across 4 KiB sectors! (ST-3, ST-6)
        if rng.gen_bool(0.6) {
            if let Ok(wal_files) = disk.read_dir("wal")
                && let Some(last_wal) = wal_files.last()
                    && let Ok(wf) = disk.open(&format!("wal/{last_wal}"), OpenOpts::open_rw()) {
                        let pos = wf.len().unwrap();
                        let mut junk = vec![0u8; rng.gen_range(5..6000)];
                        rng.fill(&mut junk[..]);
                        junk[0..4]
                            .copy_from_slice(&s3d_engine::format::WAL_RECORD_MAGIC.to_le_bytes());
                        let _ = wf.write_all_at(pos, &junk);
                    }
            if let Ok(seg_files) = disk.read_dir("seg")
                && let Some(last_seg) = seg_files.last()
                    && let Ok(sf) = disk.open(&format!("seg/{last_seg}"), OpenOpts::open_rw()) {
                        let pos = sf.len().unwrap();
                        let mut junk = vec![0u8; rng.gen_range(16..5000)];
                        rng.fill(&mut junk[..]);
                        let _ = sf.write_all_at(pos, &junk);
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
