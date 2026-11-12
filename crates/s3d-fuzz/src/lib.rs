//! Shared fuzz target harnesses (`VR-7`, `04-verification.md` §4.3) invoked by both
//! `fuzz/fuzz_targets/*.rs` (`cargo-fuzz` / `libfuzzer-sys`) and `crates/s3d-fuzz`
//! (parallel multi-hour workspace fuzz runner).

use std::collections::BTreeSet;
use std::sync::OnceLock;

use base64::Engine as _;
use bytes::BytesMut;
use http::{HeaderMap, HeaderName, HeaderValue, Method};
use s3d_disk::{Disk, OpenOpts, FaultDisk};
use s3d_engine::catalog::{BucketEntry, MemoryCatalog, ObjectVersionEntry};
use s3d_engine::checkpoint::write_checkpoint_to_file;
use s3d_engine::format::{
    decode_block_header, decode_wal_header, decode_wal_record, encode_wal_record,
    has_later_committed_record, verify_seg_header, FormatFile, WalOp, FORMAT_FILE_LEN,
    FORMAT_VERSION, WAL_RECORD_MAGIC,
};
use s3d_engine::{decode_checkpoint_bytes, decode_continuation_token, encode_continuation_token};
use s3d_proto::{
    aws_uri_encode, parse_acl_grant_header, parse_acl_xml, parse_and_verify_post_object,
    parse_bucket_versioning_xml, parse_complete_multipart_xml, parse_content_md5_header,
    parse_cors_xml, parse_create_bucket_xml, parse_delete_objects_xml,
    parse_http_or_rfc2822_date_ms, parse_iso8601_compact_ms, parse_multipart_boundary,
    parse_ownership_controls_xml, parse_public_access_block_xml, parse_s3_uri,
    parse_tagging_header, parse_tagging_xml, AwsChunkedDecoder, SigV4Verifier,
    StreamingDigestVerifier,
};
use s3d_server::router::parse_copy_source_range;
use s3d_types::{
    AccessControlPolicy, AccountRecord, BucketPolicyDoc, ChecksumAlgorithm, ChecksumState,
    ChecksumType, ObjectOwnership, OwnerInfo, ParsedRangeHeader, SecretKey, SystemMeta,
    VersioningStatus, parse_range_header,
};

fn shared_verifier() -> &'static SigV4Verifier {
    static VERIFIER: OnceLock<SigV4Verifier> = OnceLock::new();
    VERIFIER.get_or_init(|| {
        SigV4Verifier::new(
            "us-east-1",
            vec![AccountRecord {
                access_key: "AKIAIOSFODNN7EXAMPLE".to_string(),
                secret_key: SecretKey::new(
                    "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".to_string(),
                ),
                owner: OwnerInfo {
                    user_id: "0123456789abcdef".to_string(),
                    display_name: "fuzz".to_string(),
                    email: "fuzz@example.com".to_string(),
                },
            }],
        )
    })
}

/// 1. `fuzz_auth_header`: `Authorization` header lexing, date parsing, and credential verification.
pub fn fuzz_auth_header(data: &[u8]) {
    if data.len() > 64 * 1024 {
        return;
    }
    let verifier = shared_verifier();
    let uri = parse_s3_uri(Some("127.0.0.1:9000"), "/fuzz-bkt/obj", "").unwrap();
    let mut headers = HeaderMap::new();
    headers.insert("host", HeaderValue::from_static("127.0.0.1:9000"));
    if let Ok(hv) = HeaderValue::from_bytes(data) {
        headers.insert("authorization", hv);
    }
    if data.len() >= 16 {
        if let Ok(hv) = HeaderValue::from_bytes(&data[..16]) {
            headers.insert("x-amz-date", hv);
        }
    } else {
        headers.insert("x-amz-date", HeaderValue::from_static("20261112T000000Z"));
    }
    headers.insert(
        "x-amz-content-sha256",
        HeaderValue::from_static("UNSIGNED-PAYLOAD"),
    );
    let _ = verifier.verify_request(&Method::GET, &uri, &headers, 1_794_441_600_000);

    if let Ok(s) = std::str::from_utf8(data) {
        let _ = parse_iso8601_compact_ms(s);
        let _ = parse_http_or_rfc2822_date_ms(s);
        let _ = parse_content_md5_header(s);
    }
}

/// 2. `fuzz_canonical_request`: Arbitrary HTTP URI/query/headers -> SigV4 canonical request & presign.
pub fn fuzz_canonical_request(data: &[u8]) {
    if data.is_empty() || data.len() > 64 * 1024 {
        return;
    }
    let method = match data[0] % 5 {
        0 => Method::GET,
        1 => Method::PUT,
        2 => Method::HEAD,
        3 => Method::DELETE,
        _ => Method::POST,
    };
    let rest = &data[1..];
    let mut parts = rest.splitn(4, |&b| b == 0);
    let raw_path = String::from_utf8_lossy(parts.next().unwrap_or(b"/"));
    let raw_query = parts.next().map(|q| String::from_utf8_lossy(q).into_owned());
    let raw_host = parts.next().map(|h| String::from_utf8_lossy(h).into_owned());
    let raw_hdr_blob = parts.next().unwrap_or(b"");

    let _ = aws_uri_encode(&raw_path, true);
    let _ = aws_uri_encode(&raw_path, false);

    let base_domain = if data[0] & 0x80 != 0 { "s3.local" } else { "" };
    let full_uri = match &raw_query {
        Some(q) if !q.is_empty() => format!("{raw_path}?{q}"),
        _ => raw_path.into_owned(),
    };
    let Ok(parsed_uri) = parse_s3_uri(raw_host.as_deref(), &full_uri, base_domain) else {
        return;
    };

    let mut headers = HeaderMap::new();
    if let Some(h) = &raw_host
        && let Ok(hv) = HeaderValue::from_str(h) {
            headers.insert("host", hv);
        }
    for line in raw_hdr_blob.split(|&b| b == b'\n').take(32) {
        if let Some(colon) = line.iter().position(|&b| b == b':')
            && let (Ok(hn), Ok(hv)) = (
                HeaderName::from_bytes(&line[..colon]),
                HeaderValue::from_bytes(&line[colon + 1..]),
            ) {
                headers.append(hn, hv);
            }
    }

    let _ = shared_verifier().verify_request(&method, &parsed_uri, &headers, 1_794_441_600_000);
}

/// 3. `fuzz_aws_chunked`: Streaming `aws-chunked` state machine + trailer decoding across random chunk splits.
pub fn fuzz_aws_chunked(data: &[u8]) {
    if data.len() < 4 || data.len() > 256 * 1024 {
        return;
    }
    let mode = data[0] % 3;
    let step = (data[1] as usize % 64).max(1);
    let declared_len = (u16::from_le_bytes([data[2], data[3]]) as u64).min(128 * 1024);
    let wire = &data[4..];

    let (mut dec, mut ver) = match mode {
        0 => (
            AwsChunkedDecoder::new_signed(
                [0x42; 32],
                "20261112T000000Z".into(),
                "20261112/us-east-1/s3/aws4_request".into(),
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".into(),
                declared_len,
                None,
            ),
            StreamingDigestVerifier::new(Some(declared_len), None, None, None),
        ),
        1 => (
            AwsChunkedDecoder::new_signed(
                [0x42; 32],
                "20261112T000000Z".into(),
                "20261112/us-east-1/s3/aws4_request".into(),
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".into(),
                declared_len,
                Some("x-amz-checksum-crc32c".into()),
            ),
            StreamingDigestVerifier::new(
                Some(declared_len),
                None,
                None,
                Some((ChecksumAlgorithm::Crc32c, None)),
            ),
        ),
        _ => (
            AwsChunkedDecoder::new_unsigned_trailer(
                declared_len,
                "x-amz-checksum-crc64nvme".into(),
            ),
            StreamingDigestVerifier::new(
                Some(declared_len),
                None,
                None,
                Some((ChecksumAlgorithm::Crc64Nvme, None)),
            ),
        ),
    };

    let mut out = BytesMut::new();
    for slice in wire.chunks(step) {
        if dec.push_wire_bytes(slice, &mut ver, &mut out).is_err() {
            return;
        }
        out.clear();
    }
    if dec.verify_eof().is_ok() {
        let _ = ver.finish();
    }
}

fn contains_xxe_directive(raw: &[u8]) -> bool {
    raw.windows(9)
        .any(|w| w.eq_ignore_ascii_case(b"<!DOCTYPE"))
        || raw.windows(8).any(|w| w.eq_ignore_ascii_case(b"<!ENTITY"))
}

/// 4. `fuzz_xml_requests`: All S3 XML request body parsers + XXE rejection oracle (`NFR-8`) + BucketPolicy JSON.
pub fn fuzz_xml_requests(data: &[u8]) {
    if data.len() > 2_200_000 {
        return;
    }
    let has_xxe = contains_xxe_directive(data);

    let r1 = parse_create_bucket_xml(data);
    let r2 = parse_delete_objects_xml(data);
    let r3 = parse_bucket_versioning_xml(data);
    let r4 = parse_complete_multipart_xml(data);
    let r5 = parse_acl_xml(data, |_| None, |_| None);
    let r6 = parse_ownership_controls_xml(data);
    let r7 = parse_tagging_xml(data, 50);
    let r8 = parse_cors_xml(data);
    let r9 = parse_public_access_block_xml(data);

    // Live security oracle (`NFR-8`): any `<!DOCTYPE` or `<!ENTITY` MUST be rejected!
    if has_xxe {
        assert!(
            r1.is_err() || data.iter().all(|b| b.is_ascii_whitespace()),
            "XXE bypass in parse_create_bucket_xml!"
        );
        assert!(r2.is_err(), "XXE bypass in parse_delete_objects_xml!");
        assert!(r3.is_err(), "XXE bypass in parse_bucket_versioning_xml!");
        assert!(r4.is_err(), "XXE bypass in parse_complete_multipart_xml!");
        assert!(r5.is_err(), "XXE bypass in parse_acl_xml!");
        assert!(r6.is_err(), "XXE bypass in parse_ownership_controls_xml!");
        assert!(r7.is_err(), "XXE bypass in parse_tagging_xml!");
        assert!(r8.is_err(), "XXE bypass in parse_cors_xml!");
        assert!(r9.is_err(), "XXE bypass in parse_public_access_block_xml!");
    }

    if let Ok(s) = std::str::from_utf8(data) {
        let _ = parse_tagging_header(s, 10);
        let id_fn = |_: &str| None;
        let email_fn = |_: &str| None;
        let _ = parse_acl_grant_header(s, s3d_types::AclPermission::Read, &id_fn, &email_fn);
        let _ = BucketPolicyDoc::parse_and_validate(s, "fuzz-bkt");
    }
}

/// 5. `fuzz_range_header`: `Range` and `x-amz-copy-source-range` parsing + resolution oracle.
pub fn fuzz_range_header(data: &[u8]) {
    if data.len() > 16 * 1024 {
        return;
    }
    let (obj_size, raw_bytes) = if data.len() >= 8 {
        (
            u64::from_le_bytes(data[0..8].try_into().unwrap()),
            &data[8..],
        )
    } else {
        (4096u64, data)
    };
    let s = String::from_utf8_lossy(raw_bytes);
    if let ParsedRangeHeader::Single(spec) = parse_range_header(&s) {
        for sz in [0u64, 1, 4096, obj_size, u64::MAX] {
            if let Ok((start, end)) = spec.resolve(sz) {
                assert!(start <= end && end < sz, "invalid resolved range ({start}, {end}) for size {sz}");
            }
        }
    }
    if let Ok((cs, ce)) = parse_copy_source_range(&s) {
        assert!(cs <= ce, "copy-source-range start > end");
    }
}

/// 6. `fuzz_continuation_token`: `ListObjectsV2` / `ListBuckets` cursor decoding & round-trip check.
pub fn fuzz_continuation_token(data: &[u8]) {
    if data.len() > 16 * 1024 {
        return;
    }
    let s = String::from_utf8_lossy(data);
    let _ = decode_continuation_token("fuzz-bkt", &s);
    let _ = decode_continuation_token("__buckets__", &s);

    if let Some((bkt, rest)) = s.split_once(':') {
        let _ = decode_continuation_token(bkt, rest);
        if bkt.len() <= 63 && !bkt.contains(':') && rest.len() <= 1024 {
            let tok = encode_continuation_token(bkt, rest);
            assert_eq!(
                decode_continuation_token(bkt, &tok).unwrap(),
                rest,
                "continuation token round-trip mismatch"
            );
        }
    }
}

/// 7. `fuzz_post_policy`: HTML Form `PostObject` Base64 JSON Policy & `multipart/form-data` boundary parser.
pub fn fuzz_post_policy(data: &[u8]) {
    if data.is_empty() || data.len() > 128 * 1024 {
        return;
    }
    let (ct_raw, body) = match data.iter().position(|&b| b == b'\n') {
        Some(pos) if pos <= 512 => (&data[..pos], &data[pos + 1..]),
        _ => (b"multipart/form-data; boundary=BOUNDARY".as_slice(), data),
    };
    let ct = String::from_utf8_lossy(ct_raw);
    let _ = parse_multipart_boundary(&ct);
    let _ = parse_and_verify_post_object(
        shared_verifier(),
        "fuzz-bkt",
        &ct,
        bytes::Bytes::copy_from_slice(body),
        1_794_441_600_000,
    );

    // Also fuzz raw Base64 policy wrapped inside a minimal valid multipart skeleton so deep JSON policy code runs!
    if data.len() <= 8192 {
        let b64 = base64::engine::general_purpose::STANDARD.encode(data);
        let synth = format!(
            "--B\r\nContent-Disposition: form-data; name=\"key\"\r\n\r\nk\r\n--B\r\nContent-Disposition: form-data; name=\"policy\"\r\n\r\n{b64}\r\n--B\r\nContent-Disposition: form-data; name=\"x-amz-algorithm\"\r\n\r\nAWS4-HMAC-SHA256\r\n--B\r\nContent-Disposition: form-data; name=\"x-amz-credential\"\r\n\r\nAKIAIOSFODNN7EXAMPLE/20261112/us-east-1/s3/aws4_request\r\n--B\r\nContent-Disposition: form-data; name=\"x-amz-date\"\r\n\r\n20261112T000000Z\r\n--B\r\nContent-Disposition: form-data; name=\"x-amz-signature\"\r\n\r\n0000000000000000000000000000000000000000000000000000000000000000\r\n--B\r\nContent-Disposition: form-data; name=\"file\"; filename=\"a.txt\"\r\n\r\nhi\r\n--B--\r\n"
        );
        let _ = parse_and_verify_post_object(
            shared_verifier(),
            "fuzz-bkt",
            "multipart/form-data; boundary=B",
            bytes::Bytes::from(synth),
            1_794_441_600_000,
        );
    }
}

/// 8. `fuzz_wal_ckpt_decode`: Format/Segment/Block/WAL/Checkpoint binary decoders, both raw & CRC-repaired!
pub fn fuzz_wal_ckpt_decode(data: &[u8]) {
    if data.is_empty() || data.len() > 128 * 1024 {
        return;
    }

    if data.len() >= FORMAT_FILE_LEN {
        let hdr: [u8; FORMAT_FILE_LEN] = data[..FORMAT_FILE_LEN].try_into().unwrap();
        let _ = FormatFile::decode(&hdr);
    }
    if data.len() >= 32 {
        let hdr32: [u8; 32] = data[..32].try_into().unwrap();
        let _ = verify_seg_header(&hdr32, 1, 0x1122_3344_5566_7788);
        let _ = decode_wal_header(&hdr32, 1, 0x1122_3344_5566_7788);
    }
    if data.len() >= 12 {
        let hdr12: [u8; 12] = data[..12].try_into().unwrap();
        let _ = decode_block_header(&hdr12);
    }

    // 8a. Raw WAL + Checkpoint decode
    let _ = decode_wal_record(data);
    let _ = has_later_committed_record(data, 1);
    let _ = decode_checkpoint_bytes(data, None);

    // 8b. CRC-repaired WAL frame so fuzzer reaches deep inside `WalOp` payload deserialization
    if data.len() >= 20 && data.len() <= 16 * 1024 {
        let body_len = data.len() as u32;
        let mut frame = Vec::with_capacity(12 + data.len());
        frame.extend_from_slice(&WAL_RECORD_MAGIC.to_le_bytes());
        frame.extend_from_slice(&body_len.to_le_bytes());
        frame.extend_from_slice(&0u32.to_le_bytes());
        frame.extend_from_slice(data);
        let mut crc = crc32c::crc32c(&frame[0..8]);
        crc = crc32c::crc32c_append(crc, &frame[12..]);
        frame[8..12].copy_from_slice(&crc.to_le_bytes());
        let _ = decode_wal_record(&frame);
    }

    // 8c. CRC-repaired `S3DCKP01`..`S3DCKEND` checkpoint frame wrapping fuzzed inner payload bytes
    //     so fuzzer reaches deep inside `ChunkedCkptReader` and catalog snapshot deserializers!
    if data.len() <= 16 * 1024 {
        let total_len = (64 + 8 + data.len() + 4 + 32) as u64;
        let mut ckpt = Vec::with_capacity(total_len as usize);
        // 64-byte header
        ckpt.extend_from_slice(b"S3DCKP01");
        ckpt.extend_from_slice(&FORMAT_VERSION.to_le_bytes());
        ckpt.extend_from_slice(&0u32.to_le_bytes());
        ckpt.extend_from_slice(&0x1122_3344_5566_7788u64.to_le_bytes()); // uuid_lo
        ckpt.extend_from_slice(&10u64.to_le_bytes()); // ckpt_lsn
        ckpt.extend_from_slice(&20u64.to_le_bytes()); // next_seq
        ckpt.extend_from_slice(&2u32.to_le_bytes()); // next_seg_id
        ckpt.extend_from_slice(&(data[0] as u32 % 4).to_le_bytes()); // bucket_count
        ckpt.extend_from_slice(&[0u8; 12]); // reserved
        let hdr_crc = crc32c::crc32c(&ckpt[0..60]);
        ckpt.extend_from_slice(&hdr_crc.to_le_bytes());

        // Single chunk (`S3CK` | len | payload | chunk_crc)
        ckpt.extend_from_slice(&0x5333_434Bu32.to_le_bytes());
        ckpt.extend_from_slice(&(data.len() as u32).to_le_bytes());
        ckpt.extend_from_slice(data);
        let chunk_crc = crc32c::crc32c(&ckpt[64..64 + 8 + data.len()]);
        ckpt.extend_from_slice(&chunk_crc.to_le_bytes());

        // 32-byte footer (`S3DCKEND` | total_bytes | ckpt_lsn | total_crc | reserved)
        let total_crc = crc32c::crc32c(&ckpt);
        ckpt.extend_from_slice(b"S3DCKEND");
        ckpt.extend_from_slice(&total_len.to_le_bytes());
        ckpt.extend_from_slice(&10u64.to_le_bytes());
        ckpt.extend_from_slice(&total_crc.to_le_bytes());
        ckpt.extend_from_slice(&0u32.to_le_bytes());

        let _ = decode_checkpoint_bytes(&ckpt, None);
    }
}

/// Build rich initial seed corpora for each of the 8 fuzz targets (including valid WAL & checkpoint bytes,
/// XXE payloads, 12,000-deep nested XML tags, signed headers, presigned URLs, and multipart forms).
pub fn initial_seed_corpus(target_name: &str) -> Vec<Vec<u8>> {
    match target_name {
        "fuzz_auth_header" => vec![
            b"AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20261112/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_vec(),
            b"AWS AKIAIOSFODNN7EXAMPLE:sigv2".to_vec(),
            b"20261112T123456Z".to_vec(),
            b"Wed, 12 Nov 2026 12:34:56 GMT".to_vec(),
        ],
        "fuzz_canonical_request" => vec![
            b"\x01/my-bkt/dir//a+b%20c\0list-type=2&prefix=a%2Fb&max-keys=10\x00127.0.0.1:9000\0x-amz-date:20261112T000000Z\nx-amz-content-sha256:UNSIGNED-PAYLOAD\n".to_vec(),
            b"\x80/key\0X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIA%2F20261112%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20261112T000000Z&X-Amz-Expires=300&X-Amz-SignedHeaders=host&X-Amz-Signature=deadbeef\0mybkt.s3.local\0".to_vec(),
        ],
        "fuzz_aws_chunked" => vec![
            b"\x00\x10\x05\x005;chunk-signature=0000000000000000000000000000000000000000000000000000000000000000\r\nhello\r\n0;chunk-signature=0000000000000000000000000000000000000000000000000000000000000000\r\n\r\n".to_vec(),
            b"\x02\x07\x04\x004\r\ntest\r\n0\r\nx-amz-checksum-crc64nvme:AAAAAAAAAAA=\r\n\r\n".to_vec(),
        ],
        "fuzz_xml_requests" => {
            let mut deep_xml = Vec::with_capacity(75_000);
            for _ in 0..12_000 {
                deep_xml.extend_from_slice(b"<a>");
            }
            for _ in 0..12_000 {
                deep_xml.extend_from_slice(b"</a>");
            }
            vec![
                b"<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><Delete><Object><Key>&xxe;</Key></Object></Delete>".to_vec(),
                deep_xml,
                b"<Delete><Quiet>true</Quiet><Object><Key>k1</Key><ETag>\"abc\"</ETag></Object></Delete>".to_vec(),
                b"<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>\"0123456789abcdef0123456789abcdef\"</ETag></Part></CompleteMultipartUpload>".to_vec(),
                b"<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>".to_vec(),
                b"<Tagging><TagSet><Tag><Key>env</Key><Value>prod</Value></Tag></TagSet></Tagging>".to_vec(),
                b"<CORSConfiguration><CORSRule><AllowedOrigin>*</AllowedOrigin><AllowedMethod>GET</AllowedMethod></CORSRule></CORSConfiguration>".to_vec(),
                b"<PublicAccessBlockConfiguration><BlockPublicAcls>true</BlockPublicAcls></PublicAccessBlockConfiguration>".to_vec(),
                b"{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"s3:GetObject\",\"Resource\":\"arn:aws:s3:::fuzz-bkt/*\"}]}".to_vec(),
            ]
        }
        "fuzz_range_header" => vec![
            b"\x00\x10\x00\x00\x00\x00\x00\x00bytes=0-499".to_vec(),
            b"\x00\x10\x00\x00\x00\x00\x00\x00bytes=-500".to_vec(),
            b"\x00\x10\x00\x00\x00\x00\x00\x00bytes=9500-".to_vec(),
            b"\xff\xff\xff\xff\xff\xff\xff\xffbytes=0-18446744073709551615".to_vec(),
        ],
        "fuzz_continuation_token" => vec![
            format!("fuzz-bkt:{}", encode_continuation_token("fuzz-bkt", "dir/key-001")).into_bytes(),
            b"__buckets__:djE6X19idWNrZXRzX186bXktYmt0".to_vec(),
        ],
        "fuzz_post_policy" => vec![
            b"multipart/form-data; boundary=BOUND\n--BOUND\r\nContent-Disposition: form-data; name=\"key\"\r\n\r\nhello.txt\r\n--BOUND\r\nContent-Disposition: form-data; name=\"file\"; filename=\"hello.txt\"\r\nContent-Type: text/plain\r\n\r\nworld\r\n--BOUND--\r\n".to_vec(),
            b"{\"expiration\":\"2030-01-01T00:00:00Z\",\"conditions\":[{\"bucket\":\"fuzz-bkt\"},[\"starts-with\",\"$key\",\"user/\"],[\"content-length-range\",0,1048576]]}".to_vec(),
        ],
        "fuzz_wal_ckpt_decode" => {
            let mut wal_seed = Vec::new();
            let owner = OwnerInfo {
                user_id: "0123456789abcdef".into(),
                display_name: "seed".into(),
                email: "seed@example.com".into(),
            };
            let acl = AccessControlPolicy {
                owner: owner.clone(),
                grants: Vec::new(),
            };
            encode_wal_record(
                1,
                0,
                &WalOp::CreateBucket {
                    name: "seed-bkt".into(),
                    owner: owner.clone(),
                    acl: acl.clone(),
                    region: "us-east-1".into(),
                    created_ms: 1_700_000_000_000,
                    explicit_ownership: Some(ObjectOwnership::BucketOwnerEnforced),
                },
                &mut wal_seed,
            );

            // Real encoded checkpoint seed!
            let disk = FaultDisk::new();
            let cf = disk.open("seed.ckpt", OpenOpts::create_truncate_rw()).unwrap();
            let mut cat = MemoryCatalog {
                next_seq: 5,
                buckets: Default::default(),
            };
            let mut bkt = BucketEntry {
                name: "seed-bkt".into(),
                owner: owner.clone(),
                acl: acl.clone(),
                region: "us-east-1".into(),
                created_ms: 1_700_000_000_000,
                versioning: VersioningStatus::Enabled,
                explicit_ownership: Some(ObjectOwnership::ObjectWriter),
                tags: Default::default(),
                cors: None,
                policy: None,
                public_access_block: None,
                objects: Default::default(),
                uploads: Default::default(),
                completed_uploads: Default::default(),
            };
            bkt.objects.insert(
                "k1".into(),
                vec![ObjectVersionEntry {
                    seq: 1,
                    version_id: Some("v1".into()),
                    is_delete_marker: false,
                    total_size: 0,
                    etag: "\"d41d8cd98f00b204e9800998ecf8427e\"".into(),
                    checksum: ChecksumState {
                        algorithm: ChecksumAlgorithm::Crc64Nvme,
                        checksum_type: ChecksumType::FullObject,
                        value_b64: "AAAAAAAAAAA=".into(),
                        client_requested: false,
                    },
                    sys_meta: std::sync::Arc::new(SystemMeta::default()),
                    user_meta: vec![("k".into(), "v".into())],
                    owner: std::sync::Arc::new(owner),
                    acl: std::sync::Arc::new(acl),
                    tags: Default::default(),
                    last_modified_ms: 1_700_000_000_000,
                    extents: Vec::new().into(),
                    parts: None,
                }],
            );
            cat.buckets.insert("seed-bkt".into(), bkt);
            let mut live = BTreeSet::new();
            live.insert(1);
            write_checkpoint_to_file(&cf, 0x1122_3344_5566_7788, 10, 5, 2, &live, &cat).unwrap();
            let len = s3d_disk::DiskFile::len(&cf).unwrap() as usize;
            let mut ckpt_seed = vec![0u8; len];
            s3d_disk::DiskFile::read_exact_at(&cf, 0, &mut ckpt_seed).unwrap();

            vec![wal_seed, ckpt_seed]
        }
        _ => vec![b"seed".to_vec()],
    }
}
