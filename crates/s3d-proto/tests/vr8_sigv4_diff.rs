use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, UNIX_EPOCH};

use aws_credential_types::Credentials;
use aws_sigv4::http_request::{
    sign, PayloadChecksumKind, PercentEncodingMode, SignableBody, SignableRequest,
    SignatureLocation, SigningSettings, UriPathNormalizationMode,
};
use aws_sigv4::sign::v4;
use http::{HeaderMap, HeaderName, HeaderValue, Method};
use rand::rngs::StdRng;
use rand::seq::SliceRandom;
use rand::{Rng, SeedableRng};
use s3d_proto::{aws_uri_encode, parse_s3_uri, SigV4Verifier};
use s3d_types::{AccountRecord, OwnerInfo, SecretKey};
use serde::{Deserialize, Serialize};

#[derive(Serialize)]
struct BotocoreSignInput {
    mode: String,
    method: String,
    url: String,
    headers: Vec<(String, String)>,
    body_sha256: String,
    access_key: String,
    secret_key: String,
    region: String,
    timestamp: String,
    expires: u64,
}

#[derive(Deserialize)]
struct BotocoreSignOutput {
    url: String,
    headers: Vec<(String, String)>,
}

fn format_compact_utc(epoch_sec: u64) -> String {
    let days = (epoch_sec / 86_400) as i64;
    let sod = epoch_sec % 86_400;
    let h = sod / 3600;
    let m = (sod % 3600) / 60;
    let s = sod % 60;
    // Civil from days (Howard Hinnant algorithm)
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let mo = if mp < 10 { mp + 3 } else { mp - 9 };
    let yr = if mo <= 2 { y + 1 } else { y };
    format!("{yr:04}{mo:02}{d:02}T{h:02}{m:02}{s:02}Z")
}

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

fn test_accounts() -> Vec<AccountRecord> {
    vec![
        AccountRecord {
            access_key: "0555b35654ad1656d804".into(),
            secret_key: SecretKey::new(
                "h7GhxuBLTrlhVUyxSPUKUV8r/2EI4ngqJxD7iBdBYLhwluN30JaT3Q==",
            ),
            owner: OwnerInfo {
                user_id: "testid".into(),
                display_name: "M. Tester".into(),
                email: "tester@ceph.com".into(),
            },
        },
        AccountRecord {
            access_key: "NOPQRSTUVWXYZABCDEFG".into(),
            secret_key: SecretKey::new("nopqrstuvwxyzabcdefghijklmnabcdefghijklm"),
            owner: OwnerInfo {
                user_id: "altid".into(),
                display_name: "john.doe".into(),
                email: "john.doe@example.com".into(),
            },
        },
    ]
}

const METHODS: &[&str] = &["GET", "PUT", "HEAD", "POST", "DELETE"];
const RAW_SEGMENTS: &[&str] = &[
    "simple",
    "dir//double",
    "a+b",
    "with space",
    "dot/./seg",
    "pct~tilde_under-dash",
    "utf8-键名",
    "semi;colon=eq",
];
const QUERY_KEYS: &[&str] = &[
    "list-type",
    "prefix",
    "delimiter",
    "max-keys",
    "partNumber",
    "uploadId",
    "versionId",
    "encoding-type",
    "x-custom",
];
const QUERY_VALS: &[&str] = &[
    "",
    "2",
    "dir/a+b",
    "with space",
    "/",
    "100",
    "utf8-值",
    "~_.-",
];

#[derive(Clone)]
struct GeneratedCase {
    is_presign: bool,
    method: String,
    encoded_path_and_query: String,
    extra_headers: Vec<(String, String)>,
    body_sha256: String,
    account_idx: usize,
    sign_epoch_sec: u64,
    expires_sec: u64,
}

fn generate_case(rng: &mut StdRng) -> GeneratedCase {
    let is_presign = rng.gen_bool(0.35);
    let method = (*METHODS.choose(rng).unwrap()).to_string();
    let bucket = if rng.gen_bool(0.5) {
        "vr8-alpha"
    } else {
        "vr8-beta"
    };

    let seg_count = rng.gen_range(1..=3);
    let mut raw_key_parts = Vec::with_capacity(seg_count);
    for _ in 0..seg_count {
        raw_key_parts.push(*RAW_SEGMENTS.choose(rng).unwrap());
    }
    let raw_key = raw_key_parts.join("/");
    // Pre-encode path as HTTP clients (`botocore` & `aws-smithy`) send on the wire
    let mut encoded_path = format!("/{bucket}/{}", aws_uri_encode(&raw_key, false));
    if rng.gen_bool(0.15) {
        // Inject `%2F` (encoded slash distinct from literal `/`)
        encoded_path.push_str("%2Fsub");
    }

    let q_count = rng.gen_range(0..=3);
    let mut q_pairs = Vec::with_capacity(q_count);
    for _ in 0..q_count {
        let k = *QUERY_KEYS.choose(rng).unwrap();
        let v = *QUERY_VALS.choose(rng).unwrap();
        q_pairs.push(format!(
            "{}={}",
            aws_uri_encode(k, true),
            aws_uri_encode(v, true)
        ));
    }
    let encoded_path_and_query = if q_pairs.is_empty() {
        encoded_path
    } else {
        format!("{encoded_path}?{}", q_pairs.join("&"))
    };

    let mut extra_headers = Vec::new();
    if !is_presign && rng.gen_bool(0.65) {
        let val = if rng.gen_bool(0.5) {
            "  spaced   meta   value  ".to_string()
        } else {
            format!("v-{}", rng.gen_range(0..10_000))
        };
        extra_headers.push(("x-amz-meta-test".to_string(), val));
    }
    if !is_presign && rng.gen_bool(0.3) {
        extra_headers.push(("x-amz-expected-bucket-owner".to_string(), "testid".to_string()));
    }

    let body_sha256 = if is_presign || rng.gen_bool(0.4) {
        "UNSIGNED-PAYLOAD".to_string()
    } else {
        let mut digest = [0u8; 32];
        rng.fill(&mut digest);
        hex::encode(digest)
    };

    let base_epoch = 1_762_916_400u64; // 2025-11-12T03:00:00Z
    let offset = rng.gen_range(0..300u64);
    let expires_sec = rng.gen_range(60..=3600u64);

    GeneratedCase {
        is_presign,
        method,
        encoded_path_and_query,
        extra_headers,
        body_sha256,
        account_idx: rng.gen_range(0..2),
        sign_epoch_sec: base_epoch + offset,
        expires_sec,
    }
}

fn sign_with_aws_sigv4(
    c: &GeneratedCase,
    acc: &AccountRecord,
    host: &str,
) -> http::Request<()> {
    let full_url = format!("http://{host}{}", c.encoded_path_and_query);
    let mut req_builder = http::Request::builder()
        .method(c.method.as_str())
        .uri(&full_url)
        .header("host", host);
    for (k, v) in &c.extra_headers {
        req_builder = req_builder.header(k.as_str(), v.as_str());
    }
    let mut req = req_builder.body(()).unwrap();

    let identity = Credentials::new(
        acc.access_key.clone(),
        acc.secret_key.expose().to_string(),
        None,
        None,
        "vr8",
    )
    .into();

    let mut settings = SigningSettings::default();
    settings.percent_encoding_mode = PercentEncodingMode::Single;
    settings.uri_path_normalization_mode = UriPathNormalizationMode::Disabled;

    let body = if c.is_presign {
        settings.signature_location = SignatureLocation::QueryParams;
        settings.payload_checksum_kind = PayloadChecksumKind::NoHeader;
        settings.expires_in = Some(Duration::from_secs(c.expires_sec));
        SignableBody::UnsignedPayload
    } else {
        settings.signature_location = SignatureLocation::Headers;
        settings.payload_checksum_kind = PayloadChecksumKind::XAmzSha256;
        if c.body_sha256 == "UNSIGNED-PAYLOAD" {
            SignableBody::UnsignedPayload
        } else {
            SignableBody::Precomputed(c.body_sha256.clone())
        }
    };

    let sign_time = UNIX_EPOCH + Duration::from_secs(c.sign_epoch_sec);
    let params = v4::SigningParams::builder()
        .identity(&identity)
        .region("us-east-1")
        .name("s3")
        .time(sign_time)
        .settings(settings)
        .build()
        .unwrap()
        .into();

    let hdr_pairs: Vec<(&str, &str)> = req
        .headers()
        .iter()
        .map(|(k, v)| (k.as_str(), v.to_str().unwrap()))
        .collect();
    let signable =
        SignableRequest::new(c.method.as_str(), &full_url, hdr_pairs.into_iter(), body).unwrap();
    let (instructions, _) = sign(signable, &params).unwrap().into_parts();
    instructions.apply_to_request_http1x(&mut req);
    req
}

fn verify_http_req(
    verifier: &SigV4Verifier,
    method_str: &str,
    path_and_query: &str,
    headers: &HeaderMap,
    now_ms: i64,
) -> Result<(), s3d_types::S3Error> {
    let method = Method::from_bytes(method_str.as_bytes()).unwrap();
    let host_hdr = headers.get("host").and_then(|v| v.to_str().ok());
    let parsed_uri = parse_s3_uri(host_hdr, path_and_query, "")?;
    let out = verifier.verify_request(&method, &parsed_uri, headers, now_ms)?;
    assert!(out.is_authenticated, "expected authenticated outcome!");
    Ok(())
}

fn strip_origin(full_url: &str, host: &str) -> String {
    let prefix = format!("http://{host}");
    full_url
        .strip_prefix(&prefix)
        .unwrap_or(full_url)
        .to_string()
}

/// VR-8 M1 Gate: 10,000 randomized request groups.
/// 1) Signed by `aws-sigv4` -> `SigV4Verifier` MUST accept 10,000 / 10,000.
/// 2) Same 10,000 requests signed by Python `botocore` -> `SigV4Verifier` MUST accept 10,000 / 10,000.
/// 3) Randomly mutating one signed input on each of the 10,000 requests -> `SigV4Verifier` MUST reject 10,000 / 10,000.
#[test]
fn vr8_10000_groups_botocore_and_aws_sigv4_zero_misjudgments() {
    const TOTAL_GROUPS: usize = 10_000;
    let host = "127.0.0.1:28080";
    let accounts = test_accounts();
    let verifier = SigV4Verifier::new("us-east-1", accounts.clone());

    let mut rng = StdRng::seed_from_u64(0x5652_385F_2026);
    let cases: Vec<GeneratedCase> = (0..TOTAL_GROUPS).map(|_| generate_case(&mut rng)).collect();

    // Spawn single batched `botocore` signer process for all 10,000 cases
    let root = workspace_root();
    let python_bin = root.join(".venv/bin/python");
    let script = root.join("scripts/vr8_botocore_signer.py");
    let mut child = Command::new(&python_bin)
        .arg(&script)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap_or_else(|e| panic!("failed to launch {}: {e}", python_bin.display()));

    let mut child_stdin = child.stdin.take().unwrap();
    let writer_cases = cases.clone();
    let writer_accounts = accounts.clone();
    let writer_handle = std::thread::spawn(move || {
        for c in &writer_cases {
            let acc = &writer_accounts[c.account_idx];
            let mut hdrs = vec![("Host".to_string(), host.to_string())];
            hdrs.extend(c.extra_headers.clone());
            let input = BotocoreSignInput {
                mode: if c.is_presign {
                    "presign".into()
                } else {
                    "header".into()
                },
                method: c.method.clone(),
                url: format!("http://{host}{}", c.encoded_path_and_query),
                headers: hdrs,
                body_sha256: c.body_sha256.clone(),
                access_key: acc.access_key.clone(),
                secret_key: acc.secret_key.expose().to_string(),
                region: "us-east-1".into(),
                timestamp: format_compact_utc(c.sign_epoch_sec),
                expires: c.expires_sec,
            };
            serde_json::to_writer(&mut child_stdin, &input).unwrap();
            child_stdin.write_all(b"\n").unwrap();
        }
        child_stdin.flush().unwrap();
    });

    let stdout = BufReader::new(child.stdout.take().unwrap());
    let mut botocore_lines = stdout.lines();

    for (idx, c) in cases.iter().enumerate() {
        let acc = &accounts[c.account_idx];
        let now_ms = (c.sign_epoch_sec as i64) * 1000 + 5_000; // +5s within valid window

        // ---- 1. Verify `aws-sigv4` signed request is ACCEPTED ----
        let aws_req = sign_with_aws_sigv4(c, acc, host);
        let aws_pq = aws_req
            .uri()
            .path_and_query()
            .map(|pq| pq.as_str())
            .unwrap_or("/");
        verify_http_req(&verifier, &c.method, aws_pq, aws_req.headers(), now_ms)
            .unwrap_or_else(|e| {
                panic!(
                    "case #{idx} aws-sigv4 valid request wrongly rejected: {e:?}\nuri={aws_pq}\nheaders={:?}",
                    aws_req.headers()
                )
            });

        // ---- 2. Verify `botocore` signed request for the EXACT SAME input is ACCEPTED ----
        let line = botocore_lines
            .next()
            .expect("botocore signer ended early")
            .expect("failed reading botocore line");
        let boto_out: BotocoreSignOutput = serde_json::from_str(&line).unwrap();
        let boto_pq = strip_origin(&boto_out.url, host);
        let mut boto_headers = HeaderMap::new();
        for (k, v) in &boto_out.headers {
            boto_headers.append(
                HeaderName::from_bytes(k.as_bytes()).unwrap(),
                HeaderValue::from_str(v).unwrap(),
            );
        }
        verify_http_req(&verifier, &c.method, &boto_pq, &boto_headers, now_ms)
            .unwrap_or_else(|e| {
                panic!(
                    "case #{idx} botocore valid request wrongly rejected: {e:?}\nuri={boto_pq}\nheaders={boto_headers:?}"
                )
            });

        // ---- 3. Randomly mutate ONE signed input -> MUST BE REJECTED! ----
        let mut mut_method = c.method.clone();
        let mut mut_pq = aws_pq.to_string();
        let mut mut_headers = aws_req.headers().clone();
        let mut mut_now_ms = now_ms;

        let mutation_kind = rng.gen_range(0..6u8);
        match mutation_kind {
            0 => {
                // Tamper HTTP method
                mut_method = if mut_method == "GET" {
                    "DELETE".into()
                } else {
                    "GET".into()
                };
            }
            1 => {
                // Tamper URI path
                mut_pq = match mut_pq.split_once('?') {
                    Some((p, q)) => format!("{p}-tampered?{q}"),
                    None => format!("{mut_pq}-tampered"),
                };
            }
            2 => {
                // Tamper query string
                if mut_pq.contains('?') {
                    mut_pq.push_str("&tampered_param=1");
                } else {
                    mut_pq.push_str("?tampered_param=1");
                }
            }
            3 => {
                // Tamper signed `host` header value
                mut_headers.insert("host", HeaderValue::from_static("evil.example.com:28080"));
            }
            4 => {
                // Tamper time / clock skew beyond 15m (or past presign expiration)
                mut_now_ms = (c.sign_epoch_sec as i64 + c.expires_sec as i64 + 1200) * 1000;
            }
            _ => {
                // Tamper payload hash (header mode) or flip 1 hex nibble in X-Amz-Signature (presign mode)
                if c.is_presign {
                    let marker = "X-Amz-Signature=";
                    let pos = mut_pq.find(marker).unwrap() + marker.len();
                    let bytes = mut_pq.as_bytes();
                    let flipped = if bytes[pos] == b'0' { '1' } else { '0' };
                    mut_pq.replace_range(pos..pos + 1, &flipped.to_string());
                } else {
                    mut_headers.insert(
                        "x-amz-content-sha256",
                        HeaderValue::from_static(
                            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                        ),
                    );
                }
            }
        }

        let tampered_res =
            verify_http_req(&verifier, &mut_method, &mut_pq, &mut_headers, mut_now_ms);
        assert!(
            tampered_res.is_err(),
            "case #{idx} mutation kind {mutation_kind} was WRONGLY ACCEPTED! uri={mut_pq}"
        );
    }

    writer_handle.join().unwrap();
    let status = child.wait().unwrap();
    assert!(status.success(), "botocore signer exited with {status}");
    eprintln!(
        "VR-8 passed: {TOTAL_GROUPS} groups (aws-sigv4 + botocore + mutation = {} checks), 0 misjudgments.",
        TOTAL_GROUPS * 3
    );
}
