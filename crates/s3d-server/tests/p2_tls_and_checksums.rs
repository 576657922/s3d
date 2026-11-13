//! Integration tests for optional P2 features & `quick-xml 0.42.0` upgrades:
//! - `Q5`: Native HTTPS / TLS (`tokio-rustls` + `ring`) listener, config validation, and
//!   TLS `503 SlowDown` overload handling.
//! - `PR-20` / `Q6`: Extended checksum algorithms (`MD5`, `SHA512`, `XXHASH64`, `XXHASH3`,
//!   `XXHASH128`) across `PutObject`, `GetObject`, `MultipartUpload` (`COMPOSITE` vs `FULL_OBJECT`),
//!   and `GetObjectAttributes`.
//! - `PR-24` / `quick-xml 0.42.0`: `Event::GeneralRef` entity coalescing without losing
//!   interior whitespace in `PutObjectTagging` and `DeleteObjects`.

use std::fs;
use std::io::BufReader;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use hmac::{Hmac, Mac};
use http_body_util::{BodyExt, Full};
use hyper::client::conn::http1;
use hyper::Request;
use hyper_util::rt::TokioIo;
use rustls_pki_types::ServerName;
use s3d_disk::OsDisk;
use s3d_engine::{Engine, EngineConfig};
use s3d_proto::checksum::ActiveHasher;
use s3d_proto::SigV4Verifier;
use s3d_server::config::ServerConfig;
use s3d_server::metrics::ServerMetrics;
use s3d_server::run_listeners_with_telemetry;
use s3d_types::{AccountRecord, ChecksumAlgorithm, OwnerInfo, SecretKey};
use sha2::{Digest, Sha256};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
use tokio_rustls::rustls::{ClientConfig, RootCertStore};
use tokio_rustls::TlsConnector;

type HmacSha256 = Hmac<Sha256>;

const AK: &str = "AKIAIOSFODNN7EXAMPLE";
const SK: &str = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
const REGION: &str = "us-east-1";

// Test CA + end-entity ECDSA P-256 certificate valid 2020-01-01..2120-01-01 for SAN DNS:localhost, IP:127.0.0.1
const TEST_CA_CERT_PEM: &str = "\
-----BEGIN CERTIFICATE-----
MIIBYTCCAQigAwIBAgIULnziZcLMIwt+C1xArMXNAFPjC8IwCgYIKoZIzj0EAwIw
FjEUMBIGA1UEAwwLczNkLXRlc3QtY2EwIBcNMjAwMTAxMDAwMDAwWhgPMjEyMDAx
MDEwMDAwMDBaMBYxFDASBgNVBAMMC3MzZC10ZXN0LWNhMFkwEwYHKoZIzj0CAQYI
KoZIzj0DAQcDQgAEDjluiUEuQvfJaC40QbrhOmTdy6QCCknPbazscr9wBSfIBA/2
iZXKeeJtiJPnkV5zoWFbNWr0JKPkkCPb1Byro6MyMDAwHQYDVR0OBBYEFAODpdk6
fGKuLHzZl21AcoE5HfMtMA8GA1UdEwEB/wQFMAMBAf8wCgYIKoZIzj0EAwIDRwAw
RAIgQN6KzxJHGBEXMwVxtRmtEwiaWXqVI9BHByVqmD6bel8CIEq477PfLdujF5Y+
FK7E/oXrGl65c4TJthwT2uLLG5Zz
-----END CERTIFICATE-----
";

const TEST_CERT_PEM: &str = "\
-----BEGIN CERTIFICATE-----
MIIBfjCCASWgAwIBAgIUCpqwm7XIsvjxYN1K3PQV5xIzieAwCgYIKoZIzj0EAwIw
FjEUMBIGA1UEAwwLczNkLXRlc3QtY2EwIBcNMjAwMTAxMDAwMDAwWhgPMjEyMDAx
MDEwMDAwMDBaMBQxEjAQBgNVBAMMCWxvY2FsaG9zdDBZMBMGByqGSM49AgEGCCqG
SM49AwEHA0IABDeQsEkUin2WtXS0xujL8XDpbBU37SQh8j2MwtpyNJwhpa8kz1Y4
7hQa2jhFQhJZ5aq6xeLixOPD2DiIEFpKfKqjUTBPMAwGA1UdEwEB/wQCMAAwDgYD
VR0PAQH/BAQDAgeAMBMGA1UdJQQMMAoGCCsGAQUFBwMBMBoGA1UdEQQTMBGCCWxv
Y2FsaG9zdIcEfwAAATAKBggqhkjOPQQDAgNHADBEAiAkEcdJ8m8uVCavIHcvOHxr
q0or1NSRRXMlzuwNSmP2/QIgN84POaTow5zoHRST31v11k299O3SbpKubeF4L/1E
yw8=
-----END CERTIFICATE-----
";

const TEST_KEY_PEM: &str = "\
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgdSsuEOPrSpUp0Nkj
+AmexYZOKKyRu2UJTUeDqPMFC3+hRANCAAQ3kLBJFIp9lrV0tMboy/Fw6WwVN+0k
IfI9jMLacjScIaWvJM9WOO4UGto4RUISWeWqusXi4sTjw9g4iBBaSnyq
-----END PRIVATE KEY-----
";

fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key).unwrap();
    mac.update(data);
    mac.finalize().into_bytes().into()
}

fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

fn derive_signing_key(secret: &str, date_ymd: &str, region: &str) -> [u8; 32] {
    let k_date = hmac_sha256(format!("AWS4{secret}").as_bytes(), date_ymd.as_bytes());
    let k_region = hmac_sha256(&k_date, region.as_bytes());
    let k_service = hmac_sha256(&k_region, b"s3");
    hmac_sha256(&k_service, b"aws4_request")
}

fn now_amz_date() -> (String, String) {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let hh = rem / 3600;
    let mm = (rem % 3600) / 60;
    let ss = rem % 60;

    let z = days + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if m <= 2 { y + 1 } else { y };

    let ymd = format!("{year:04}{m:02}{d:02}");
    let full = format!("{ymd}T{hh:02}{mm:02}{ss:02}Z");
    (ymd, full)
}

fn canonical_query_str(raw_query: &str) -> String {
    if raw_query.is_empty() {
        return String::new();
    }
    let mut pairs: Vec<(String, String)> = raw_query
        .split('&')
        .filter(|s| !s.is_empty())
        .map(|part| match part.split_once('=') {
            Some((k, v)) => (k.to_string(), v.to_string()),
            None => (part.to_string(), String::new()),
        })
        .collect();
    pairs.sort();
    pairs
        .into_iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("&")
}

fn build_signed_req_with_headers(
    method: &str,
    host: &str,
    uri: &str,
    extra_headers: &[(&str, &str)],
    body: Bytes,
) -> Request<Full<Bytes>> {
    let (ymd, amz_date) = now_amz_date();
    let payload_hash = sha256_hex(&body);
    let (path, query) = match uri.split_once('?') {
        Some((p, q)) => (p, canonical_query_str(q)),
        None => (uri, String::new()),
    };

    let mut hdrs: Vec<(String, String)> = vec![
        ("host".into(), host.to_string()),
        ("x-amz-content-sha256".into(), payload_hash.clone()),
        ("x-amz-date".into(), amz_date.clone()),
    ];
    for (k, v) in extra_headers {
        hdrs.push((k.to_ascii_lowercase(), (*v).trim().to_string()));
    }
    hdrs.sort_by(|a, b| a.0.cmp(&b.0));

    let canonical_headers: String = hdrs
        .iter()
        .map(|(k, v)| format!("{k}:{v}\n"))
        .collect();
    let signed_headers: String = hdrs
        .iter()
        .map(|(k, _)| k.as_str())
        .collect::<Vec<_>>()
        .join(";");

    let canonical_req = format!(
        "{method}\n{path}\n{query}\n{canonical_headers}\n{signed_headers}\n{payload_hash}"
    );
    let scope = format!("{ymd}/{REGION}/s3/aws4_request");
    let sts = format!(
        "AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{}",
        sha256_hex(canonical_req.as_bytes())
    );
    let sig = hex::encode(hmac_sha256(
        &derive_signing_key(SK, &ymd, REGION),
        sts.as_bytes(),
    ));
    let auth_hdr = format!(
        "AWS4-HMAC-SHA256 Credential={AK}/{scope}, SignedHeaders={signed_headers}, Signature={sig}"
    );

    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header("Host", host)
        .header("x-amz-date", amz_date)
        .header("x-amz-content-sha256", payload_hash)
        .header("Authorization", auth_hdr)
        .header("Content-Length", body.len().to_string());
    for (k, v) in extra_headers {
        builder = builder.header(*k, *v);
    }
    builder.body(Full::new(body)).unwrap()
}

async fn send_http(
    addr: std::net::SocketAddr,
    req: Request<Full<Bytes>>,
) -> (u16, http::HeaderMap, Bytes) {
    let stream = TcpStream::connect(addr).await.unwrap();
    let io = TokioIo::new(stream);
    let (mut sender, conn) = http1::handshake(io).await.unwrap();
    tokio::spawn(async move {
        let _ = conn.await;
    });
    let resp = sender.send_request(req).await.unwrap();
    let status = resp.status().as_u16();
    let headers = resp.headers().clone();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    (status, headers, body)
}

fn build_tls_connector() -> TlsConnector {
    let mut reader = BufReader::new(TEST_CA_CERT_PEM.as_bytes());
    let certs: Vec<_> = rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let mut roots = RootCertStore::empty();
    for c in certs {
        roots.add(c).unwrap();
    }
    let client_cfg = ClientConfig::builder_with_provider(Arc::new(
        tokio_rustls::rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth();
    TlsConnector::from(Arc::new(client_cfg))
}

async fn send_https(
    addr: std::net::SocketAddr,
    connector: &TlsConnector,
    mut req: Request<Full<Bytes>>,
) -> (u16, http::HeaderMap, Bytes) {
    req.headers_mut()
        .insert("connection", http::HeaderValue::from_static("close"));
    let tcp = TcpStream::connect(addr).await.unwrap();
    let server_name = ServerName::try_from("localhost").unwrap();
    let tls_stream = connector.connect(server_name, tcp).await.unwrap();
    let io = TokioIo::new(tls_stream);
    let (mut sender, conn) = http1::handshake(io).await.unwrap();
    let conn_task = tokio::spawn(async move {
        let _ = conn.await;
    });
    let resp = sender.send_request(req).await.unwrap();
    let status = resp.status().as_u16();
    let headers = resp.headers().clone();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    drop(sender);
    let _ = conn_task.await;
    (status, headers, body)
}

fn default_accounts() -> Vec<AccountRecord> {
    vec![AccountRecord {
        owner: OwnerInfo {
            user_id: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".into(),
            display_name: "tester".into(),
            email: "tester@example.com".into(),
        },
        access_key: AK.into(),
        secret_key: SecretKey::new(SK),
    }]
}

#[tokio::test]
async fn q5_https_tls_server_and_overload() {
    let tmp = tempfile::tempdir().unwrap();
    let cert_path = tmp.path().join("cert.pem");
    let key_path = tmp.path().join("key.pem");
    fs::write(&cert_path, TEST_CERT_PEM).unwrap();
    fs::write(&key_path, TEST_KEY_PEM).unwrap();

    // Config validation: partial TLS config must be rejected
    let bad_cfg = ServerConfig {
        tls_cert_file: Some(cert_path.clone()),
        ..ServerConfig::default()
    };
    assert!(bad_cfg.validate().is_err());

    let data_dir = tmp.path().join("data");
    let disk = OsDisk::new(&data_dir).unwrap();
    let engine = Engine::open(
        disk,
        EngineConfig {
            reserved_disk_bytes: 0,
            ..EngineConfig::default()
        },
    )
    .unwrap();

    let s3_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let admin_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let s3_addr = s3_listener.local_addr().unwrap();

    let cfg = ServerConfig {
        tls_cert_file: Some(cert_path),
        tls_key_file: Some(key_path),
        max_connections: 2,
        idle_timeout: Duration::from_secs(10),
        ..ServerConfig::default()
    };
    assert!(cfg.validate().is_ok());

    let auth = Arc::new(SigV4Verifier::new(REGION.to_string(), default_accounts()));
    let metrics = Arc::new(ServerMetrics::default());
    let (stop_tx, stop_rx) = oneshot::channel::<()>();

    let srv = tokio::spawn(async move {
        run_listeners_with_telemetry(
            s3_listener,
            admin_listener,
            engine,
            auth,
            cfg,
            metrics,
            || false,
            || None,
            async move {
                let _ = stop_rx.await;
            },
        )
        .await
    });

    let connector = build_tls_connector();
    let host = format!("localhost:{}", s3_addr.port());

    // 1. CreateBucket over HTTPS
    let (st, _, _) = send_https(
        s3_addr,
        &connector,
        build_signed_req_with_headers("PUT", &host, "/tls-bucket", &[], Bytes::new()),
    )
    .await;
    assert_eq!(st, 200);

    // 2. PutObject + GetObject over HTTPS
    let payload = Bytes::from_static(b"encrypted-in-transit-over-tls13");
    let (st, put_hdrs, _) = send_https(
        s3_addr,
        &connector,
        build_signed_req_with_headers("PUT", &host, "/tls-bucket/hello.txt", &[], payload.clone()),
    )
    .await;
    assert_eq!(st, 200);
    assert!(put_hdrs.contains_key("etag"));

    let (st, _, got_body) = send_https(
        s3_addr,
        &connector,
        build_signed_req_with_headers("GET", &host, "/tls-bucket/hello.txt", &[], Bytes::new()),
    )
    .await;
    assert_eq!(st, 200);
    assert_eq!(got_body, payload);

    // 3. Overload (`max_connections = 2`) over HTTPS returns 503 SlowDown over TLS
    tokio::time::sleep(Duration::from_millis(25)).await;
    let held_tcp_1 = TcpStream::connect(s3_addr).await.unwrap();
    let held_tls_1 = connector
        .connect(ServerName::try_from("localhost").unwrap(), held_tcp_1)
        .await
        .unwrap();
    let held_tcp_2 = TcpStream::connect(s3_addr).await.unwrap();
    let held_tls_2 = connector
        .connect(ServerName::try_from("localhost").unwrap(), held_tcp_2)
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;

    let (st_overload, _, overload_body) = send_https(
        s3_addr,
        &connector,
        build_signed_req_with_headers("GET", &host, "/tls-bucket/hello.txt", &[], Bytes::new()),
    )
    .await;
    assert_eq!(st_overload, 503);
    assert!(std::str::from_utf8(&overload_body)
        .unwrap()
        .contains("<Code>SlowDown</Code>"));

    drop(held_tls_1);
    drop(held_tls_2);
    let _ = stop_tx.send(());
    srv.await.unwrap().unwrap();
}

fn compute_b64(alg: ChecksumAlgorithm, data: &[u8]) -> String {
    let mut h = ActiveHasher::new(alg);
    h.update(data);
    h.finalize_b64()
}

fn extract_xml_tag(xml: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = xml.find(&open)? + open.len();
    let end = xml[start..].find(&close)? + start;
    Some(xml[start..end].to_string())
}

#[tokio::test]
async fn pr20_q6_all_five_p2_checksums_and_quick_xml_042_entities() {
    let tmp = tempfile::tempdir().unwrap();
    let disk = OsDisk::new(tmp.path()).unwrap();
    let engine = Engine::open(
        disk,
        EngineConfig {
            reserved_disk_bytes: 0,
            ..EngineConfig::default()
        },
    )
    .unwrap();

    let s3_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let admin_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let s3_addr = s3_listener.local_addr().unwrap();
    let host = format!("127.0.0.1:{}", s3_addr.port());

    let auth = Arc::new(SigV4Verifier::new(REGION.to_string(), default_accounts()));
    let metrics = Arc::new(ServerMetrics::default());
    let (stop_tx, stop_rx) = oneshot::channel::<()>();

    let srv = tokio::spawn(async move {
        run_listeners_with_telemetry(
            s3_listener,
            admin_listener,
            engine,
            auth,
            ServerConfig::default(),
            metrics,
            || false,
            || None,
            async move {
                let _ = stop_rx.await;
            },
        )
        .await
    });

    // Create bucket
    let (st, _, _) = send_http(
        s3_addr,
        build_signed_req_with_headers("PUT", &host, "/p2-csum", &[], Bytes::new()),
    )
    .await;
    assert_eq!(st, 200);

    let p2_algs = [
        ChecksumAlgorithm::Md5,
        ChecksumAlgorithm::Sha512,
        ChecksumAlgorithm::XxHash64,
        ChecksumAlgorithm::XxHash3,
        ChecksumAlgorithm::XxHash128,
    ];

    let body_single = Bytes::from_static(b"s3d-p2-extended-checksum-payload-0123456789");
    let part1 = Bytes::from(vec![b'A'; 5 * 1024 * 1024 + 13]);
    let part2 = Bytes::from_static(b"final-tail-part-p2-checksum");

    for alg in p2_algs {
        let alg_str = alg.as_aws_str();
        let hdr_name = alg.header_name();
        let good_b64 = compute_b64(alg, &body_single);
        let key = format!("/p2-csum/single-{}", alg_str.to_ascii_lowercase());

        // 1. Bad digest -> 400 BadDigest
        let wrong_bytes = vec![0xAAu8; alg.digest_byte_len()];
        let wrong_b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &wrong_bytes);
        let (st_bad, _, bad_xml) = send_http(
            s3_addr,
            build_signed_req_with_headers(
                "PUT",
                &host,
                &key,
                &[(hdr_name, &wrong_b64)],
                body_single.clone(),
            ),
        )
        .await;
        assert_eq!(st_bad, 400, "alg={alg_str}");
        assert!(std::str::from_utf8(&bad_xml).unwrap().contains("<Code>BadDigest</Code>"));

        // 2. Valid single-PUT + GET with x-amz-checksum-mode=ENABLED
        let (st_put, put_hdrs, _) = send_http(
            s3_addr,
            build_signed_req_with_headers(
                "PUT",
                &host,
                &key,
                &[(hdr_name, &good_b64)],
                body_single.clone(),
            ),
        )
        .await;
        assert_eq!(st_put, 200, "alg={alg_str}");
        assert_eq!(put_hdrs.get(hdr_name).unwrap().to_str().unwrap(), good_b64);
        assert_eq!(
            put_hdrs.get("x-amz-checksum-type").unwrap().to_str().unwrap(),
            "FULL_OBJECT"
        );

        let (st_get, get_hdrs, got_bytes) = send_http(
            s3_addr,
            build_signed_req_with_headers(
                "GET",
                &host,
                &key,
                &[("x-amz-checksum-mode", "ENABLED")],
                Bytes::new(),
            ),
        )
        .await;
        assert_eq!(st_get, 200, "alg={alg_str}");
        assert_eq!(got_bytes, body_single);
        assert_eq!(get_hdrs.get(hdr_name).unwrap().to_str().unwrap(), good_b64);

        // 3. Multipart with FULL_OBJECT on non-linear P2 checksum -> 400 InvalidRequest
        let mpu_key = format!("/p2-csum/mpu-{}", alg_str.to_ascii_lowercase());
        let (st_full_mpu, _, full_mpu_xml) = send_http(
            s3_addr,
            build_signed_req_with_headers(
                "POST",
                &host,
                &format!("{mpu_key}?uploads="),
                &[
                    ("x-amz-checksum-algorithm", alg_str),
                    ("x-amz-checksum-type", "FULL_OBJECT"),
                ],
                Bytes::new(),
            ),
        )
        .await;
        assert_eq!(st_full_mpu, 400, "alg={alg_str} FULL_OBJECT MPU must reject");
        assert!(std::str::from_utf8(&full_mpu_xml)
            .unwrap()
            .contains("<Code>InvalidRequest</Code>"));

        // 4. Multipart COMPOSITE succeeds and computes composite digest `<b64>-2`
        let (st_init, _, init_xml) = send_http(
            s3_addr,
            build_signed_req_with_headers(
                "POST",
                &host,
                &format!("{mpu_key}?uploads="),
                &[("x-amz-checksum-algorithm", alg_str)],
                Bytes::new(),
            ),
        )
        .await;
        assert_eq!(st_init, 200, "alg={alg_str}");
        let upload_id =
            extract_xml_tag(std::str::from_utf8(&init_xml).unwrap(), "UploadId").unwrap();

        let p1_b64 = compute_b64(alg, &part1);
        let (st_p1, p1_hdrs, _) = send_http(
            s3_addr,
            build_signed_req_with_headers(
                "PUT",
                &host,
                &format!("{mpu_key}?partNumber=1&uploadId={upload_id}"),
                &[(hdr_name, &p1_b64)],
                part1.clone(),
            ),
        )
        .await;
        assert_eq!(st_p1, 200);
        let etag1 = p1_hdrs.get("etag").unwrap().to_str().unwrap().to_string();

        let p2_b64 = compute_b64(alg, &part2);
        let (st_p2, p2_hdrs, _) = send_http(
            s3_addr,
            build_signed_req_with_headers(
                "PUT",
                &host,
                &format!("{mpu_key}?partNumber=2&uploadId={upload_id}"),
                &[(hdr_name, &p2_b64)],
                part2.clone(),
            ),
        )
        .await;
        assert_eq!(st_p2, 200);
        let etag2 = p2_hdrs.get("etag").unwrap().to_str().unwrap().to_string();

        let xml_tag = alg.xml_tag_name();
        let complete_xml = format!(
            "<CompleteMultipartUpload>\
             <Part><PartNumber>1</PartNumber><ETag>{etag1}</ETag><{xml_tag}>{p1_b64}</{xml_tag}></Part>\
             <Part><PartNumber>2</PartNumber><ETag>{etag2}</ETag><{xml_tag}>{p2_b64}</{xml_tag}></Part>\
             </CompleteMultipartUpload>"
        );
        let (st_comp, comp_hdrs, comp_body) = send_http(
            s3_addr,
            build_signed_req_with_headers(
                "POST",
                &host,
                &format!("{mpu_key}?uploadId={upload_id}"),
                &[],
                Bytes::from(complete_xml),
            ),
        )
        .await;
        assert_eq!(st_comp, 200, "alg={alg_str} body={}", String::from_utf8_lossy(&comp_body));
        let comp_val = comp_hdrs.get(hdr_name).unwrap().to_str().unwrap();
        assert!(comp_val.ends_with("-2"), "expected composite -2 suffix, got {comp_val}");

        // GetObjectAttributes verifies XML serialization of Checksum<ALG> + ObjectParts
        let (st_attr, _, attr_body) = send_http(
            s3_addr,
            build_signed_req_with_headers(
                "GET",
                &host,
                &format!("{mpu_key}?attributes="),
                &[(
                    "x-amz-object-attributes",
                    "Checksum,ObjectParts,ObjectSize",
                )],
                Bytes::new(),
            ),
        )
        .await;
        assert_eq!(st_attr, 200, "alg={alg_str}");
        let attr_xml = std::str::from_utf8(&attr_body).unwrap();
        assert!(attr_xml.contains(&format!("<{xml_tag}>")), "attr_xml={attr_xml}");
        assert!(attr_xml.contains("<ChecksumType>COMPOSITE</ChecksumType>"));
    }

    // 5. quick-xml 0.42.0 Event::GeneralRef entity + interior whitespace coalescing regression test
    // Put an object whose key contains `&`, `<1>`, `"q"`, and spaces (percent-encoded in URI)
    let tricky_uri = "/p2-csum/dir/a%20%26%20b%20%3C1%3E%20%22q%22%20%26%20end.txt";
    let (st_put_tricky, _, _) = send_http(
        s3_addr,
        build_signed_req_with_headers("PUT", &host, tricky_uri, &[], Bytes::from_static(b"x")),
    )
    .await;
    assert_eq!(st_put_tricky, 200);

    // 5a. `&amp;` in Tag Key decodes to `&` and hits S3 Tag charset validation (`InvalidTag`, NOT `MalformedXML`)
    let bad_tag_xml = Bytes::from_static(
        b"<Tagging><TagSet><Tag><Key>k &amp; 1</Key><Value>ok</Value></Tag></TagSet></Tagging>",
    );
    let (st_bad_tag, _, bad_tag_body) = send_http(
        s3_addr,
        build_signed_req_with_headers(
            "PUT",
            &host,
            &format!("{tricky_uri}?tagging="),
            &[],
            bad_tag_xml,
        ),
    )
    .await;
    assert_eq!(st_bad_tag, 400);
    assert!(std::str::from_utf8(&bad_tag_body)
        .unwrap()
        .contains("<Code>InvalidTag</Code>"));

    // 5b. Numeric character references (`&#43;` = `+`, `&#61;` = `=`, `&#64;` = `@`) surrounded by spaces in Tagging
    let tag_xml = Bytes::from_static(
        b"<Tagging><TagSet><Tag><Key>k &#43; 1</Key><Value>a &#61; b &#64; c</Value></Tag></TagSet></Tagging>",
    );
    let (st_tag_put, _, _) = send_http(
        s3_addr,
        build_signed_req_with_headers(
            "PUT",
            &host,
            &format!("{tricky_uri}?tagging="),
            &[],
            tag_xml,
        ),
    )
    .await;
    assert_eq!(st_tag_put, 200);

    let (st_tag_get, _, tag_get_body) = send_http(
        s3_addr,
        build_signed_req_with_headers(
            "GET",
            &host,
            &format!("{tricky_uri}?tagging="),
            &[],
            Bytes::new(),
        ),
    )
    .await;
    assert_eq!(st_tag_get, 200);
    let tag_get_str = std::str::from_utf8(&tag_get_body).unwrap();
    assert!(
        tag_get_str.contains("<Key>k + 1</Key>"),
        "got: {tag_get_str}"
    );
    assert!(
        tag_get_str.contains("<Value>a = b @ c</Value>"),
        "got: {tag_get_str}"
    );

    // 5c. DeleteObjects using named & numeric XML entities (`&amp;`, `&lt;`, `&gt;`, `&quot;`, `&#38;`) in <Key>
    let del_body = Bytes::from_static(
        b"<Delete><Object><Key>dir/a &amp; b &lt;1&gt; &quot;q&quot; &#38; end.txt</Key></Object></Delete>",
    );
    let mut md5_h = ActiveHasher::new(ChecksumAlgorithm::Md5);
    md5_h.update(&del_body);
    let del_md5 = md5_h.finalize_b64();
    let (st_del, _, _) = send_http(
        s3_addr,
        build_signed_req_with_headers(
            "POST",
            &host,
            "/p2-csum?delete=",
            &[("Content-MD5", &del_md5)],
            del_body,
        ),
    )
    .await;
    assert_eq!(st_del, 200);

    // Verify object was actually deleted (404 NoSuchKey)
    let (st_after, _, _) = send_http(
        s3_addr,
        build_signed_req_with_headers("GET", &host, tricky_uri, &[], Bytes::new()),
    )
    .await;
    assert_eq!(st_after, 404);

    let _ = stop_tx.send(());
    srv.await.unwrap().unwrap();
}
