//! M2 HTTP protocol integration tests:
//! - Virtual-Hosted style addressing (`{bucket}.s3.local`, `PR-2`)
//! - `STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER` (`PR-12`, `PR-27`)
//! - HTML Form `PostObject` with SigV4 (`AWS4-HMAC-SHA256`, `FR-48`)
//! - CORS `OPTIONS` preflight & normal `Origin` header propagation (`?cors`)

use std::sync::Arc;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use bytes::Bytes;
use hmac::{Hmac, Mac};
use http_body_util::{BodyExt, Full};
use hyper::client::conn::http1;
use hyper::Request;
use hyper_util::rt::TokioIo;
use s3d_disk::OsDisk;
use s3d_engine::{Engine, EngineConfig};
use s3d_proto::SigV4Verifier;
use s3d_server::config::ServerConfig;
use s3d_server::metrics::ServerMetrics;
use s3d_server::run_listeners_with_store;
use s3d_types::{AccountRecord, ObjectOwnership, OwnerInfo, SecretKey};
use sha2::{Digest, Sha256};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;

type HmacSha256 = Hmac<Sha256>;

const AK: &str = "AKIAIOSFODNN7EXAMPLE";
const SK: &str = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
const REGION: &str = "us-east-1";
const BASE_DOMAIN: &str = "s3.local";

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
    // Civil date conversion from epoch days
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

async fn send_raw(
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
    let hdrs = resp.headers().clone();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    (status, hdrs, body)
}

fn sign_request(
    method: &str,
    uri_path: &str,
    canonical_query: &str,
    extra_headers: &[(&str, &str)],
    payload_sha_hdr: &str,
    body: Bytes,
) -> (Request<Full<Bytes>>, String, String, [u8; 32]) {
    let (ymd, amz_date) = now_amz_date();
    let mut hdr_map: std::collections::BTreeMap<String, String> = std::collections::BTreeMap::new();
    for (k, v) in extra_headers {
        hdr_map.insert(k.to_ascii_lowercase(), v.trim().to_string());
    }
    hdr_map.insert("x-amz-date".to_string(), amz_date.clone());
    hdr_map.insert(
        "x-amz-content-sha256".to_string(),
        payload_sha_hdr.to_string(),
    );

    let signed_headers = hdr_map.keys().cloned().collect::<Vec<_>>().join(";");
    let mut canon_hdrs = String::new();
    for (k, v) in &hdr_map {
        canon_hdrs.push_str(k);
        canon_hdrs.push(':');
        canon_hdrs.push_str(v);
        canon_hdrs.push('\n');
    }

    let canon_req = format!(
        "{method}\n{uri_path}\n{canonical_query}\n{canon_hdrs}\n{signed_headers}\n{payload_sha_hdr}"
    );
    let scope = format!("{ymd}/{REGION}/s3/aws4_request");
    let sts = format!(
        "AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{}",
        sha256_hex(canon_req.as_bytes())
    );
    let signing_key = derive_signing_key(SK, &ymd, REGION);
    let seed_sig = hex::encode(hmac_sha256(&signing_key, sts.as_bytes()));
    let auth_hdr = format!(
        "AWS4-HMAC-SHA256 Credential={AK}/{scope}, SignedHeaders={signed_headers}, Signature={seed_sig}"
    );

    let uri_full = if canonical_query.is_empty() {
        uri_path.to_string()
    } else {
        format!("{uri_path}?{canonical_query}")
    };
    let mut builder = Request::builder().method(method).uri(uri_full);
    for (k, v) in &hdr_map {
        builder = builder.header(k.as_str(), v.as_str());
    }
    builder = builder.header("authorization", auth_hdr);
    (
        builder.body(Full::new(body)).unwrap(),
        seed_sig,
        amz_date,
        signing_key,
    )
}

#[tokio::test]
async fn m2_virtual_hosted_streaming_trailer_cors_and_post_sigv4() {
    let dir = tempfile::tempdir().unwrap();
    let disk = OsDisk::new(dir.path()).unwrap();
    let engine = Engine::open(
        disk,
        EngineConfig {
            default_object_ownership: ObjectOwnership::ObjectWriter,
            ..EngineConfig::default()
        },
    )
    .unwrap();

    let accounts = vec![AccountRecord {
        owner: OwnerInfo {
            user_id: "u-main".to_string(),
            display_name: "Main User".to_string(),
            email: "main@example.com".to_string(),
        },
        access_key: AK.to_string(),
        secret_key: SecretKey::new(SK),
    }];
    let auth = Arc::new(SigV4Verifier::new(REGION.to_string(), accounts));
    let mut cfg = ServerConfig::default();
    cfg.base_domain = BASE_DOMAIN.to_string();

    let s3_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let s3_addr = s3_listener.local_addr().unwrap();
    let admin_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (stop_tx, stop_rx) = oneshot::channel::<()>();

    let srv_handle = tokio::spawn(async move {
        run_listeners_with_store(
            s3_listener,
            admin_listener,
            engine,
            auth,
            cfg,
            Arc::new(ServerMetrics::default()),
            || false,
            async move {
                let _ = stop_rx.await;
            },
        )
        .await
        .unwrap();
    });

    // 1. Virtual-Hosted style CreateBucket (`Host: vh-bkt.s3.local:<port>`, `PUT /`)
    let vh_host = format!("vh-bkt.{BASE_DOMAIN}:{}", s3_addr.port());
    let (req, _, _, _) = sign_request(
        "PUT",
        "/",
        "",
        &[("host", &vh_host), ("content-length", "0")],
        &sha256_hex(b""),
        Bytes::new(),
    );
    let (st, _, _) = send_raw(s3_addr, req).await;
    assert_eq!(st, 200, "Virtual-Hosted CreateBucket must succeed");

    // 2. `STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER` with CRC32C over Virtual-Hosted addressing!
    // Per `PR-12`, non-final `aws-chunked` chunks must be >= 8 KiB (8192 bytes).
    let mut payload_vec = vec![b'A'; 8192];
    payload_vec.extend_from_slice(b"Hello M2 streaming signed payload with CRC32C trailer!");
    let payload: &[u8] = &payload_vec;
    let c1 = &payload[..8192];
    let c2 = &payload[8192..];
    let crc_val = crc32c::crc32c(payload);
    let crc_b64 = B64.encode(crc_val.to_be_bytes());

    let (ymd, amz_date) = now_amz_date();
    let scope = format!("{ymd}/{REGION}/s3/aws4_request");
    let signing_key = derive_signing_key(SK, &ymd, REGION);

    // Build wire body after computing seed signature
    let decoded_len_str = payload.len().to_string();
    let canon_hdrs = format!(
        "content-encoding:aws-chunked\nhost:{vh_host}\nx-amz-content-sha256:STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER\nx-amz-date:{amz_date}\nx-amz-decoded-content-length:{decoded_len_str}\nx-amz-trailer:x-amz-checksum-crc32c\n"
    );
    let signed_hdrs = "content-encoding;host;x-amz-content-sha256;x-amz-date;x-amz-decoded-content-length;x-amz-trailer";
    let canon_req = format!(
        "PUT\n/trailer-obj.txt\n\n{canon_hdrs}\n{signed_hdrs}\nSTREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER"
    );
    let sts0 = format!(
        "AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{}",
        sha256_hex(canon_req.as_bytes())
    );
    let sig0 = hex::encode(hmac_sha256(&signing_key, sts0.as_bytes()));

    let empty_sha = sha256_hex(b"");
    let sts1 = format!(
        "AWS4-HMAC-SHA256-PAYLOAD\n{amz_date}\n{scope}\n{sig0}\n{empty_sha}\n{}",
        sha256_hex(c1)
    );
    let sig1 = hex::encode(hmac_sha256(&signing_key, sts1.as_bytes()));

    let sts2 = format!(
        "AWS4-HMAC-SHA256-PAYLOAD\n{amz_date}\n{scope}\n{sig1}\n{empty_sha}\n{}",
        sha256_hex(c2)
    );
    let sig2 = hex::encode(hmac_sha256(&signing_key, sts2.as_bytes()));

    let sts_eof = format!(
        "AWS4-HMAC-SHA256-PAYLOAD\n{amz_date}\n{scope}\n{sig2}\n{empty_sha}\n{empty_sha}"
    );
    let sig_eof = hex::encode(hmac_sha256(&signing_key, sts_eof.as_bytes()));

    let canon_trailer = format!("x-amz-checksum-crc32c:{crc_b64}\n");
    let sts_trl = format!(
        "AWS4-HMAC-SHA256-TRAILER\n{amz_date}\n{scope}\n{sig_eof}\n{}",
        sha256_hex(canon_trailer.as_bytes())
    );
    let sig_trl = hex::encode(hmac_sha256(&signing_key, sts_trl.as_bytes()));

    let mut wire = Vec::new();
    wire.extend_from_slice(format!("{:x};chunk-signature={sig1}\r\n", c1.len()).as_bytes());
    wire.extend_from_slice(c1);
    wire.extend_from_slice(b"\r\n");
    wire.extend_from_slice(format!("{:x};chunk-signature={sig2}\r\n", c2.len()).as_bytes());
    wire.extend_from_slice(c2);
    wire.extend_from_slice(b"\r\n");
    wire.extend_from_slice(format!("0;chunk-signature={sig_eof}\r\n").as_bytes());
    wire.extend_from_slice(format!("x-amz-checksum-crc32c:{crc_b64}\r\n").as_bytes());
    wire.extend_from_slice(format!("x-amz-trailer-signature:{sig_trl}\r\n\r\n").as_bytes());

    let put_req = Request::builder()
        .method("PUT")
        .uri("/trailer-obj.txt")
        .header("host", &vh_host)
        .header("content-encoding", "aws-chunked")
        .header(
            "x-amz-content-sha256",
            "STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER",
        )
        .header("x-amz-date", &amz_date)
        .header("x-amz-decoded-content-length", &decoded_len_str)
        .header("x-amz-trailer", "x-amz-checksum-crc32c")
        .header("content-length", wire.len().to_string())
        .header(
            "authorization",
            format!("AWS4-HMAC-SHA256 Credential={AK}/{scope}, SignedHeaders={signed_hdrs}, Signature={sig0}"),
        )
        .body(Full::new(Bytes::from(wire.clone())))
        .unwrap();
    let (st, put_hdrs, _) = send_raw(s3_addr, put_req).await;
    assert_eq!(st, 200, "STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER PutObject must succeed");
    assert_eq!(
        put_hdrs
            .get("x-amz-checksum-crc32c")
            .unwrap()
            .to_str()
            .unwrap(),
        crc_b64
    );

    // Negative test: tamper 1 hex char in `x-amz-trailer-signature` -> must reject!
    let bad_sig_trl = format!(
        "{}{}",
        if sig_trl.starts_with('a') { 'b' } else { 'a' },
        &sig_trl[1..]
    );
    let bad_wire = String::from_utf8_lossy(&wire)
        .replace(&sig_trl, &bad_sig_trl)
        .into_bytes();
    let bad_req = Request::builder()
        .method("PUT")
        .uri("/trailer-bad.txt")
        .header("host", &vh_host)
        .header("content-encoding", "aws-chunked")
        .header(
            "x-amz-content-sha256",
            "STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER",
        )
        .header("x-amz-date", &amz_date)
        .header("x-amz-decoded-content-length", &decoded_len_str)
        .header("x-amz-trailer", "x-amz-checksum-crc32c")
        .header("content-length", bad_wire.len().to_string())
        .header(
            "authorization",
            format!("AWS4-HMAC-SHA256 Credential={AK}/{scope}, SignedHeaders={signed_hdrs}, Signature={sig0}"),
        )
        .body(Full::new(Bytes::from(bad_wire)))
        .unwrap();
    // Note: sig0 was signed for `/trailer-obj.txt`, so sign `/trailer-bad.txt` properly so only trailer sig fails!
    let _ = bad_req;
    let canon_req_bad = format!(
        "PUT\n/trailer-bad.txt\n\n{canon_hdrs}\n{signed_hdrs}\nSTREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER"
    );
    let sig0_bad = hex::encode(hmac_sha256(
        &signing_key,
        format!(
            "AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{}",
            sha256_hex(canon_req_bad.as_bytes())
        )
        .as_bytes(),
    ));
    let sig1_bad = hex::encode(hmac_sha256(
        &signing_key,
        format!(
            "AWS4-HMAC-SHA256-PAYLOAD\n{amz_date}\n{scope}\n{sig0_bad}\n{empty_sha}\n{}",
            sha256_hex(c1)
        )
        .as_bytes(),
    ));
    let sig2_bad = hex::encode(hmac_sha256(
        &signing_key,
        format!(
            "AWS4-HMAC-SHA256-PAYLOAD\n{amz_date}\n{scope}\n{sig1_bad}\n{empty_sha}\n{}",
            sha256_hex(c2)
        )
        .as_bytes(),
    ));
    let sig_eof_bad = hex::encode(hmac_sha256(
        &signing_key,
        format!("AWS4-HMAC-SHA256-PAYLOAD\n{amz_date}\n{scope}\n{sig2_bad}\n{empty_sha}\n{empty_sha}").as_bytes(),
    ));
    let mut bad_wire2 = Vec::new();
    bad_wire2.extend_from_slice(format!("{:x};chunk-signature={sig1_bad}\r\n", c1.len()).as_bytes());
    bad_wire2.extend_from_slice(c1);
    bad_wire2.extend_from_slice(b"\r\n");
    bad_wire2.extend_from_slice(format!("{:x};chunk-signature={sig2_bad}\r\n", c2.len()).as_bytes());
    bad_wire2.extend_from_slice(c2);
    bad_wire2.extend_from_slice(b"\r\n");
    bad_wire2.extend_from_slice(format!("0;chunk-signature={sig_eof_bad}\r\n").as_bytes());
    bad_wire2.extend_from_slice(format!("x-amz-checksum-crc32c:{crc_b64}\r\n").as_bytes());
    bad_wire2.extend_from_slice(format!("x-amz-trailer-signature:{bad_sig_trl}\r\n\r\n").as_bytes());

    let bad_req2 = Request::builder()
        .method("PUT")
        .uri("/trailer-bad.txt")
        .header("host", &vh_host)
        .header("content-encoding", "aws-chunked")
        .header(
            "x-amz-content-sha256",
            "STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER",
        )
        .header("x-amz-date", &amz_date)
        .header("x-amz-decoded-content-length", &decoded_len_str)
        .header("x-amz-trailer", "x-amz-checksum-crc32c")
        .header("content-length", bad_wire2.len().to_string())
        .header(
            "authorization",
            format!("AWS4-HMAC-SHA256 Credential={AK}/{scope}, SignedHeaders={signed_hdrs}, Signature={sig0_bad}"),
        )
        .body(Full::new(Bytes::from(bad_wire2)))
        .unwrap();
    let (st_bad, _, _) = send_raw(s3_addr, bad_req2).await;
    assert_eq!(st_bad, 400, "Tampered trailer signature must be rejected");

    // Verify Virtual-Hosted GetObject reads exact bytes back
    let (get_req, _, _, _) = sign_request(
        "GET",
        "/trailer-obj.txt",
        "",
        &[("host", &vh_host), ("x-amz-checksum-mode", "ENABLED")],
        &empty_sha,
        Bytes::new(),
    );
    let (st_get, get_hdrs, get_body) = send_raw(s3_addr, get_req).await;
    assert_eq!(st_get, 200);
    assert_eq!(&get_body[..], payload);
    assert_eq!(
        get_hdrs
            .get("x-amz-checksum-crc32c")
            .unwrap()
            .to_str()
            .unwrap(),
        crc_b64
    );

    // 3. HTML Form `PostObject` with SigV4 (`AWS4-HMAC-SHA256`) + `success_action_status=201`
    let post_policy_json = serde_json::json!({
        "expiration": "2099-12-31T23:59:59Z",
        "conditions": [
            {"bucket": "vh-bkt"},
            ["starts-with", "$key", "uploads/"],
            {"x-amz-algorithm": "AWS4-HMAC-SHA256"},
            {"x-amz-credential": format!("{AK}/{scope}")},
            {"x-amz-date": amz_date},
            {"success_action_status": "201"}
        ]
    })
    .to_string();
    let policy_b64 = B64.encode(post_policy_json.as_bytes());
    let post_sig = hex::encode(hmac_sha256(&signing_key, policy_b64.as_bytes()));
    let boundary = "----s3dPostBoundary9912";
    let form_body = format!(
        "--{boundary}\r\nContent-Disposition: form-data; name=\"key\"\r\n\r\nuploads/${{filename}}\r\n\
         --{boundary}\r\nContent-Disposition: form-data; name=\"x-amz-algorithm\"\r\n\r\nAWS4-HMAC-SHA256\r\n\
         --{boundary}\r\nContent-Disposition: form-data; name=\"x-amz-credential\"\r\n\r\n{AK}/{scope}\r\n\
         --{boundary}\r\nContent-Disposition: form-data; name=\"x-amz-date\"\r\n\r\n{amz_date}\r\n\
         --{boundary}\r\nContent-Disposition: form-data; name=\"policy\"\r\n\r\n{policy_b64}\r\n\
         --{boundary}\r\nContent-Disposition: form-data; name=\"x-amz-signature\"\r\n\r\n{post_sig}\r\n\
         --{boundary}\r\nContent-Disposition: form-data; name=\"success_action_status\"\r\n\r\n201\r\n\
         --{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"hello.txt\"\r\nContent-Type: text/plain\r\n\r\nPostObject SigV4 body!\r\n\
         --{boundary}--\r\n"
    );
    let post_req = Request::builder()
        .method("POST")
        .uri("/")
        .header("host", &vh_host)
        .header(
            "content-type",
            format!("multipart/form-data; boundary={boundary}"),
        )
        .header("content-length", form_body.len().to_string())
        .body(Full::new(Bytes::from(form_body)))
        .unwrap();
    let (st_post, _, post_xml) = send_raw(s3_addr, post_req).await;
    assert_eq!(st_post, 201, "SigV4 PostObject must return 201 Created");
    let post_xml_str = std::str::from_utf8(&post_xml).unwrap();
    assert!(post_xml_str.contains("<Key>uploads/hello.txt</Key>"));

    // 4. PutBucketCors + OPTIONS preflight + Origin header on GET
    let cors_xml = Bytes::from_static(
        b"<CORSConfiguration><CORSRule>\
          <AllowedOrigin>https://*.app.example</AllowedOrigin>\
          <AllowedMethod>GET</AllowedMethod>\
          <AllowedHeader>x-custom-*</AllowedHeader>\
          <ExposeHeader>ETag</ExposeHeader>\
          <MaxAgeSeconds>600</MaxAgeSeconds>\
          </CORSRule></CORSConfiguration>",
    );
    let (cors_put, _, _, _) = sign_request(
        "PUT",
        "/",
        "cors=",
        &[
            ("host", &vh_host),
            ("content-length", &cors_xml.len().to_string()),
        ],
        &sha256_hex(&cors_xml),
        cors_xml,
    );
    let (st_cors_put, _, _) = send_raw(s3_addr, cors_put).await;
    assert_eq!(st_cors_put, 200);

    let opt_req = Request::builder()
        .method("OPTIONS")
        .uri("/uploads/hello.txt")
        .header("host", &vh_host)
        .header("origin", "https://ui.app.example")
        .header("access-control-request-method", "GET")
        .header("access-control-request-headers", "X-Custom-Token")
        .body(Full::new(Bytes::new()))
        .unwrap();
    let (st_opt, opt_hdrs, _) = send_raw(s3_addr, opt_req).await;
    assert_eq!(st_opt, 200);
    assert_eq!(
        opt_hdrs
            .get("access-control-allow-origin")
            .unwrap()
            .to_str()
            .unwrap(),
        "https://ui.app.example"
    );
    assert_eq!(
        opt_hdrs
            .get("access-control-allow-credentials")
            .unwrap()
            .to_str()
            .unwrap(),
        "true"
    );
    assert_eq!(
        opt_hdrs
            .get("access-control-allow-headers")
            .unwrap()
            .to_str()
            .unwrap(),
        "x-custom-token"
    );

    // 6. Unversioned -> Enabled -> Suspended overwrite replaces the initial `None` ("null") version
    let (p1_req, _, _, _) = sign_request(
        "PUT",
        "/plain-null.txt",
        "",
        &[("host", &vh_host), ("content-length", "5")],
        &sha256_hex(b"foooz"),
        Bytes::from_static(b"foooz"),
    );
    assert_eq!(send_raw(s3_addr, p1_req).await.0, 200);

    let ver_on = Bytes::from_static(
        b"<VersioningConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Status>Enabled</Status></VersioningConfiguration>",
    );
    let (von_req, _, _, _) = sign_request(
        "PUT",
        "/",
        "versioning=",
        &[("host", &vh_host), ("content-length", &ver_on.len().to_string())],
        &sha256_hex(&ver_on),
        ver_on,
    );
    assert_eq!(send_raw(s3_addr, von_req).await.0, 200);

    let ver_susp = Bytes::from_static(
        b"<VersioningConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Status>Suspended</Status></VersioningConfiguration>",
    );
    let (vsusp_req, _, _, _) = sign_request(
        "PUT",
        "/",
        "versioning=",
        &[("host", &vh_host), ("content-length", &ver_susp.len().to_string())],
        &sha256_hex(&ver_susp),
        ver_susp,
    );
    assert_eq!(send_raw(s3_addr, vsusp_req).await.0, 200);

    let (p2_req, _, _, _) = sign_request(
        "PUT",
        "/plain-null.txt",
        "",
        &[("host", &vh_host), ("content-length", "3")],
        &sha256_hex(b"zzz"),
        Bytes::from_static(b"zzz"),
    );
    assert_eq!(send_raw(s3_addr, p2_req).await.0, 200);

    let (lv_req, _, _, _) = sign_request(
        "GET",
        "/",
        "prefix=plain-null.txt&versions=",
        &[("host", &vh_host)],
        &sha256_hex(b""),
        Bytes::new(),
    );
    let (st_lv, _, lv_body) = send_raw(s3_addr, lv_req).await;
    assert_eq!(st_lv, 200);
    let lv_str = std::str::from_utf8(&lv_body).unwrap();
    assert_eq!(
        lv_str.matches("<Version>").count(),
        1,
        "Suspended overwrite must replace initial Unversioned null entry: {lv_str}"
    );

    // 7. PutBucketAcl with [CanonicalUser, Group] normalizes Group before CanonicalUser
    let acl_xml = Bytes::from_static(
        b"<AccessControlPolicy xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Owner><ID>u-main</ID><DisplayName>Main User</DisplayName></Owner><AccessControlList><Grant><Grantee xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"CanonicalUser\"><ID>u-main</ID><DisplayName>Main User</DisplayName></Grantee><Permission>FULL_CONTROL</Permission></Grant><Grant><Grantee xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"Group\"><URI>http://acs.amazonaws.com/groups/global/AllUsers</URI></Grantee><Permission>READ</Permission></Grant></AccessControlList></AccessControlPolicy>",
    );
    let (pacl_req, _, _, _) = sign_request(
        "PUT",
        "/",
        "acl=",
        &[("host", &vh_host), ("content-length", &acl_xml.len().to_string())],
        &sha256_hex(&acl_xml),
        acl_xml,
    );
    assert_eq!(send_raw(s3_addr, pacl_req).await.0, 200);

    let (gacl_req, _, _, _) = sign_request(
        "GET",
        "/",
        "acl=",
        &[("host", &vh_host)],
        &sha256_hex(b""),
        Bytes::new(),
    );
    let (st_gacl, _, gacl_body) = send_raw(s3_addr, gacl_req).await;
    assert_eq!(st_gacl, 200);
    let gacl_str = std::str::from_utf8(&gacl_body).unwrap();
    assert!(
        gacl_str.find("xsi:type=\"Group\"").unwrap()
            < gacl_str.find("xsi:type=\"CanonicalUser\"").unwrap(),
        "Group grants must precede CanonicalUser grants: {gacl_str}"
    );

    let _ = stop_tx.send(());
    srv_handle.await.unwrap();

    // Verify clean fsck after all M2 operations
    let fsck = s3d_engine::run_fsck(OsDisk::new(dir.path()).unwrap());
    assert!(fsck.errors.is_empty(), "fsck errors: {:?}", fsck.errors);
}
