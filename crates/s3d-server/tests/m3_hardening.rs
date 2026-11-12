//! Milestone M3 server & CLI hardening integration tests:
//! - `NFR-9`: `max_connections` overflow -> `503 SlowDown`, slow incomplete header disconnect,
//!   and idle keep-alive connection disconnect.
//! - `NFR-10` & `NFR-7`: JSON structured access logs (`request_id`, `caller`, `op`, `bucket`,
//!   `status`, `error_code`, `bytes`, `latency_us`) and zero secret leakage.
//! - `NFR-11` & `NFR-12`: Prometheus `/metrics` histograms/gauges + admin port isolation with
//!   buckets literally named `metrics` and `health`.
//! - `NFR-13` & `NFR-14`: Real `s3d serve` `SIGTERM` graceful drain + checkpoint-on-exit,
//!   `s3d compact`, and `s3d fsck` exit codes on clean vs corrupted storage.
//! - `NFR-16`: HTTP `503 SlowDown` on low disk space while HTTP `GET` and `DELETE` succeed.

use std::fs;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use hmac::{Hmac, Mac};
use http_body_util::{BodyExt, Full};
use hyper::client::conn::http1;
use hyper::Request;
use hyper_util::rt::TokioIo;
use s3d_disk::{FaultDisk, OsDisk};
use s3d_engine::{Engine, EngineConfig};
use s3d_proto::SigV4Verifier;
use s3d_server::config::ServerConfig;
use s3d_server::metrics::ServerMetrics;
use s3d_server::run_listeners_with_telemetry;
use s3d_types::{AccountRecord, OwnerInfo, SecretKey};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;

type HmacSha256 = Hmac<Sha256>;

const AK: &str = "AKIAIOSFODNN7EXAMPLE";
const SK: &str = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
const REGION: &str = "us-east-1";

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

fn build_signed_req(
    method: &str,
    host: &str,
    path: &str,
    body: Bytes,
) -> Request<Full<Bytes>> {
    let (ymd, amz_date) = now_amz_date();
    let payload_hash = sha256_hex(&body);
    let canonical_headers =
        format!("host:{host}\nx-amz-content-sha256:{payload_hash}\nx-amz-date:{amz_date}\n");
    let signed_headers = "host;x-amz-content-sha256;x-amz-date";
    let canonical_req = format!(
        "{method}\n{path}\n\n{canonical_headers}\n{signed_headers}\n{payload_hash}"
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

    Request::builder()
        .method(method)
        .uri(path)
        .header("Host", host)
        .header("x-amz-date", amz_date)
        .header("x-amz-content-sha256", payload_hash)
        .header("Authorization", auth_hdr)
        .header("Content-Length", body.len().to_string())
        .body(Full::new(body))
        .unwrap()
}

async fn send_once(
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

fn test_auth() -> Arc<SigV4Verifier> {
    Arc::new(SigV4Verifier::new(
        REGION.to_string(),
        vec![AccountRecord {
            owner: OwnerInfo {
                user_id: "0123456789abcdef".into(),
                display_name: "main".into(),
                email: "main@example.com".into(),
            },
            access_key: AK.into(),
            secret_key: SecretKey::new(SK),
        }],
    ))
}

#[tokio::test]
async fn nfr9_connection_limits_header_timeout_and_idle_timeout() {
    let dir = tempfile::tempdir().unwrap();
    let disk = OsDisk::new(dir.path()).unwrap();
    let engine = Engine::open(disk, EngineConfig::default()).unwrap();
    let s3_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let admin_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let s3_addr = s3_listener.local_addr().unwrap();

    let cfg = ServerConfig {
        max_connections: 2,
        header_read_timeout: Duration::from_millis(220),
        idle_timeout: Duration::from_millis(260),
        ..ServerConfig::default()
    };
    let metrics = Arc::new(ServerMetrics::default());
    let (stop_tx, stop_rx) = oneshot::channel::<()>();

    let eng_h = Arc::clone(&engine);
    let eng_m = Arc::clone(&engine);
    let srv = tokio::spawn(async move {
        run_listeners_with_telemetry(
            s3_listener,
            admin_listener,
            engine,
            test_auth(),
            cfg,
            metrics,
            move || eng_h.is_read_only_poisoned(),
            move || Some(eng_m.metrics_snapshot()),
            async move {
                let _ = stop_rx.await;
            },
        )
        .await
        .unwrap();
    });

    let host = s3_addr.to_string();

    // 1. Hold 2 active keep-alive connections (`max_connections = 2`), verify 3rd gets 503 SlowDown
    let c1 = TcpStream::connect(s3_addr).await.unwrap();
    let (mut s1, conn1) = http1::handshake(TokioIo::new(c1)).await.unwrap();
    tokio::spawn(async move {
        let _ = conn1.await;
    });
    let r1 = s1
        .send_request(build_signed_req("GET", &host, "/", Bytes::new()))
        .await
        .unwrap();
    assert_eq!(r1.status().as_u16(), 200);
    let _ = r1.into_body().collect().await.unwrap();

    let c2 = TcpStream::connect(s3_addr).await.unwrap();
    let (mut s2, conn2) = http1::handshake(TokioIo::new(c2)).await.unwrap();
    tokio::spawn(async move {
        let _ = conn2.await;
    });
    let r2 = s2
        .send_request(build_signed_req("GET", &host, "/", Bytes::new()))
        .await
        .unwrap();
    assert_eq!(r2.status().as_u16(), 200);
    let _ = r2.into_body().collect().await.unwrap();

    // 3rd concurrent connection MUST receive 503 SlowDown
    let (status3, _, body3) =
        send_once(s3_addr, build_signed_req("GET", &host, "/", Bytes::new())).await;
    assert_eq!(status3, 503);
    let xml3 = String::from_utf8_lossy(&body3);
    assert!(xml3.contains("<Code>SlowDown</Code>"), "got: {xml3}");

    // 2. Idle keep-alive timeout (`260ms`): wait for s1 & s2 to be closed by server automatically!
    drop(s2);
    let t_idle = Instant::now();
    tokio::time::sleep(Duration::from_millis(380)).await;
    assert!(
        s1.send_request(build_signed_req("GET", &host, "/", Bytes::new()))
            .await
            .is_err(),
        "expected idle connection s1 to be closed after {:?}",
        t_idle.elapsed()
    );
    drop(s1);

    // 3. Slow header timeout (`220ms`): send partial request headers and verify server disconnects
    let mut slow = TcpStream::connect(s3_addr).await.unwrap();
    slow.write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nX-Slow: ")
        .await
        .unwrap();
    let t0 = Instant::now();
    let mut buf = [0u8; 256];
    let n = tokio::time::timeout(Duration::from_secs(2), slow.read(&mut buf))
        .await
        .expect("server did not close slow-header connection in time")
        .unwrap_or(0);
    let elapsed = t0.elapsed();
    // Server either closes immediately (n == 0) or writes 408/400 and closes
    if n > 0 {
        let mut rest = Vec::new();
        let _ = tokio::time::timeout(Duration::from_secs(1), slow.read_to_end(&mut rest))
            .await
            .expect("connection should close after timeout response");
    }
    assert!(
        elapsed < Duration::from_secs(1),
        "slow header disconnect took too long: {elapsed:?}"
    );

    let _ = stop_tx.send(());
    srv.await.unwrap();
}

#[tokio::test]
async fn nfr11_nfr12_prometheus_metrics_and_admin_port_isolation() {
    let dir = tempfile::tempdir().unwrap();
    let disk = OsDisk::new(dir.path()).unwrap();
    let engine = Engine::open(disk, EngineConfig::default()).unwrap();
    let s3_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let admin_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let s3_addr = s3_listener.local_addr().unwrap();
    let admin_addr = admin_listener.local_addr().unwrap();

    let metrics = Arc::new(ServerMetrics::default());
    let (stop_tx, stop_rx) = oneshot::channel::<()>();

    let eng_h = Arc::clone(&engine);
    let eng_m = Arc::clone(&engine);
    let srv_eng = Arc::clone(&engine);
    let srv = tokio::spawn(async move {
        run_listeners_with_telemetry(
            s3_listener,
            admin_listener,
            srv_eng,
            test_auth(),
            ServerConfig::default(),
            metrics,
            move || eng_h.is_read_only_poisoned(),
            move || Some(eng_m.metrics_snapshot()),
            async move {
                let _ = stop_rx.await;
            },
        )
        .await
        .unwrap();
    });

    let host = s3_addr.to_string();

    // Create buckets literally named `metrics` and `health` on S3 port (`NFR-12`)
    for bkt in ["metrics", "health"] {
        let (st, _, _) = send_once(
            s3_addr,
            build_signed_req("PUT", &host, &format!("/{bkt}"), Bytes::new()),
        )
        .await;
        assert_eq!(st, 200, "CreateBucket /{bkt} failed");

        let payload = Bytes::from(format!("payload-for-{bkt}"));
        let (st_put, _, _) = send_once(
            s3_addr,
            build_signed_req("PUT", &host, &format!("/{bkt}/item.txt"), payload.clone()),
        )
        .await;
        assert_eq!(st_put, 200);

        let (st_get, _, body) = send_once(
            s3_addr,
            build_signed_req("GET", &host, &format!("/{bkt}/item.txt"), Bytes::new()),
        )
        .await;
        assert_eq!(st_get, 200);
        assert_eq!(body, payload);
    }

    // Trigger a checkpoint & GC run so checkpoint/GC counters are exercised
    engine.write_checkpoint().await.unwrap();
    engine.compact().await.unwrap();

    // Query `/health` and `/metrics` on isolated admin port (`NFR-11`, `NFR-12`)
    let admin_host = admin_addr.to_string();
    let (st_h, _, body_h) = send_once(
        admin_addr,
        Request::builder()
            .method("GET")
            .uri("/health")
            .header("Host", &admin_host)
            .body(Full::new(Bytes::new()))
            .unwrap(),
    )
    .await;
    assert_eq!(st_h, 200);
    assert_eq!(std::str::from_utf8(&body_h).unwrap().trim(), "{\"status\":\"ok\"}");

    let (st_m, _, body_m) = send_once(
        admin_addr,
        Request::builder()
            .method("GET")
            .uri("/metrics")
            .header("Host", &admin_host)
            .body(Full::new(Bytes::new()))
            .unwrap(),
    )
    .await;
    assert_eq!(st_m, 200);
    let prom = String::from_utf8(body_m.to_vec()).unwrap();

    for expected in [
        "s3d_operation_requests_total{op=\"CreateBucket\",status=\"200\"} 2",
        "s3d_operation_requests_total{op=\"PutObject\",status=\"200\"} 2",
        "s3d_operation_requests_total{op=\"GetObject\",status=\"200\"} 2",
        "s3d_operation_duration_seconds_bucket{op=\"PutObject\",status=\"200\"",
        "s3d_fsync_duration_seconds_bucket{kind=\"wal\"",
        "s3d_fsync_duration_seconds_bucket{kind=\"seg\"",
        "s3d_fsync_duration_seconds_bucket{kind=\"ckpt\"",
        "s3d_group_commit_batch_size_bucket{",
        "s3d_wal_bytes ",
        "s3d_segment_live_ratio ",
        "s3d_gc_runs_total 1",
        "s3d_checkpoints_total 1",
        "s3d_catalog_buckets 2",
        "s3d_catalog_object_versions 2",
        "s3d_catalog_open_uploads 0",
    ] {
        assert!(
            prom.contains(expected),
            "missing Prometheus metric '{expected}' in:\n{prom}"
        );
    }

    let _ = stop_tx.send(());
    srv.await.unwrap();
}

#[tokio::test]
async fn nfr16_http_low_disk_space_returns_503_slowdown_while_get_and_delete_succeed() {
    let disk = FaultDisk::new();
    let engine = Engine::open(
        disk.clone(),
        EngineConfig {
            reserved_disk_bytes: 2 * 1024 * 1024 * 1024,
            ..EngineConfig::default()
        },
    )
    .unwrap();
    let s3_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let admin_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let s3_addr = s3_listener.local_addr().unwrap();

    let metrics = Arc::new(ServerMetrics::default());
    let (stop_tx, stop_rx) = oneshot::channel::<()>();
    let eng_h = Arc::clone(&engine);
    let eng_m = Arc::clone(&engine);
    let srv = tokio::spawn(async move {
        run_listeners_with_telemetry(
            s3_listener,
            admin_listener,
            engine,
            test_auth(),
            ServerConfig::default(),
            metrics,
            move || eng_h.is_read_only_poisoned(),
            move || Some(eng_m.metrics_snapshot()),
            async move {
                let _ = stop_rx.await;
            },
        )
        .await
        .unwrap();
    });

    let host = s3_addr.to_string();
    assert_eq!(
        send_once(s3_addr, build_signed_req("PUT", &host, "/lowdisk", Bytes::new()))
            .await
            .0,
        200
    );
    assert_eq!(
        send_once(
            s3_addr,
            build_signed_req("PUT", &host, "/lowdisk/existing", Bytes::from_static(b"keep"))
        )
        .await
        .0,
        200
    );

    // Simulate nearly full disk (< 2 GiB free)
    disk.set_available_bytes(100 * 1024 * 1024);

    let (st_put, _, body_put) = send_once(
        s3_addr,
        build_signed_req("PUT", &host, "/lowdisk/new", Bytes::from_static(b"reject")),
    )
    .await;
    assert_eq!(st_put, 503);
    assert!(String::from_utf8_lossy(&body_put).contains("<Code>SlowDown</Code>"));

    // GET & DELETE still work!
    let (st_get, _, body_get) = send_once(
        s3_addr,
        build_signed_req("GET", &host, "/lowdisk/existing", Bytes::new()),
    )
    .await;
    assert_eq!(st_get, 200);
    assert_eq!(&body_get[..], b"keep");

    let (st_del, _, _) = send_once(
        s3_addr,
        build_signed_req("DELETE", &host, "/lowdisk/existing", Bytes::new()),
    )
    .await;
    assert_eq!(st_del, 204);

    let _ = stop_tx.send(());
    srv.await.unwrap();
}

#[cfg(unix)]
#[tokio::test]
async fn nfr10_nfr13_nfr14_cli_json_logs_sigterm_checkpoint_compact_and_fsck() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let data_dir = dir.path().join("data");
    let cred_path = dir.path().join("credentials.toml");
    fs::write(
        &cred_path,
        format!(
            "[[accounts]]\nuser_id = \"0123456789abcdef\"\ndisplay_name = \"main\"\nemail = \"main@example.com\"\naccess_key = \"{AK}\"\nsecret_key = \"{SK}\"\n"
        ),
    )
    .unwrap();
    fs::set_permissions(&cred_path, fs::Permissions::from_mode(0o600)).unwrap();

    // Reserve two free loopback ports
    let l1 = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let s3_addr = l1.local_addr().unwrap();
    let l2 = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let admin_addr = l2.local_addr().unwrap();
    drop(l1);
    drop(l2);

    let bin = env!("CARGO_BIN_EXE_s3d");
    let mut child = Command::new(bin)
        .args([
            "serve",
            "--listen",
            &s3_addr.to_string(),
            "--admin-listen",
            &admin_addr.to_string(),
            "--data-dir",
            data_dir.to_str().unwrap(),
            "--credentials-file",
            cred_path.to_str().unwrap(),
            "--log-format",
            "json",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn s3d serve");

    // Wait until `/health` responds 200 OK
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if Instant::now() > deadline {
            let _ = child.kill();
            panic!("s3d serve did not become healthy within 10s");
        }
        if let Ok(stream) = TcpStream::connect(admin_addr).await {
            let io = TokioIo::new(stream);
            if let Ok((mut sender, conn)) = http1::handshake(io).await {
                tokio::spawn(async move {
                    let _ = conn.await;
                });
                if let Ok(resp) = sender
                    .send_request(
                        Request::builder()
                            .method("GET")
                            .uri("/health")
                            .header("Host", admin_addr.to_string())
                            .body(Full::new(Bytes::new()))
                            .unwrap(),
                    )
                    .await
                    && resp.status().as_u16() == 200 {
                        break;
                    }
            }
        }
        tokio::time::sleep(Duration::from_millis(40)).await;
    }

    let host = s3_addr.to_string();
    assert_eq!(
        send_once(s3_addr, build_signed_req("PUT", &host, "/cli-bkt", Bytes::new()))
            .await
            .0,
        200
    );
    let payload = Bytes::from(vec![0x7A; 4096]);
    assert_eq!(
        send_once(
            s3_addr,
            build_signed_req("PUT", &host, "/cli-bkt/obj1", payload.clone())
        )
        .await
        .0,
        200
    );
    let (st_get, _, got_body) = send_once(
        s3_addr,
        build_signed_req("GET", &host, "/cli-bkt/obj1", Bytes::new()),
    )
    .await;
    assert_eq!(st_get, 200);
    assert_eq!(got_body, payload);

    // Also trigger a 404 NoSuchKey to verify `error_code` field in JSON access log
    let (st_404, _, _) = send_once(
        s3_addr,
        build_signed_req("GET", &host, "/cli-bkt/missing-key", Bytes::new()),
    )
    .await;
    assert_eq!(st_404, 404);

    // Send SIGTERM via `kill -TERM <pid>` (`NFR-14`)
    let pid_str = child.id().to_string();
    assert!(
        Command::new("kill")
            .args(["-TERM", &pid_str])
            .status()
            .unwrap()
            .success()
    );

    let output = child.wait_with_output().expect("wait s3d exit");
    assert!(
        output.status.success(),
        "s3d serve exited non-zero on SIGTERM: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout_str = String::from_utf8(output.stdout).unwrap();
    let stderr_str = String::from_utf8(output.stderr).unwrap();

    // [NFR-7] Secret key MUST NEVER appear in stdout or stderr!
    assert!(!stdout_str.contains(SK), "secret key leaked in stdout!");
    assert!(!stderr_str.contains(SK), "secret key leaked in stderr!");

    // [NFR-10] Parse JSON log lines and verify all 8 structured access log fields
    let mut s3_req_logs = Vec::new();
    for line in stdout_str.lines().filter(|l| !l.trim().is_empty()) {
        let v: serde_json::Value = serde_json::from_str(line)
            .unwrap_or_else(|e| panic!("non-JSON log line: {line} ({e})"));
        if v.get("fields")
            .and_then(|f| f.get("message"))
            .and_then(|m| m.as_str())
            == Some("s3_request")
        {
            s3_req_logs.push(v["fields"].clone());
        }
    }
    assert_eq!(s3_req_logs.len(), 4, "expected 4 s3_request log entries: {s3_req_logs:?}");

    for entry in &s3_req_logs {
        for required_key in [
            "request_id",
            "caller",
            "op",
            "bucket",
            "status",
            "error_code",
            "bytes",
            "latency_us",
        ] {
            assert!(
                entry.get(required_key).is_some(),
                "missing NFR-10 field '{required_key}' in {entry}"
            );
        }
    }
    let put_log = s3_req_logs
        .iter()
        .find(|e| e["op"] == "PutObject")
        .expect("PutObject log");
    assert_eq!(put_log["bucket"], "cli-bkt");
    assert_eq!(put_log["status"], 200);
    assert_eq!(put_log["error_code"], "");
    assert_eq!(put_log["bytes"], 4096);

    let err_log = s3_req_logs
        .iter()
        .find(|e| e["status"] == 404)
        .expect("404 GetObject log");
    assert_eq!(err_log["error_code"], "NoSuchKey");

    // [NFR-14] Verify checkpoint file was written on graceful SIGTERM exit!
    let ckpt_entries: Vec<_> = fs::read_dir(data_dir.join("ckpt"))
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().to_string())
        .filter(|n| n.starts_with("ckpt-"))
        .collect();
    assert!(
        !ckpt_entries.is_empty(),
        "expected shutdown checkpoint in ckpt/, found none"
    );

    // [NFR-14] Run `s3d compact` CLI
    let compact_out = Command::new(bin)
        .args(["compact", "--data-dir", data_dir.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(compact_out.status.success());

    // [NFR-13] Run `s3d fsck` on healthy directory -> exit 0, status == "ok"
    let fsck_ok = Command::new(bin)
        .args(["fsck", "--data-dir", data_dir.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(fsck_ok.status.success(), "clean fsck failed: {fsck_ok:?}");
    let rep_ok: serde_json::Value = serde_json::from_slice(&fsck_ok.stdout).unwrap();
    assert_eq!(rep_ok["status"], "ok");
    assert_eq!(rep_ok["bytes_verified"], 4096);

    // [NFR-13] Corrupt a byte inside `seg/00000001.seg` -> `s3d fsck` MUST exit non-zero (1)!
    let seg_path = data_dir.join("seg/00000001.seg");
    let mut seg_bytes = fs::read(&seg_path).unwrap();
    seg_bytes[64] ^= 0xFF;
    fs::write(&seg_path, &seg_bytes).unwrap();

    let fsck_bad = Command::new(bin)
        .args(["fsck", "--data-dir", data_dir.to_str().unwrap()])
        .output()
        .unwrap();
    assert_eq!(fsck_bad.status.code(), Some(1), "corrupt fsck should exit 1");
    let rep_bad: serde_json::Value = serde_json::from_slice(&fsck_bad.stdout).unwrap();
    assert_eq!(rep_bad["status"], "corrupted");
    assert!(!rep_bad["errors"].as_array().unwrap().is_empty());
}
