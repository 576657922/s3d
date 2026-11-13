//! `s3d-bench` (`VR-9`): End-to-end performance, memory, cold-recovery, and `fsck` verification
//! suite covering `NFR-1`..`NFR-6` against a real `s3d serve` child process.

use std::convert::Infallible;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use bytes::Bytes;
use clap::Parser;
use hmac::{Hmac, Mac};
use http_body::{Body, Frame, SizeHint};
use http_body_util::{BodyExt, Full};
use hyper::client::conn::http1;
use hyper::Request;
use hyper_util::rt::TokioIo;
use md5::Md5;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use s3d_disk::{Disk, DiskFile, OpenOpts, OsDisk};
use s3d_engine::{Engine, EngineConfig};
use s3d_model::InMemoryVerifiedStream;
use s3d_types::{
    CallerContext, CreateBucketReq, ObjectOwnership, ObjectStore, OwnerInfo, Preconditions,
    PutObjectReq, RawSseHeaders, RawUploadObjectLockHeaders, RequestPolicyContext, SystemMeta,
    MAX_SINGLE_PUT_BYTES,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use tokio::net::TcpStream;

type HmacSha256 = Hmac<Sha256>;

const AK: &str = "AKIAIOSFODNN7EXAMPLE";
const SK: &str = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
const REGION: &str = "us-east-1";

const ONE_MIB: usize = 1024 * 1024;
const ONE_GIB: u64 = 1024 * 1024 * 1024;
const TEN_GIB: u64 = 10 * ONE_GIB;

#[derive(Parser, Debug)]
#[command(name = "s3d-bench", about = "VR-9 NFR-1..NFR-6 benchmark & acceptance gate")]
struct Args {
    /// Path to compiled `s3d` binary (defaults to sibling `s3d` next to `s3d-bench` or `target/release/s3d`).
    #[arg(long)]
    s3d_bin: Option<PathBuf>,

    /// Output JSON report path.
    #[arg(long, default_value = "reports/m3-bench.json")]
    report: PathBuf,

    /// Duration in seconds for each of NFR-1 (PUT) and NFR-2 (GET). Spec §9 requires 300s (5 min).
    #[arg(long, default_value_t = 300)]
    put_get_secs: u64,

    /// Number of object versions for NFR-4 / NFR-6. Spec §9 requires 1,000,000.
    #[arg(long, default_value_t = 1_000_000)]
    million_count: usize,

    /// Total bytes for NFR-5 large streaming multipart upload. Spec §9 requires 10 GiB.
    #[arg(long, default_value_t = TEN_GIB)]
    nfr5_upload_bytes: u64,

    /// Optional working directory for temporary benchmark datasets and `fio` files
    /// (defaults to a fresh system tempdir; use a mounted ext4/XFS volume inside containers).
    #[arg(long)]
    work_dir: Option<PathBuf>,

    #[arg(long, hide = true)]
    internal_loopback_port: Option<u16>,

    #[arg(long, hide = true)]
    internal_loopback_file: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize)]
struct LatencySummary {
    samples: usize,
    p50_ms: f64,
    p95_ms: f64,
    p99_ms: f64,
    max_ms: f64,
}

#[derive(Debug, Clone, Serialize)]
struct DiskBaselineReport {
    baseline_source: String,
    iterations: usize,
    seq_write_runs_mib_s: Vec<f64>,
    seq_write_median_mib_s: f64,
    seq_read_runs_mib_s: Vec<f64>,
    seq_read_median_mib_s: f64,
    md5_single_core_runs_mib_s: Vec<f64>,
    md5_single_core_median_mib_s: f64,
    http_crc32c_loopback_runs_mib_s: Vec<f64>,
    http_crc32c_loopback_median_mib_s: f64,
    /// Spec §9 M3 baseline-locked single-stream `PutObject` ceiling:
    /// `min(seq_write_median_mib_s, md5_single_core_median_mib_s)` because S3 `FR-1` mandates
    /// serial 64-round RFC 1321 MD5 `ETag` computation over every single-stream `PutObject`.
    effective_single_stream_put_baseline_mib_s: f64,
    /// Single-connection HTTP/1.1 TCP loopback + `ST-5` `CRC32C` streaming read ceiling:
    /// `min(seq_read_median_mib_s, http_crc32c_loopback_median_mib_s)` (equals raw `fio` on
    /// cloud/NVMe disks; prevents RAM-cached VM virtual disks from exceeding TCP loopback speed).
    effective_single_stream_get_baseline_mib_s: f64,
}

#[derive(Debug, Clone, Serialize)]
struct Nfr1SmallPutReport {
    duration_secs: f64,
    concurrency: usize,
    object_bytes: usize,
    total_ops: usize,
    ops_per_sec: f64,
    latency: LatencySummary,
    target_min_ops_per_sec: f64,
    target_max_p99_ms: f64,
    passed: bool,
}

#[derive(Debug, Clone, Serialize)]
struct Nfr2SmallGetReport {
    duration_secs: f64,
    concurrency: usize,
    object_bytes: usize,
    total_ops: usize,
    ops_per_sec: f64,
    latency: LatencySummary,
    target_min_ops_per_sec: f64,
    target_max_p99_ms: f64,
    passed: bool,
}

#[derive(Debug, Clone, Serialize)]
struct Nfr3LargeStreamReport {
    object_bytes: u64,
    iterations: usize,
    put_runs_mib_s: Vec<f64>,
    put_median_mib_s: f64,
    put_ratio_vs_raw_disk: f64,
    put_ratio_vs_effective_baseline: f64,
    target_min_put_ratio: f64,
    get_runs_mib_s: Vec<f64>,
    get_median_mib_s: f64,
    get_ratio_vs_disk: f64,
    get_ratio_vs_effective_baseline: f64,
    target_min_get_ratio: f64,
    fsck_verified_bytes: u64,
    raw_disk_formula_passed: bool,
    passed: bool,
}

#[derive(Debug, Clone, Serialize)]
struct Nfr4ListMillionReport {
    total_objects: usize,
    page_size: usize,
    queries: usize,
    latency: LatencySummary,
    target_max_p99_ms: f64,
    passed: bool,
}

#[derive(Debug, Clone, Serialize)]
struct Nfr5MemoryReport {
    idle_rss_mib: f64,
    target_max_idle_rss_mib: f64,
    streamed_object_bytes: u64,
    rss_samples_during_upload: usize,
    peak_upload_rss_mib: f64,
    max_allowed_peak_rss_mib: f64,
    fsck_verified_bytes: u64,
    passed: bool,
}

#[derive(Debug, Clone, Serialize)]
struct Nfr6ColdRecoveryReport {
    total_versions: usize,
    checkpoint_versions: usize,
    wal_replay_versions: usize,
    kill9_to_health200_secs: f64,
    target_max_secs: f64,
    fsck_verified_versions: usize,
    passed: bool,
}

#[derive(Debug, Clone, Serialize)]
struct FullBenchReport {
    generated_at_epoch_s: u64,
    os: String,
    arch: String,
    cpu_cores_available: usize,
    disk_baseline: DiskBaselineReport,
    nfr1_small_put: Nfr1SmallPutReport,
    nfr2_small_get: Nfr2SmallGetReport,
    nfr3_large_stream: Nfr3LargeStreamReport,
    nfr4_list_1m: Nfr4ListMillionReport,
    nfr5_memory: Nfr5MemoryReport,
    nfr6_cold_recovery: Nfr6ColdRecoveryReport,
    all_passed: bool,
}

/// Zero-allocation streaming HTTP request body yielding slices of a shared `256 KiB` `Bytes` buffer.
struct CountingChunkBody {
    chunk: Bytes,
    remaining: u64,
    total: u64,
}

impl CountingChunkBody {
    fn new(chunk: Bytes, total: u64) -> Self {
        Self {
            chunk,
            remaining: total,
            total,
        }
    }
}

impl Body for CountingChunkBody {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        if self.remaining == 0 {
            return Poll::Ready(None);
        }
        let step = (self.chunk.len() as u64).min(self.remaining) as usize;
        self.remaining -= step as u64;
        let data = if step == self.chunk.len() {
            self.chunk.clone()
        } else {
            self.chunk.slice(..step)
        };
        Poll::Ready(Some(Ok(Frame::data(data))))
    }

    fn is_end_stream(&self) -> bool {
        self.remaining == 0
    }

    fn size_hint(&self) -> SizeHint {
        SizeHint::with_exact(self.total)
    }
}

fn summarize_latencies_us(mut us: Vec<u64>) -> LatencySummary {
    us.sort_unstable();
    let n = us.len();
    if n == 0 {
        return LatencySummary {
            samples: 0,
            p50_ms: 0.0,
            p95_ms: 0.0,
            p99_ms: 0.0,
            max_ms: 0.0,
        };
    }
    let pick = |pct: f64| -> f64 {
        let idx = ((n as f64 * pct).ceil() as usize)
            .saturating_sub(1)
            .min(n - 1);
        (us[idx] as f64) / 1000.0
    };
    LatencySummary {
        samples: n,
        p50_ms: pick(0.50),
        p95_ms: pick(0.95),
        p99_ms: pick(0.99),
        max_ms: (us[n - 1] as f64) / 1000.0,
    }
}

fn median_f64(vals: &[f64]) -> f64 {
    let mut s = vals.to_vec();
    s.sort_by(|a, b| a.partial_cmp(b).unwrap());
    s[s.len() / 2]
}

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

/// Sign an S3 request using `UNSIGNED-PAYLOAD` or an explicit payload hash.
fn sign_s3_headers(
    method: &str,
    host: &str,
    path: &str,
    canonical_query: &str,
    payload_hash: &str,
) -> (String, String) {
    let (ymd, amz_date) = now_amz_date();
    let canonical_headers =
        format!("host:{host}\nx-amz-content-sha256:{payload_hash}\nx-amz-date:{amz_date}\n");
    let signed_headers = "host;x-amz-content-sha256;x-amz-date";
    let canonical_req = format!(
        "{method}\n{path}\n{canonical_query}\n{canonical_headers}\n{signed_headers}\n{payload_hash}"
    );
    let scope = format!("{ymd}/{REGION}/s3/aws4_request");
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{}",
        sha256_hex(canonical_req.as_bytes())
    );
    let signing_key = derive_signing_key(SK, &ymd, REGION);
    let sig = hex::encode(hmac_sha256(&signing_key, string_to_sign.as_bytes()));
    let auth = format!(
        "AWS4-HMAC-SHA256 Credential={AK}/{scope}, SignedHeaders={signed_headers}, Signature={sig}"
    );
    (amz_date, auth)
}

fn build_fixed_req(
    method: &str,
    host: &str,
    path: &str,
    canonical_query: &str,
    payload_hash: &str,
    body: Bytes,
) -> Request<Full<Bytes>> {
    let (amz_date, auth) = sign_s3_headers(method, host, path, canonical_query, payload_hash);
    let uri = if canonical_query.is_empty() {
        path.to_string()
    } else {
        format!("{path}?{canonical_query}")
    };
    let mut b = Request::builder()
        .method(method)
        .uri(uri)
        .header("Host", host)
        .header("x-amz-date", amz_date)
        .header("x-amz-content-sha256", payload_hash)
        .header("Authorization", auth);
    if matches!(method, "PUT" | "POST") {
        b = b.header("Content-Length", body.len().to_string());
    }
    b.body(Full::new(body)).unwrap()
}

fn build_streaming_req(
    method: &str,
    host: &str,
    path: &str,
    canonical_query: &str,
    chunk: Bytes,
    total_len: u64,
) -> Request<CountingChunkBody> {
    let payload_hash = "UNSIGNED-PAYLOAD";
    let (amz_date, auth) = sign_s3_headers(method, host, path, canonical_query, payload_hash);
    let uri = if canonical_query.is_empty() {
        path.to_string()
    } else {
        format!("{path}?{canonical_query}")
    };
    Request::builder()
        .method(method)
        .uri(uri)
        .header("Host", host)
        .header("x-amz-date", amz_date)
        .header("x-amz-content-sha256", payload_hash)
        .header("Content-Length", total_len.to_string())
        .header("Authorization", auth)
        .body(CountingChunkBody::new(chunk, total_len))
        .unwrap()
}

fn pick_free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn resolve_s3d_binary(explicit: Option<PathBuf>) -> PathBuf {
    if let Some(p) = explicit {
        assert!(p.exists(), "explicit --s3d-bin {} does not exist", p.display());
        return p;
    }
    if let Ok(exe) = std::env::current_exe()
        && let Some(dir) = exe.parent() {
            let sibling = dir.join("s3d");
            if sibling.exists() {
                return sibling;
            }
        }
    let fallback = PathBuf::from("target/release/s3d");
    assert!(
        fallback.exists(),
        "could not find compiled `s3d` binary at {}; run `cargo build --release -p s3d-server --bin s3d` first",
        fallback.display()
    );
    fallback
}

struct RunningS3d {
    child: Child,
    s3_addr: String,
    admin_addr: String,
    data_dir: PathBuf,
    s3d_bin: PathBuf,
}

impl RunningS3d {
    async fn spawn(s3d_bin: &Path, work_dir: &Path, data_dir: &Path) -> Self {
        fs::create_dir_all(work_dir).unwrap();
        fs::create_dir_all(data_dir).unwrap();
        let creds_path = work_dir.join("credentials.toml");
        let creds_body = format!(
            "[[accounts]]\naccess_key = \"{AK}\"\nsecret_key = \"{SK}\"\nuser_id = \"0123456789abcdef\"\ndisplay_name = \"bench\"\nemail = \"bench@example.com\"\n"
        );
        fs::write(&creds_path, creds_body).unwrap();
        fs::set_permissions(&creds_path, fs::Permissions::from_mode(0o600)).unwrap();

        let s3_port = pick_free_port();
        let admin_port = pick_free_port();
        let s3_addr = format!("127.0.0.1:{s3_port}");
        let admin_addr = format!("127.0.0.1:{admin_port}");

        let cfg_path = work_dir.join("s3d.toml");
        let cfg_body = format!(
            "listen = \"{s3_addr}\"\nadmin_listen = \"{admin_addr}\"\ndata_dir = \"{}\"\ncredentials_file = \"{}\"\nregion = \"{REGION}\"\nmax_connections = 1024\nreserved_disk_bytes = 536870912\ngroup_commit_window_ms = 1\ngroup_commit_max_batch = 64\n",
            data_dir.display(),
            creds_path.display()
        );
        fs::write(&cfg_path, cfg_body).unwrap();

        let child = Command::new(s3d_bin)
            .args(["serve", "--config", cfg_path.to_str().unwrap()])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("failed to spawn s3d serve");

        let inst = Self {
            child,
            s3_addr,
            admin_addr,
            data_dir: data_dir.to_path_buf(),
            s3d_bin: s3d_bin.to_path_buf(),
        };
        inst.wait_until_healthy(Duration::from_secs(60)).await;
        inst
    }

    fn pid(&self) -> u32 {
        self.child.id()
    }

    async fn wait_until_healthy(&self, timeout: Duration) {
        let deadline = Instant::now() + timeout;
        loop {
            if let Ok(stream) = TcpStream::connect(&self.admin_addr).await
                && let Ok((mut sender, conn)) = http1::handshake(TokioIo::new(stream)).await {
                    tokio::spawn(async move {
                        let _ = conn.await;
                    });
                    let req = Request::builder()
                        .method("GET")
                        .uri("/health")
                        .header("Host", &self.admin_addr)
                        .body(Full::new(Bytes::new()))
                        .unwrap();
                    if let Ok(resp) = sender.send_request(req).await
                        && resp.status().as_u16() == 200 {
                            return;
                        }
                }
            assert!(
                Instant::now() < deadline,
                "timed out waiting for s3d /health 200 OK on {}",
                self.admin_addr
            );
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }

    fn sigterm_and_wait(&mut self) {
        let _ = Command::new("kill")
            .args(["-TERM", &self.child.id().to_string()])
            .status();
        let _ = self.child.wait();
    }

    fn sigkill_and_wait(&mut self) {
        let _ = Command::new("kill")
            .args(["-KILL", &self.child.id().to_string()])
            .status();
        let _ = self.child.wait();
    }

    fn run_fsck_json(&self) -> serde_json::Value {
        let out = Command::new(&self.s3d_bin)
            .args(["fsck", "--data-dir", self.data_dir.to_str().unwrap()])
            .output()
            .expect("failed to execute s3d fsck");
        assert!(
            out.status.success(),
            "s3d fsck failed (exit {:?}): stdout={} stderr={}",
            out.status.code(),
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        serde_json::from_slice(&out.stdout).expect("invalid JSON from s3d fsck")
    }
}

impl Drop for RunningS3d {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn sample_process_rss_mib(pid: u32) -> Option<f64> {
    #[cfg(target_os = "linux")]
    {
        if let Ok(status) = fs::read_to_string(format!("/proc/{pid}/status")) {
            for line in status.lines() {
                if let Some(rest) = line.strip_prefix("VmRSS:") {
                    let kib_str = rest.trim().split_whitespace().next()?;
                    let kib: u64 = kib_str.parse().ok()?;
                    return Some((kib as f64) / 1024.0);
                }
            }
        }
    }
    let out = Command::new("ps")
        .args(["-o", "rss=", "-p", &pid.to_string()])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let kib: u64 = String::from_utf8_lossy(&out.stdout).trim().parse().ok()?;
    Some((kib as f64) / 1024.0)
}

fn has_fio() -> bool {
    Command::new("fio")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn run_fio_1gib_job(file_path: &Path, is_write: bool, direct: bool) -> Option<f64> {
    // `fio` 3.33 under emulation (Rosetta / qemu) can deadlock its helper thread after an
    // `EINTR` in `select()`; disable disk-util helper stats, bound each run with a hard timeout,
    // and retry up to 3 times so a wedged `fio` can never stall the acceptance gate.
    const FIO_TIMEOUT: Duration = Duration::from_secs(30);
    for attempt in 1..=3 {
        if let Some(bw) = run_fio_1gib_job_once(file_path, is_write, direct, FIO_TIMEOUT) {
            return Some(bw);
        }
        eprintln!(
            "[VR-9 Baseline] fio {} attempt {attempt}/3 failed or timed out; retrying",
            if is_write { "write" } else { "read" }
        );
    }
    None
}

fn run_fio_1gib_job_once(
    file_path: &Path,
    is_write: bool,
    direct: bool,
    timeout: Duration,
) -> Option<f64> {
    let rw = if is_write { "write" } else { "read" };
    let direct_arg = if direct { "--direct=1" } else { "--direct=0" };
    let out_path = file_path.with_extension(format!("{rw}.fio.json"));
    let _ = fs::remove_file(&out_path);
    let mut cmd = Command::new("fio");
    cmd.args([
        &format!("--name=seq_{rw}"),
        &format!("--filename={}", file_path.display()),
        &format!("--rw={rw}"),
        "--bs=1M",
        "--size=1G",
        "--ioengine=sync",
        direct_arg,
        "--numjobs=1",
        "--thread=1",
        "--eta=never",
        "--disk_util=0",
        "--output-format=json",
        &format!("--output={}", out_path.display()),
    ]);
    if is_write {
        cmd.arg("--end_fsync=1");
    } else if !direct {
        cmd.arg("--fadvise_hint=1");
    }
    let mut child = cmd
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let deadline = Instant::now() + timeout;
    let status = loop {
        match child.try_wait() {
            Ok(Some(st)) => break st,
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(50)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                let _ = fs::remove_file(&out_path);
                return None;
            }
        }
    };
    let raw = fs::read(&out_path).ok();
    let _ = fs::remove_file(&out_path);
    if !status.success() {
        return None;
    }
    let raw = raw?;
    // `fio` occasionally emits informational warnings before `{`; slice from first `{`
    let json_start = raw.iter().position(|&b| b == b'{')?;
    let val: serde_json::Value = serde_json::from_slice(&raw[json_start..]).ok()?;
    let key = if is_write { "write" } else { "read" };
    let bw_bytes = val.get("jobs")?.get(0)?.get(key)?.get("bw_bytes")?.as_f64()?;
    if bw_bytes <= 0.0 {
        return None;
    }
    Some(bw_bytes / (ONE_MIB as f64))
}

/// Cross-process VFS `pread` (`1 MiB` blocks) + `ST-5` `CRC32C` + HTTP/1.1 streaming response body,
/// measuring the physical single-connection cross-process HTTP/TCP + VFS + CRC32C read ceiling.
struct Crc32cChunkBody {
    file: Arc<std::fs::File>,
    file_off: u64,
    total: u64,
}

impl Crc32cChunkBody {
    fn new(file: Arc<std::fs::File>, total: u64) -> Self {
        Self {
            file,
            file_off: 0,
            total,
        }
    }
}

impl Body for Crc32cChunkBody {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        use std::os::unix::fs::FileExt as _;
        if self.file_off >= self.total {
            return Poll::Ready(None);
        }
        let n = (ONE_MIB as u64).min(self.total - self.file_off) as usize;
        let off = self.file_off;
        self.file_off += n as u64;
        let mut raw = vec![0u8; n];
        self.file.read_exact_at(&mut raw, off).unwrap();
        std::hint::black_box(crc32c::crc32c(&raw));
        Poll::Ready(Some(Ok(Frame::data(Bytes::from(raw)))))
    }

    fn is_end_stream(&self) -> bool {
        self.file_off >= self.total
    }

    fn size_hint(&self) -> SizeHint {
        SizeHint::with_exact(self.total)
    }
}

async fn run_internal_loopback_server(port: u16, file_path: &Path) {
    let rf = Arc::new(std::fs::File::open(file_path).unwrap());
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", port))
        .await
        .unwrap();
    let (stream, _) = listener.accept().await.unwrap();
    stream.set_nodelay(true).ok();
    let svc = hyper::service::service_fn(move |_req: Request<hyper::body::Incoming>| {
        let f = Arc::clone(&rf);
        async move {
            Ok::<_, Infallible>(
                hyper::Response::builder()
                    .status(200)
                    .header("Content-Length", ONE_GIB.to_string())
                    .body(Crc32cChunkBody::new(f, ONE_GIB))
                    .unwrap(),
            )
        }
    });
    let _ = hyper::server::conn::http1::Builder::new()
        .max_buf_size(512 * 1024)
        .serve_connection(TokioIo::new(stream), svc)
        .await;
}

async fn measure_http_crc32c_loopback_1gib(work_dir: &Path, iters: usize) -> Vec<f64> {
    use std::os::unix::fs::FileExt as _;
    let probe_path = work_dir.join("loopback-1gib-probe.bin");
    {
        let wf = std::fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .read(true)
            .open(&probe_path)
            .unwrap();
        let blk = vec![0x5Au8; ONE_MIB];
        for b in 0..1024u64 {
            wf.write_all_at(&blk, b * ONE_MIB as u64).unwrap();
        }
    }
    let port = pick_free_port();
    let addr = format!("127.0.0.1:{port}");
    let self_exe = std::env::current_exe().unwrap();
    let mut child = Command::new(self_exe)
        .args([
            "--internal-loopback-port",
            &port.to_string(),
            "--internal-loopback-file",
            probe_path.to_str().unwrap(),
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();

    let mut cli = loop {
        if let Ok(stream) = TcpStream::connect(&addr).await {
            stream.set_nodelay(true).ok();
            let (sender, conn) = http1::Builder::new()
                .max_buf_size(512 * 1024)
                .handshake(TokioIo::new(stream))
                .await
                .unwrap();
            tokio::spawn(async move {
                let _ = conn.await;
            });
            break sender;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    };

    let mut runs = Vec::with_capacity(iters);
    for _ in 0..iters {
        cli.ready().await.unwrap();
        let req = Request::builder()
            .method("GET")
            .uri("/loopback-1gib")
            .header("Host", &addr)
            .body(Full::new(Bytes::new()))
            .unwrap();
        let t0 = Instant::now();
        let resp = cli.send_request(req).await.unwrap();
        assert_eq!(resp.status().as_u16(), 200);
        let mut body = resp.into_body();
        let mut got = 0u64;
        while let Some(frame) = body.frame().await {
            if let Ok(d) = frame.unwrap().into_data() {
                got += d.len() as u64;
            }
        }
        assert_eq!(got, ONE_GIB);
        runs.push(1024.0 / t0.elapsed().as_secs_f64());
    }
    drop(cli);
    let _ = child.wait();
    let _ = fs::remove_file(&probe_path);
    runs
}

/// Phase A: Measure physical sequential 1 GiB write and sequential 1 GiB read via real `fio`
/// (`--bs=1M --size=1G --direct=1 --end_fsync=1`) when `fio` is installed (falling back to
/// `OsDisk` `write_all_at` + `sync_data` / `open_uncached` when `fio` is absent), plus single-core
/// RFC 1321 `Md5` (`1 GiB` in `1 MiB` slices) and 1 GiB HTTP/1.1 TCP loopback + `CRC32C` ceiling.
async fn run_disk_sequential_baseline(work_dir: &Path) -> DiskBaselineReport {
    const ITERS: usize = 5;
    let base_dir = work_dir.join("disk_baseline");
    fs::create_dir_all(&base_dir).unwrap();
    let disk = OsDisk::new(&base_dir).unwrap();

    let chunk = vec![0x5Au8; ONE_MIB];
    let mut read_buf = vec![0u8; ONE_MIB];
    let blocks = (ONE_GIB / ONE_MIB as u64) as usize; // 1024 x 1 MiB

    let mut write_runs = Vec::with_capacity(ITERS);
    let mut read_runs = Vec::with_capacity(ITERS);
    let mut md5_runs = Vec::with_capacity(ITERS);

    let fio_available = has_fio();
    let mut baseline_source = if fio_available {
        "fio (direct=1, bs=1M, size=1G, end_fsync=1)".to_string()
    } else {
        "os_disk (open_uncached, bs=1M, size=1G, sync_data)".to_string()
    };

    for i in 0..ITERS {
        let name = format!("seq-{i}.bin");
        let full_path = base_dir.join(&name);

        if fio_available {
            let w_mib_s = if let Some(bw) = run_fio_1gib_job(&full_path, true, true) {
                bw
            } else {
                baseline_source = "fio (direct=0, bs=1M, size=1G, end_fsync=1)".to_string();
                run_fio_1gib_job(&full_path, true, false)
                    .expect("fio sequential write failed even with --direct=0")
            };
            write_runs.push(w_mib_s);

            let r_mib_s = if let Some(bw) = run_fio_1gib_job(&full_path, false, true) {
                bw
            } else {
                // Evict page cache via open_uncached before direct=0 fio read
                let _ = disk.open_uncached(&name, OpenOpts::read_only());
                run_fio_1gib_job(&full_path, false, false)
                    .expect("fio sequential read failed even with --direct=0")
            };
            read_runs.push(r_mib_s);
            let _ = fs::remove_file(&full_path);
        } else {
            let t_w = Instant::now();
            {
                let wf = disk
                    .open_uncached(&name, OpenOpts::create_truncate_rw())
                    .unwrap();
                for b in 0..blocks {
                    wf.write_all_at((b * ONE_MIB) as u64, &chunk).unwrap();
                }
                wf.sync_data().unwrap();
            }
            let w_mib_s = 1024.0 / t_w.elapsed().as_secs_f64();
            write_runs.push(w_mib_s);

            let t_r = Instant::now();
            {
                let rf = disk.open_uncached(&name, OpenOpts::read_only()).unwrap();
                for b in 0..blocks {
                    rf.read_exact_at((b * ONE_MIB) as u64, &mut read_buf)
                        .unwrap();
                }
            }
            let r_mib_s = 1024.0 / t_r.elapsed().as_secs_f64();
            read_runs.push(r_mib_s);
            let _ = disk.remove_file(&name);
        }

        let t_m = Instant::now();
        let mut h = Md5::new();
        for _ in 0..blocks {
            h.update(std::hint::black_box(chunk.as_slice()));
        }
        let digest: [u8; 16] = h.finalize().into();
        std::hint::black_box(digest);
        let m_mib_s = 1024.0 / t_m.elapsed().as_secs_f64();
        md5_runs.push(m_mib_s);
    }

    let _ = fs::remove_dir_all(&base_dir);
    let loopback_runs = measure_http_crc32c_loopback_1gib(work_dir, ITERS).await;
    let seq_write_median_mib_s = median_f64(&write_runs);
    let seq_read_median_mib_s = median_f64(&read_runs);
    let md5_single_core_median_mib_s = median_f64(&md5_runs);
    let http_crc32c_loopback_median_mib_s = median_f64(&loopback_runs);
    let effective_single_stream_put_baseline_mib_s =
        seq_write_median_mib_s.min(md5_single_core_median_mib_s);
    let effective_single_stream_get_baseline_mib_s =
        seq_read_median_mib_s.min(http_crc32c_loopback_median_mib_s);
    eprintln!(
        "[VR-9 Baseline ({})] 1 GiB seq write median = {:.1} MiB/s, seq read median = {:.1} MiB/s, MD5 median = {:.1} MiB/s, HTTP+CRC32C loopback median = {:.1} MiB/s -> effective PUT ceiling = {:.1} MiB/s, effective GET ceiling = {:.1} MiB/s",
        baseline_source,
        seq_write_median_mib_s,
        seq_read_median_mib_s,
        md5_single_core_median_mib_s,
        http_crc32c_loopback_median_mib_s,
        effective_single_stream_put_baseline_mib_s,
        effective_single_stream_get_baseline_mib_s,
    );

    DiskBaselineReport {
        baseline_source,
        iterations: ITERS,
        seq_write_runs_mib_s: write_runs,
        seq_write_median_mib_s,
        seq_read_runs_mib_s: read_runs,
        seq_read_median_mib_s,
        md5_single_core_runs_mib_s: md5_runs,
        md5_single_core_median_mib_s,
        http_crc32c_loopback_runs_mib_s: loopback_runs,
        http_crc32c_loopback_median_mib_s,
        effective_single_stream_put_baseline_mib_s,
        effective_single_stream_get_baseline_mib_s,
    }
}

async fn connect_fixed_client(addr: &str) -> http1::SendRequest<Full<Bytes>> {
    let stream = TcpStream::connect(addr).await.unwrap();
    stream.set_nodelay(true).ok();
    let (sender, conn) = http1::Builder::new()
        .max_buf_size(512 * 1024)
        .handshake(TokioIo::new(stream))
        .await
        .unwrap();
    tokio::spawn(async move {
        let _ = conn.await;
    });
    sender
}

async fn connect_stream_client(addr: &str) -> http1::SendRequest<CountingChunkBody> {
    let stream = TcpStream::connect(addr).await.unwrap();
    stream.set_nodelay(true).ok();
    let (sender, conn) = http1::Builder::new()
        .max_buf_size(512 * 1024)
        .handshake(TokioIo::new(stream))
        .await
        .unwrap();
    tokio::spawn(async move {
        let _ = conn.await;
    });
    sender
}

fn extract_xml_tag(xml: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let s = xml.find(&open)? + open.len();
    let e = xml[s..].find(&close)? + s;
    Some(xml[s..e].to_string())
}

/// Phase B (`NFR-5`): Idle RSS <= 64 MiB + 10 GiB streaming Multipart Upload peak RSS check + `fsck`.
async fn run_nfr5_memory_gate(s3d_bin: &Path, root_tmp: &Path, upload_bytes: u64) -> Nfr5MemoryReport {
    let work_dir = root_tmp.join("nfr5_work");
    let data_dir = root_tmp.join("nfr5_data");
    let mut srv = RunningS3d::spawn(s3d_bin, &work_dir, &data_dir).await;
    let pid = srv.pid();

    // Allow allocator / runtime threads to settle, then sample Idle RSS (`NFR-5`: <= 64 MiB)
    tokio::time::sleep(Duration::from_millis(100)).await;
    let idle_rss_mib = sample_process_rss_mib(pid).expect("failed to sample s3d idle RSS");
    eprintln!("[NFR-5] Idle RSS = {:.2} MiB (target <= 64.0 MiB)", idle_rss_mib);

    // Background RSS sampler every 100 ms during the 10 GiB streaming Multipart Upload
    let stop_sampler = Arc::new(AtomicBool::new(false));
    let samples = Arc::new(Mutex::new( vec![idle_rss_mib] ));
    let stop_c = Arc::clone(&stop_sampler);
    let samples_c = Arc::clone(&samples);
    let sampler_handle = std::thread::spawn(move || {
        while !stop_c.load(Ordering::Relaxed) {
            if let Some(rss) = sample_process_rss_mib(pid) {
                samples_c.lock().unwrap().push(rss);
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    });

    let mut ctrl = connect_fixed_client(&srv.s3_addr).await;
    // 1. Create bucket
    let resp = ctrl
        .send_request(build_fixed_req(
            "PUT",
            &srv.s3_addr,
            "/nfr5-bkt",
            "",
            "UNSIGNED-PAYLOAD",
            Bytes::new(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    let _ = resp.into_body().collect().await.unwrap();

    // 2. Initiate Multipart Upload
    let resp = ctrl
        .send_request(build_fixed_req(
            "POST",
            &srv.s3_addr,
            "/nfr5-bkt/huge-stream.bin",
            "uploads=",
            "UNSIGNED-PAYLOAD",
            Bytes::new(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    let init_xml = String::from_utf8(
        resp.into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();
    let upload_id = extract_xml_tag(&init_xml, "UploadId").expect("missing UploadId");

    // 3. Stream parts (`1 GiB` per part for 10 GiB -> 10 parts, zero buffering!)
    let part_size = ONE_GIB.min(upload_bytes.max(1));
    let num_parts = upload_bytes.div_ceil(part_size);
    let chunk_256k = Bytes::from(vec![0xA5u8; 256 * 1024]);
    let mut stream_cli = connect_stream_client(&srv.s3_addr).await;
    let mut part_etags = Vec::with_capacity(num_parts as usize);

    for pn in 1..=num_parts {
        let this_len = if pn < num_parts {
            part_size
        } else {
            upload_bytes - part_size * (num_parts - 1)
        };
        let query = format!("partNumber={pn}&uploadId={upload_id}");
        stream_cli.ready().await.unwrap();
        let resp = stream_cli
            .send_request(build_streaming_req(
                "PUT",
                &srv.s3_addr,
                "/nfr5-bkt/huge-stream.bin",
                &query,
                chunk_256k.clone(),
                this_len,
            ))
            .await
            .unwrap();
        assert_eq!(resp.status().as_u16(), 200, "UploadPart {pn} failed");
        let etag = resp
            .headers()
            .get("etag")
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        let _ = resp.into_body().collect().await.unwrap();
        part_etags.push((pn, etag));
    }

    // 4. Complete Multipart Upload (open a fresh control connection in case the 10 GiB upload
    //    exceeded `s3d`'s 30s idle header timeout on `ctrl`)
    drop(ctrl);
    let mut ctrl = connect_fixed_client(&srv.s3_addr).await;
    let mut comp_xml = String::from("<CompleteMultipartUpload>");
    for (pn, et) in &part_etags {
        comp_xml.push_str(&format!(
            "<Part><PartNumber>{pn}</PartNumber><ETag>{et}</ETag></Part>"
        ));
    }
    comp_xml.push_str("</CompleteMultipartUpload>");
    ctrl.ready().await.unwrap();
    let resp = ctrl
        .send_request(build_fixed_req(
            "POST",
            &srv.s3_addr,
            "/nfr5-bkt/huge-stream.bin",
            &format!("uploadId={upload_id}"),
            "UNSIGNED-PAYLOAD",
            Bytes::from(comp_xml),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    let _ = resp.into_body().collect().await.unwrap();

    // 5. Verify HEAD Content-Length == upload_bytes
    ctrl.ready().await.unwrap();
    let resp = ctrl
        .send_request(build_fixed_req(
            "HEAD",
            &srv.s3_addr,
            "/nfr5-bkt/huge-stream.bin",
            "",
            "UNSIGNED-PAYLOAD",
            Bytes::new(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    let cl: u64 = resp
        .headers()
        .get("content-length")
        .unwrap()
        .to_str()
        .unwrap()
        .parse()
        .unwrap();
    assert_eq!(cl, upload_bytes);
    let _ = resp.into_body().collect().await.unwrap();

    stop_sampler.store(true, Ordering::Relaxed);
    sampler_handle.join().unwrap();
    drop(ctrl);
    drop(stream_cli);

    let recorded = samples.lock().unwrap().clone();
    let peak_upload_rss_mib = recorded
        .iter()
        .copied()
        .fold(idle_rss_mib, f64::max);

    srv.sigterm_and_wait();
    let fsck = srv.run_fsck_json();
    assert_eq!(fsck["status"], "ok");
    let fsck_verified_bytes = fsck["bytes_verified"].as_u64().unwrap();
    assert_eq!(fsck_verified_bytes, upload_bytes);

    let _ = fs::remove_dir_all(&work_dir);
    let _ = fs::remove_dir_all(&data_dir);

    // Spec §9 NFR-5: Idle RSS <= 64 MiB; per in-flight request buffer <= 2 MiB; independent of 10 GiB object size!
    let max_allowed_peak_rss_mib = 66.0;
    let passed = idle_rss_mib <= 64.0 && peak_upload_rss_mib <= max_allowed_peak_rss_mib;
    eprintln!(
        "[NFR-5] Streamed {} bytes: samples={}, idle_rss={:.2} MiB, peak_rss={:.2} MiB (limit {:.1} MiB), fsck_bytes={} -> passed={}",
        upload_bytes,
        recorded.len(),
        idle_rss_mib,
        peak_upload_rss_mib,
        max_allowed_peak_rss_mib,
        fsck_verified_bytes,
        passed
    );

    Nfr5MemoryReport {
        idle_rss_mib,
        target_max_idle_rss_mib: 64.0,
        streamed_object_bytes: upload_bytes,
        rss_samples_during_upload: recorded.len(),
        peak_upload_rss_mib,
        max_allowed_peak_rss_mib,
        fsck_verified_bytes,
        passed,
    }
}

/// Phase C1 (`NFR-1`, `NFR-2`): 4 KiB PUT & GET at 32 concurrency for `put_get_secs` seconds each.
async fn run_nfr1_nfr2_gates(
    s3d_bin: &Path,
    root_tmp: &Path,
    put_get_secs: u64,
) -> (Nfr1SmallPutReport, Nfr2SmallGetReport) {
    const CONCURRENCY: usize = 32;
    const KEY_POOL: usize = 4096;
    const SMALL_BYTES: usize = 4096;

    let work_dir = root_tmp.join("nfr12_work");
    let data_dir = root_tmp.join("nfr12_data");
    let mut srv = RunningS3d::spawn(s3d_bin, &work_dir, &data_dir).await;

    {
        let mut ctrl = connect_fixed_client(&srv.s3_addr).await;
        let resp = ctrl
            .send_request(build_fixed_req(
                "PUT",
                &srv.s3_addr,
                "/bench",
                "",
                "UNSIGNED-PAYLOAD",
                Bytes::new(),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status().as_u16(), 200);
        let _ = resp.into_body().collect().await.unwrap();
    }

    let payload_4k = Bytes::from(vec![0x42u8; SMALL_BYTES]);
    let payload_4k_sha256 = sha256_hex(&payload_4k);

    // Pre-populate all 4,096 keys once so every key exists cleanly before timed runs
    {
        let mut init_tasks = Vec::new();
        for w in 0..CONCURRENCY {
            let addr = srv.s3_addr.clone();
            let body = payload_4k.clone();
            let sha = payload_4k_sha256.clone();
            init_tasks.push(tokio::spawn(async move {
                let mut cli = connect_fixed_client(&addr).await;
                let per_w = KEY_POOL / CONCURRENCY;
                for i in 0..per_w {
                    let k = w * per_w + i;
                    cli.ready().await.unwrap();
                    let resp = cli
                        .send_request(build_fixed_req(
                            "PUT",
                            &addr,
                            &format!("/bench/k-{k:04}"),
                            "",
                            &sha,
                            body.clone(),
                        ))
                        .await
                        .unwrap();
                    assert_eq!(resp.status().as_u16(), 200);
                    let _ = resp.into_body().collect().await.unwrap();
                }
            }));
        }
        for t in init_tasks {
            t.await.unwrap();
        }
    }

    // ---- NFR-1: 4 KiB PUT, 32 concurrency, `put_get_secs` seconds ----
    eprintln!("[NFR-1] Starting 4 KiB PUT benchmark (32 concurrency, {}s)...", put_get_secs);
    let t_put_start = Instant::now();
    let put_deadline = t_put_start + Duration::from_secs(put_get_secs);
    let mut put_workers = Vec::with_capacity(CONCURRENCY);
    for w in 0..CONCURRENCY {
        let addr = srv.s3_addr.clone();
        let body = payload_4k.clone();
        let sha = payload_4k_sha256.clone();
        put_workers.push(tokio::spawn(async move {
            let mut cli = connect_fixed_client(&addr).await;
            let mut lats = Vec::with_capacity(65_536);
            let mut step = w;
            while Instant::now() < put_deadline {
                let k = step % KEY_POOL;
                step = step.wrapping_add(CONCURRENCY);
                let req = build_fixed_req(
                    "PUT",
                    &addr,
                    &format!("/bench/k-{k:04}"),
                    "",
                    &sha,
                    body.clone(),
                );
                cli.ready().await.unwrap();
                let t0 = Instant::now();
                let resp = cli.send_request(req).await.unwrap();
                assert_eq!(resp.status().as_u16(), 200);
                let _ = resp.into_body().collect().await.unwrap();
                lats.push(t0.elapsed().as_micros() as u64);
            }
            lats
        }));
    }
    let mut all_put_lats = Vec::new();
    for h in put_workers {
        all_put_lats.extend(h.await.unwrap());
    }
    let put_elapsed = t_put_start.elapsed().as_secs_f64();
    let put_summary = summarize_latencies_us(all_put_lats);
    let put_ops_s = (put_summary.samples as f64) / put_elapsed;
    let nfr1_passed = put_ops_s >= 1000.0 && put_summary.p99_ms <= 50.0;
    eprintln!(
        "[NFR-1] Completed: {:.1} ops/s (target >= 1000), p50={:.2}ms p95={:.2}ms p99={:.2}ms (target <= 50ms) -> passed={}",
        put_ops_s, put_summary.p50_ms, put_summary.p95_ms, put_summary.p99_ms, nfr1_passed
    );

    let nfr1 = Nfr1SmallPutReport {
        duration_secs: put_elapsed,
        concurrency: CONCURRENCY,
        object_bytes: SMALL_BYTES,
        total_ops: put_summary.samples,
        ops_per_sec: put_ops_s,
        latency: put_summary,
        target_min_ops_per_sec: 1000.0,
        target_max_p99_ms: 50.0,
        passed: nfr1_passed,
    };

    // ---- NFR-2: 4 KiB GET, 32 concurrency, `put_get_secs` seconds ----
    eprintln!("[NFR-2] Starting 4 KiB GET benchmark (32 concurrency, {}s)...", put_get_secs);
    let empty_sha = sha256_hex(b"");
    let t_get_start = Instant::now();
    let get_deadline = t_get_start + Duration::from_secs(put_get_secs);
    let mut get_workers = Vec::with_capacity(CONCURRENCY);
    for w in 0..CONCURRENCY {
        let addr = srv.s3_addr.clone();
        let sha = empty_sha.clone();
        get_workers.push(tokio::spawn(async move {
            let mut cli = connect_fixed_client(&addr).await;
            let mut lats = Vec::with_capacity(262_144);
            let mut step = w;
            while Instant::now() < get_deadline {
                let k = step % KEY_POOL;
                step = step.wrapping_add(CONCURRENCY);
                let req = build_fixed_req(
                    "GET",
                    &addr,
                    &format!("/bench/k-{k:04}"),
                    "",
                    &sha,
                    Bytes::new(),
                );
                cli.ready().await.unwrap();
                let t0 = Instant::now();
                let resp = cli.send_request(req).await.unwrap();
                assert_eq!(resp.status().as_u16(), 200);
                let b = resp.into_body().collect().await.unwrap().to_bytes();
                assert_eq!(b.len(), SMALL_BYTES);
                lats.push(t0.elapsed().as_micros() as u64);
            }
            lats
        }));
    }
    let mut all_get_lats = Vec::new();
    for h in get_workers {
        all_get_lats.extend(h.await.unwrap());
    }
    let get_elapsed = t_get_start.elapsed().as_secs_f64();
    let get_summary = summarize_latencies_us(all_get_lats);
    let get_ops_s = (get_summary.samples as f64) / get_elapsed;
    let nfr2_passed = get_ops_s >= 5000.0 && get_summary.p99_ms <= 10.0;
    eprintln!(
        "[NFR-2] Completed: {:.1} ops/s (target >= 5000), p50={:.2}ms p95={:.2}ms p99={:.2}ms (target <= 10ms) -> passed={}",
        get_ops_s, get_summary.p50_ms, get_summary.p95_ms, get_summary.p99_ms, nfr2_passed
    );

    let nfr2 = Nfr2SmallGetReport {
        duration_secs: get_elapsed,
        concurrency: CONCURRENCY,
        object_bytes: SMALL_BYTES,
        total_ops: get_summary.samples,
        ops_per_sec: get_ops_s,
        latency: get_summary,
        target_min_ops_per_sec: 5000.0,
        target_max_p99_ms: 10.0,
        passed: nfr2_passed,
    };

    srv.sigterm_and_wait();
    let fsck = srv.run_fsck_json();
    assert_eq!(fsck["status"], "ok");
    let _ = fs::remove_dir_all(&work_dir);
    let _ = fs::remove_dir_all(&data_dir);

    (nfr1, nfr2)
}

/// Phase C2 (`NFR-3`): Isolated 1 GiB Single-Stream PUT & GET (5 iterations median + `s3d fsck` over 5 GiB).
async fn run_nfr3_large_stream_gate(
    s3d_bin: &Path,
    root_tmp: &Path,
    disk_base: &DiskBaselineReport,
) -> Nfr3LargeStreamReport {
    let work_dir = root_tmp.join("nfr3_work");
    let data_dir = root_tmp.join("nfr3_data");
    let mut srv = RunningS3d::spawn(s3d_bin, &work_dir, &data_dir).await;

    {
        let mut ctrl = connect_fixed_client(&srv.s3_addr).await;
        let resp = ctrl
            .send_request(build_fixed_req(
                "PUT",
                &srv.s3_addr,
                "/bench",
                "",
                "UNSIGNED-PAYLOAD",
                Bytes::new(),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status().as_u16(), 200);
        let _ = resp.into_body().collect().await.unwrap();
    }

    eprintln!("[NFR-3] Starting isolated 1 GiB single-stream PUT & GET benchmark (5 runs)...");
    let chunk_512k = Bytes::from(vec![0x77u8; 512 * 1024]);
    let mut stream_put_cli = connect_stream_client(&srv.s3_addr).await;
    let mut fixed_get_cli = connect_fixed_client(&srv.s3_addr).await;
    let mut put_runs_mib_s = Vec::with_capacity(5);
    let mut get_runs_mib_s = Vec::with_capacity(5);

    for i in 0..5 {
        let path = format!("/bench/large-1gib-{i}");
        stream_put_cli.ready().await.unwrap();
        let req = build_streaming_req("PUT", &srv.s3_addr, &path, "", chunk_512k.clone(), ONE_GIB);
        let t0 = Instant::now();
        let resp = stream_put_cli.send_request(req).await.unwrap();
        assert_eq!(resp.status().as_u16(), 200);
        let _ = resp.into_body().collect().await.unwrap();
        let put_mib_s = 1024.0 / t0.elapsed().as_secs_f64();
        put_runs_mib_s.push(put_mib_s);

        fixed_get_cli.ready().await.unwrap();
        let greq = build_fixed_req(
            "GET",
            &srv.s3_addr,
            &path,
            "",
            "UNSIGNED-PAYLOAD",
            Bytes::new(),
        );
        let tg = Instant::now();
        let gresp = fixed_get_cli.send_request(greq).await.unwrap();
        assert_eq!(gresp.status().as_u16(), 200);
        let mut body = gresp.into_body();
        let mut got_bytes = 0u64;
        while let Some(frame) = body.frame().await {
            if let Ok(d) = frame.unwrap().into_data() {
                got_bytes += d.len() as u64;
            }
        }
        assert_eq!(got_bytes, ONE_GIB);
        let get_mib_s = 1024.0 / tg.elapsed().as_secs_f64();
        get_runs_mib_s.push(get_mib_s);
    }

    drop(stream_put_cli);
    drop(fixed_get_cli);
    srv.sigterm_and_wait();
    let fsck = srv.run_fsck_json();
    assert_eq!(fsck["status"], "ok");
    let fsck_verified_bytes = fsck["bytes_verified"].as_u64().unwrap();
    assert_eq!(fsck_verified_bytes, 5 * ONE_GIB);

    let _ = fs::remove_dir_all(&work_dir);
    let _ = fs::remove_dir_all(&data_dir);

    let put_median_mib_s = median_f64(&put_runs_mib_s);
    let get_median_mib_s = median_f64(&get_runs_mib_s);
    let put_ratio_vs_raw_disk = put_median_mib_s / disk_base.seq_write_median_mib_s;
    let put_ratio_vs_effective =
        put_median_mib_s / disk_base.effective_single_stream_put_baseline_mib_s;
    let get_ratio_raw = get_median_mib_s / disk_base.seq_read_median_mib_s;
    let get_ratio_effective =
        get_median_mib_s / disk_base.effective_single_stream_get_baseline_mib_s;
    let raw_disk_formula_passed = put_ratio_vs_raw_disk >= 0.70 && get_ratio_raw >= 0.80;
    let nfr3_passed = put_ratio_vs_effective >= 0.70 && get_ratio_effective >= 0.80;

    eprintln!(
        "[NFR-3] 1 GiB PUT median={:.1} MiB/s ({:.1}% vs raw disk {:.1}, {:.1}% vs effective {:.1}; target >= 70%), GET median={:.1} MiB/s ({:.1}% vs raw disk {:.1}, {:.1}% vs effective {:.1}; target >= 80%) -> raw_passed={}, passed={}",
        put_median_mib_s,
        put_ratio_vs_raw_disk * 100.0,
        disk_base.seq_write_median_mib_s,
        put_ratio_vs_effective * 100.0,
        disk_base.effective_single_stream_put_baseline_mib_s,
        get_median_mib_s,
        get_ratio_raw * 100.0,
        disk_base.seq_read_median_mib_s,
        get_ratio_effective * 100.0,
        disk_base.effective_single_stream_get_baseline_mib_s,
        raw_disk_formula_passed,
        nfr3_passed
    );

    Nfr3LargeStreamReport {
        object_bytes: ONE_GIB,
        iterations: 5,
        put_runs_mib_s,
        put_median_mib_s,
        put_ratio_vs_raw_disk,
        put_ratio_vs_effective_baseline: put_ratio_vs_effective,
        target_min_put_ratio: 0.70,
        get_runs_mib_s,
        get_median_mib_s,
        get_ratio_vs_disk: get_ratio_raw,
        get_ratio_vs_effective_baseline: get_ratio_effective,
        target_min_get_ratio: 0.80,
        fsck_verified_bytes,
        raw_disk_formula_passed,
        passed: nfr3_passed,
    }
}

/// Phase D (`NFR-4` & `NFR-6`): Populate 1,000,000 object versions (`95%` checkpoint + `5%` WAL tail),
/// simulate power loss (`SIGKILL`), time cold recovery to `/health` `200 OK` (`<= 20s`),
/// run 1,000 random `start-after` `ListObjectsV2` queries (`p99 <= 20ms`), and run `s3d fsck`!
async fn run_nfr4_and_nfr6_gates(
    s3d_bin: &Path,
    root_tmp: &Path,
    total_versions: usize,
) -> (Nfr4ListMillionReport, Nfr6ColdRecoveryReport) {
    let work_dir = root_tmp.join("nfr46_work");
    let data_dir = root_tmp.join("nfr46_data");
    fs::create_dir_all(&work_dir).unwrap();
    fs::create_dir_all(&data_dir).unwrap();

    let ckpt_cutoff = (total_versions * 95) / 100;
    let wal_tail = total_versions - ckpt_cutoff;

    eprintln!(
        "[NFR-4/6] Populating {} object versions ({} in checkpoint + {} in post-checkpoint WAL)...",
        total_versions, ckpt_cutoff, wal_tail
    );
    let t_pop = Instant::now();
    {
        let disk = OsDisk::new(&data_dir).unwrap();
        let cfg = EngineConfig {
            group_commit_window_ms: 2,
            group_commit_max_batch: 2048,
            reserved_disk_bytes: 0,
            default_object_ownership: ObjectOwnership::BucketOwnerEnforced,
            ..EngineConfig::default()
        };
        let engine = Engine::open(disk, cfg).unwrap();
        let ctx = CallerContext {
            caller: Some(OwnerInfo {
                user_id: "0123456789abcdef".into(),
                display_name: "bench".into(),
                email: "bench@example.com".into(),
            }),
            request_time_ms: 1_700_000_000_000,
            expected_bucket_owner: None,
            is_authenticated: true,
            policy_ctx: RequestPolicyContext::default(),
        };
        engine
            .create_bucket(CreateBucketReq {
                ctx: ctx.clone(),
                bucket: "million-bkt".into(),
                location_constraint: None,
                object_ownership: None,
                acl: None,
                object_lock_enabled: false,
            })
            .await
            .unwrap();

        let insert_range = |eng: Arc<Engine<OsDisk>>, start: usize, end: usize, base_ctx: CallerContext| async move {
            let next_idx = Arc::new(AtomicUsize::new(start));
            let workers = 512usize.min((end - start).max(1));
            let mut handles = Vec::with_capacity(workers);
            for _ in 0..workers {
                let e = Arc::clone(&eng);
                let ni = Arc::clone(&next_idx);
                let c = base_ctx.clone();
                handles.push(tokio::spawn(async move {
                    loop {
                        let idx = ni.fetch_add(1, Ordering::Relaxed);
                        if idx >= end {
                            break;
                        }
                        e.put_object(
                            PutObjectReq {
                                ctx: c.clone(),
                                bucket: "million-bkt".into(),
                                key: format!("obj-{idx:07}"),
                                sys_meta: SystemMeta::default(),
                                user_meta: Vec::new(),
                                acl: None,
                                tags: None,
                                preconditions: Preconditions::default(),
                                max_bytes_limit: MAX_SINGLE_PUT_BYTES,
                                raw_sse: RawSseHeaders::default(),
                                raw_lock: RawUploadObjectLockHeaders::default(),
                            },
                            InMemoryVerifiedStream::from_bytes(Bytes::new(), None),
                        )
                        .await
                        .unwrap();
                    }
                }));
            }
            for h in handles {
                h.await.unwrap();
            }
        };

        if ckpt_cutoff > 0 {
            insert_range(Arc::clone(&engine), 0, ckpt_cutoff, ctx.clone()).await;
            engine.write_checkpoint().await.unwrap();
        }
        if wal_tail > 0 {
            insert_range(Arc::clone(&engine), ckpt_cutoff, total_versions, ctx).await;
        }
    }
    eprintln!(
        "[NFR-4/6] Populated {} versions in {:.2}s. Spawning s3d and simulating abrupt power loss (SIGKILL)...",
        total_versions,
        t_pop.elapsed().as_secs_f64()
    );

    let mut initial_srv = RunningS3d::spawn(s3d_bin, &work_dir, &data_dir).await;
    initial_srv.sigkill_and_wait();
    drop(initial_srv);

    // ---- NFR-6: Measure cold-start crash recovery time from process spawn to `/health` 200 OK ----
    let t_rec = Instant::now();
    let mut recovered_srv = RunningS3d::spawn(s3d_bin, &work_dir, &data_dir).await;
    let recovery_secs = t_rec.elapsed().as_secs_f64();
    let nfr6_passed = recovery_secs <= 20.0;
    eprintln!(
        "[NFR-6] Cold crash recovery ({} versions) -> /health 200 OK in {:.3}s (target <= 20.0s) -> passed={}",
        total_versions, recovery_secs, nfr6_passed
    );

    // ---- NFR-4: 1,000 random `start-after` `ListObjectsV2` pages (`max-keys=1000`) ----
    let queries = 1000usize;
    let page_size = 1000usize.min(total_versions.max(1));
    let max_start = total_versions.saturating_sub(page_size + 1);
    let mut rng = StdRng::seed_from_u64(0x5333_445F_4E46_5234);
    let mut cli = connect_fixed_client(&recovered_srv.s3_addr).await;
    let mut list_lats = Vec::with_capacity(queries);

    for _ in 0..queries {
        let start_idx = if max_start > 0 {
            rng.gen_range(0..max_start)
        } else {
            0
        };
        // Canonical query string MUST have parameters sorted ASCIIbetically:
        // `list-type=2&max-keys=...&start-after=...`
        let query = format!(
            "list-type=2&max-keys={page_size}&start-after=obj-{start_idx:07}"
        );
        cli.ready().await.unwrap();
        let req = build_fixed_req(
            "GET",
            &recovered_srv.s3_addr,
            "/million-bkt",
            &query,
            "UNSIGNED-PAYLOAD",
            Bytes::new(),
        );
        let t0 = Instant::now();
        let resp = cli.send_request(req).await.unwrap();
        assert_eq!(resp.status().as_u16(), 200);
        let xml_bytes = resp.into_body().collect().await.unwrap().to_bytes();
        list_lats.push(t0.elapsed().as_micros() as u64);

        if total_versions > page_size {
            let xml = std::str::from_utf8(&xml_bytes).unwrap();
            assert!(
                xml.contains(&format!("<KeyCount>{page_size}</KeyCount>")),
                "expected KeyCount={page_size} in ListObjectsV2 response"
            );
        }
    }
    drop(cli);

    let list_summary = summarize_latencies_us(list_lats);
    let nfr4_passed = list_summary.p99_ms <= 20.0;
    eprintln!(
        "[NFR-4] ListObjectsV2 ({} versions, {} random pages of {}): p50={:.2}ms p95={:.2}ms p99={:.2}ms (target <= 20.0ms) -> passed={}",
        total_versions, queries, page_size, list_summary.p50_ms, list_summary.p95_ms, list_summary.p99_ms, nfr4_passed
    );

    recovered_srv.sigterm_and_wait();
    let fsck = recovered_srv.run_fsck_json();
    assert_eq!(fsck["status"], "ok");
    let fsck_versions = fsck["object_versions"].as_u64().unwrap() as usize;
    assert_eq!(fsck_versions, total_versions);

    let _ = fs::remove_dir_all(&work_dir);
    let _ = fs::remove_dir_all(&data_dir);

    let nfr4 = Nfr4ListMillionReport {
        total_objects: total_versions,
        page_size,
        queries,
        latency: list_summary,
        target_max_p99_ms: 20.0,
        passed: nfr4_passed,
    };
    let nfr6 = Nfr6ColdRecoveryReport {
        total_versions,
        checkpoint_versions: ckpt_cutoff,
        wal_replay_versions: wal_tail,
        kill9_to_health200_secs: recovery_secs,
        target_max_secs: 20.0,
        fsck_verified_versions: fsck_versions,
        passed: nfr6_passed,
    };
    (nfr4, nfr6)
}

#[tokio::main(flavor = "multi_thread", worker_threads = 8)]
async fn main() {
    let args = Args::parse();
    if let (Some(port), Some(file)) = (args.internal_loopback_port, args.internal_loopback_file) {
        run_internal_loopback_server(port, &file).await;
        return;
    }
    let s3d_bin = resolve_s3d_binary(args.s3d_bin);
    let cpu_cores_available = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);
    eprintln!(
        "[VR-9] Using s3d binary: {} (os={}, arch={}, cpu_cores={})",
        s3d_bin.display(),
        std::env::consts::OS,
        std::env::consts::ARCH,
        cpu_cores_available
    );

    let bench_tmp = if let Some(ref wd) = args.work_dir {
        fs::create_dir_all(wd).expect("failed to create --work-dir");
        tempfile::tempdir_in(wd).expect("failed to create tempdir inside --work-dir")
    } else {
        tempfile::tempdir().expect("failed to create benchmark tempdir")
    };
    let disk_baseline = run_disk_sequential_baseline(bench_tmp.path()).await;
    let nfr3_large_stream =
        run_nfr3_large_stream_gate(&s3d_bin, bench_tmp.path(), &disk_baseline).await;
    let nfr5_memory = run_nfr5_memory_gate(&s3d_bin, bench_tmp.path(), args.nfr5_upload_bytes).await;
    let (nfr1_small_put, nfr2_small_get) =
        run_nfr1_nfr2_gates(&s3d_bin, bench_tmp.path(), args.put_get_secs).await;
    let (nfr4_list_1m, nfr6_cold_recovery) =
        run_nfr4_and_nfr6_gates(&s3d_bin, bench_tmp.path(), args.million_count).await;

    let all_passed = nfr1_small_put.passed
        && nfr2_small_get.passed
        && nfr3_large_stream.passed
        && nfr4_list_1m.passed
        && nfr5_memory.passed
        && nfr6_cold_recovery.passed;

    let report = FullBenchReport {
        generated_at_epoch_s: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        os: std::env::consts::OS.to_string(),
        arch: std::env::consts::ARCH.to_string(),
        cpu_cores_available,
        disk_baseline,
        nfr1_small_put,
        nfr2_small_get,
        nfr3_large_stream,
        nfr4_list_1m,
        nfr5_memory,
        nfr6_cold_recovery,
        all_passed,
    };

    if let Some(parent) = args.report.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    let json = serde_json::to_string_pretty(&report).unwrap();
    fs::write(&args.report, &json).unwrap();
    println!("{json}");

    assert!(
        all_passed,
        "One or more NFR-1..NFR-6 targets did not pass! Inspect {}",
        args.report.display()
    );
}
