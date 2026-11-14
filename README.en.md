# s3d — Crash-Safe Single-Node S3-Compatible Object Storage

[简体中文](README.md) | **English** | [日本語](README.ja.md)

`s3d` is a crash-safe, single-node, S3-compatible object storage server written from scratch in safe Rust (Edition 2024, `unsafe_code = "forbid"`). It ships with its own log-structured storage engine (append-only segment files + WAL group commit + atomic checkpoints + lock-free snapshot reads + background compaction GC) and a ten-layer formal/automated verification suite (`VR-1` to `VR-10`).

- **Compatibility baseline**: Against all **545** single-node target cases of [`ceph/s3-tests`](https://github.com/ceph/s3-tests) (commit `5b39871`), **526 / 545 (96.5%)** pass: P0 `240/249`, P1 `182/190`, P2 `104/106` (`object_lock` 39/39, `lifecycle` 20/20, `encryption` 41/41, `logging` 4/6). `0` cases are deferred as unimplemented; each of the remaining 19 is an upstream client or spec divergence, proven case by case with packet captures or source inspection (see [`docs/deviations.md`](docs/deviations.md) and [`reports/p0-ceiling-proof.json`](reports/p0-ceiling-proof.json)).
- **No external storage engine**: No off-the-shelf key-value store (RocksDB, sled, redb, SQLite, LMDB, etc.). The only non-safe code in the workspace is two POSIX FFI wrappers in `crates/s3d-disk/src/os.rs` (`statvfs` and `F_NOCACHE`/`posix_fadvise`), audited by Miri and a static CI gate.

---

## Measured Performance and Verification (`Linux x86-64, 2 vCPU, 7 GB RAM`)

Full 300-second benchmark data is archived in [`reports/linux-x86_64-bench.json`](reports/linux-x86_64-bench.json) (Apple Silicon native results for comparison: [`reports/m3-bench.json`](reports/m3-bench.json)):

| Metric | Scenario | Spec threshold | Measured on `Linux x86-64 (2 vCPU, 7 GB)` | Status |
| --- | --- | --- | --- | --- |
| **`NFR-1`** | 4 KiB `PutObject` (32 concurrent, 300s, group-commit durable) | `≥ 1,000 ops/s` and `p99 ≤ 50 ms` | **`3,049.2 ops/s`**, `p50 = 4.05 ms`, **`p99 = 41.11 ms`** | PASS |
| **`NFR-2`** | 4 KiB `GetObject` (32 concurrent, 300s) | `≥ 5,000 ops/s` and `p99 ≤ 10 ms` | **`31,669.1 ops/s`**, `p50 = 0.91 ms`, **`p99 = 3.58 ms`** | PASS |
| **`NFR-3`** | 1 GiB single-stream `PutObject` / `GetObject` (vs. `fio --direct=1` raw disk `308.8 / 350.2 MiB/s`) | PUT `≥ 70%` of raw disk, GET `≥ 80%` of raw disk | PUT **`334.5 MiB/s` (`108.3%`)**, GET **`1,374.9 MiB/s` (`392.6%`)** | PASS |
| **`NFR-4`** | Random `start-after` `ListObjectsV2` on a 1M-object bucket (1,000 keys/page, 1,000 queries) | `p99 ≤ 20 ms` | `p50 = 1.18 ms`, **`p99 = 1.50 ms`** | PASS |
| **`NFR-5`** | Resident memory (idle / peak `VmRSS` during a `10 GiB` streaming multipart upload) | idle `≤ 64 MiB`, peak `≤ 66 MiB` | idle **`11.18 MiB`**, `10 GiB` upload peak **`25.52 MiB`** | PASS |
| **`NFR-6`** | Cold recovery after `SIGKILL` with 1M object versions (950k in checkpoint + 50k in WAL) until `/health 200` | `≤ 20 s` | **`1.204 s`** (offline `s3d fsck`: `0` errors) | PASS |

Ten-layer verification gates (`VR-1` to `VR-10`), as archived:
- **`VR-1` / `VR-2`**: `s3d-model` covers all 63 operations with `51/51` `FR` annotations (`119/119` spec requirement IDs mechanically traceable across the workspace); **100,000** random P0+P1+P2 `proptest` operation sequences differentially checked against the engine with `0` diffs.
- **`VR-3`**: **100,000** mid-syscall power cuts injected at 4 KiB sector granularity by `FaultDisk` (covering checkpoints, WAL pruning, GC and multi-segment multipart uploads) with `0` violations.
- **`VR-4`**: Exhaustive `Loom` interleavings + **10,000** randomized `Shuttle` schedules + `s3d-check` HTTP-level WGL linearizability over **10,000** per-key histories (16 clients, 240,000 signed requests) with `0` violations.
- **`VR-5` / `VR-6` / `VR-8`**: Full `ceph/s3-tests` at **526 / 545** on both `Linux x86-64` and `macOS ARM64` ([`linux-x86_64-junit.xml`](reports/linux-x86_64-junit.xml), [`m4-junit.xml`](reports/m4-junit.xml)); `boto3 1.44` + `awscli v1` end-to-end 1 GiB multipart SHA-256 check passes; **10,000** SigV4 differential/tamper groups (30,000 verdicts) with `0` misjudgments.
- **`VR-7` / `VR-10`**: 8 `cargo-fuzz` targets (`LLVM libFuzzer` + `SanitizerCoverage` + `AddressSanitizer`), **1 hour each (`3,606–3,609s`)**, **323,360,642** coverage-guided executions with `0` crashes ([`vr7-cargo-fuzz-report.json`](reports/vr7-cargo-fuzz-report.json)); `cargo +nightly miri test --workspace --lib` reports `0` UB / `0` leaks.

---

## Features

| Tier | Capabilities |
| --- | --- |
| **P0 core** | Bucket CRUD, path-style & virtual-hosted-style addressing, streaming object `PUT`/`GET`/`HEAD`/`DELETE`, range reads, conditional read/write/delete (`If-Match` / `If-None-Match` / time conditions, evaluated atomically at the commit point), `CopyObject`, full multipart upload (`Create`/`UploadPart`/`UploadPartCopy`/`Complete`/`Abort`/`ListParts`/`ListMultipartUploads`), `ListObjects` V1 & `ListObjectsV2` (HMAC tamper-proof cursors), batch `DeleteObjects`, `GetObjectAttributes`, SigV4 header auth and presigned URLs, `aws-chunked` streaming signatures with trailing checksums |
| **P1 multi-tenancy & versioning** | Versioning (`Enabled`/`Suspended`, delete markers, `ListObjectVersions`), bucket/object tagging (`?tagging`), Object Ownership (`BucketOwnerEnforced`/`ObjectWriter`/`BucketOwnerPreferred`), ACLs (canned ACLs / grant headers / XML), IAM bucket policies (`ExplicitDeny > Allow > ACL`, `PublicAccessBlock`, `?policyStatus`), CORS and `OPTIONS` preflight, browser form `PostObject` |
| **P2 enterprise & security** | Object Lock WORM (`Governance`/`Compliance` retention, `LegalHold`, `x-amz-bypass-governance-retention`), background lifecycle expiration (`?lifecycle`, `x-amz-expiration`), server-side encryption (`?encryption` default encryption, `SSE-S3`, `SSE-C` with seekable streaming AES-256-CTR; customer keys are never persisted in plaintext), bucket logging configuration (`?logging`), native TLS 1.2/1.3 (`tokio-rustls`), all **10 checksum algorithms** (`CRC32`, `CRC32C`, `CRC64NVME`, `SHA1`, `SHA256`, `MD5`, `SHA512`, `XXHASH64`, `XXHASH3`, `XXHASH128`) |
| **Operations & observability** | Separate admin port with `/health` and `/metrics` (Prometheus text format), structured JSON request logs (keys/signatures redacted), graceful `SIGTERM` shutdown with 30s drain, low-disk-space `503 SlowDown` protection, offline full integrity check `s3d fsck`, manual/background segment compaction `s3d compact` |

---

## Repository Layout

```text
crates/
  s3d-types/    Domain types, error codes, ObjectStore trait and streaming digest interfaces
  s3d-disk/     Disk abstraction: production OsDisk and fault/power-cut injecting FaultDisk
  s3d-model/    Pure in-memory executable reference model (VR-1; all 63 operations, FR-1..FR-51 annotated)
  s3d-engine/   Log-structured storage engine (segments, WAL group commit, checkpoints, GC, fsck)
  s3d-proto/    S3 HTTP/XML codec, SigV4 verification, aws-chunked, Policy/CORS/PostObject
  s3d-server/   HTTP/HTTPS server, overload protection, config loading and the `s3d` CLI binary
  s3d-check/    HTTP-level per-key concurrency load generator and WGL (Wing & Gong / Lowe) linearizability checker (VR-4)
  s3d-bench/    End-to-end acceptance benchmarks: throughput, memory, 1M-object listing, kill -9 cold recovery (VR-9)
  s3d-fuzz/     Structured fuzzing core and corpus regression driver (used by the 8 libFuzzer targets under fuzz/, VR-7)
docs/
  01-architecture.md      Overall architecture and boundary contracts
  02-storage-engine.md    On-disk format, WAL/checkpoints, crash recovery and concurrency protocols
  03-protocol-and-api.md  S3 protocol stack, SigV4, error codes, P0/P1/P2 operation mapping
  04-verification.md      Design of the ten-layer verification suite (VR-1..VR-10)
  05-roadmap.md           Milestone delivery log and Q1..Q6 resolution ledger
  deviations.md           ceph/s3-tests deviation register (checked by gate G1)
scripts/
  ci_gate.sh              One-shot local/CI blocking gate (G4)
  run_s3tests_gate.py     Self-contained s3-tests launcher, runner and offline fsck checker (VR-5)
  vr6_real_clients.py     boto3 1.44 + awscli v1 + 1 GiB multipart end-to-end acceptance (VR-6)
  run_libfuzzer_gate.py   Parallel 8-target cargo-fuzz (libFuzzer) gate (VR-7)
  verify_fr_traceability.py Requirement ID 100% traceability scanner (VR-1)
  verify_p0_ceiling.py    Packet-capture and source-level proof of the P0 ceiling (G1)
```

---

## Quick Start

### 1. Build

Requires Rust `1.85+` (latest `stable` recommended, Edition 2024):

```bash
cargo build --release -p s3d-server --bin s3d
```

### 2. Configure accounts and the server

Create a credentials file `credentials.toml` with mode `0600` (`s3d` refuses to start if permissions are too broad):

```toml
[[accounts]]
user_id = "0123456789abcdef"
display_name = "demo"
email = "demo@example.com"
access_key = "AKIAIOSFODNN7EXAMPLE"
secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
```

```bash
chmod 600 credentials.toml
```

Create an optional config file `s3d.toml` (unknown fields are rejected; every core option can be overridden on the CLI):

```toml
listen = "127.0.0.1:8000"
admin_listen = "127.0.0.1:9000"
data_dir = "./data"
region = "us-east-1"
credentials_file = "./credentials.toml"
default_object_ownership = "BucketOwnerEnforced"
group_commit_window_ms = 1
group_commit_max_batch = 64
max_connections = 1024
log_format = "json"
# To enable native HTTPS (TLS 1.2 / 1.3), set both of these:
# tls_cert_file = "./cert.pem"
# tls_key_file  = "./key.pem"
```

### 3. Run and operate

```bash
# Start the S3 service (S3 on port 8000; admin port 9000 serves /health and /metrics)
./target/release/s3d serve --config s3d.toml

# Use awscli
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE \
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY \
aws --endpoint-url http://127.0.0.1:8000 --region us-east-1 s3 mb s3://my-bucket

# Offline full integrity check (with the server stopped: verifies FORMAT, checkpoints, WAL and CRC32C of every segment block)
./target/release/s3d fsck --data-dir ./data

# Manually trigger segment compaction
./target/release/s3d compact --data-dir ./data --gc-live-ratio 0.5
```

---

## Running the Verification Gates

```bash
# One-shot PR blocking gate (unsafe/forbidden-dependency audit + FR traceability + clippy + release tests + Miri + VR-6 + s3-tests P0)
bash scripts/ci_gate.sh

# Full 545-case ceph/s3-tests gate with ratchet regression check
.venv/bin/python scripts/run_s3tests_gate.py --select ALL --junitxml reports/m4-junit.xml
.venv/bin/python scripts/check_junit.py reports/m4-junit.xml --min-passed 526

# VR-9 full performance and cold-recovery benchmark (NFR-1..NFR-6 + fio baseline + fsck)
cargo build --release -p s3d-server -p s3d-bench
./target/release/s3d-bench --s3d-bin ./target/release/s3d --put-get-secs 300 --report reports/m3-bench.json

# Reproduce in the standard Linux x86-64 (2 vCPU, 7 GB RAM) acceptance container
docker build --platform=linux/amd64 -f Dockerfile.linux-accept -t s3d-linux-accept:latest .
```

---

## License

Apache-2.0
