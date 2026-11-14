# s3d

[简体中文](README.zh-CN.md) | **English** | [日本語](README.md)

[![CI](https://github.com/576657922/s3d/actions/workflows/ci.yml/badge.svg?branch=main&event=push)](https://github.com/576657922/s3d/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

A single-node, S3-compatible object store written in Rust. The storage engine (append-only segment files plus a WAL) is written from scratch; it does not use RocksDB or any other existing key-value store.

The goal is simple: once s3d has returned success for a write, the data survives a process crash or a power cut. That property is checked with a disk layer that simulates power loss, and with differential tests against a reference model.

> **Status:** an experimental personal project. It has not been run in production, so do not use it to store data you care about.

## Highlights

- **S3-compatible:** of the 808 tests in [ceph/s3-tests](https://github.com/ceph/s3-tests), 545 remain after excluding tests that also fail against AWS itself (`fails_on_aws`) and out-of-scope features such as KMS, multi-tenancy and SigV2. s3d passes 526 of those 545 (exclusions in [tests/s3tests-manifest.json](tests/s3tests-manifest.json), the 19 failures explained in [docs/deviations.md](docs/deviations.md)). Works with the AWS CLI and boto3 out of the box.
- **Crash-safe:** 100,000 simulated power cuts at 4 KiB-sector granularity, with no acknowledged write lost.
- **Small and quick to recover:** 11 MiB of memory when idle and a 26 MiB peak during a 10 GiB upload. After a SIGKILL with one million object versions on disk, it serves requests again in 1.2 s (measured locally).
- **Single binary:** no external database or service needed.
- **Features:** multipart upload, versioning, bucket policies and ACLs, Object Lock, lifecycle expiration, server-side encryption (SSE-S3 / SSE-C), TLS and more. See [Supported features](#supported-features).

## Where it fits

Mature S3-compatible stores already exist: MinIO, Garage, SeaweedFS, RustFS and others. s3d does not try to compete with them on features or distributed deployment. It deliberately stays single-node and focuses on one question: how far can tests go in showing that acknowledged writes are never lost?

## Quick start

Requires Rust 1.85 or later.

```bash
# 1. Build
cargo build --release -p s3d-server --bin s3d

# 2. Create credentials (s3d refuses to start unless the file is mode 0600)
cat > credentials.toml <<'EOF'
[[accounts]]
user_id = "0123456789abcdef"
display_name = "demo"
email = "demo@example.com"
access_key = "AKIAIOSFODNN7EXAMPLE"
secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
EOF
chmod 600 credentials.toml

# 3. Start (S3 on port 8000; /health and /metrics on admin port 9000)
./target/release/s3d serve --listen 127.0.0.1:8000 --admin-listen 127.0.0.1:9000 \
  --data-dir ./data --credentials-file ./credentials.toml

# 4. From another terminal, use the AWS CLI
export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
aws --endpoint-url http://127.0.0.1:8000 --region us-east-1 s3 mb s3://my-bucket
aws --endpoint-url http://127.0.0.1:8000 --region us-east-1 s3 cp ./README.md s3://my-bucket/
```

For the config file, TLS and maintenance commands, see [Configuration and operations](#configuration-and-operations).

## How it works

The `PutObject` path:

```mermaid
sequenceDiagram
    participant C as Client
    participant S as s3d
    participant Seg as Segment file
    participant W as WAL
    C->>S: PUT (body streamed)
    S->>Seg: Append data
    S->>S: Verify checksums
    S->>Seg: fdatasync (batched with concurrent writes)
    S->>W: Append metadata and fdatasync (commit point)
    S->>S: Update in-memory index
    S-->>C: 200 OK
```

- **Writes:** the body is appended to a segment file; the write is committed once its metadata record is in the WAL and `fdatasync` returns. Concurrent writes share a single `fdatasync` (group commit).
- **Recovery on restart:** load the newest checkpoint, then replay the WAL after it. A torn record at the tail is truncated; corruption in the middle stops startup.
- **Reads and GC:** segments being read are reference-counted, so garbage collection never deletes a file that is still in use.
- **fsync failures:** if `fsync` returns an error, s3d switches to read-only and rejects further writes, because the on-disk state after a failed `fsync` cannot be trusted.

Details: [docs/02-storage-engine.md](docs/02-storage-engine.md) (in Chinese).

## Testing

| What is checked | How | Scale | When |
| --- | --- | --- | --- |
| Behaves as specified | Random operation sequences run against an in-memory reference model and compared (proptest) | 1M sequences | Nightly (10k per PR) |
| No data lost on power loss | FaultDisk drops and reorders unsynced writes per 4 KiB sector and drops unsynced directory changes, then restarts | 100k power cuts | Nightly (1,000 per PR) |
| Concurrency | Loom (exhaustively explores simplified models of the segment-release and group-commit protocols, written in the tests), Shuttle (random schedules over the real engine), linearizability checking over HTTP (WGL) | 10k Shuttle schedules, 10k WGL histories | Nightly |
| S3 compatibility | ceph/s3-tests | 526 of 545 pass | Nightly (P0: at least 240 of 249 per PR) |
| Real clients | boto3 and AWS CLI, 1 GiB multipart upload with SHA-256 check | 1 GiB | Every PR |
| SigV4 signing | Differential tests against botocore signatures, plus tamper detection | 10k cases | Every PR |
| Robust input handling | cargo-fuzz (libFuzzer + AddressSanitizer), 8 targets | 1 hour each | Nightly |
| Undefined behavior | Miri | All library tests | Every PR |

CI results are on [GitHub Actions](https://github.com/576657922/s3d/actions/workflows/ci.yml). Test design is described in [docs/04-verification.md](docs/04-verification.md); records of local runs are in [reports/](reports/).

`unsafe` appears only in two functions in `crates/s3d-disk/src/os.rs` (calls to `statvfs` and `F_NOCACHE` / `posix_fadvise`). Every other crate is compiled with `unsafe_code = "forbid"`.

## Performance (measured locally)

Measured on Linux x86-64 with 2 vCPUs and 7 GB of RAM. Raw data: [reports/linux-x86_64-bench.json](reports/linux-x86_64-bench.json).

| Scenario | Result |
| --- | --- |
| 4 KiB PUT, 32 concurrent, 300 s (durable on disk before the response) | 3,049 ops/s, p50 4.0 ms, p99 41 ms |
| 4 KiB GET, 32 concurrent, 300 s | 31,669 ops/s, p50 0.9 ms, p99 3.6 ms |
| 1 GiB PUT / GET, single stream | PUT 334 MiB/s, GET 1,375 MiB/s (*) |
| ListObjectsV2 on a bucket with 1M objects (1,000 keys per page, random start) | p50 1.2 ms, p99 1.5 ms |
| Memory (RSS) | 11 MiB idle, 26 MiB peak during a 10 GiB upload |
| SIGKILL with 1M versions on disk, then restart until it responds | 1.2 s (`s3d fsck` afterwards: 0 errors) |

(*) The GET figure is served from the page cache, not read from disk. On the same machine, `fio --direct=1` measured the raw disk at 309 MiB/s for writes and 350 MiB/s for reads.

## Known issues

- In the 4 KiB PUT benchmark, the maximum latency has an outlier of 33 s (p99 is 41 ms). The cause has not been investigated yet.

## Configuration and operations

The config file `s3d.toml` is optional. Unknown fields are rejected as errors, and the main settings can be overridden by CLI flags.

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
# To enable native HTTPS (TLS 1.2 / 1.3), set both of the following:
# tls_cert_file = "./cert.pem"
# tls_key_file  = "./key.pem"
```

```bash
# Start with the config file
./target/release/s3d serve --config s3d.toml

# Offline full integrity check (while stopped: verifies FORMAT, checkpoints, WAL and the CRC32C of every segment block)
./target/release/s3d fsck --data-dir ./data

# Run segment compaction manually
./target/release/s3d compact --data-dir ./data --gc-live-ratio 0.5
```

## Supported features

| Level | Features |
| --- | --- |
| **P0 core** | Bucket CRUD, path-style & virtual-hosted-style addressing, streaming object `PUT`/`GET`/`HEAD`/`DELETE`, range reads, conditional read/write/delete (`If-Match` / `If-None-Match` / time conditions, evaluated atomically at the commit point), `CopyObject`, full multipart upload (`Create`/`UploadPart`/`UploadPartCopy`/`Complete`/`Abort`/`ListParts`/`ListMultipartUploads`), `ListObjects` V1 & `ListObjectsV2` (HMAC tamper-proof cursors), batch `DeleteObjects`, `GetObjectAttributes`, SigV4 header auth and presigned URLs, `aws-chunked` streaming signatures with trailing checksums |
| **P1 multi-tenancy & versioning** | Versioning (`Enabled`/`Suspended`, delete markers, `ListObjectVersions`), bucket/object tagging (`?tagging`), Object Ownership (`BucketOwnerEnforced`/`ObjectWriter`/`BucketOwnerPreferred`), ACLs (canned ACLs / grant headers / XML), IAM bucket policies (`ExplicitDeny > Allow > ACL`, `PublicAccessBlock`, `?policyStatus`), CORS and `OPTIONS` preflight, browser form `PostObject` |
| **P2 enterprise & security** | Object Lock WORM (`Governance`/`Compliance` retention, `LegalHold`, `x-amz-bypass-governance-retention`), background lifecycle expiration (`?lifecycle`, `x-amz-expiration`), server-side encryption (`?encryption` default encryption, `SSE-S3`, `SSE-C` with seekable streaming AES-256-CTR; customer keys are never persisted in plaintext), bucket logging configuration (`?logging`), native TLS 1.2/1.3 (`tokio-rustls`), all **10 checksum algorithms** (`CRC32`, `CRC32C`, `CRC64NVME`, `SHA1`, `SHA256`, `MD5`, `SHA512`, `XXHASH64`, `XXHASH3`, `XXHASH128`) |
| **Operations & observability** | Separate admin port with `/health` and `/metrics` (Prometheus text format), structured JSON request logs (keys/signatures redacted), graceful `SIGTERM` shutdown with 30s drain, low-disk-space `503 SlowDown` protection, offline full integrity check `s3d fsck`, manual/background segment compaction `s3d compact` |

## Repository layout

```text
crates/
  s3d-types/    Domain types, error codes, ObjectStore trait and streaming digest interfaces
  s3d-disk/     Disk abstraction: production OsDisk and fault/power-cut injecting FaultDisk
  s3d-model/    In-memory reference model (VR-1; all 63 operations, FR-1..FR-51 annotated)
  s3d-engine/   Log-structured storage engine (segments, WAL group commit, checkpoints, GC, fsck)
  s3d-proto/    S3 HTTP/XML codec, SigV4 verification, aws-chunked, Policy/CORS/PostObject
  s3d-server/   HTTP/HTTPS server, overload protection, config loading and the `s3d` CLI binary
  s3d-check/    HTTP-level per-key concurrency load generator and WGL (Wing & Gong / Lowe) linearizability checker (VR-4)
  s3d-bench/    End-to-end benchmarks: throughput, memory, 1M-object listing, kill -9 cold recovery (VR-9)
  s3d-fuzz/     Structured fuzzing core and corpus regression driver (used by the 8 libFuzzer targets under fuzz/, VR-7)
docs/
  00-requirements.md      Requirements specification (in Chinese)
  01-architecture.md      Overall architecture and boundary contracts
  02-storage-engine.md    On-disk format, WAL/checkpoints, crash recovery and concurrency protocols
  03-protocol-and-api.md  S3 protocol stack, SigV4, error codes, P0/P1/P2 operation mapping
  04-verification.md      Design of the ten test layers (VR-1..VR-10)
  05-roadmap.md           Milestone log and Q1..Q6 resolution ledger
  deviations.md           Failing ceph/s3-tests cases and why
scripts/
  ci_gate.sh              Runs the local/CI blocking gate in one go
  run_s3tests_gate.py     Starts s3d, runs s3-tests, then runs fsck (VR-5)
  vr6_real_clients.py     boto3 + AWS CLI + 1 GiB multipart end-to-end test (VR-6)
  run_libfuzzer_gate.py   Parallel 8-target cargo-fuzz (libFuzzer) gate (VR-7)
  verify_fr_traceability.py Checks that every requirement ID maps to code (VR-1)
  verify_p0_ceiling.py    Checks the recorded reasons for failing P0 cases (G1)
```

## Running the tests locally

```bash
# Run the PR blocking gate (unsafe & banned-dependency audit + requirement tracing + clippy + release tests + Miri + real clients + s3-tests P0)
bash scripts/ci_gate.sh

# Run the 545 targeted ceph/s3-tests cases and check that the pass count has not regressed
.venv/bin/python scripts/run_s3tests_gate.py --select ALL --junitxml reports/m4-junit.xml
.venv/bin/python scripts/check_junit.py reports/m4-junit.xml --min-passed 526

# Performance and cold-recovery benchmarks (including the fio baseline and fsck)
cargo build --release -p s3d-server -p s3d-bench
./target/release/s3d-bench --s3d-bin ./target/release/s3d --put-get-secs 300 --report reports/m3-bench.json

# Reproduce in a Linux x86-64 (2 vCPU, 7 GB RAM) container
docker build --platform=linux/amd64 -f Dockerfile.linux-accept -t s3d-linux-accept:latest .
```

## License

[Apache-2.0](LICENSE)
