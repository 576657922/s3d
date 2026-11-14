# s3d

**简体中文** | [English](README.en.md) | [日本語](README.md)

[![CI](https://github.com/576657922/s3d/actions/workflows/ci.yml/badge.svg?branch=main&event=push)](https://github.com/576657922/s3d/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

一个单机运行的 S3 兼容对象存储，用 Rust 编写。存储引擎（只追加的段文件 + WAL）也是自己实现的，没有用 RocksDB 之类现成的键值库。

目标只有一个：只要 s3d 对一次写入返回了成功，进程崩溃或者断电之后数据都还在。这一点用模拟断电的磁盘层和对照参考模型的差分测试来验证。

> **状态**：个人实验项目，没有在生产环境跑过，请不要用它存重要数据。

## 特点

- **兼容 S3**：[ceph/s3-tests](https://github.com/ceph/s3-tests) 共 808 项，去掉 AWS 本身也通不过的用例（`fails_on_aws`）和 KMS、多租户、SigV2 等不在范围内的功能后剩 545 项，通过 526 项（排除明细见 [tests/s3tests-manifest.json](tests/s3tests-manifest.json)，未通过的 19 项及原因见 [docs/deviations.md](docs/deviations.md)）。awscli、boto3 可以直接用。
- **崩溃安全**：按 4 KiB 扇区粒度模拟断电 10 万次，已确认的写入一次都没丢。
- **占用小、恢复快**：空闲时内存 11 MiB，上传 10 GiB 时峰值 26 MiB。存有 100 万个对象版本时被强杀，1.2 秒后恢复服务（本地实测）。
- **单个二进制**：不需要外部数据库或服务。
- **主要功能**：分片上传、版本控制、桶策略和 ACL、对象锁、生命周期、服务端加密（SSE-S3 / SSE-C）、TLS 等，完整列表见[功能列表](#功能列表)。

## 定位

S3 兼容存储已经有 MinIO、Garage、SeaweedFS、RustFS 等成熟实现。s3d 不在功能数量或分布式部署上和它们比，而是只做单机，专注一个问题：能用测试把「已确认的写入不会丢」证明到什么程度。

## 快速开始

需要 Rust 1.85 或更高版本。

```bash
# 1. 编译
cargo build --release -p s3d-server --bin s3d

# 2. 创建凭据文件（权限不是 0600 时 s3d 会拒绝启动）
cat > credentials.toml <<'EOF'
[[accounts]]
user_id = "0123456789abcdef"
display_name = "demo"
email = "demo@example.com"
access_key = "AKIAIOSFODNN7EXAMPLE"
secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
EOF
chmod 600 credentials.toml

# 3. 启动（S3 端口 8000；/health 和 /metrics 在管理端口 9000）
./target/release/s3d serve --listen 127.0.0.1:8000 --admin-listen 127.0.0.1:9000 \
  --data-dir ./data --credentials-file ./credentials.toml

# 4. 在另一个终端用 awscli 操作
export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
aws --endpoint-url http://127.0.0.1:8000 --region us-east-1 s3 mb s3://my-bucket
aws --endpoint-url http://127.0.0.1:8000 --region us-east-1 s3 cp ./README.md s3://my-bucket/
```

配置文件、TLS 和运维命令见[配置与运维](#配置与运维)。

## 工作原理

`PutObject` 的流程：

```mermaid
sequenceDiagram
    participant C as 客户端
    participant S as s3d
    participant Seg as 段文件
    participant W as WAL
    C->>S: PUT（请求体流式传输）
    S->>Seg: 追加写入数据
    S->>S: 校验 checksum
    S->>Seg: fdatasync（和同时到达的写入合并成一次）
    S->>W: 追加元数据并 fdatasync（提交点）
    S->>S: 更新内存索引
    S-->>C: 200 OK
```

- **写入**：请求体追加到段文件；元数据写进 WAL 并 `fdatasync` 成功的那一刻，这次写入才算提交。同时到达的写入共用一次 `fdatasync`（group commit）。
- **重启恢复**：加载最新的检查点，再重放它之后的 WAL。尾部写了一半的记录会被截掉；中间有损坏则拒绝启动。
- **读取与 GC**：正在被读的段文件有引用计数保护，垃圾回收不会删掉还在用的文件。
- **fsync 失败**：`fsync` 一旦报错，s3d 切换为只读，不再接受写入，因为失败之后磁盘上的状态已经不可信。

细节见 [docs/02-storage-engine.md](docs/02-storage-engine.md)。

## 测试

| 验证什么 | 方法 | 规模 | 什么时候跑 |
| --- | --- | --- | --- |
| 行为符合规格 | 随机操作序列同时跑引擎和内存参考模型，对比结果（proptest） | 100 万条序列 | 每晚（PR 时 1 万条） |
| 断电不丢数据 | FaultDisk 按 4 KiB 扇区丢弃、打乱未同步的写入，丢弃未同步的目录变更，然后重启检查 | 10 万次 | 每晚（PR 时 1,000 次） |
| 并发正确性 | Loom（在测试里写的简化模型上，穷举段文件释放和 group commit 两个协议的线程交错）、Shuttle（在真实引擎上随机调度）、HTTP 层线性一致性检查（WGL） | Shuttle 1 万种调度，WGL 1 万条历史 | 每晚 |
| S3 兼容性 | ceph/s3-tests | 545 项通过 526 项 | 每晚（PR 时跑 P0，249 项至少过 240 项） |
| 真实客户端 | boto3 和 awscli 上传 1 GiB 分片并核对 SHA-256 | 1 GiB | 每个 PR |
| SigV4 签名 | 和 botocore 的签名做差分测试，加篡改检测 | 1 万组 | 每个 PR |
| 输入处理的健壮性 | cargo-fuzz（libFuzzer + AddressSanitizer），8 个目标 | 每个 1 小时 | 每晚 |
| 未定义行为 | Miri | 全部库测试 | 每个 PR |

CI 结果见 [GitHub Actions](https://github.com/576657922/s3d/actions/workflows/ci.yml)。各层测试的设计见 [docs/04-verification.md](docs/04-verification.md)，本地运行记录在 [reports/](reports/)。

只有 `crates/s3d-disk/src/os.rs` 里的两个函数用了 `unsafe`（调用 `statvfs` 和 `F_NOCACHE` / `posix_fadvise`），其余 crate 都以 `unsafe_code = "forbid"` 编译。

## 性能（本地实测）

测试环境：Linux x86-64，2 vCPU，7 GB 内存。原始数据见 [reports/linux-x86_64-bench.json](reports/linux-x86_64-bench.json)。

| 场景 | 结果 |
| --- | --- |
| 4 KiB PUT，32 并发，300 秒（返回前已落盘） | 3,049 ops/s，p50 4.0 ms，p99 41 ms |
| 4 KiB GET，32 并发，300 秒 | 31,669 ops/s，p50 0.9 ms，p99 3.6 ms |
| 1 GiB 单流 PUT / GET | PUT 334 MiB/s，GET 1,375 MiB/s（※） |
| 100 万对象的桶上做 ListObjectsV2（每页 1,000 个键，随机起点） | p50 1.2 ms，p99 1.5 ms |
| 内存（RSS） | 空闲 11 MiB，上传 10 GiB 时峰值 26 MiB |
| 存有 100 万个版本时 SIGKILL，到重启后能响应 | 1.2 秒（之后 `s3d fsck` 0 错误） |

※ GET 的数字来自页缓存，不是磁盘读速度。同一台机器上用 `fio --direct=1` 测得磁盘本身写 309 MiB/s、读 350 MiB/s。

## 已知问题

- 4 KiB PUT 压测中，最大延迟出现过 33 秒的离群值（p99 是 41 ms），原因还没查。

## 配置与运维

配置文件 `s3d.toml` 可选。未知字段会直接报错拒绝，主要配置项都可以用命令行参数覆盖。

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
# 如需启用原生 HTTPS（TLS 1.2 / 1.3），同时配置以下两项：
# tls_cert_file = "./cert.pem"
# tls_key_file  = "./key.pem"
```

```bash
# 用配置文件启动
./target/release/s3d serve --config s3d.toml

# 离线全量校验（停机状态下逐块核对 FORMAT、检查点、WAL 与全部段文件的 CRC32C）
./target/release/s3d fsck --data-dir ./data

# 手动触发段压缩回收
./target/release/s3d compact --data-dir ./data --gc-live-ratio 0.5
```

## 功能列表

| 级别 | 支持能力 |
| --- | --- |
| **P0 核心** | 桶 CRUD、Path-style & Virtual-hosted-style 寻址、对象流式 `PUT`/`GET`/`HEAD`/`DELETE`、Range 读、条件读写删（`If-Match` / `If-None-Match` / 时间条件，提交点原子求值）、`CopyObject`、完整分片上传（`Create`/`UploadPart`/`UploadPartCopy`/`Complete`/`Abort`/`ListParts`/`ListMultipartUploads`）、`ListObjects` V1 & `ListObjectsV2`（HMAC 防篡改游标）、批量 `DeleteObjects`、`GetObjectAttributes`、SigV4 Header 与预签名 URL、`aws-chunked` 流式签名与尾部校验和 |
| **P1 多租户与版本** | 多版本控制（`Enabled`/`Suspended`、删除标记、`ListObjectVersions`）、桶/对象标签（`?tagging`）、Object Ownership（`BucketOwnerEnforced`/`ObjectWriter`/`BucketOwnerPreferred`）、ACL（Canned ACL / Grant 头 / XML）、IAM Bucket Policy（`ExplicitDeny > Allow > ACL`、`PublicAccessBlock`、`?policyStatus`）、CORS 与 `OPTIONS` 预检、浏览器表单 `PostObject` |
| **P2 企业级与安全扩展** | 对象锁 WORM（`Governance`/`Compliance` 保留期、`LegalHold`、`x-amz-bypass-governance-retention`）、生命周期过期后台清扫（`?lifecycle`、`x-amz-expiration`）、服务端加密（`?encryption` 默认加密、`SSE-S3`、`SSE-C` AES-256-CTR 寻址流式加解密，零明文客户密钥落盘）、桶日志配置（`?logging`）、原生 TLS 1.2/1.3（`tokio-rustls`）、全部 **10 种校验和算法**（`CRC32`、`CRC32C`、`CRC64NVME`、`SHA1`、`SHA256`、`MD5`、`SHA512`、`XXHASH64`、`XXHASH3`、`XXHASH128`） |
| **运维与可观测性** | 独立管理端口 `/health` 与 `/metrics`（Prometheus 文本格式）、JSON 结构化请求日志（自动脱敏密钥/签名）、`SIGTERM` 30 秒排空优雅停机、低磁盘空间 `503 SlowDown` 保护、离线全量校验 `s3d fsck`、手动/后台段压缩 `s3d compact` |

## 目录结构

```text
crates/
  s3d-types/    领域类型、错误码、ObjectStore trait 与流式摘要接口
  s3d-disk/     磁盘抽象层：生产用 OsDisk 与注入故障/断电的 FaultDisk
  s3d-model/    内存参考模型（VR-1，覆盖全部 63 个操作，带 FR-1..FR-51 标注）
  s3d-engine/   自研日志结构存储引擎（段文件、WAL Group Commit、检查点、GC、fsck）
  s3d-proto/    S3 HTTP/XML 编解码、SigV4 验签、aws-chunked、Policy/CORS/PostObject
  s3d-server/   HTTP/HTTPS 服务、过载保护、配置加载与 `s3d` CLI 二进制
  s3d-check/    HTTP 层单 Key 并发压测与 WGL（Wing & Gong / Lowe）线性一致性检查器（VR-4）
  s3d-bench/    端到端压测：吞吐、内存、百万对象列举、kill -9 冷恢复（VR-9）
  s3d-fuzz/     结构化模糊测试核心与语料回归驱动（配合 fuzz/ 下 8 个 libFuzzer 目标，VR-7）
docs/
  00-requirements.md      需求规格书
  01-architecture.md      总体架构与边界契约
  02-storage-engine.md    磁盘格式、WAL/检查点、崩溃恢复与并发协议
  03-protocol-and-api.md  S3 协议栈、SigV4、错误码与 P0/P1/P2 操作映射
  04-verification.md      十层测试（VR-1..VR-10）的设计
  05-roadmap.md           里程碑记录与 Q1..Q6 闭环台账
  deviations.md           未通过的 ceph/s3-tests 用例及原因
scripts/
  ci_gate.sh              一键运行本地/CI 阻断门禁
  run_s3tests_gate.py     启动 s3d、跑 s3-tests、结束后做 fsck（VR-5）
  vr6_real_clients.py     boto3 + awscli + 1 GiB 分片端到端测试（VR-6）
  run_libfuzzer_gate.py   8 目标并行 cargo-fuzz（libFuzzer）门禁（VR-7）
  verify_fr_traceability.py 检查每个需求编号都能对应到代码（VR-1）
  verify_p0_ceiling.py    核对 P0 未通过用例登记的原因（G1）
```

## 在本地跑测试

```bash
# 一键运行 PR 阻断门禁（unsafe/禁用依赖审计 + 需求编号追溯 + clippy + release 全测 + Miri + 真实客户端 + s3-tests P0）
bash scripts/ci_gate.sh

# 跑全部 545 项 ceph/s3-tests，并检查通过数没有倒退
.venv/bin/python scripts/run_s3tests_gate.py --select ALL --junitxml reports/m4-junit.xml
.venv/bin/python scripts/check_junit.py reports/m4-junit.xml --min-passed 526

# 性能与冷恢复压测（含 fio 基线与 fsck）
cargo build --release -p s3d-server -p s3d-bench
./target/release/s3d-bench --s3d-bin ./target/release/s3d --put-get-secs 300 --report reports/m3-bench.json

# 在 Linux x86-64（2 vCPU，7 GB 内存）容器中复现
docker build --platform=linux/amd64 -f Dockerfile.linux-accept -t s3d-linux-accept:latest .
```

## 许可证

[Apache-2.0](LICENSE)
