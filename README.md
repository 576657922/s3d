# s3d — 单机崩溃安全 S3 兼容对象存储

`s3d` 是一个用纯安全 Rust（Edition 2024，`unsafe_code = "forbid"`）从零实现的单机崩溃安全 S3 兼容对象存储服务，配套自研日志结构存储引擎（Append-Only 段文件 + WAL Group Commit + 原子检查点 + 无锁快照读 + 后台压缩 GC）与十层形式化/自动化验证体系（`VR-1`～`VR-10`）。

- **兼容性基线**：基于 [`ceph/s3-tests`](https://github.com/ceph/s3-tests)（提交 `5b39871`）全部 **545** 个单节点目标用例实测通过 **526 / 545（96.5%）**，其中 P0 `240/249`、P1 `182/190`、P2 `104/106`（`object_lock` 39/39、`lifecycle` 20/20、`encryption` 41/41、`logging` 4/6），`0` 项未实现延后，其余 19 项均为已逐条抓包/源码证明的上游客户端或规格分歧（见 [`docs/deviations.md`](docs/deviations.md) 与 [`reports/p0-ceiling-proof.json`](reports/p0-ceiling-proof.json)）。
- **零外部存储引擎依赖**：不引入 RocksDB、sled、redb、SQLite、LMDB 等任何现成键值库；全工作区仅 `crates/s3d-disk/src/os.rs` 包含两处经 Miri 与静态门禁审计的 POSIX FFI 包装（`statvfs` 与 `F_NOCACHE`/`posix_fadvise`）。

---

## 功能概览

| 级别 | 支持能力 |
| --- | --- |
| **P0 核心** | 桶 CRUD、Path-style & Virtual-hosted-style 寻址、对象流式 `PUT`/`GET`/`HEAD`/`DELETE`、Range 读、条件读写删（`If-Match` / `If-None-Match` / 时间条件，提交点原子求值）、`CopyObject`、完整分片上传（`Create`/`UploadPart`/`UploadPartCopy`/`Complete`/`Abort`/`ListParts`/`ListMultipartUploads`）、`ListObjects` V1 & `ListObjectsV2`（HMAC 防篡改游标）、批量 `DeleteObjects`、`GetObjectAttributes`、SigV4 Header 与预签名 URL、`aws-chunked` 流式签名与尾部校验和 |
| **P1 多租户与版本** | 多版本控制（`Enabled`/`Suspended`、删除标记、`ListObjectVersions`）、桶/对象标签（`?tagging`）、Object Ownership（`BucketOwnerEnforced`/`ObjectWriter`/`BucketOwnerPreferred`）、ACL（Canned ACL / Grant 头 / XML）、IAM Bucket Policy（`ExplicitDeny > Allow > ACL`、`PublicAccessBlock`、`?policyStatus`）、CORS 与 `OPTIONS` 预检、浏览器表单 `PostObject` |
| **P2 企业级与安全扩展** | 对象锁 WORM（`Governance`/`Compliance` 保留期、`LegalHold`、`x-amz-bypass-governance-retention`）、生命周期过期后台清扫（`?lifecycle`、`x-amz-expiration`）、服务端加密（`?encryption` 默认加密、`SSE-S3`、`SSE-C` AES-256-CTR 寻址流式加解密，零明文客户密钥落盘）、桶日志配置（`?logging`）、原生 TLS 1.2/1.3（`tokio-rustls`）、全部 **10 种校验和算法**（`CRC32`、`CRC32C`、`CRC64NVME`、`SHA1`、`SHA256`、`MD5`、`SHA512`、`XXHASH64`、`XXHASH3`、`XXHASH128`） |
| **运维与可观测性** | 独立管理端口 `/health` 与 `/metrics`（Prometheus 文本格式）、JSON 结构化请求日志（自动脱敏密钥/签名）、`SIGTERM` 30 秒排空优雅停机、低磁盘空间 `503 SlowDown` 保护、离线全量校验 `s3d fsck`、手动/后台段压缩 `s3d compact` |

---

## 目录结构

```text
crates/
  s3d-types/    领域类型、错误码、ObjectStore trait 与流式摘要接口
  s3d-disk/     Disk 抽象层：生产 OsDisk 与故障/断电注入替身 FaultDisk
  s3d-model/    纯内存可执行参考模型（VR-1，覆盖全部 63 个操作与 FR-1..FR-51 标注）
  s3d-engine/   自研日志结构存储引擎（段文件、WAL Group Commit、检查点、GC、fsck）
  s3d-proto/    S3 HTTP/XML 协议编解码、SigV4 验签、aws-chunked、Policy/CORS/PostObject
  s3d-server/   HTTP/HTTPS 服务组装、连接过载保护、配置加载与 `s3d` CLI 二进制
  s3d-check/    HTTP 层单 Key 并发压测与 Wing & Gong / Lowe (WGL) 线性一致性检查器（VR-4）
  s3d-bench/    端到端性能、内存、百万对象列举与 kill -9 冷恢复验收压测工具（VR-9）
  s3d-fuzz/     结构化模糊测试核心与语料回归驱动（配合 fuzz/ 下 8 个 libFuzzer 目标，VR-7）
docs/
  01-architecture.md      总体架构与边界契约
  02-storage-engine.md    存储引擎物理格式、WAL/检查点、崩溃恢复与并发协议
  03-protocol-and-api.md  S3 协议栈、SigV4、错误码与 P0/P1/P2 操作规格映射
  04-verification.md      十层验证体系（VR-1..VR-10）设计
  05-roadmap.md           里程碑交付记录与 Q1..Q6 闭环台账
  deviations.md           ceph/s3-tests 兼容性偏差登记表（G1 门禁校核）
scripts/
  ci_gate.sh              本地与 CI 一键阻断门禁脚本（G4）
  run_s3tests_gate.py     自包含 s3-tests 启动、执行与离线 fsck 校验器（VR-5）
  vr6_real_clients.py     boto3 1.44 + awscli v1 + 1 GiB 分片端到端验收脚本（VR-6）
  run_libfuzzer_gate.py   8 目标并行 cargo-fuzz (libFuzzer) 门禁脚本（VR-7）
  verify_fr_traceability.py 需求编号 100% 落位扫描脚本（VR-1）
  verify_p0_ceiling.py    P0 理论上限抓包与源码机械证明脚本（G1）
```

---

## 快速开始

### 1. 编译

要求 Rust `1.85+`（推荐最新 `stable`，Edition 2024）：

```bash
cargo build --release -p s3d-server --bin s3d
```

### 2. 配置账号与服务

创建权限为 `0600` 的凭据文件 `credentials.toml`（权限过宽时 `s3d` 会拒绝启动）：

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

创建可选配置文件 `s3d.toml`（未知字段会严格报错拒绝，所有核心项均可通过 CLI 参数覆盖）：

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
# 如需启用原生 HTTPS (TLS 1.2 / 1.3)，同时配置以下两项：
# tls_cert_file = "./cert.pem"
# tls_key_file  = "./key.pem"
```

### 3. 启动服务与日常运维

```bash
# 启动 S3 服务（业务端口 8000，管理端口 9000 提供 /health 与 /metrics）
./target/release/s3d serve --config s3d.toml

# 使用 awscli 操作
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE \
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY \
aws --endpoint-url http://127.0.0.1:8000 --region us-east-1 s3 mb s3://my-bucket

# 离线全量完整性校验（停机状态下逐块核对 FORMAT、检查点、WAL 与全部段文件 CRC32C）
./target/release/s3d fsck --data-dir ./data

# 手动触发段空间压缩回收
./target/release/s3d compact --data-dir ./data --gc-live-ratio 0.5
```

---

## 运行验证门禁

```bash
# 一键运行 PR 阻断门禁（unsafe/禁用依赖审计 + FR 追溯 + clippy + release 全测 + Miri + VR-6 + s3-tests P0）
bash scripts/ci_gate.sh

# 运行全量 545 项 ceph/s3-tests 门禁与棘轮防退化检查
.venv/bin/python scripts/run_s3tests_gate.py --select ALL --junitxml reports/m4-junit.xml
.venv/bin/python scripts/check_junit.py reports/m4-junit.xml --min-passed 526

# 运行 VR-9 全套性能与冷恢复基准（NFR-1..NFR-6 + fio 对比 + fsck）
cargo build --release -p s3d-server -p s3d-bench
./target/release/s3d-bench --s3d-bin ./target/release/s3d --put-get-secs 300 --report reports/m3-bench.json

# 在 Linux x86-64 (2 vCPU, 7 GB RAM) 标准验收容器中复现
docker build --platform=linux/amd64 -f Dockerfile.linux-accept -t s3d-linux-accept:latest .
```

---

## 许可证

Apache-2.0
