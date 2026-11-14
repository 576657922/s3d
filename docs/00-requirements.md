# S3 兼容对象存储 需求规格书

Nov 12, 2026 · @chen fangfang

## 1. 概述

v1 交付一个单机、强一致、崩溃安全的 S3 兼容对象存储服务（工作代号 `s3d`），以 ceph/s3-tests 中 545 个目标用例为兼容性裁判。存储引擎、SigV4 校验和验证工具全部自研，验证方法照搬 S3 团队验证 ShardStore 的论文。

**目标**

| ID | 目标 | 可量化判据 |
| --- | --- | --- |
| G1 | S3 API 兼容 | s3-tests 目标集：P0 ≥ 245/249，P1 ≥ 171/190；做 M4 时 P2 ≥ 85/106 |
| G2 | 强一致 | 已确认写入对其后发起的 GET、HEAD、LIST 立即可见；按 key 的操作历史可线性化 |
| G3 | 崩溃安全 | 10 万次随机掉电注入：已确认写入 0 丢失、0 半对象、0 已删数据复活 |
| G4 | 可验证 | 参考模型对拍、崩溃注入、并发模型检查进 CI，任何回归阻断合并 |
| G5 | 零外部依赖 | 单个二进制，不依赖数据库、消息队列或其他服务 |

**非目标**（v1 不做，相关子资源请求返回 501 `NotImplemented`）：多节点、复制、纠删码；IAM / STS API；SSE-KMS；S3 Select；静态网站托管；跨区域与同区域复制；存储类转换与归档恢复；Access Points、Object Lambda、多区域接入点；目录桶（Express One Zone）、S3 Tables、S3 Vectors；SigV2、SigV4a；事件通知、Inventory、Analytics、计费。

**完成定义**：G1～G5 判据全部达成；每个未通过的目标用例都在偏差清单里写明原因；`s3d fsck` 对验收数据集报告 0 错误。

## 2. 约定与术语

需求级别用「必须 / 应当 / 可以」，对应 RFC 2119 的 MUST / SHOULD / MAY。需求编号为 `前缀-序号`，测试、偏差清单和验收记录都直接引用编号。优先级 P0 在 M1 交付，P1 在 M2 交付，P2 在 M4 选做。

| 前缀 | 范围 |
| --- | --- |
| G | 总目标 |
| PR | 协议层：寻址、认证、通用头、错误、校验和、授权 |
| FR | 功能语义 |
| ST | 存储引擎 |
| NFR | 非功能 |
| VR | 验证 |
| Q | 未决问题 |

| 术语 | 定义 |
| --- | --- |
| 已确认写入 | 服务端已返回 2xx 的写操作 |
| 提交点 | 写入的 WAL 提交记录 fsync 完成的时刻，此后才允许返回 2xx |
| 版本 | 对象某次写入产生的不可变快照，由 versionId 标识 |
| 删除标记 | 版本化桶里不带 versionId 的 DELETE 产生的占位版本，使当前读返回 404 |
| null 版本 | 未开启或已暂停版本控制时写入的版本，versionId 字面值为 `null` |
| 段文件 | 对象数据的追加写文件，内部按 extent 定位 |
| extent | 段文件内一段连续字节：（段 ID，偏移，长度，CRC32C） |
| 全对象校验和 | 覆盖对象全部字节的校验和，类型名 FULL\_OBJECT |
| 组合校验和 | 把各分片校验和拼接后再算一次，值后缀 `-分片数`，类型名 COMPOSITE |
| 参考模型 | 用最简单的方式实现同一接口的内存版 S3 语义，作为可执行规格 |
| 对拍 | 同一操作序列同时喂给实现和参考模型，逐步比较结果 |
| 目标集 | s3-tests 中纳入验收的 545 个用例，见附录 A |
| 偏差清单 | 记录每个未通过目标用例的编号、原因和依据的文件，随代码入库 |

## 3. 运行环境与技术选型

用 Rust 写单个二进制，跑在 Linux x86-64 上；开发与验收机是 2 vCPU、7 GB 内存、约 30 GB 可用磁盘。选 Rust 的主要理由是 ShardStore 同样用 Rust（约 4 万行），论文用到的 proptest、shuttle、loom 可以直接拿来用。

| 项 | 决定 | 备注 |
| --- | --- | --- |
| 工具链 | Rust stable 1.97，edition 2024 | Cargo.lock 入库锁版本 |
| 运行时 / HTTP | tokio 1.54、hyper 1.12、hyper-util | HTTP/1.1；必须支持 `Expect: 100-continue` |
| XML | quick-xml 0.42 | 关闭 DTD 与外部实体 |
| 摘要与 CRC | md-5、sha1、sha2、hmac、crc32fast、crc32c、crc64fast-nvme | P2 算法另加 xxhash-rust |
| 测试 | proptest 1.12、shuttle 0.9、loom 0.7、libfuzzer-sys 0.4 | 对应 VR-2、VR-3、VR-4、VR-7 |
| 配置 / CLI / 日志 | toml、clap 4、tracing | — |
| 外部测试工具 | Python 3.13、boto3 1.44、awscli v1、s3-tests | 来自 PyPI 和 GitHub |

版本号是 2026-11-12 crates.io 与 PyPI 上的最新版；s3-tests 固定在提交 `5b39871`（2026-10-12）。

**禁止依赖**（必须自研的部分）：嵌入式数据库（sled、RocksDB、redb、SQLite 等）、现成的 S3 服务端实现、服务端 SigV4 校验库。aws-sigv4 这类客户端签名库只能当 dev-dependency，在测试里生成签名。

**部署形态**：`s3d serve --config s3d.toml`，默认监听 `127.0.0.1:8000`，HTTP 明文（TLS 为 P2）。账号和密钥从静态凭证文件加载，至少支持 6 个账号，满足 s3-tests 的配置要求（附录 B）。

**代码结构**（Cargo workspace）：`s3d-proto`（寻址、SigV4、aws-chunked、XML）、`s3d-engine`（WAL、索引、段文件、GC）、`s3d-model`（参考模型）、`s3d-disk`（`Disk` trait 与 FaultDisk）、`s3d-server`（路由与操作）、`s3d-check`（线性一致性检查器）、`fuzz/`。

&#91;embedded content: s3d 架构 · 生产路径与测试替身\]

生产路径从上到下单向调用；FaultDisk 替换真实文件系统做崩溃注入，s3d-model 在 ObjectStore 接口上与引擎对拍。

## 4. 协议层

所有请求先过寻址、认证、授权，带 body 的写请求再过校验和，然后进入操作路由。这几关的行为以 AWS 文档、s3-tests 断言和 boto3 1.44.0 本机实测为准。

### 4.1 寻址

| ID | 级别 | 要求 |
| --- | --- | --- |
| PR-1 | P0 | 必须支持 path-style：`/{bucket}` 与 `/{bucket}/{key}`。boto3 1.44.0 对 `http://localhost:<port>` 端点默认就用 path-style（实测） |
| PR-2 | P1 | 应当支持 virtual-hosted：`{bucket}.{base_domain}`，`base_domain` 可配置 |
| PR-3 | P0 | key 只做一次百分号解码；`+` 按字面量处理；保留连续 `/`、首尾 `/` 以及 `.`、`..` 段，不做路径归一化 |
| PR-4 | P0 | 区域默认 `us-east-1`，可配置；签名凭证里的区域不符 → 400 `AuthorizationHeaderMalformed` |
| PR-5 | P0 | 子资源按 query 参数识别（`?uploads`、`?versioning`、`?tagging` 等）；未实现的子资源 → 501 `NotImplemented` |

### 4.2 认证（SigV4）

| 模式 | 识别方式 | 级别 |
| --- | --- | --- |
| Header 签名 | `Authorization: AWS4-HMAC-SHA256 ...` | P0 |
| 预签名 URL | query 含 `X-Amz-Algorithm=AWS4-HMAC-SHA256` | P0 |
| 不签名 payload | `x-amz-content-sha256: UNSIGNED-PAYLOAD` | P0 |
| 签名 payload | `x-amz-content-sha256` 为 64 位十六进制 | P0 |
| 分块签名 | `STREAMING-AWS4-HMAC-SHA256-PAYLOAD` + `Content-Encoding: aws-chunked` | P0 |
| 分块不签名 + 尾部校验和 | `STREAMING-UNSIGNED-PAYLOAD-TRAILER` | P0 |
| 分块签名 + 尾部校验和 | `STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER` | P1 |
| 浏览器表单 POST | `multipart/form-data` + policy 签名 | P1 |
| 匿名 | 无任何签名 | P0，由 ACL / 策略决定是否放行 |
| SigV2、SigV4a | — | 不做：400 `InvalidRequest`，提示改用 AWS4-HMAC-SHA256 |

| ID | 级别 | 要求 |
| --- | --- | --- |
| PR-6 | P0 | 规范请求按 SigV4 规则构造：S3 的 URI 路径不二次编码、不归一化；query 按键排序；签名头小写、去首尾空白、合并连续空白 |
| PR-7 | P0 | 签名比较必须常数时间；签名密钥按（日期，区域，服务）缓存 |
| PR-8 | P0 | 未知 AK → 403 `InvalidAccessKeyId`；签名不符 → 403 `SignatureDoesNotMatch`；Authorization 头格式错 → 400 `AuthorizationHeaderMalformed` |
| PR-9 | P0 | 请求时间与服务端时钟相差超过 15 分钟 → 403 `RequestTimeTooSkewed` |
| PR-10 | P0 | 预签名 `X-Amz-Expires` 取值 1～604800（7 天）；越界或已过期 → 403（s3-tests 断言） |
| PR-11 | P0 | 签名 payload 的哈希与实际 body 不符 → 400 `XAmzContentSHA256Mismatch` |
| PR-12 | P0 | aws-chunked：签名模式下逐块校验 chunk 签名；非末块 ≥ 8 KiB；只允许一个尾部块；解码后长度必须等于 `x-amz-decoded-content-length` |
| PR-13 | P0 | 必须支持 `Expect: 100-continue`：鉴权与授权都通过才发 100，否则直接返回 403（s3-tests `test_100_continue`）。boto3 每个 PUT 都带这个头（实测） |
| PR-14 | P0 | 必须接受 `Transfer-Encoding: chunked` 的 PUT（s3-tests `test_object_write_with_chunked_transfer_encoding`） |

### 4.3 通用请求与响应

| ID | 级别 | 要求 |
| --- | --- | --- |
| PR-15 | P0 | 每个响应带 `x-amz-request-id`（16 位大写十六进制）、`x-amz-id-2`、`Date`、`Server: s3d`；错误 XML 里的 `RequestId` 与响应头一致 |
| PR-16 | P0 | XML 命名空间固定为 `http://s3.amazonaws.com/doc/2006-03-01/`；XML 内时间用 ISO 8601 毫秒 UTC（`2026-11-12T00:00:00.000Z`），`Last-Modified` 用 HTTP-date |
| PR-17 | P0 | ETag 一律带双引号 |
| PR-18 | P0 | 错误响应：`<Error><Code/><Message/><Resource/><RequestId/><HostId/></Error>`，按需附 `Key`、`BucketName`、`UploadId`；HEAD 请求的错误只回状态码，不带 body |
| PR-19 | P0 | 请求头总大小 ≤ 8 KB，超出 → 400 `RequestHeaderSectionTooLarge` |

常用错误码：

| Code | HTTP | 典型场景 |
| --- | --- | --- |
| AccessDenied | 403 | 无权限、预签名过期 |
| AuthorizationHeaderMalformed | 400 | 区域不符、签名头格式错 |
| BadDigest | 400 | `Content-MD5` 或 `x-amz-checksum-*` 与数据不符 |
| BucketAlreadyExists | 409 | 桶名已被其他账号占用 |
| BucketAlreadyOwnedByYou | 409 | 重复创建自己的桶（s3-tests 断言 409） |
| BucketNotEmpty | 409 | 删除非空桶 |
| ConditionalRequestConflict | 409 | 条件写与并发操作冲突 |
| EntityTooLarge | 400 | 单次 PUT 超过 5 GiB |
| EntityTooSmall | 400 | 非末分片小于 5 MiB |
| InvalidAccessKeyId | 403 | 未知 AK |
| InvalidArgument | 400 | 参数值非法，如 versionId 格式错 |
| InvalidBucketName | 400 | 桶名违反命名规则 |
| InvalidDigest | 400 | `Content-MD5` 格式错 |
| InvalidPart / InvalidPartOrder | 400 | Complete 列表里的分片不存在、ETag 不符或非升序 |
| InvalidRange | 416 | Range 不可满足 |
| InvalidRequest | 400 | 自复制且无任何变更、缺少必需头 |
| KeyTooLongError | 400 | key 超过 1024 字节 |
| MalformedXML | 400 | 请求 XML 非法 |
| MetadataTooLarge | 400 | 用户元数据超过 2 KB |
| MethodNotAllowed | 405 | 对删除标记版本发 GET 等 |
| MissingContentLength | 411 | PUT 既无 `Content-Length` 也非 chunked |
| NoSuchBucket / NoSuchKey / NoSuchUpload / NoSuchVersion | 404 | 资源不存在 |
| NotImplemented | 501 | 未实现的子资源或功能 |
| PreconditionFailed | 412 | 条件读写不满足 |
| RequestTimeTooSkewed | 403 | 时钟偏差超过 15 分钟 |
| SignatureDoesNotMatch | 403 | 签名错误 |
| SlowDown | 503 | 过载保护触发 |
| XAmzContentSHA256Mismatch | 400 | payload 哈希不符 |

### 4.4 校验和

| ID | 级别 | 要求 |
| --- | --- | --- |
| PR-20 | P0 | 支持 CRC32、CRC32C、CRC64NVME、SHA1、SHA256 和 `Content-MD5`；MD5、XXHASH64、XXHASH3、XXHASH128、SHA512 为 P2 |
| PR-21 | P0 | 请求带 `x-amz-checksum-<alg>` 或 `Content-MD5` 时，服务端必须独立计算并比较；不符 → 400 `BadDigest`，数据不得变为可见 |
| PR-22 | P0 | 请求没带任何校验和时，服务端计算并保存 CRC64NVME 全对象校验和（与 AWS 默认完整性保护一致） |
| PR-23 | P0 | PutObject、UploadPart 响应回显 `x-amz-checksum-<alg>`；SDK 靠这个回显在 Complete 请求里带回各分片校验和 |
| PR-24 | P0 | GetObject / HeadObject 只在请求带 `x-amz-checksum-mode: ENABLED` 时返回校验和头与 `x-amz-checksum-type` |
| PR-25 | P0 | 组合校验和 = 各分片原始摘要按段号拼接后再算一次，值后缀 `-N`；全对象 CRC 用 CRC 合并公式从分片 CRC 算出，不回读数据 |
| PR-26 | P0 | CreateMultipartUpload 省略 `x-amz-checksum-type` 时：CRC64NVME 取 FULL\_OBJECT，其余取 COMPOSITE（AWS 文档未写默认值，暂定，见 Q1） |
| PR-27 | P0 | `x-amz-trailer` 只接受 crc32、crc32c、crc64nvme、sha1、sha256 五种 |

分片上传的校验和类型矩阵（按 AWS 文档）：

| 算法 | FULL\_OBJECT | COMPOSITE | 级别 |
| --- | --- | --- | --- |
| CRC64NVME | 是 | 否 | P0 |
| CRC32 | 是 | 是 | P0 |
| CRC32C | 是 | 是 | P0 |
| SHA1 | 否 | 是 | P0 |
| SHA256 | 否 | 是 | P0 |
| MD5、XXHASH64、XXHASH3、XXHASH128、SHA512 | 否 | 是 | P2 |

boto3 1.44.0 实测：PutObject 与 UploadPart 默认带 `x-amz-checksum-crc32` 和 `x-amz-sdk-checksum-algorithm: CRC32`；CreateMultipartUpload 带 `x-amz-checksum-algorithm: CRC32`，不带类型。HTTP 端点下 payload 一律是 `UNSIGNED-PAYLOAD`，ListObjectsV2 默认带 `encoding-type=url`。

### 4.5 授权

账号就是主体，v1 没有 IAM 用户与身份策略；授权只看资源归属、桶策略、ACL 和 PublicAccessBlock。

| ID | 级别 | 要求 |
| --- | --- | --- |
| PR-28 | P0 | 桶和对象归创建它的账号所有。P1 上线前，只有所有者能访问，其他账号与匿名请求 → 403 `AccessDenied` |
| PR-29 | P0 | 请求带 `x-amz-expected-bucket-owner` 且与桶所有者不符 → 403 `AccessDenied` |
| PR-30 | P1 | 判定顺序：桶策略显式 Deny → 拒绝（对所有者同样生效）；否则资源所有者放行；否则桶策略 Allow 或 ACL 授权放行；其余拒绝 |
| PR-31 | P1 | 对象级请求里的「所有者」是对象所有者，`ObjectWriter` 下可能不是桶所有者；桶所有者始终可以删除桶内对象 |
| PR-32 | P1 | Object Ownership 为 `BucketOwnerEnforced` 时 ACL 不参与判定；请求带 `bucket-owner-full-control` 以外的 ACL → 400 `AccessControlListNotSupported` |
| PR-33 | P1 | PublicAccessBlock 先于判定生效：`BlockPublicAcls` 拒绝设置公开 ACL，`IgnorePublicAcls` 忽略已有公开 ACL，`BlockPublicPolicy` 拒绝写入公开策略，`RestrictPublicBuckets` 让公开策略只对所有者生效 |

## 5. API 范围

v1 共 63 个操作：P0 有 21 个，覆盖桶、对象、列举和分片上传；P1 有 28 个，覆盖版本、标签、CORS、ACL、策略和表单上传；P2 有 14 个，是对象锁、生命周期、加密和日志。表中 `{b}` 是桶名，`{k}` 是对象 key。

| 操作 | 请求特征 | 级别 | s3-tests 领域 |
| --- | --- | --- | --- |
| ListBuckets | `GET /`，支持 `max-buckets`（1～10,000）、`continuation-token`、`prefix`、`bucket-region` | P0 | bucket |
| CreateBucket | `PUT /{b}`，可带 `CreateBucketConfiguration` | P0 | bucket |
| HeadBucket、DeleteBucket | `HEAD /{b}`、`DELETE /{b}` | P0 | bucket |
| GetBucketLocation | `GET /{b}?location` | P0 | bucket |
| ListObjects、ListObjectsV2 | `GET /{b}`、`GET /{b}?list-type=2` | P0 | list\_v1、list\_v2 |
| PutObject、GetObject、HeadObject、DeleteObject | `PUT`、`GET`、`HEAD`、`DELETE /{b}/{k}` | P0 | object\_core、conditional |
| DeleteObjects | `POST /{b}?delete` | P0 | delete\_multi |
| CopyObject | `PUT /{b}/{k}` + `x-amz-copy-source` | P0 | copy |
| GetObjectAttributes | `GET /{b}/{k}?attributes` + `x-amz-object-attributes` | P0 | checksum、multipart |
| CreateMultipartUpload | `POST /{b}/{k}?uploads` | P0 | multipart |
| UploadPart、UploadPartCopy | `PUT /{b}/{k}?partNumber=N&uploadId=U`，后者带 `x-amz-copy-source` | P0 | multipart |
| CompleteMultipartUpload、AbortMultipartUpload | `POST`、`DELETE /{b}/{k}?uploadId=U` | P0 | multipart |
| ListParts、ListMultipartUploads | `GET /{b}/{k}?uploadId=U`、`GET /{b}?uploads` | P0 | multipart |
| Get/PutBucketVersioning、ListObjectVersions | `?versioning`、`GET /{b}?versions` | P1 | versioning |
| Get/Put/DeleteObjectTagging、Get/Put/DeleteBucketTagging | `?tagging` | P1 | tagging |
| Get/Put/DeleteBucketCors 与预检 | `?cors`、`OPTIONS /{b}/{k}` | P1 | cors |
| Get/Put/DeleteBucketPolicy、GetBucketPolicyStatus | `?policy`、`?policyStatus` | P1 | policy |
| Get/Put/DeletePublicAccessBlock | `?publicAccessBlock` | P1 | policy |
| Get/PutBucketAcl、Get/PutObjectAcl | `?acl` | P1 | acl |
| Get/Put/DeleteBucketOwnershipControls | `?ownershipControls` | P1 | acl |
| PostObject | `POST /{b}`，`multipart/form-data` | P1 | post\_object |
| 对象锁：Get/PutObjectLockConfiguration、Get/PutObjectRetention、Get/PutObjectLegalHold | `?object-lock`、`?retention`、`?legal-hold` | P2 | object\_lock |
| 生命周期：Get/PutBucketLifecycleConfiguration、DeleteBucketLifecycle，含后台执行器 | `?lifecycle` | P2 | lifecycle |
| 加密：Get/Put/DeleteBucketEncryption，对象操作上的 SSE-C、SSE-S3 请求头 | `?encryption` | P2 | encryption |
| Get/PutBucketLogging | `?logging` | P2 | logging |

以下子资源一律返回 501 `NotImplemented`：`?website`、`?replication`、`?notification`、`?inventory`、`?analytics`、`?metrics`、`?intelligent-tiering`、`?accelerate`、`?requestPayment`、`?select`、`?restore`、`?torrent`。

## 6. 关键语义

所有写操作在提交点原子生效，同一 key 按提交顺序线性化，条件在提交点重新求值。括号里的用例名是该条的裁判。

### 6.1 写入

| ID | 级别 | 要求 |
| --- | --- | --- |
| FR-1 | P0 | PUT 原子：成功后整体可见，失败不留任何可见痕迹 |
| FR-2 | P0 | 同一 key 并发 PUT 按提交顺序生效，最后提交者胜出；任何读必须返回某一次完整写入，不得混合（`test_atomic_dual_write_*`） |
| FR-3 | P0 | `x-amz-meta-*` 键名小写化保存，值原样回放；键和值的 UTF-8 字节合计 ≤ 2 KB |
| FR-4 | P0 | 保存并回放 `Content-Type`（缺省 `binary/octet-stream`）、`Content-Encoding`、`Content-Disposition`、`Content-Language`、`Cache-Control`、`Expires` |
| FR-5 | P0 | 保存 `Content-Encoding` 前去掉所有 `aws-chunked` 项，去光则不保存该头（`test_object_content_encoding_aws_chunked`） |
| FR-6 | P0 | `x-amz-storage-class` 只接受 `STANDARD`，其他值 → 400 `InvalidStorageClass` |
| FR-7 | P0 | ETag：单次 PUT 为内容 MD5 十六进制；分片对象为各分片 MD5 原始字节拼接后再算 MD5，加 `-N` |
| FR-8 | P0 | PUT 响应带 ETag、校验和回显；版本化桶带 `x-amz-version-id` |

### 6.2 读取

| ID | 级别 | 要求 |
| --- | --- | --- |
| FR-9 | P0 | Range 支持 `bytes=a-b`、`bytes=a-`、`bytes=-n`，返回 206 + `Content-Range`；不可满足（含空对象带 Range）→ 416 `InvalidRange`；多区间忽略 Range 返回整对象（实现前对照 AWS 核实） |
| FR-10 | P0 | `partNumber=N` 返回第 N 个分片并带 `x-amz-mp-parts-count`；普通对象只接受 1；越界 → 400 `InvalidPart`（`test_non_multipart_get_part`） |
| FR-11 | P0 | `response-content-type` 等 6 个覆盖参数只对签名请求生效；匿名请求带了 → 400 `InvalidRequest` |
| FR-12 | P0 | 条件读：`If-Match` 不满足 → 412；`If-None-Match` 命中 → 304；`If-Modified-Since` 未修改 → 304；`If-Unmodified-Since` 不满足 → 412 |
| FR-13 | P0 | 条件组合：`If-Match` 为真且 `If-Unmodified-Since` 为假 → 200；`If-None-Match` 为假且 `If-Modified-Since` 为真 → 304 |
| FR-14 | P0 | HEAD 与 GET 返回同一组响应头；带 `versionId` 时读指定版本 |

### 6.3 条件写与条件删除

| ID | 级别 | 要求 |
| --- | --- | --- |
| FR-15 | P0 | PutObject 与 CompleteMultipartUpload：`If-None-Match: *` 且对象已存在 → 412；`If-Match: <etag>` 不匹配 → 412，对象不存在 → 404 `NoSuchKey` |
| FR-16 | P0 | DeleteObject、DeleteObjects 支持 `If-Match: <etag>` 和 `If-Match: *`（AWS 自 2025-09-16 起支持），只对当前版本求值；不匹配 → 412；对象不存在 → 404；当前版本是删除标记时 `If-Match: *` → 412；DeleteObjects 的条件失败按对象记入 `<Error>` |
| FR-17 | P0 | 条件在提交点求值，不在收到请求时；同一 key 的两个条件写同时提交，只有一个成功，另一个得到 412 |

### 6.4 复制

| ID | 级别 | 要求 |
| --- | --- | --- |
| FR-18 | P0 | `x-amz-copy-source` 为 `/{b}/{k}` 或 `{b}/{k}`，可带 `?versionId=`，先 URL 解码 |
| FR-19 | P0 | `x-amz-metadata-directive`：`COPY`（默认）沿用源元数据，`REPLACE` 用请求里的；`x-amz-tagging-directive` 同理（P1） |
| FR-20 | P0 | 源与目标相同且没有任何属性变化 → 400 `InvalidRequest`（`test_object_copy_to_itself`） |
| FR-21 | P0 | 源对象大于 5 GiB → 400 `InvalidRequest`，应改用 UploadPartCopy |
| FR-22 | P0 | `x-amz-copy-source-if-match`、`-if-none-match`、`-if-modified-since`、`-if-unmodified-since` 不满足 → 412 |
| FR-23 | P0 | 响应体为 `CopyObjectResult`（ETag、LastModified、校验和）；源 key 不存在 → 404 `NoSuchKey`，源桶不存在 → 404 `NoSuchBucket` |

### 6.5 分片上传

| ID | 级别 | 要求 |
| --- | --- | --- |
| FR-24 | P0 | UploadId 不透明，含至少 128 位随机数 |
| FR-25 | P0 | 段号 1～10,000；同一段号重传以后到者为准 |
| FR-26 | P0 | Complete 校验：非升序 → 400 `InvalidPartOrder`；分片不存在或 ETag 不符 → 400 `InvalidPart`；非末分片小于 5 MiB → 400 `EntityTooSmall`；空列表 → 400 `MalformedXML` |
| FR-27 | P0 | Complete 原子：对象要么完整出现，要么不出现。设计决定：完成后 UploadId 保留 24 小时，重复 Complete 返回同一结果 |
| FR-28 | P0 | Abort 后的 UploadPart、Complete、再次 Abort → 404 `NoSuchUpload`；分片数据交给 GC 回收 |
| FR-29 | P0 | ListParts 与 ListMultipartUploads 每页 ≤ 1000，支持 `part-number-marker`、`key-marker`、`upload-id-marker`、`prefix`、`delimiter` |
| FR-30 | P0 | 分片对象保留每段边界，供 `partNumber` 读取和 GetObjectAttributes 的 `ObjectParts` 使用 |
| FR-31 | P0 | UploadPartCopy 的 `x-amz-copy-source-range: bytes=a-b`：格式错 → 400 `InvalidArgument`；超出源对象 → `InvalidRange` |

### 6.6 版本控制（P1）

| ID | 要求 |
| --- | --- |
| FR-32 | 状态机：未开启 → 开启 ⇄ 暂停，不能回到未开启 |
| FR-33 | 开启时每次写入生成新 versionId：不透明、URL 安全、全局唯一，同一 key 内按写入顺序可排序 |
| FR-34 | 暂停时写入的 versionId 为 `null`，覆盖已有的 null 版本 |
| FR-35 | 不带 versionId 的 DELETE：开启时新增删除标记；暂停时写入 null 删除标记并替换已有 null 版本；响应带 `x-amz-delete-marker: true` 与 `x-amz-version-id` |
| FR-36 | 带 versionId 的 DELETE 永久删除该版本；删掉删除标记即恢复上一个版本 |
| FR-37 | 当前版本是删除标记时，GET/HEAD → 404 `NoSuchKey` 并带 `x-amz-delete-marker: true`；按 versionId GET 删除标记 → 405 `MethodNotAllowed` |
| FR-38 | ListObjectVersions：key 升序，同 key 内新版本在前；用 `key-marker` + `version-id-marker` 分页；`IsLatest` 标出当前版本；删除标记以 `DeleteMarker` 元素列出 |

### 6.7 列举

| ID | 级别 | 要求 |
| --- | --- | --- |
| FR-39 | P0 | 按 key 的 UTF-8 字节序升序 |
| FR-40 | P0 | `delimiter` 可以是任意字符串；`CommonPrefixes` 去重，且计入 `max-keys` |
| FR-41 | P0 | `max-keys` 默认且最大为 1000；`max-keys=0` 返回空列表且 `IsTruncated=false`（`test_bucket_list_maxkeys_zero`） |
| FR-42 | P0 | V2 的 `continuation-token` 不透明且带完整性校验，伪造 → 400 `InvalidArgument`；支持 `start-after`、`fetch-owner`、`KeyCount` |
| FR-43 | P0 | `encoding-type=url` 时对响应里的 Key、Prefix、Delimiter、StartAfter、CommonPrefixes 做 URL 编码；boto3 默认带这个参数 |
| FR-44 | P0 | V1 支持 `marker`；`NextMarker` 只在带 `delimiter` 时返回 |
| FR-45 | P0 | 列举反映所有已确认写入（强一致） |

### 6.8 批量删除与桶

| ID | 级别 | 要求 |
| --- | --- | --- |
| FR-46 | P0 | DeleteObjects 一次 ≤ 1000 个 key；必须带 `Content-MD5` 或任一 `x-amz-checksum-*`，否则 400 `InvalidRequest` |
| FR-47 | P0 | `Quiet` 模式只回报错误；删除不存在的 key 视为成功；每个 key 单独原子，整个请求不原子 |
| FR-48 | P0 | 桶名按第 7 节规则校验，违规 → 400 `InvalidBucketName` |
| FR-49 | P0 | 重复创建：同账号 → 409 `BucketAlreadyOwnedByYou`；其他账号 → 409 `BucketAlreadyExists` |
| FR-50 | P0 | 桶内还有任何版本或删除标记时删桶 → 409 `BucketNotEmpty` |
| FR-51 | P1 | 新桶 Object Ownership 默认值可配置：`BucketOwnerEnforced`（与 AWS 当前默认一致，ACL 关闭）或 `ObjectWriter`；跑 s3-tests 时取 `ObjectWriter`（见 Q2） |

## 7. 限制与常量

默认值一律照搬 AWS 当前配额，只有对象大小上限和桶数上限可配置。超限在读完请求头后、写入数据前就拒绝；长度未知（chunked）时边读边计数，超限立即中止。

| 项 | 值 | 超出时 | 依据 |
| --- | --- | --- | --- |
| 桶名长度 | 3～63 字符 | 400 `InvalidBucketName` | AWS 命名规则 |
| 桶名字符 | 小写字母、数字、`.`、`-`；首尾是字母或数字；无相邻 `.`；不能是 IP 地址格式 | 400 `InvalidBucketName` | AWS 命名规则 |
| 桶名保留前缀 | `xn--`、`sthree-`、`amzn-s3-demo-` | 400 `InvalidBucketName` | AWS 命名规则 |
| 桶名保留后缀 | `-s3alias`、`--ol-s3`、`.mrap`、`--x-s3`、`--table-s3`、`-an`（v1 不支持账号区域命名空间） | 400 `InvalidBucketName` | AWS 命名规则 |
| 每账号桶数 | 可配置，默认 10,000 | 400 `TooManyBuckets` | 设计决定 |
| key 长度 | ≤ 1024 字节（UTF-8） | 400 `KeyTooLongError` | AWS |
| 用户元数据 | ≤ 2 KB | 400 `MetadataTooLarge` | AWS |
| 请求头总大小 | ≤ 8 KB | 400 `RequestHeaderSectionTooLarge` | AWS |
| 单次 PUT | ≤ 5 GiB | 400 `EntityTooLarge` | AWS |
| 对象大小 | ≤ 48.8 TiB（AWS 2025-12-02 起，公告口径 50 TB）；可配置，默认同值 | 400 `EntityTooLarge` | AWS 配额页 |
| 分片数 / 段号 | ≤ 10,000 / 1～10,000 | 400 `InvalidArgument` | AWS 配额页 |
| 分片大小 | 5 MiB～5 GiB，末片无下限 | 400 `EntityTooSmall` / `EntityTooLarge` | AWS 配额页 |
| 列举每页（对象、版本、分片、上传） | ≤ 1000 | 截断并置 `IsTruncated=true` | AWS 配额页 |
| ListBuckets 每页 | `max-buckets` 1～10,000 | 400 `InvalidArgument` | AWS API |
| DeleteObjects | ≤ 1000 个 key | 400（`test_multi_object_delete_key_limit`） | AWS + s3-tests |
| 对象标签 | ≤ 10 个；键 ≤ 128 字符，值 ≤ 256 字符 | 400 `InvalidTag` | s3-tests |
| 桶标签 | ≤ 50 个 | 400 `InvalidTag` | AWS |
| 预签名有效期 | 1～604,800 秒 | 403 | s3-tests |
| 时钟偏差 | ≤ 15 分钟 | 403 `RequestTimeTooSkewed` | AWS |
| aws-chunked 块大小 | 非末块 ≥ 8 KiB，只允许 1 个尾部块 | 拒绝请求 | AWS 校验和文档 |
| CopyObject 源对象 | ≤ 5 GiB | 400 `InvalidRequest` | AWS |
| 桶策略 | ≤ 20 KB | 400 | AWS |
| CORS 规则 / 生命周期规则 | ≤ 100 / ≤ 1000 条 | 400 | AWS |

## 8. 存储引擎

引擎是自研的日志结构设计：对象数据追加写进段文件，元数据走 WAL 加内存有序索引加定期检查点，提交点是一条 fsync 过的 WAL 记录。所有磁盘 IO 都走 `Disk` trait：生产用真实文件系统，测试换成 FaultDisk 注入故障。

### 8.1 数据模型

| 记录 | 关键字段 |
| --- | --- |
| Bucket | name、owner、created\_ms、versioning（Unversioned / Enabled / Suspended）、ownership、acl、policy、cors、tags、lifecycle、lock\_cfg、encryption\_cfg |
| ObjectVersion | bucket、key、version\_id、seq（全局单调 u64）、is\_delete\_marker、size、etag、checksum（alg、type、value、各分片值）、系统元数据、用户元数据、tags、acl、owner、last\_modified\_ms、extents、part\_sizes、lock（mode、retain\_until、legal\_hold）、sse |
| Upload | upload\_id、bucket、key、initiated\_ms、owner、checksum（alg、type）、元数据、parts（段号 → size、etag、checksum、extents）、state（Open / Completed / Aborted） |
| 索引 | `(bucket, key) → 版本链`，版本链按 seq 倏序；`(bucket, key, upload_id) → Upload`；两者都是按 UTF-8 字节序的有序映射 |

### 8.2 磁盘布局

```text
<data_dir>/
  FORMAT              格式版本 + 实例 UUID，只写一次
  wal/00000001.log    元数据预写日志，单文件 256 MiB 后滚动
  ckpt/ckpt-<lsn>     元数据全量快照
  seg/00000001.seg    对象数据段，追加写，单文件 1 GiB 后滚动
  tmp/                启动时清空
```

WAL 记录格式为 `len:u32 | crc32c:u32 | lsn:u64 | type:u8 | payload`，payload 是带版本号的紧凑二进制编码。段文件内每个数据块 ≤ 1 MiB，块头为 `magic | len | crc32c`。

### 8.3 写路径

1. 鉴权和限额检查通过后，数据流式写入当前活跃段，同时算 MD5 和请求要求的校验和。
2. 数据读完后校验：不符则返回 400，不写 WAL，已写的块变成垃圾等 GC 回收。
3. `fdatasync` 段文件。
4. 在 key 锁内重新求值条件（FR-17），追加 WAL 提交记录（extents + 元数据）并 `fdatasync`，这一刻就是提交点。
5. 更新内存索引，释放 key 锁，返回 2xx。

多个请求的第 3、4 步合并成一次 fsync（group commit）：最多等 1 ms，或攒够 64 个提交立即刷盘，两个值都可配置。

### 8.4 持久化与完整性

| ID | 要求 |
| --- | --- |
| ST-1 | 返回 2xx 前，数据与元数据都已 fsync 到磁盘 |
| ST-2 | 崩溃恢复后，所有已确认写入可读，内容与校验和逐字节一致 |
| ST-3 | 未确认的写入要么完整可见，要么完全不可见，不存在半个对象 |
| ST-4 | 已确认的删除或覆盖，恢复后旧数据不得复活 |
| ST-5 | 读出的每个块必须通过 CRC32C 校验；不通过 → 500 `InternalError` 并记日志，绝不返回坏数据 |
| ST-6 | WAL 尾部的撕裂记录（CRC 不符或长度越界）视为未提交，截断后继续；中间记录损坏 → 拒绝启动并报告位置 |
| ST-7 | 新建段文件或 WAL 文件后 fsync 父目录；删除文件前先在 WAL 里记录 |
| ST-8 | 检查点原子替换：写临时文件 → fsync → rename → fsync 目录；恢复只信任完整的检查点 |
| ST-9 | key 不映射为文件路径，文件名只由引擎生成的数字 ID 组成 |

### 8.5 空间回收

- 段的存活字节比低于阈值（默认 50%）时压缩：存活 extent 拷到新段 → fsync → WAL 写重定位记录 → 旧段进入待删列表。
- 待删段要等所有在途读释放引用后才删除（epoch 或引用计数）。
- 被拒绝的写入、已删除的版本、Abort 掉的分片，都只是让 extent 变成垃圾，统一由压缩回收。
- 压缩与前台写并发；压缩中途崩溃不得丢数据，也不得让同一数据出现两份可见副本，这一条纳入 VR-3。

### 8.6 并发

- 同一 key 的提交在 key 锁内串行，不同 key 并行。
- 读不加锁：先从索引拿版本快照（extent 列表 + 引用），读的过程中对象被覆盖或删除不影响这次读。
- 分片可并行写入；Complete 在 key 锁内提交。
- 每个 key 上的 PUT、GET、HEAD、DELETE 历史必须可线性化，由 VR-4 检查。

### 8.7 恢复与容量

- 启动顺序：校验 FORMAT → 加载最新的完整检查点 → 从检查点 LSN 重放 WAL → 截断撕裂尾部 → 核对段文件长度 → 清空 tmp → 开始监听端口。
- 检查点触发：WAL 自上次检查点起增长超过 256 MiB，或满 10 分钟。
- 元数据全部常驻内存：每个版本 ≤ 512 字节（不含用户元数据和标签），设计上限 1,000 万版本每节点。超出上限留到 v2，届时换成磁盘 LSM 索引。

## 9. 非功能需求

性能目标按验收机（2 vCPU、7 GB）、本机回环定，大对象吞吐用 fio 实测的磁盘带宽做基线。所有数值在 M3 用基线复核后锁定。

| ID | 指标 | 目标 | 测法 |
| --- | --- | --- | --- |
| NFR-1 | 小对象 PUT | 4 KiB、32 并发：≥ 1,000 次/秒，p99 ≤ 50 ms | 自研压测工具，跑 5 分钟 |
| NFR-2 | 小对象 GET | 4 KiB、32 并发：≥ 5,000 次/秒，p99 ≤ 10 ms | 同上 |
| NFR-3 | 大对象单流 | PUT ≥ fio 顺序写带宽的 70%；GET ≥ fio 顺序读带宽的 80% | 1 GiB 对象，取 5 次中位数 |
| NFR-4 | 列举 | 100 万对象的桶，每页 1000 key，p99 ≤ 20 ms | 随机起点翻页 1,000 次 |
| NFR-5 | 内存 | 空载 RSS ≤ 64 MiB；每个在途请求缓冲 ≤ 2 MiB；占用与对象大小无关（全程流式） | 上传 10 GiB 对象时采样 RSS |
| NFR-6 | 冷启动恢复 | 100 万版本 ≤ 20 秒 | 断电后重启计时 |
| NFR-7 | 密钥安全 | secret 不进日志和错误信息；凭证文件权限不是 0600 时拒绝启动 | 代码审查 + 日志扫描 |
| NFR-8 | XML 安全 | 禁用 DTD 与实体展开；XML 请求体上限：CompleteMultipartUpload 2 MiB，其余 1 MiB | 模糊测试 + XXE 用例 |
| NFR-9 | 连接保护 | 请求头 30 秒内未读完则断开；空闲连接 60 秒关闭；并发连接超上限 → 503 `SlowDown` | 慢速客户端脚本 |
| NFR-10 | 日志 | JSON 结构化日志：request\_id、账号、操作、桶、状态码、错误码、字节数、耗时 | 日志字段校验测试 |
| NFR-11 | 指标 | Prometheus 文本格式：按操作与状态码的请求数和延迟直方图、fsync 延迟、group commit 批大小、WAL 大小、段存活率、GC 进度、索引条数 | 抓取并校验 |
| NFR-12 | 管理端口 | `/metrics` 与 `/health` 走独立端口（默认 `127.0.0.1:9000`），避免与名为 metrics 或 health 的桶冲突 | 集成测试 |
| NFR-13 | 离线校验 | `s3d fsck` 校验全部段块 CRC、WAL 与检查点一致性、索引引用完整性，输出 JSON 报告 | 注入损坏后必须报出 |
| NFR-14 | 运维命令 | `s3d compact` 手动触发压缩；SIGTERM 后停止接新连接，等在途请求最多 30 秒，写检查点后退出 | 集成测试 |
| NFR-15 | 配置 | TOML 文件 + 命令行覆盖；未知配置项报错退出，不静默忽略 | 单元测试 |
| NFR-16 | 磁盘空间 | 可用空间低于保留值（默认 2 GiB）时拒绝新写入，返回 503 SlowDown；读、删除和压缩照常工作，保留空间保证压缩能跑完 | 填满磁盘的集成测试 |

## 10. 验证方案

验证分十层，前四层照搬 ShardStore 论文：参考模型、一致性对拍、崩溃一致性检查、并发模型检查。论文里参考模型只有 450 行，约占 4.4 万行实现的 1%，这套方法拦下了 16 个本会上线的问题。任何新发现的 bug，都先在对应层补一个能复现的失败用例，再修。

| ID | 层 | 方法 | 通过标准 |
| --- | --- | --- | --- |
| VR-1 | 参考模型 | `s3d-model` 用有序映射实现全部 P0/P1 语义，不持久化、不优化，与引擎实现同一个 `ObjectStore` trait；规模保持在能逐行审读 | 每条 FR 都能在模型里找到对应代码 |
| VR-2 | 一致性对拍 | proptest 生成随机操作序列（PUT、GET、DELETE、LIST、Copy、分片、版本切换、条件写），同时跑引擎与模型，逐步比较返回值和可见状态；失败自动最小化。参数带偏置：小 key 空间制造冲突，大小取 0、1、5 MiB−1、5 MiB 等边界，key 含 Unicode、`/`、公共前缀 | CI 每次 1 万条、夜间 100 万条，0 差异 |
| VR-3 | 崩溃一致性 | FaultDisk 实现 `Disk` trait：掉电时未 fsync 的写可任意丢弃、截断或按 4 KiB 扇区部分落盘，跨文件可重排；fsync 可注入 EIO。每轮：随机操作 → 随机时刻掉电 → 从持久视图重启 → 检查 ST-1～ST-4，以及恢复后能继续正常读写 | CI 1,000 次、M3 门槛 10 万次，0 违例 |
| VR-4 | 并发 | shuttle 随机调度测大场景（GC 与读、group commit、Complete 与 Abort 竞争）；loom 穷举小原语（提交队列、引用计数）；HTTP 层 16 个客户端在 8 个 key 上随机读写，用自写的 WGL 检查器按 key 校验线性一致性 | 1 万条历史 0 违例 |
| VR-5 | 兼容性 | s3-tests 目标集（附录 A）：每次提交跑 P0，夜间跑全集，结果存 JUnit XML | 已通过的用例变失败即阻断；未通过的必须在偏差清单里 |
| VR-6 | 真实客户端 | boto3 1.44 与 awscli v1 脚本：mb、cp、sync、ls、rm、presign；1 GiB 分片上传后下载比对 SHA-256；版本化桶上的覆盖与恢复 | 全部通过 |
| VR-7 | 模糊测试 | cargo-fuzz 目标：Authorization 解析、规范请求构造、aws-chunked 解码、XML 请求体、Range、continuation-token、POST policy、WAL 记录解码 | 每个目标 ≥ 1 小时 0 崩溃 |
| VR-8 | SigV4 差分 | 同一请求分别用 botocore 和 aws-sigv4 签名，服务端都必须通过；随机篡改任一签名输入（方法、路径、query、签名头、时间、payload 哈希）必须被拒 | 1 万组 0 误判 |
| VR-9 | 性能 | NFR-1～NFR-6 的压测脚本入库，M3 起每周跑并存档 | 不低于 NFR 目标，且不比上周退步超过 10% |
| VR-10 | 内存安全 | 默认 `#![forbid(unsafe_code)]`；确需 unsafe 的模块单独审查，并在 CI 里跑 Miri | 0 未审查的 unsafe |

崩溃测试还有一条硬规则：fsync 一旦报错，服务必须进入只读失败态，不得重试 fsync 后把写入当作成功。页缓存里的脏数据在 fsync 失败后状态未知，重试成功不代表已落盘。

## 11. 里程碑与验收门槛

五个里程碑串行推进，只有门槛全部达成才进入下一个；M4 选做。每个里程碑结束时更新偏差清单，并存档一份 s3-tests JUnit 报告。

| 里程碑 | 范围 | 退出门槛 |
| --- | --- | --- |
| M0 骨架 | workspace、`Disk` trait 与 FaultDisk 雏形、WAL + 段文件最小实现、SigV4 header 签名、桶的增删查、PUT/GET/HEAD/DELETE、参考模型雏形、s3-tests 能跑起来 | boto3 冒烟（建桶、上传、下载、删除）通过；bucket 与 object\_core 共 55 个用例通过 ≥ 44 个 |
| M1 P0 全量 | 列举 V1/V2、分片上传、复制、条件读写与条件删除、全部 P0 校验和、aws-chunked、预签名、DeleteObjects、GetObjectAttributes | P0 ≥ 237/249；VR-2 10 万条序列 0 差异；VR-3 1 万次 0 违例；VR-6 全部通过 |
| M2 P1 | 版本控制、标签、CORS、ACL 与 Object Ownership、桶策略与 PublicAccessBlock、表单 POST、virtual-hosted 寻址 | P0 ≥ 245/249；P1 ≥ 171/190 |
| M3 加固 | 压缩与 GC、`s3d fsck`、指标与日志、性能调优、模糊测试、线性一致性检查 | NFR-1～NFR-6 达标；VR-3 10 万次 0 违例；VR-4 1 万条历史 0 违例；VR-7 每个目标 1 小时 0 崩溃 |
| M4 P2（选做） | 对象锁、生命周期过期、SSE-C 与 SSE-S3、桶日志配置 | P2 ≥ 85/106 |

## 12. 风险与未决问题

最大的风险是 s3-tests 与 AWS 真实行为的分歧，其次是 P1 的策略求值工作量。未决问题都给了暂定做法，不阻塞 M0。

| 风险 | 影响 | 对策 |
| --- | --- | --- |
| s3-tests 断言与 AWS 行为不一致，但没标 `fails_on_aws` | 为了过测试偏离 AWS | 以 AWS 文档为准，冲突用例进偏差清单并注明依据 |
| 2 vCPU 虚拟盘 fsync 慢 | NFR-1 不达标 | group commit；目标按 fio 基线复核 |
| 元数据全部常驻内存 | 超过 1,000 万版本后内存不够 | v1 接受这个上限，接近时告警；v2 换磁盘 LSM 索引 |
| 崩溃模型比真实文件系统宽松 | 漏掉真实故障 | FaultDisk 取最弱假设：未 fsync 的写全部可丢、可撕裂、可跨文件重排 |
| fsync 失败后状态未知 | 数据静默丢失 | 报错即进入只读失败态，需人工介入（见第 10 节） |
| ACL 与策略共 97 个用例，策略求值复杂 | M2 延期 | 先做 s3-tests 用到的条件运算符子集；遇到不支持的运算符，在 PutBucketPolicy 时就拒绝（400 `MalformedPolicy`） |
| 当前环境下载不了 GitHub release 二进制（API 被拦） | rclone、warp 等客户端用不上 | 真实客户端以 boto3、awscli v1 为准；压测用自研工具 |

| ID | 问题 | 暂定做法 |
| --- | --- | --- |
| Q1 | CreateMultipartUpload 省略 `x-amz-checksum-type` 时，CRC32、CRC32C、SHA1、SHA256 的默认类型（AWS 文档没写） | 取 COMPOSITE；有 AWS 账号时实测核实 |
| Q2 | 新桶默认 Object Ownership：AWS 默认 `BucketOwnerEnforced`（ACL 关闭），而 s3-tests 的 ACL 用例需要 ACL 打开 | 做成配置项，跑测时取 `ObjectWriter` |
| Q3 | GetObject 收到多区间 Range 时 AWS 的确切行为 | 返回整个对象（FR-9） |
| Q4 | versionId 是否要模仿 AWS 的 32 字符格式 | 只保证不透明、URL 安全、≤ 64 字符 |
| Q5 | v1 是否支持 TLS（s3-tests 默认用 HTTP） | 列为 P2 |
| Q6 | MD5、XXHASH 系列、SHA512 何时升到 P1 | SDK 默认开始使用它们时再升 |

## 13. 附录

### A. s3-tests 覆盖矩阵

数据来自 s3-tests 提交 `5b39871` 里的 test\_s3.py 与 test\_headers.py，共 808 个测试函数；排除 263 个后，目标集是 545 个。领域按用例名和 marker 静态归类（只解析源码，未执行测试），归类脚本随仓库提交。

| 排除原因 | 数量 |
| --- | --- |
| 标了 `fails_on_aws`（断言与 AWS 行为不同） | 200 |
| SSE-KMS | 27 |
| 只测 SigV2（`auth_aws2`） | 21 |
| RGW 多租户（用例名含 tenant） | 9 |
| 存储类转换与云端归档 | 3 |
| IAM API | 2 |
| BitTorrent | 1 |
| 合计 | 263 |

| 领域 | 目标数 | 级别 | 里程碑 |
| --- | --- | --- | --- |
| auth（签名、预签名、请求头校验） | 41 | P0 | M1 |
| list\_v2 | 40 | P0 | M1 |
| list\_v1 | 37 | P0 | M1 |
| object\_core | 33 | P0 | M0～M1 |
| multipart | 32 | P0 | M1 |
| bucket | 22 | P0 | M0 |
| copy | 17 | P0 | M1 |
| conditional | 13 | P0 | M1 |
| checksum | 10 | P0 | M1 |
| delete\_multi | 4 | P0 | M1 |
| **P0 小计** | **249** |  |  |
| policy（含 PublicAccessBlock） | 53 | P1 | M2 |
| acl（含 Object Ownership） | 44 | P1 | M2 |
| post\_object | 36 | P1 | M2 |
| versioning | 31 | P1 | M2 |
| tagging | 17 | P1 | M2 |
| cors | 9 | P1 | M2 |
| **P1 小计** | **190** |  |  |
| encryption（SSE-C、SSE-S3） | 41 | P2 | M4 |
| object\_lock | 39 | P2 | M4 |
| lifecycle | 20 | P2 | M4 |
| logging | 6 | P2 | M4 |
| **P2 小计** | **106** |  |  |
| **合计** | **545** |  |  |

门槛按测试函数计。P2 里的 `test_copy_enc` 和 `test_copy_part_enc` 是参数化用例，收集时会展开成多项，展开项全部通过才算该函数通过。

### B. s3-tests 运行配置

- harness 启动时读取 `[DEFAULT]`、`[fixtures]`、`[s3 main]`、`[s3 alt]`、`[s3 tenant]`、`[iam]`、`[iam root]`、`[iam alt root]` 八个段，缺一段就报错；因此凭证文件至少预置 6 个账号。
- harness 的客户端统一用 SigV4 和 `endpoint_url = http://host:port`，不传区域；s3d 的签名区域保持默认 `us-east-1`。
- 跑目标集的命令：

```bash
S3TEST_CONF=s3d.conf tox -- s3tests/functional/test_s3.py s3tests/functional/test_headers.py \
  -m 'not fails_on_aws and not auth_aws2 and not iam_account and not iam_user and not cloud_transition and not cloud_restore and not lifecycle_transition' \
  -k 'not tenant and not kms and not transition and not torrent'
```

- 这条过滤和附录 A 的静态统计用同一套规则；M0 时用 `--collect-only` 复核实际收集数。

* 凭证文件里每个账号都要带 `user_id`、`display_name`、`email`，并与 s3-tests 配置逐字一致：test\_s3.py 里约 90 处拿它们比对 `Owner.ID` 和 `DisplayName`，ACL 用例还会按 email 授权。

### C. 配置项

| 键 | 默认值 | 说明 |
| --- | --- | --- |
| `listen` | `127.0.0.1:8000` | S3 接口 |
| `admin_listen` | `127.0.0.1:9000` | `/metrics` 与 `/health` |
| `data_dir` | `./data` | 数据目录 |
| `region` | `us-east-1` | 签名区域 |
| `credentials_file` | `./credentials.toml` | 账号与密钥，文件权限须为 0600 |
| `base_domain` | 空 | 非空时启用 virtual-hosted 寻址 |
| `max_object_size` | 48.8 TiB | 对象大小上限 |
| `max_buckets_per_account` | 10000 | 每账号桶数 |
| `default_object_ownership` | `BucketOwnerEnforced` | 跑 s3-tests 时设为 `ObjectWriter` |
| `group_commit_window_ms` / `group_commit_max_batch` | 1 / 64 | group commit |
| `segment_size` / `wal_file_size` | 1 GiB / 256 MiB | 文件滚动大小 |
| `checkpoint_wal_bytes` / `checkpoint_interval` | 256 MiB / 10 min | 检查点触发条件 |
| `gc_live_ratio` | 0.5 | 低于此存活率触发压缩 |
| `completed_upload_retention` | 24 h | FR-27 |
| `max_connections` | 1024 | 超出返回 503 `SlowDown` |
| `log_format` | `json` | NFR-10 |

### D. 来源

- [ceph/s3-tests](https://github.com/ceph/s3-tests)（提交 `5b39871`，2026-10-12）
- [Amazon S3 multipart upload limits](https://docs.aws.amazon.com/AmazonS3/latest/userguide/qfacts.html)
- [Amazon S3 increases the maximum object size to 50 TB](https://aws.amazon.com/about-aws/whats-new/2025/12/amazon-s3-maximum-object-size-50-tb)（2025-12-02）
- [Amazon S3 now supports conditional deletes in S3 general purpose buckets](https://aws.amazon.com/about-aws/whats-new/2025/09/amazon-s3-conditional-deletes-s3-general-purpose-buckets)（2025-09-16）
- [How to perform conditional deletes](https://docs.aws.amazon.com/AmazonS3/latest/userguide/conditional-deletes.html)
- [Checking object integrity in Amazon S3](https://docs.aws.amazon.com/AmazonS3/latest/userguide/checking-object-integrity.html)
- [Checking object integrity for data uploads](https://docs.aws.amazon.com/AmazonS3/latest/userguide/checking-object-integrity-upload.html)
- [CreateMultipartUpload API Reference](https://docs.aws.amazon.com/AmazonS3/latest/API/API_CreateMultipartUpload.html)
- [General purpose bucket naming rules](https://docs.aws.amazon.com/AmazonS3/latest/userguide/bucketnamingrules.html)
- [Bornholt et al., Using Lightweight Formal Methods to Validate a Key-Value Storage Node in Amazon S3, SOSP 2021](https://www.cs.utexas.edu/%7Ebornholt/papers/shardstore-sosp21.pdf)
- 本机实测（2026-11-12）：boto3 / botocore 1.44.0 对本地端点的请求抓包；crates.io 索引与 PyPI 的版本查询
