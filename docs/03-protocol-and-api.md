# 03 · S3 协议层与操作语义细则

本文档将《需求规格书》第 4～7 节（`PR-1`～`PR-33`、`FR-1`～`FR-51`）细化为无歧义的字节级解析规则、状态机、数学公式与判定决策表，供 `s3d-proto`、`s3d-server` 与 `s3d-model` 共同遵循。

---

## 1. 寻址、URI 解码与子资源路由（`PR-1`～`PR-5`）

### 1.1 Virtual-Hosted 与 Path-Style 识别

1. 取 `Host` 头，剥离可选 `:port` 后转小写。
2. 若配置了非空 `base_domain`：
   - `host == base_domain`：无桶根请求（`GET /` → `ListBuckets`）。
   - `host` 以 `.{base_domain}` 结尾：前缀即为 `{bucket}`，请求路径整体作为 `/{key}`（前导 `/` 剥离后即为对象 key，允许桶名含 `.`）。
3. 其余情况一律按 **Path-Style** 解析：`/` → 根；`/{bucket}` 或 `/{bucket}/` → 桶级请求；`/{bucket}/{key...}` → 对象级请求。

### 1.2 URI 路径解码与规范化铁律（`PR-3`, `PR-6`）

S3 在对象 key 解码与 SigV4 规范路径上与通用 Web 框架不同，严禁调用会自动折叠路径的路由库：

| 阶段 | 处理规则 | 示例：线上收到 `/my-bkt/a//b/./..%2Fc+d%20e` |
| --- | --- | --- |
| 对象 key 提取（`PR-3`） | 剥离 `/{bucket}/` 后，仅做**一次** `%XX` 字节解码；`+` 保持 `0x2B` 字面量；保留连续 `/`、首尾 `/`、`.`、`..`；校验合法 UTF-8（非法 → `400 InvalidURI`） | `bucket = "my-bkt"`<br>`key = "a//b/./../c+d e"` |
| SigV4 `CanonicalURI`（`PR-6`） | 对原始请求路径（未把 `%2F` 还原为 `/` 前）扫描：已有合法 `%XX` 仅将十六进制字母转大写，**不二次编码**；其余非保留字符（`A-Z a-z 0-9 - _ . ~ /` 之外的字节，含字面量 `+` 和空格）编码为大写 `%XX`；绝不归一化 `.`、`..`、`//` | `/my-bkt/a//b/./..%2Fc%2Bd%20e` |

### 1.3 子资源路由优先级（`PR-5`）

同一个 HTTP 方法 + 路径可通过 query 参数区分不同操作，按以下顺序匹配：
1. **未实现黑名单子资源**（规格书第 5 节末尾 12 项：`website`、`replication`、`notification`、`inventory`、`analytics`、`metrics`、`intelligent-tiering`、`accelerate`、`requestPayment`、`select`、`restore`、`torrent`，以及 P2 未开启时的对应参数）→ 立即返回 `501 NotImplemented`。
2. **精确动作子资源**（互斥，若同时携带多个不兼容动作参数 → `400 InvalidArgument`）：
   - 桶级：`location`、`delete`、`uploads`、`versions`、`versioning`、`tagging`、`cors`、`policy`、`policyStatus`、`publicAccessBlock`、`acl`、`ownershipControls`、`object-lock`、`lifecycle`、`encryption`、`logging`；无动作参数时 `GET` 按 `list-type=2` 分流 `ListObjectsV2` 与 `ListObjectsV1`。
   - 对象级：`uploads`（POST → `CreateMultipartUpload`）、`uploadId`（配合 `partNumber` → `UploadPart`/`UploadPartCopy`；无 `partNumber` 按 GET/POST/DELETE 分流 `ListParts`/`Complete`/`Abort`）、`attributes`、`tagging`、`acl`、`retention`、`legal-hold`。

---

## 2. SigV4 认证与流式解码状态机（`PR-6`～`PR-14`, `PR-27`）

### 2.1 认证模式分流与密钥缓存

- **签名派生密钥缓存（`PR-7`）**：进程内维护 `RwLock<HashMap<(AccountId, [u8; 8]), [u8; 32]>>`（键为 `(账号, YYYYMMDD)`，因为 `region` 与 `"s3"` 固定），省去每次请求 4 轮 HMAC-SHA256 派生；每日最多新增 `N_accounts` 条，定期清理 2 天前的条目。所有最终签名比对一律使用常数时间异或累加（`ct_eq`），杜绝计时侧信道。
- **时钟检查（`PR-9`, `PR-10`）**：
  - Header 签名：优先取 `x-amz-date`，无则取 `Date`；与服务端当前 UTC 时间绝对差 `> 900s`（15 分钟）→ `403 RequestTimeTooSkewed`。
  - 预签名 URL：`X-Amz-Date` 超前服务端超过 15 分钟 → `403 RequestTimeTooSkewed`；`X-Amz-Expires` 不在 `1..=604800` 整数范围 → `400 AuthorizationQueryParametersError` / `403 AccessDenied`（对齐 `s3-tests` 断言：越界或 `now > sign_time + expires` 统一按用例断言返回 `403 AccessDenied`）。

### 2.2 `aws-chunked` 与尾部校验和状态机（`PR-12`, `PR-27`）

当 `x-amz-content-sha256` 为以下三者之一时启用分块解码器：
1. `STREAMING-AWS4-HMAC-SHA256-PAYLOAD`（逐块验签，无尾部头）
2. `STREAMING-UNSIGNED-PAYLOAD-TRAILER`（无块签名，带尾部校验和头）
3. `STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER`（P1：逐块验签 + 尾部校验和头 + `x-amz-trailer-signature`）

**状态机转移**：

```text
[ReadChunkHeader] ──读 `<hex_len>[;chunk-signature=<64hex>]\r\n`──▶
   ├─ hex_len > 0:
   │    ├─ 校验已累计长度 + hex_len <= x-amz-decoded-content-length (超出则报错)
   │    ├─ 流式读满 hex_len 字节 + `\r\n`
   │    ├─ 签名模式下算 chunk SHA256 并验证 chunk-signature（种子 prev_sig 初始为请求头签名）
   │    └─ 回到 [ReadChunkHeader]（若下一块存在，则本块必须满足 hex_len >= 8192，否则拒绝请求 PR-12）
   └─ hex_len == 0:
        ├─ 校验累计解码字节数 == x-amz-decoded-content-length（不等 → 400 IncompleteBody）
        ├─ 签名模式下验证 0 长度末块的 chunk-signature
        ├─ 无 TRAILER 模式：读末尾 `\r\n` → [Done]
        └─ 带 TRAILER 模式：进入 [ReadTrailers]
             ├─ 读取 `<lower-header-name>:<value>\r\n` 直至空行 `\r\n`（仅允许 1 个尾部块）
             ├─ 核对尾部头名必须与请求头 `x-amz-trailer` 声明一致，且仅限 crc32/crc32c/crc64nvme/sha1/sha256（PR-27）
             ├─ P1 签名模式验证 `x-amz-trailer-signature`（种子为 0 长度末块的签名）
             └─ 比对流式累积出的摘要与尾部声明值（不符 → 400 BadDigest，PR-21）→ [Done]
```

**`Content-Encoding` 净化（`FR-5`）**：按 `,` 拆分请求头 `Content-Encoding`，剔除大小写无关的 `aws-chunked` 项并去首尾空白；若剩余非空则重新以 `, ` 拼接存入系统元数据，若为空则不保存 `Content-Encoding` 头。

---

## 3. 校验和体系与 CRC GF(2) 合并算法（`PR-20`～`PR-26`）

### 3.1 单次写入与默认校验和规则

- 客户端携带任一 `x-amz-checksum-<alg>`（最多允许携带一种算法，多种同时出现 → `400 InvalidRequest`）或 `Content-MD5`：流式独立计算并比对 Base64 编码值；不合法 Base64 / 长度不对 → `400 InvalidDigest` / `InvalidRequest`；值不匹配 → `400 BadDigest`。
- 客户端**未携带**任何 `x-amz-checksum-*` 时：服务端流式计算并持久化 **CRC64NVME**（类型 `FULL_OBJECT`，`PR-22`）；注意此时 `PutObject` 响应是否回显取决于 AWS 规范（`PR-23`：客户端带了算法时原样回显，未带时按实测行为回显或保存供 `ENABLED` 模式读取）。
- `GetObject` / `HeadObject` 仅当请求携带 `x-amz-checksum-mode: ENABLED` 时返回 `x-amz-checksum-<alg>` 与 `x-amz-checksum-type`（`PR-24`）；若带 Range 读取整个对象边界才返回全对象校验和，子区间 Range 不返回校验和头。

### 3.2 分片上传全对象 CRC 数学合并公式（`PR-25`）

当 `CreateMultipartUpload` 的校验和类型为 `FULL_OBJECT`（适用于 `CRC64NVME`、`CRC32`、`CRC32C`）时，`CompleteMultipartUpload` **严禁回读各分片底层数据**，直接由各分片已保存的 CRC 值与分片字节长度合并得出。

三种算法均为标准反射型 CRC（`init = !0`，`xorout = !0`）：
- `CRC32`（IEEE）：位宽 $w = 32$，反射多项式 `0xEDB88320`
- `CRC32C`（Castagnoli）：位宽 $w = 32$，反射多项式 `0x82F63B78`
- `CRC64NVME`：位宽 $w = 64$，反射多项式 `0x9A6C9329AC4BC9B5`

设 $T$ 为在未异或寄存器后追加 `1` 个零比特的 $\text{GF}(2)^w$ 线性变换矩阵（$w \times w$ 比特矩阵，由单步无符号右移加条件异或多项式生成）。由于 `init == xorout`，利用线性叠加消去首尾掩码后，两段数据 $A$ 与 $B$（字节长度为 $\text{len}_B$，比特数 $m = 8 \cdot \text{len}_B$）的最终 CRC 满足精确恒等式：

$$\text{CRC}(A \Vert B) = T^{8 \cdot \text{len}_B}\!\left(\text{CRC}(A)\right) \oplus \text{CRC}(B)$$

- 通过矩阵二进制快速幂（Repeated Squaring）计算 $T^{8 \cdot \text{len}_B}$，合并两个分片的复杂度仅为 $O(w \log \text{len}_B)$；即使合并 10,000 个分片，纯 CPU 耗时也不足 **0.5 ms**。
- **组合校验和（`COMPOSITE`）**：将所选各分片的原始二进制摘要字节按 `PartNumber` 升序拼接，再执行一次同算法摘要，Base64 编码后追加 `-{N}`（如 `XXXX==-3`，`PR-25`）。

---

## 4. 条件求值真值表与错误优先级（`FR-12`～`FR-17`, `FR-22`）

### 4.1 条件读（`GET` / `HEAD`，对象存在且非删除标记时）

时间戳比较精度按 HTTP-date 向下取整到**秒**（`obj_sec = last_modified_ms / 1000`）：
- `If-Match` 谓词为真 $\iff$ 列表含 `*` 或含去除 `W/` 后的精确双引号 `ETag`。
- `If-Unmodified-Since` 谓词为真 $\iff$ `obj_sec <= header_sec`（非法日期格式按 HTTP 规范忽略该头）。
- `If-None-Match` 谓词为真 $\iff$ 列表不含 `*` 且不含当前 `ETag`。
- `If-Modified-Since` 谓词为真 $\iff$ `obj_sec > header_sec`（非法日期或晚于服务端当前时间的日期忽略该头）。

**求值先后顺序（严格满足 `FR-12` 与 `FR-13`）**：

| 步骤 | 请求携带的头与求值结果 | 立即动作 / 下一步 |
| --- | --- | --- |
| 1 | 带 `If-Match`：结果为**假** | 返回 `412 PreconditionFailed` |
| 1' | 带 `If-Match`：结果为**真** | **跳过第 2 步**（即使同时带了为假的 `If-Unmodified-Since` 也不报 412，进入第 3 步，`FR-13`） |
| 2 | 未带 `If-Match`，带 `If-Unmodified-Since`：结果为**假** | 返回 `412 PreconditionFailed` |
| 3 | 带 `If-None-Match`：结果为**假**（即 ETag 命中） | 返回 `304 Not Modified`（带 `ETag`、`Last-Modified` 等缓存头，忽略 `If-Modified-Since`，`FR-13`） |
| 3' | 带 `If-None-Match`：结果为**真**（ETag 未命中） | 若同时带 `If-Modified-Since` 且为假 → 按 RFC 7232 不触发 304（以 `If-None-Match` 为准返回 `200`；M0 跑 `s3-tests` `conditional` 集复核） |
| 4 | 未带 `If-None-Match`，带 `If-Modified-Since`：结果为**假** | 返回 `304 Not Modified` |
| 5 | 全部通过 | 继续处理 `Range` / `partNumber`，返回 `200 OK` 或 `206 Partial Content` |

### 4.2 条件写与条件删除（在 `KeyLock` 提交点求值，`FR-15`～`FR-17`）

定义“当前可见对象存在”为：该 key 的版本链非空，且最新头版本 `head.is_delete_marker == false`。

| 操作 | 条件头 | 当前无版本 | 当前头版本是删除标记 | 当前存在有效对象（`ETag = E`） |
| --- | --- | --- | --- | --- |
| `PutObject` / `CompleteMultipart` | `If-None-Match: *` | **放行提交** | **放行提交** | `412 PreconditionFailed` |
| `PutObject` / `CompleteMultipart` | `If-Match: <x>` | `404 NoSuchKey` | `404 NoSuchKey` | `x == E` 放行，否则 `412 PreconditionFailed` |
| `DeleteObject` / `DeleteObjects` 单项 | `If-Match: *` | `404 NoSuchKey` | `412 PreconditionFailed`（`FR-16`） | **放行删除** |
| `DeleteObject` / `DeleteObjects` 单项 | `If-Match: <x>` | `404 NoSuchKey` | `404 NoSuchKey` | `x == E` 放行，否则 `412 PreconditionFailed` |

> 若同一请求同时带 `If-Match` 与 `If-None-Match: *`，直接返回 `400 InvalidRequest`（或按 AWS 条件写规范拒绝不支持的条件头组合）。`CopyObject` 先对源快照按 4.1 节等价逻辑求值 `x-amz-copy-source-if-*`（但把 `304` 分支统一映射为 `412 PreconditionFailed`，`FR-22`），再在目标 key 锁内按上表求值目标侧 `If-Match` / `If-None-Match`。

---

## 5. 核心 API 关键边界细则（P0）

### 5.1 列举与防伪造分页游标（`FR-39`～`FR-45`）

- **流式归并去重器**：对 `BTreeMap::range(start_key..)` 顺序迭代：
  1. 若 key 不以 `prefix` 开头，立即 `break` 结束扫描（`O(page_size)`，与桶总对象数无关）。
  2. 若提供了非空 `delimiter`，在 `key[prefix.len()..]` 中查找首个 `delimiter` 出现位置 `pos`：
     - 找到：产出 `CommonPrefix = &key[.. prefix.len() + pos + delimiter.len()]`，并将 `BTreeMap` 游标直接二分跳过该前缀区间所有后续 key（例如将最后字节 `+1` 构造下界），避免某虚拟目录下有 50 万对象时退化为全表扫描！
     - 未找到：产出普通 `Contents` 项。
  3. `Contents` 与 `CommonPrefixes` 合计达到 `max-keys` 时停止；仅当后续确实还有至少 1 个匹配项时置 `IsTruncated = true`（向前多探 1 项，杜绝恰好等于 `max-keys` 时误置 `IsTruncated = true`）。
- **`ListObjectsV2` `continuation-token` 结构（`FR-42`）**：
  - 明文载荷：`ver(1B) | bucket_name_sha256_prefix(8B) | last_emitted_key_bytes`。
  - 签名保护：`token = Base64UrlNoPad(payload || HMAC_SHA256(instance_secret, payload)[..16])`（实例启动时随机生成或从 `FORMAT.instance_uuid` 派生密钥）。
  - 解码失败、桶不匹配或 HMAC 校验不通过 → `400 InvalidArgument`。

### 5.2 分片上传边界与 24 小时幂等保留（`FR-24`～`FR-31`）

- `CompleteMultipartUpload` 严格按以下顺序校验，确保返回 `s3-tests` 期望的精确错误码（`FR-26`）：
  1. XML 语法错误或 `<Part>` 列表为空 → `400 MalformedXML`。
  2. 遍历请求 `<Part>` 列表，检查 `PartNumber` 严格单调递增（`prev < curr`，且在 `1..=10000`）→ 违规立即报 `400 InvalidPartOrder`。
  3. 检查 Upload 会话状态：
     - 不存在或 `Aborted` → `404 NoSuchUpload`。
     - 已处于 `Completed`（24 小时保留期内，`FR-27`）：核对请求 `<Part>` 列表与完成时快照一致则返回缓存的 `200 CompleteMultipartUploadResult`；若不同则返回 `404 NoSuchUpload` / `400 InvalidPart`。
  4. 对照 `Open` 会话中已上传分片表：逐项检查 `PartNumber` 存在且 `ETag`（忽略双引号包裹差异）匹配，若请求 `<Part>` 附带了分片校验和头同时核对分片校验和 → 不符报 `400 InvalidPart`。
  5. 检查除列表中**最后一项**外的所有分片 `size >= 5 * 1024 * 1024`（5 MiB）→ 不足报 `400 EntityTooSmall`；检查总大小 `<= max_object_size` → 超出报 `400 EntityTooLarge`。
  6. 进入目标 key 锁求值 `If-None-Match` / `If-Match` 并写入 `WalRecord::CompleteUpload`（未被选中的多余已上传分片在提交同时转入段垃圾等待 GC）。

### 5.3 Range、`partNumber` 与响应头覆盖（`FR-9`～`FR-11`）

- 同时携带 `Range` 请求头与 `?partNumber=` 查询参数 → `400 InvalidRequest`。
- **Range 解析（`FR-9`）**：
  - 仅识别 `bytes=` 前缀（其他单位忽略或报 `416`）。
  - 包含 `,` 的多区间请求（如 `bytes=0-0,2-3`）：忽略 `Range` 头，按 `200 OK` 返回完整对象（对应 `Q3`）。
  - 空对象（`size == 0`）携带任何单区间 `Range` → `416 InvalidRange`（附带 `Content-Range: bytes */0`）。
  - `bytes=a-b`（要求 `a <= b` 且 `a < size`，`b` 截断至 `size - 1`）、`bytes=a-`（要求 `a < size`）、`bytes=-n`（要求 `n > 0`，取末尾 `min(n, size)` 字节）；不满足 → `416 InvalidRange`（附带 `Content-Range: bytes */{size}`）。
- **响应头覆盖参数（`FR-11`）**：`response-content-type`、`response-content-language`、`response-expires`、`response-cache-control`、`response-content-disposition`、`response-content-encoding` 六个参数仅在请求已通过签名认证（Header SigV4 或预签名 URL）时替换响应头；**匿名请求**只要出现其中任一参数 → `400 InvalidRequest`。

---

## 6. P1 授权、标签、CORS 与表单上传精确规范（M2 细化落地）

### 6.1 统一授权求值链（Bucket Policy + PublicAccessBlock + OwnershipControls + ACL，`PR-28`～`PR-33`）

对任意桶/对象操作 `(CallerContext, S3Action, ResourceArn, PolicyEvalContext)`，严格按以下 5 步顺序求值：

1. **`x-amz-expected-bucket-owner` 核对**：与 `bucket.owner.user_id` 不一致 → `403 AccessDenied`。
2. **Bucket Policy 显式 `Deny`**：若桶存在策略且任意匹配 `(Principal, Action, Resource, Condition)` 的 Statement 为 `Effect: "Deny"` → **立即 `403 AccessDenied`**（对桶主/对象主同样生效，且不受 `RestrictPublicBuckets` 屏蔽）。
3. **Bucket Policy 显式 `Allow`**：若存在匹配 Statement 为 `Effect: "Allow"`：
   - 若桶 `PublicAccessBlock.RestrictPublicBuckets == true` 且桶策略为公开策略（或命中公开 Statement），则**仅对桶主放行**，非桶主忽略该 `Allow`；
   - 否则 → **放行**。
4. **资源所有者与 ACL 求值**：
   - **管理类子资源**（`?policy`、`?policyStatus`、`?publicAccessBlock`、`?ownershipControls`、`?tagging`、`?cors`、`?versioning`）：仅资源所有者（桶级看 `bucket.owner`；对象级 `?tagging` 看 `ver.owner`，`BucketOwnerEnforced` 下看 `bucket.owner`）放行，**ACL 不授予标签或策略类权限**。
   - **数据与 ACL 子资源**：
     - `BucketOwnerEnforced`：禁用桶/对象 ACL 授权，仅 `caller == bucket.owner` 放行。
     - `BucketOwnerPreferred` / `ObjectWriter`：若 `PublicAccessBlock.IgnorePublicAcls == true`，求值时过滤 `AllUsers` 与 `AuthenticatedUsers` 两条公开组授权；桶主/对象主隐式保留 `READ_ACP`/`WRITE_ACP`（桶主保留桶全部管理权及对桶内任意对象的删除权 `PR-31`），`ListObjects*` 查桶 `READ`，`PutObject`/`PostObject`/`Multipart` 查桶 `WRITE`，`GetObject`/`HeadObject` 查对象 `READ`（**绝不**用桶 `READ` 替代对象 `READ`，亦**绝不**用对象 `WRITE` 替代桶 `WRITE`）。
5. **缺失对象 `404` vs `403` 掩码规则**：当 `GetObject`/`HeadObject`/`GetObjectAcl`/`GetObjectTagging`/`GetObjectAttributes` 目标 key 不存在（或头版本为删除标记）时，以 `s3:ListBucket` + 条件上下文 `s3:prefix = <target_key>` 重新求值调用者对桶的列举权：有列举权返回 `404 NoSuchKey`（删除标记带 `x-amz-delete-marker: true`，非版本化空 key 带 `x-amz-delete-marker: false`），无列举权返回 `403 AccessDenied`。

### 6.2 Bucket Policy 语法与条件运算符精确表

- **容量上限**：原始 JSON ≤ 20 KiB（超出或语法非法 → `400 MalformedPolicy`；原样保存原始字符串供 `GET ?policy` 逐字节返回）。
- **结构约束**：`Version` 支持 `"2012-10-17"` / `"2008-10-17"`；`Effect` 仅限 `"Allow"` / `"Deny"`；**`"Effect": "Allow"` 严禁搭配 `"NotPrincipal"`**（直接返回 `400 MalformedPolicy`）；`Resource` 必须匹配 `arn:aws:s3:::*`、`arn:aws:s3:::*/*`、`arn:aws:s3:::{bucket}` 或 `arn:aws:s3:::{bucket}/*`（指向其他具体桶名 → `400 MalformedPolicy`）。
- **支持的 `Condition` 运算符白名单**（未知运算符在 `PutBucketPolicy` 阶段拒绝并报 `400 MalformedPolicy`；所有基础运算符均支持追加 `...IfExists` 后缀）：

| 类别 | 运算符列表 | 求值规则 |
| --- | --- | --- |
| 字符串比较 | `StringEquals`, `StringNotEquals`, `StringEqualsIgnoreCase`, `StringNotEqualsIgnoreCase`, `StringLike`, `StringNotLike` | `StringLike` 支持 `*`（0+ 字符）与 `?`（单字符）；否定运算符在无 `IfExists` 且上下文缺省该键时求值为 `false` |
| 数值比较 | `NumericEquals`, `NumericNotEquals`, `NumericLessThan`, `NumericLessThanEquals`, `NumericGreaterThan`, `NumericGreaterThanEquals` | 解析 `f64`/`i64` 数值比较 |
| 布尔与空值 | `Bool`, `Null` | `Null: {"k": "true"}` 当且仅当上下文不存在键 `k` 时为真 |
| 网络地址 | `IpAddress`, `NotIpAddress` | IPv4 / IPv6 CIDR 网段匹配（对接 `aws:SourceIp`） |

- **支持的上下文条件键**：`s3:ExistingObjectTag/<k>`、`s3:RequestObjectTag/<k>`、`s3:x-amz-acl`、`s3:x-amz-grant-full-control`（及 `-read`/`-write`/`-read-acp`/`-write-acp`）、`s3:x-amz-copy-source`（去前导 `/` 归一化）、`s3:x-amz-metadata-directive`（仅请求显式携带该头时存在）、`s3:prefix`、`s3:delimiter`、`aws:Referer`、`aws:SourceIp`。
- **`?policyStatus` 与 `BlockPublicPolicy` 公开判定**：Statement 为 `Effect: "Allow"` 且 `Principal` 含 `"*"`（`"*"` 或 `{"AWS": "*"}`），且不含将访问收敛到固定非通配 IP/主体的限制条件时判定为公开策略；桶 `IsPublic = true` 当且仅当（未设 `IgnorePublicAcls` 且非 `BucketOwnerEnforced` 且桶 ACL 含 `AllUsers`/`AuthenticatedUsers`）或（未设 `RestrictPublicBuckets` 且桶策略含公开 Statement）。

### 6.3 ACL、`?ownershipControls`、标签（`?tagging`）与 CORS（`?cors`）映射表

| 子系统 | 核心规则与状态码 |
| --- | --- |
| **`?ownershipControls`** | `GET` 返回 `<OwnershipControls><Rule><ObjectOwnership>...</ObjectOwnership></Rule></OwnershipControls>`（若经 `DELETE` 删除则返回 `404 OwnershipControlsNotFoundError`；`DELETE` 本身幂等返回 `204`）。`PUT` 设为 `BucketOwnerEnforced` 前校验当前桶 ACL 必须为桶主默认私有 ACL，否则返回 `400 InvalidBucketAclWithObjectOwnership`。 |
| **桶标签 vs 对象标签** | 标签统一按 `Key` 字典序（`BTreeMap`）存储与输出；单键 `1..=128` 字符、单值 `0..=256` 字符、禁止同集重复键（违规报 `400 InvalidTag`）。桶标签上限 50 个，无标签时 `GET /{b}?tagging` 返回 `404 NoSuchTagSet`；对象标签上限 10 个，无标签时 `GET /{b}/{k}?tagging` 返回 `200 OK` 空 `<TagSet/>`，`PUT` 返回 `200 OK`，`DELETE` 返回 `204 No Content`。`x-amz-tagging` 按 URL Query 解析（无 `=` 视为值 `""`）；非空标签集在 `GET`/`HEAD` 响应附加 `x-amz-tagging-count`。 |
| **CORS 与 `OPTIONS`** | `OPTIONS` 预检**免认证**（忽略签名/预签名参数与桶私有策略）：缺 `Origin` 或非法/缺 `Access-Control-Request-Method` → `400 BadRequest`；无配置或无规则同时匹配 `Origin`、`Method` 及全部 `Access-Control-Request-Headers` → `403 Forbidden`。匹配规则 `<AllowedOrigin>` 为字面量 `"*"` 时返回 `Access-Control-Allow-Origin: *`，其余通配/精确规则回显请求 `Origin`。普通请求携带 `Origin` 时（无论是 `2xx` 还是 `403`/`404` 错误响应），按 `Access-Control-Request-Method`（若有）或实际 HTTP 方法匹配规则附加 CORS 响应头。 |

### 6.4 HTML 表单上传 `PostObject`（`POST /{b}`）校验表

1. **`multipart/form-data` 解析铁律**：仅当 part 的 `Content-Disposition` 中 `name` 大小写无关等于 `"file"` 时识别为文件流（忽略非 `file` 字段自带的 `filename="..."` 参数，并忽略 `file` 之后的任何字段）；在求值 `$key` 条件前先将 `key` 中的 `${filename}` 替换为 `file` 段的原始文件名（保留反斜杠 `\` 字面量不转义）。
2. **表单签名双模式**：
   - 全匿名：未携带 `AWSAccessKeyId` / `x-amz-credential` / `policy` / `signature` → 跳过表单策略，按桶 `s3:PutObject` 匿名权限判定。
   - POST SigV2：`AWSAccessKeyId` + `policy` + `signature`（`Base64(HMAC-SHA1(secret, policy_b64))`）。
   - POST SigV4：`x-amz-algorithm=AWS4-HMAC-SHA256` + `x-amz-credential` + `x-amz-date` + `policy` + `x-amz-signature`（`Hex(HMAC-SHA256(signing_key, policy_b64))`）。
   - 缺字段 → `400 InvalidArgument`；未知 AK → `403 InvalidAccessKeyId`；签名不符 → `403 SignatureDoesNotMatch`。
3. **Policy JSON 校验**：顶层键区分大小写，必须同时含 `"expiration"`（严格 `YYYY-MM-DDTHH:MM:SS[.sss]Z`，格式错误 → `400 InvalidPolicyDocument`，已过期 → `403 AccessDenied`）与 `"conditions"` 数组。条件支持 `{"field": "val"}`、`["eq", "$field", "val"]`、`["starts-with", "$field", "prefix"]`、`["content-length-range", min, max]`（操作符与字段名不区分大小写，字段值区分大小写）。除豁免字段（`file`、`policy`、签名字段、`x-ignore-*`、`x-amz-checksum-*`）外，表单字段与策略条件须双向覆盖且包含匹配的 `bucket` 条件（不满足 → `403 AccessDenied`；文件超 `max` → `400 EntityTooLarge`；低于 `min` → `400 EntityTooSmall`）。
4. **成功响应**：携带非空 `success_action_redirect` / `redirect` 时返回 `303 See Other`（`Location` 追加 `bucket`、`key`、`etag` 查询参数）；否则按 `success_action_status` 返回 `200 OK`、`201 Created`（无 `xmlns` 的 `<PostResponse>` XML）或默认 `204 No Content`。
