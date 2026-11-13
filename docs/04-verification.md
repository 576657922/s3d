# 04 · 验证体系与测试替身设计

本文档将《需求规格书》第 10 节十层验证（`VR-1`～`VR-10`）落地为可实现的测试替身架构、状态机生成器、崩溃形式化模型与 CI 门禁机制。测试基础设施与生产引擎同步开发，任何缺陷修复必须先在对应验证层补入可复现用例。

---

## 1. 参考模型与状态机对拍（`VR-1`, `VR-2`）

### 1.1 `s3d-model` 设计约束（`VR-1`）

- **纯内存可执行规格（零持久化 / 零并发优化）**：`s3d-model` 仅使用一把粗粒度 `Mutex<ModelState>` 串行保护内存中的 `BTreeMap`，不做分块、不写磁盘、不做锁细化或异步流水线优化（M0 基础桶与对象 CRUD 约 500 行；随 M1～M4 扩展至覆盖 `ObjectStore` 全部 **63 个操作**——含 P0 全量、P1 多租户 IAM Bucket Policy / ACL / CORS / 版本控制 / 分片上传、P2 对象锁 WORM / 生命周期清扫 / SSE-S3 & SSE-C / 桶日志及全部 10 种校验和——总计约 4,280 行纯安全平铺状态机代码，支持 `O(1)` `Clone` 快照）。
- **100% 机械可追溯性**：模型生产代码中每个需求分支均以 `// [FR-N]` 显式标注需求编号；内置单元测试 `tests::vr1_all_51_fr_annotated_in_model` 与独立门禁脚本 `scripts/verify_fr_traceability.py` 自动扫描源码，强制校验 `FR-1`～`FR-51`（51/51）及全规格书 `PR`/`ST`/`NFR`/`VR`（共 **119/119** 个需求 ID）100% 落位，缺失任一编号即阻断 CI。

### 1.2 符号句柄双射与确定性上下文（`VR-2` 核心机制）

引擎与模型各自独立生成不透明的 `versionId` 与 `uploadId`。为使多步随机操作序列能够精确逐步比对，对拍驱动器维护双射映射表 `IdBijection`：
1. 生成器不直接填写字符串 ID，而是生成符号槽位（如 `SymUpload(0..4)`、`SymVersion(0..8)`、`UseCapturedEtag(slot)`）。
2. 执行器分别把符号槽位翻译为引擎侧真实 ID 与模型侧真实 ID 发起调用，收到响应后检验两侧：
   - 成功/错误码完全一致；
   - `ETag`、`Checksum`、字节内容、列表项顺序完全一致；
   - `versionId` 结构等价（同为 `null`、同为未开启版本无此头、或同为新分配的唯一 ID 并记入双射表）。
3. **确定性时钟**：每次操作在 `CallerContext.request_time_ms` 中注入单调可控的虚拟时间戳（支持“同秒操作”与“前进 2 秒”两种动作），使 `Last-Modified`、`If-Modified-Since`、`If-Unmodified-Since` 在两侧 100% 确定性对齐。

### 1.3 参数偏置生成器（Biased Strategy）

为最大化状态冲突率与边界覆盖，proptest 生成器采用如下偏置分布：

| 维度 | 偏置取值分布 | 覆盖意图 |
| --- | --- | --- |
| Bucket | 3 个固定桶名（含开启/暂停/未开启版本切换及 `object_lock_enabled` 桶级 WORM 开关）+ 10% 非法桶名 | 桶生命周期、版本状态机转换（`FR-32`）、对象锁联动 |
| Key | 70% 取自 4 个热点 key（`k1`, `k2`, `dir/a`, `dir/b`）；30% 取边界 key（含连续 `//`、首尾 `/`、`.`、`..`、`+`、空格、CJK/Emoji、1024B 极限与 1025B 超限） | 写覆盖、版本链堆叠、列举 `delimiter`/`prefix` 折叠（`PR-3`, `FR-40`） |
| 数据大小 | `{0, 1, 4095, 4096, 8192, 65535, 65536, 5 MiB - 1, 5 MiB}` | 空对象、扇区边界、段块切分边界、分片最小尺寸 `EntityTooSmall`（`FR-25`） |
| 校验和、加密与对象锁（P0+P1+P2） | 均匀/偏置采样全部 **10 种 `ChecksumAlgorithm`**（含 P2 `MD5`/`SHA512`/`XXHASH64`/`XXHASH3`/`XXHASH128`）、SSE-S3 / SSE-C 密钥槽、Governance / Compliance 保留期、Legal Hold 及 `x-amz-bypass-governance-retention` 删除 | 覆盖 P0+P1+P2 全特性组合状态转移 |
| 异常流注入 | 15% 写操作在流末尾返回 `BodyStreamError::BadDigest` 或 `ClientDisconnected` | 验证失败写入 0 可见残留（`FR-1`, `PR-21`） |

---

## 2. `FaultDisk` 崩溃形式化模型与判定器（`VR-3`）

### 2.1 最弱持久化假设模型（`s3d-disk::FaultDisk`）

真实文件系统（ext4/xfs）在掉电时可能发生未 `fsync` 页丢弃、4 KiB 块部分写入、跨文件落盘乱序及目录项丢失。`FaultDisk` 采用最严格（对引擎最不利）的内存状态模型：

```rust
pub struct FaultDiskState {
    /// 已通过 sync_data / sync_dir 确认持久化的物理镜像
    durable_dirs: BTreeMap<String, BTreeSet<String>>,
    durable_files: BTreeMap<InodeId, DurableInode>,   // 按 4096 B 扇区存储

    /// 尚未 sync_dir 的目录变更队列（Create / Rename / Unlink）
    pending_dir_ops: Vec<PendingDirOp>,

    /// 尚未 sync_data 的文件脏写记录（按 4 KiB 扇区拆分 + 待决 set_len）
    pending_file_writes: BTreeMap<InodeId, Vec<DirtySectorWrite>>,

    /// 故障注入控制器（在指定第 N 次 sync 或随机概率返回 DiskError::IoError / NoSpace）
    fault_plan: FaultPlan,
}
```

- **正常读写**：进程读操作看到 `durable + pending` 合并后的页缓存视图（与 OS Page Cache 一致）。
- **`sync_data(inode)`**：若命中 `EIO` 注入点则返回 `Err(DiskError::IoError)`（此时 `pending` 脏扇区保持不确定状态）；否则将该 `inode` 的全部 `pending_file_writes` 刷入 `durable_files`。
- **`sync_dir(dir)`**：将该目录下的 `pending_dir_ops` 刷入 `durable_dirs`（若未调用 `sync_dir` 即掉电，新建的段/WAL 文件或 `rename` 的检查点有 50% 概率在恢复后的目录中消失，直接检验 `ST-7` 与 `ST-8`）。
- **系统调用中途 / 4 KiB 扇区粒度断电触发器（`arm_mid_io_power_cut(countdown)`）**：在每次目录变更、`set_len`、`sync_data`/`sync_dir` 以及 `write_all_at` **内部的 4 KiB 扇区循环中**逐次递减计数器；归零瞬间立即中断当前写入（仅前半部分扇区进入 `pending_sectors`，后半部分扇区从未写出）并使后续所有磁盘 I/O 返回 `IoError`，配合 `128 KiB`、`1 MiB + 37 B`、`5 MiB + 19 B`（跨 11 个段文件与 1,280+ 个扇区）大对象、多段分片上传、`compact()` 与 `write_checkpoint()` 真实检验写途中断电的原子回滚与持久化边界。
- **模拟掉电（`power_cut(seed)`）**：
  1. 丢弃所有句柄与排他锁。
  2. 对每个未 `sync_dir` 的目录项变更，按伪随机布尔值决定保留或丢弃。
  3. 将所有文件未 `sync_data` 的 `DirtySectorWrite` 汇总打乱（模拟**跨文件乱序落盘**），随机抽取子集写入 `durable_files`；并按 20% 概率对某个脏 4 KiB 扇区制造前 `k` 字节写入、后 `4096 - k` 字节保留旧值/全零的**扇区撕裂**。
  4. 以此生成的 `durable_*` 克隆出全新 `FaultDisk` 实例用于重启恢复。

### 2.2 崩溃不变量判定器（Crash Oracle）

每轮测试由多线程并发驱动引擎执行随机序列，同时由独立的 `HistoryRecorder` 记录每步状态，在随机时刻触发 `power_cut` 并重启引擎：

1. **已确认不丢失（`ST-1`, `ST-2`）**：掉电前已返回 `2xx` 且掉电时无同 key 并发在途覆盖的所有对象版本，重启后 `GET` 必须成功，返回字节、`ETag`、`Checksum` 逐位匹配。
2. **原子无半成品（`ST-3`）**：掉电瞬间处于在途（已发起但未收到响应）的写/删请求 $W$，恢复后的状态必须严格等于“$W$ 完全未发生（保持前一确认版本）”或“$W$ 完整成功（字节与摘要完全等于 $W$ 的输入）”二者之一，绝不允许读到 `500 InternalError`、截断对象或元数据与数据不匹配。
3. **零幽灵复活（`ST-4`）**：掉电前已返回 `2xx` 的删除或覆盖，旧版本数据绝不重新变为可见。
4. **`fsync EIO` 熔断专项断言**：注入 `sync_data -> IoError` 后，断言当次及后续所有写操作均返回 `InternalError`，内存读操作绝看不到该失败批次的数据；随后掉电重启，断言恢复到 `EIO` 前的干净状态且可继续正常读写。
5. **恢复后活性与自检**：重启后先执行引擎级 `fsck`（必须 `0` 错误），再继续执行 30 步新读写与一次强制 `compact`（覆盖 GC 掉电恢复，`8.5`）。

---

## 3. 并发调度检查与线性一致性（`VR-4`）

### 3.1 `Loom` 穷举测试集（小原语，穷尽所有线程交错）

控制每个用例状态空间在 3 线程、≤ 5 步原语操作以内：
1. `loom_segment_pin_vs_delete`：2 个读线程获取/释放 `SegmentPin`，1 个 GC 线程将段置为 `PendingDelete` 并尝试删除，断言“读期间文件绝不被删”且“最后释放者必定触发删除，0 泄漏”。
2. `loom_group_commit_poison`：2 个写线程入队等待刷盘，1 个 `CommitWorker` 遇到 `EIO` 置 `ReadOnlyPoisoned`，断言无死锁、无悬挂唤醒、无未刷盘索引写入。

### 3.2 `Shuttle` 随机调度测试集（引擎全模块并发）

开启 `--features shuttle` 配合内存 `FaultDisk`（每次测试跑 10,000 次随机调度种子）：
1. **GC 与前台读写竞争**：4 协程在 2 个小段上高频覆写/读取同一批 key，1 协程循环执行 `compact()`。
2. **分片上传竞争**：同一 `uploadId` 上并发重传相同 `partNumber`（`FR-25`）+ 并发发起 `CompleteMultipartUpload` 与 `AbortMultipartUpload`（`FR-28`）。
3. **条件写互斥竞争**：4 协程对同一 key 同时发起 `PutObject(If-None-Match: *)` 或基于同一旧 `ETag` 的 `PutObject(If-Match)` / `DeleteObject(If-Match)`，断言严格最多 1 个返回 `200/204`，其余返回 `412`（`FR-17`）。

### 3.3 HTTP 层单 Key WGL 线性一致性检查器（`s3d-check`）

1. **压测负载**：启动真实 `s3d serve` 进程，16 个异步 HTTP 客户端在 8 个热点 key 上随机发起 `PutObject`、条件 `PutObject`、`GetObject`、`HeadObject`、`DeleteObject`、条件 `DeleteObject`。
2. **紧凑指纹载荷**：每次 `PutObject` 写入确定性自描述载荷（头部编码 `(client_id: u16, op_id: u64)`，填充至随机大小），客户端仅记录 `(key, invoke_mono_ns, complete_mono_ns, OpKind, OutcomeFingerprint)`，内存占用极小。
3. **WGL 算法验证**：按 key 切分独立操作历史（每条历史约 1,000～2,000 个重叠事件），运行带状态记忆化剪枝（Bitset Memoization）的 Wing & Gong / Lowe 回溯搜索算法，验证存在一条满足实时偏序（Real-time Order）的单线程串行执行序列与单 key S3 状态机完全吻合。10,000 条历史要求 `0` 违例。

---

## 4. 兼容性、差分、模糊测试与性能门禁（`VR-5`～`VR-10`）

### 4.1 `s3-tests` 自动化门禁与偏差闭环（`VR-5`）

- **`scripts/classify_s3tests.py`**：使用 Python `ast` 模块静态解析 `s3-tests`（提交 `5b39871`）的 `test_s3.py` 与 `test_headers.py`，校验排除 263 个非目标用例后精确产出 545 个目标用例清单（`P0=249, P1=190, P2=106`），输出 JSON 清单入库。
- **棘轮防退化门禁（Ratchet Gate）**：
  - 仓库维护已通过用例基线列表 `tests/s3tests-passed.txt` 与偏差清单 `docs/deviations.md`。
  - CI 解析 `tox` 产出的 JUnit XML：
    1. 任何已在 `s3tests-passed.txt` 中的用例变为失败/错误 → **立即阻断合并**。
    2. 里程碑验收时，所有目标集内未通过的用例必须 100% 出现在 `docs/deviations.md` 中且附有原因，否则阻断验收。

### 4.2 SigV4 双端差分与篡改测试（`VR-8`）

编写 Python + Rust 联测驱动，随机生成 10,000 组覆盖特殊 URI（含 `%2F`、`+`、空格、Unicode、`//`、`..`）、多值排序 query、前后空白请求头、预签名 URL、`aws-chunked` 的请求：
1. 正向：同一请求分别用 Python `botocore`（1.44.0）和 Rust `aws-sigv4` 签名，发往 `s3d-proto` 验签器，要求 **100% 通过**。
2. 反向：对每组已签名请求随机单点篡改（改 HTTP 方法、增删一个字节路径、调换 query 值、修改签名头值、拨快时钟 16 分钟、翻转 1 比特 body），要求 **100% 拒绝且错误码精确匹配**。

### 4.3 八个 `cargo-fuzz` 目标清单（`VR-7`）

位于 `fuzz/fuzz_targets/`，全部处理不可信字节流，要求无 `panic!`、无整数溢出、无 OOM（限制单次输入上限）：
1. `fuzz_auth_header`：`Authorization` 头词法与字段解析。
2. `fuzz_canonical_request`：任意 HTTP 请求行/头构造 SigV4 规范请求与 URI 编码。
3. `fuzz_aws_chunked`：`aws-chunked` 流式状态机与尾部头解析（随机切分字节块喂入）。
4. `fuzz_xml_requests`：全部 XML 请求体解析器（含万级嵌套标签与伪造 `<!DOCTYPE>` / `<!ENTITY>` 攻击载荷，验证 `NFR-8`）。
5. `fuzz_range_header`：`Range` 与 `x-amz-copy-source-range` 解析。
6. `fuzz_continuation_token`：`ListObjectsV2` / `ListBuckets` 游标解码与验签。
7. `fuzz_post_policy`：P1 `PostObject` Base64 JSON Policy 与表单边界解析。
8. `fuzz_wal_ckpt_decode`：向 WAL 记录解码器与检查点解析器喂入随机损坏字节，验证只返回 `Err` 绝不崩溃或分配超大内存。

### 4.4 自研压测工具与 CI 分级矩阵（`VR-9`, `VR-10`）

- **`s3d-bench`（内置于 workspace）**：基于 `tokio` + `hyper` 连接池直接生成预构造签名请求，精确测量 `NFR-1`（4 KiB PUT 32 并发）、`NFR-2`（4 KiB GET 32 并发）、`NFR-3`（1 GiB 流式吞吐对比 `fio` JSON 结果）、`NFR-4`（100 万对象随机 `start-after` 翻页延迟）、`NFR-5`（采样 `/proc/self/status` `VmRSS`）、`NFR-6`（100 万版本 kill -9 后重启至 `/health` 200 耗时）。
- **CI 执行分级**：

| 触发时机 | 执行内容 | 耗时预算 |
| --- | --- | --- |
| **每次 PR / Push** | `cargo clippy` + `#![forbid(unsafe_code)]` 扫描 + `s3d-disk` Miri（`VR-10`）；单元与集成测试；`VR-2` 对拍 10,000 条；`VR-3` 掉电 1,000 次；`VR-4` Loom 全集 + Shuttle 1,000 次；`VR-5` `s3-tests` P0 全集；`VR-6` `boto3`/`awscli` 冒烟 | ≤ 12 分钟 |
| **夜间流水线（Nightly）** | `VR-2` 对拍 100 万条；`VR-3` 掉电 10 万次；`VR-4` Shuttle 10,000 次 + WGL 线性一致性 10,000 条历史；`VR-5` `s3-tests` P0+P1(+P2) 全集；`VR-7` 8 个 fuzz 目标各跑 1 小时；`VR-8` SigV4 差分 10,000 组 | 约 2～3 小时 |
| **每周 / 里程碑门禁** | `VR-9` 全套 `NFR-1`～`NFR-6` 性能基线回归（退步 > 10% 告警阻断）+ 全量验收数据集 `s3d fsck` | 约 40 分钟 |
