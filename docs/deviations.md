# s3-tests 兼容性偏差清单（Deviations Register）

本文件是《S3 兼容对象存储 需求规格书》第 1、2、10（`VR-5`）、11 节规定的随库验收交付物。

**维护铁律**：
1. 以 `ceph/s3-tests` 提交 `5b39871`（2026-10-12）筛选出的 **545 个目标用例**为基准。
2. 每个里程碑退出时，`目标集 - 实际通过集` 中的**每一个**未通过用例都必须登记在本文件第 2 节表格中；存在未登记的失败用例时 CI 直接阻断验收。
3. 当 `s3-tests` 断言与 AWS 官方文档或真实 S3 行为冲突（但上游漏标 `fails_on_aws`）时，**实现以 AWS 真实行为为准**，在此登记冲突原因并附 AWS 文档章节或抓包依据（第 12 节风险对策）。
4. 已通过并进入 `tests/s3tests-passed.txt` 基线的用例严禁退化回本清单。

---

## 1. 里程碑达成度总览

| 级别 | 领域数 | 目标用例数 | 门槛要求 | 当前通过数 | 当前登记偏差数 | 最近更新里程碑 |
| --- | --- | --- | --- | --- | --- | --- |
| **M0 子集（bucket + object_core）** | 2 | 55 | M0 ≥ 44 | **48 / 55** | 7 | **M0 已达成**（`reports/m0-junit.xml`） |
| **P0** | 10 | 249 | M1 ≥ 237 / M2 ≥ 245 | 48（M0 子集已跑） | 7 | M0 |
| **P1** | 6 | 190 | M2 ≥ 171 | —（待 M2 首跑） | 0 | 初始化 |
| **P2** | 4 | 106 | M4 ≥ 85（选做） | —（待 M4 首跑） | 0 | 初始化 |
| **合计** | **20** | **545** | — | **48** | **7** | **M0** |

---

## 2. 偏差明细表

> **分类枚举**：
> - `AWS_DIVERGENCE`：`s3-tests` 用例断言偏离 AWS S3 当前规范或上游脚本缺陷（漏标 `fails_on_aws`），`s3d` 选择对齐规格书与 AWS。
> - `DEFERRED_MILESTONE`：属于当前里程碑尚未交付的后序特性，计划在目标里程碑消除。
> - `INTENTIONAL_LIMIT`：受 v1 明确非目标或简化策略边界限制（如冷门 Policy 条件运算符在 `PutBucketPolicy` 阶段显式拒绝）。

| 用例全名 (`file::test_func`) | 领域 | 级别 | 关联需求 ID | 偏差分类 | `s3-tests` 期望行为 | `s3d` 实际行为 | 原因与 AWS 依据 | 引入里程碑 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `s3tests/functional/test_s3.py::test_bucket_create_exists` | `bucket` | P0 | `FR-49` | `AWS_DIVERGENCE` | 捕获 `ClientError` 后断言 `e.status == 409` | 返回 `409 BucketAlreadyOwnedByYou`（触发上游 `AttributeError: 'BucketAlreadyOwnedByYou' object has no attribute 'status'`） | `s3d` 行为完全符合 `FR-49`；`ceph/s3-tests` `5b39871` 第 3847-3848 行已提取 `status, error_code = _get_status_and_error_code(e.response)`，但误写 boto2 属性 `e.status` 导致自身崩溃 | M0 |
| `s3tests/functional/test_s3.py::test_bucket_recreate_not_overriding` | `bucket` | P0 | `FR-49` | `AWS_DIVERGENCE` | 同账号重复 `CreateBucket` 返回 `200 OK` | 返回 `409 BucketAlreadyOwnedByYou` | 规格书 `FR-49` 与第 4.3 节明确要求同账号重复创建桶返回 `409 BucketAlreadyOwnedByYou`（对齐非 `us-east-1` 标准区域行为，不覆盖已有对象） | M0 |
| `s3tests/functional/test_s3.py::test_bucket_get_location` | `bucket` | P0 | `GetBucketLocation` | `AWS_DIVERGENCE` | 依赖 Ceph RGW `[s3 main] api_name` 作为非空 `LocationConstraint` 创建并读回 | 未配置 RGW `api_name` 时 `SKIPPED: no api_name configured` | AWS S3 默认区域 `us-east-1` 的 `GetBucketLocation` 返回空 `<LocationConstraint/>`（`None`），且 `CreateBucketConfiguration` 传 `us-east-1` 在真实 AWS 返回 `InvalidLocationConstraint` | M0 |
| `s3tests/functional/test_s3.py::test_get_object_attributes` | `object_core` | P0 | `GetObjectAttributes` | `DEFERRED_MILESTONE` | `GET /{b}/{k}?attributes` 返回对象属性 | 返回 `501 NotImplemented` | `?attributes` 子资源按里程碑表归属 **M1** 交付，将在 M1 消除 | M0 |
| `s3tests/functional/test_s3.py::test_get_checksum_object_attributes` | `object_core` | P0 | `GetObjectAttributes` | `DEFERRED_MILESTONE` | `GET /{b}/{k}?attributes` 返回校验和与属性 | 返回 `501 NotImplemented` | `?attributes` 子资源按里程碑表归属 **M1** 交付，将在 M1 消除 | M0 |
| `s3tests/functional/test_s3.py::test_expected_bucket_owner` | `bucket` | P0 | `PR-30`～`PR-32` | `DEFERRED_MILESTONE` | 调用 `PutBucketAcl` 设置 `public-read-write` 后校验 `x-amz-expected-bucket-owner` | `PutBucketAcl`（`?acl`）返回 `501 NotImplemented` | 桶 ACL 子资源归属 **M2（P1）**，将在 M2 消除 | M0 |
| `s3tests/functional/test_s3.py::test_bucket_create_special_key_names` | `bucket` | P0 | `PR-30`～`PR-32` | `DEFERRED_MILESTONE` | 上传并读回特殊 key 后调用 `PutObjectAcl` | 对象 PUT/LIST/GET 全过，`PutObjectAcl`（`?acl`）返回 `501 NotImplemented` | 对象 ACL 子资源归属 **M2（P1）**，将在 M2 消除 | M0 |
