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
| **M0 子集（bucket + object_core）** | 2 | 55 | M0 ≥ 44 | **52 / 55**（M0 首跑 48/55，M1 消除全部 4 项延后） | 3 | M1 |
| **P0** | 10 | 249 | M1 ≥ 237 / M2 ≥ 245 | **240 / 249**（96.4%，0 项 `DEFERRED_MILESTONE`） | 9 | **M1 已达成**（`reports/m1-junit.xml`） |
| **P1** | 6 | 190 | M2 ≥ 171 | —（待 M2 首跑） | 0 | 初始化 |
| **P2** | 4 | 106 | M4 ≥ 85（选做） | —（待 M4 首跑） | 0 | 初始化 |
| **合计** | **20** | **545** | — | **240** | **9** | **M1** |

---

## 2. 偏差明细表

> **分类枚举**：
> - `AWS_DIVERGENCE`：`s3-tests` 用例断言偏离 AWS S3 当前规范或上游脚本/客户端缺陷（漏标 `fails_on_aws`），`s3d` 选择对齐规格书与 AWS。
> - `DEFERRED_MILESTONE`：属于当前里程碑尚未交付的后序特性，计划在目标里程碑消除。
> - `INTENTIONAL_LIMIT`：受 v1 明确非目标或简化策略边界限制（如冷门 Policy 条件运算符在 `PutBucketPolicy` 阶段显式拒绝）。

| 用例全名 (`file::test_func`) | 领域 | 级别 | 关联需求 ID | 偏差分类 | `s3-tests` 期望行为 | `s3d` 实际行为 | 原因与 AWS 依据 | 引入里程碑 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `s3tests/functional/test_s3.py::test_bucket_create_exists` | `bucket` | P0 | `FR-49` | `AWS_DIVERGENCE` | 捕获 `ClientError` 后断言 `e.status == 409` | 返回 `409 BucketAlreadyOwnedByYou`（触发上游 `AttributeError: 'BucketAlreadyOwnedByYou' object has no attribute 'status'`） | `s3d` 行为完全符合 `FR-49`；`ceph/s3-tests` `5b39871` 第 3847-3848 行已提取 `status, error_code = _get_status_and_error_code(e.response)`，但误写 boto2 属性 `e.status` 导致自身崩溃 | M0 |
| `s3tests/functional/test_s3.py::test_bucket_recreate_not_overriding` | `bucket` | P0 | `FR-49` | `AWS_DIVERGENCE` | 同账号重复 `CreateBucket` 返回 `200 OK` | 返回 `409 BucketAlreadyOwnedByYou` | 规格书 `FR-49` 与第 4.3 节明确要求同账号重复创建桶返回 `409 BucketAlreadyOwnedByYou`（对齐非 `us-east-1` 标准区域行为，不覆盖已有对象） | M0 |
| `s3tests/functional/test_s3.py::test_bucket_get_location` | `bucket` | P0 | `GetBucketLocation` | `AWS_DIVERGENCE` | 依赖 Ceph RGW `[s3 main] api_name` 作为非空 `LocationConstraint` 创建并读回 | 未配置 RGW `api_name` 时 `SKIPPED: no api_name configured` | AWS S3 默认区域 `us-east-1` 的 `GetBucketLocation` 返回空 `<LocationConstraint/>`（`None`），且 `CreateBucketConfiguration` 传 `us-east-1` 在真实 AWS 返回 `InvalidLocationConstraint` | M0 |
| `s3tests/functional/test_s3.py::test_bucket_list_prefix_unreadable` | `list_v1` | P0 | `FR-39` | `AWS_DIVERGENCE` | `list_objects(Prefix='\x0a')` 解析后 `response['Prefix'] == '\x0a'` | 按 AWS ListObjects V1 规范在 `encoding-type=url` 下输出 `<EncodingType>url</EncodingType><Prefix>%0A</Prefix>`；`botocore 1.44` 解析为 `'%0A'` | `botocore` 客户端 `set_list_objects_encoding_type_url` 自动注入 `encoding-type=url`，而 `botocore.handlers.decode_list_object` 的 `top_level_keys` 仅解码 `['Delimiter', 'Marker', 'NextMarker']`（漏掉 `'Prefix'`，对比 `decode_list_object_v2` 包含 `'Prefix'` 故 `test_bucket_listv2_prefix_unreadable` 通过）；AWS S3 官方 API 文档明确规定 `encoding-type=url` 时服务端必须对 `<Prefix>` 做 URL 编码 | M1 |
| `s3tests/functional/test_headers.py::test_bucket_create_bad_authorization_empty` | `auth` | P0 | `PR-6` | `AWS_DIVERGENCE` | 在 `before-call` 事件注入空 `Authorization: ''` 后期望 `403 AccessDenied` | 收到 `botocore` 正常签名的合法请求并返回 `200 OK`（若真实线缆发送空 `Authorization` 则 `s3d` 返回 `403 AccessDenied`） | 上游 `test_headers.py:368` 已标 `@pytest.mark.fails_on_rgw` 并注释 `# TODO: once we have learned how to manipulate the authorization header`：`botocore` 在 `before-call` 之后才执行签名器覆盖 `Authorization` 头，导致客户端发出的实际 HTTP 报文是完全合法的 SigV4 请求 | M1 |
| `s3tests/functional/test_headers.py::test_bucket_create_bad_authorization_none` | `auth` | P0 | `PR-6` | `AWS_DIVERGENCE` | 在 `before-call` 事件删除 `Authorization` 后期望 `403 AccessDenied` | 收到 `botocore` 随后重新生成的合法 SigV4 请求并返回 `200 OK`（真实匿名 `CreateBucket` 在 `s3d` 返回 `403 AccessDenied`） | 同上（`test_headers.py:378`，`@pytest.mark.fails_on_rgw`）：`before-call` 触发时尚未签名，`del headers['Authorization']` 为空操作 | M1 |
| `s3tests/functional/test_headers.py::test_object_create_bad_authorization_empty` | `auth` | P0 | `PR-6` | `AWS_DIVERGENCE` | 在 `before-call` 事件注入空 `Authorization: ''` 后期望 `403 AccessDenied` | 收到 `botocore` 随后覆盖签名的合法 `PutObject` 请求并返回 `200 OK` | 同上（`test_headers.py`，`@pytest.mark.fails_on_rgw`）：客户端侧事件钩子挂载时机早于 `botocore` 签名器 | M1 |
| `s3tests/functional/test_headers.py::test_object_create_bad_authorization_none` | `auth` | P0 | `PR-6` | `AWS_DIVERGENCE` | 在 `before-call` 事件删除 `Authorization` 后期望 `403 AccessDenied` | 收到 `botocore` 随后生成的合法签名 `PutObject` 请求并返回 `200 OK` | 同上（`test_headers.py`，`@pytest.mark.fails_on_rgw`）：客户端侧事件钩子挂载时机早于 `botocore` 签名器 | M1 |
| `s3tests/functional/test_headers.py::test_object_create_bad_contentlength_none` | `auth` | P0 | `PR-13` | `AWS_DIVERGENCE` | 在 `before-call` 事件删除 `Content-Length` 后期望 `411 MissingContentLength` | `urllib3` 底层发送时自动补齐真实 `Content-Length`，服务端收到合法报文返回 `200 OK`（真实无 `Content-Length` 且非 chunked 的 `PutObject` 在 `s3d` 返回 `411 MissingContentLength`） | 同上（`test_headers.py`，`@pytest.mark.fails_on_rgw` 注释 `# TODO: once we have learned how to remove the content-length header`）：`botocore`/`urllib3` 在序列化阶段自动计算并填充 `Content-Length` | M1 |

---

## 3. 已消除的历史延后项记录

| 用例全名 (`file::test_func`) | 引入里程碑 | 消除里程碑 | 解决说明 |
| --- | --- | --- | --- |
| `s3tests/functional/test_s3.py::test_get_object_attributes` | M0 | **M1** | 实现 `GET /{b}/{k}?attributes`（`GetObjectAttributes`）后通过 |
| `s3tests/functional/test_s3.py::test_get_checksum_object_attributes` | M0 | **M1** | 实现全套 P0 校验和与 `GetObjectAttributes` 后通过 |
| `s3tests/functional/test_s3.py::test_expected_bucket_owner` | M0 | **M1** | 实现桶/对象 `?acl` 与 `x-amz-expected-bucket-owner` 校验后通过 |
| `s3tests/functional/test_s3.py::test_bucket_create_special_key_names` | M0 | **M1** | 实现对象 `?acl` 后通过 |
