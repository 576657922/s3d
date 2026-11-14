# s3d — クラッシュセーフなシングルノード S3 互換オブジェクトストレージ

[简体中文](README.zh-CN.md) | [English](README.en.md) | **日本語**

`s3d` は、安全な Rust（Edition 2024、`unsafe_code = "forbid"`）でゼロから実装した、クラッシュセーフなシングルノード S3 互換オブジェクトストレージサーバーです。独自のログ構造化ストレージエンジン（追記専用セグメントファイル + WAL グループコミット + アトミックなチェックポイント + ロックフリーなスナップショット読み取り + バックグラウンドのコンパクション GC）と、10 層の形式的・自動検証スイート（`VR-1`〜`VR-10`）を備えています。

- **互換性ベースライン**：[`ceph/s3-tests`](https://github.com/ceph/s3-tests)（コミット `5b39871`）のシングルノード対象 **545** ケース中 **526 / 545（96.5%）** が合格しています。内訳は P0 `240/249`、P1 `182/190`、P2 `104/106`（`object_lock` 39/39、`lifecycle` 20/20、`encryption` 41/41、`logging` 4/6）です。未実装による先送りは `0` 件で、残りの 19 件はいずれも上流クライアントまたは仕様との相違であり、パケットキャプチャやソースコード調査で 1 件ずつ根拠を示しています（[`docs/deviations.md`](docs/deviations.md) と [`reports/p0-ceiling-proof.json`](reports/p0-ceiling-proof.json) を参照）。
- **外部ストレージエンジン不使用**：RocksDB、sled、redb、SQLite、LMDB などの既製キーバリューストアは一切使用していません。ワークスペース内で安全でないコードは、`crates/s3d-disk/src/os.rs` にある 2 つの POSIX FFI ラッパー（`statvfs` と `F_NOCACHE`/`posix_fadvise`）のみで、Miri と静的 CI ゲートで監査しています。

---

## 実測パフォーマンスと検証結果（`Linux x86-64, 2 vCPU, 7 GB RAM`）

300 秒間のベンチマーク全データは [`reports/linux-x86_64-bench.json`](reports/linux-x86_64-bench.json) に保存しています（比較用の Apple Silicon ネイティブ結果：[`reports/m3-bench.json`](reports/m3-bench.json)）。

| 指標 | シナリオ | 仕様の基準値 | `Linux x86-64 (2 vCPU, 7 GB)` での実測値 | 結果 |
| --- | --- | --- | --- | --- |
| **`NFR-1`** | 4 KiB `PutObject`（並列 32、300 秒、グループコミットで永続化） | `≥ 1,000 ops/s` かつ `p99 ≤ 50 ms` | **`3,049.2 ops/s`**、`p50 = 4.05 ms`、**`p99 = 41.11 ms`** | PASS |
| **`NFR-2`** | 4 KiB `GetObject`（並列 32、300 秒） | `≥ 5,000 ops/s` かつ `p99 ≤ 10 ms` | **`31,669.1 ops/s`**、`p50 = 0.91 ms`、**`p99 = 3.58 ms`** | PASS |
| **`NFR-3`** | 1 GiB シングルストリーム `PutObject` / `GetObject`（`fio --direct=1` による生ディスク `308.8 / 350.2 MiB/s` と比較） | PUT は生ディスクの `≥ 70%`、GET は `≥ 80%` | PUT **`334.5 MiB/s`（`108.3%`）**、GET **`1,374.9 MiB/s`（`392.6%`）** | PASS |
| **`NFR-4`** | 100 万オブジェクトのバケットに対するランダム `start-after` の `ListObjectsV2`（1 ページ 1,000 キー、1,000 回） | `p99 ≤ 20 ms` | `p50 = 1.18 ms`、**`p99 = 1.50 ms`** | PASS |
| **`NFR-5`** | 常駐メモリ（アイドル時 / `10 GiB` ストリーミングマルチパートアップロード中のピーク `VmRSS`） | アイドル `≤ 64 MiB`、ピーク `≤ 66 MiB` | アイドル **`11.18 MiB`**、`10 GiB` アップロード時ピーク **`25.52 MiB`** | PASS |
| **`NFR-6`** | 100 万オブジェクトバージョン（チェックポイント 95 万 + WAL 5 万）で `SIGKILL` 後、`/health 200` までのコールドリカバリ | `≤ 20 s` | **`1.204 s`**（オフライン `s3d fsck` のエラー `0` 件） | PASS |

10 層の検証ゲート（`VR-1`〜`VR-10`）の記録：
- **`VR-1` / `VR-2`**：`s3d-model` は全 63 操作を網羅し、`FR` 注釈は `51/51`（ワークスペース全体で仕様の要件 ID `119/119` を機械的に追跡可能）。`proptest` による P0+P1+P2 のランダム操作列 **100,000** 件をエンジンと差分比較し、差異 `0` 件。
- **`VR-3`**：`FaultDisk` により 4 KiB セクタ単位でシステムコール途中の電源断を **100,000** 回注入（チェックポイント、WAL の削除、GC、複数セグメントにまたがるマルチパートアップロードを含む）し、違反 `0` 件。
- **`VR-4`**：`Loom` による全インターリーブ探索 + `Shuttle` のランダムスケジュール **10,000** 回 + `s3d-check` による HTTP レベルの WGL 線形化可能性検査（キーごとの履歴 **10,000** 件、16 クライアント、署名付きリクエスト 240,000 件）で違反 `0` 件。
- **`VR-5` / `VR-6` / `VR-8`**：`Linux x86-64` と `macOS ARM64` の両方で `ceph/s3-tests` 全件 **526 / 545** 合格（[`linux-x86_64-junit.xml`](reports/linux-x86_64-junit.xml)、[`m4-junit.xml`](reports/m4-junit.xml)）。`boto3 1.44` + `awscli v1` による 1 GiB マルチパートのエンドツーエンド SHA-256 検証に合格。SigV4 の差分・改ざんテスト **10,000** グループ（判定 30,000 回）で誤判定 `0` 件。
- **`VR-7` / `VR-10`**：`cargo-fuzz`（`LLVM libFuzzer` + `SanitizerCoverage` + `AddressSanitizer`）の 8 ターゲットを**各 1 時間（`3,606〜3,609 秒`）**実行し、カバレッジ誘導の実行 **323,360,642** 回でクラッシュ `0` 件（[`vr7-cargo-fuzz-report.json`](reports/vr7-cargo-fuzz-report.json)）。`cargo +nightly miri test --workspace --lib` で UB `0` 件 / リーク `0` 件。

---

## 機能一覧

| レベル | 対応機能 |
| --- | --- |
| **P0 コア** | バケット CRUD、パス形式・仮想ホスト形式のアドレッシング、ストリーミングによるオブジェクトの `PUT`/`GET`/`HEAD`/`DELETE`、Range 読み取り、条件付き読み取り・書き込み・削除（`If-Match` / `If-None-Match` / 時刻条件。コミット時点でアトミックに評価）、`CopyObject`、マルチパートアップロード一式（`Create`/`UploadPart`/`UploadPartCopy`/`Complete`/`Abort`/`ListParts`/`ListMultipartUploads`）、`ListObjects` V1 と `ListObjectsV2`（HMAC による改ざん防止カーソル）、一括 `DeleteObjects`、`GetObjectAttributes`、SigV4 ヘッダー認証と署名付き URL、`aws-chunked` ストリーミング署名とトレーラーチェックサム |
| **P1 マルチテナント・バージョニング** | バージョニング（`Enabled`/`Suspended`、削除マーカー、`ListObjectVersions`）、バケット/オブジェクトのタグ（`?tagging`）、Object Ownership（`BucketOwnerEnforced`/`ObjectWriter`/`BucketOwnerPreferred`）、ACL（Canned ACL / Grant ヘッダー / XML）、IAM バケットポリシー（`ExplicitDeny > Allow > ACL`、`PublicAccessBlock`、`?policyStatus`）、CORS と `OPTIONS` プリフライト、ブラウザフォームによる `PostObject` |
| **P2 エンタープライズ・セキュリティ** | オブジェクトロック WORM（`Governance`/`Compliance` の保持期間、`LegalHold`、`x-amz-bypass-governance-retention`）、ライフサイクルによる期限切れのバックグラウンド削除（`?lifecycle`、`x-amz-expiration`）、サーバー側暗号化（`?encryption` によるデフォルト暗号化、`SSE-S3`、シーク可能なストリーミング AES-256-CTR による `SSE-C`。顧客キーを平文で保存しない）、バケットロギング設定（`?logging`）、ネイティブ TLS 1.2/1.3（`tokio-rustls`）、全 **10 種類のチェックサムアルゴリズム**（`CRC32`、`CRC32C`、`CRC64NVME`、`SHA1`、`SHA256`、`MD5`、`SHA512`、`XXHASH64`、`XXHASH3`、`XXHASH128`） |
| **運用・可観測性** | 独立した管理ポートでの `/health` と `/metrics`（Prometheus テキスト形式）、構造化 JSON リクエストログ（キー・署名はマスク）、`SIGTERM` による 30 秒のドレイン付きグレースフルシャットダウン、ディスク残量不足時の `503 SlowDown` 保護、オフライン完全整合性チェック `s3d fsck`、手動/バックグラウンドのセグメントコンパクション `s3d compact` |

---

## ディレクトリ構成

```text
crates/
  s3d-types/    ドメイン型、エラーコード、ObjectStore トレイト、ストリーミングダイジェストのインターフェース
  s3d-disk/     ディスク抽象化層：本番用 OsDisk と、障害・電源断を注入する FaultDisk
  s3d-model/    純粋なインメモリ実行可能リファレンスモデル（VR-1。全 63 操作、FR-1..FR-51 注釈付き）
  s3d-engine/   ログ構造化ストレージエンジン（セグメント、WAL グループコミット、チェックポイント、GC、fsck）
  s3d-proto/    S3 HTTP/XML コーデック、SigV4 検証、aws-chunked、Policy/CORS/PostObject
  s3d-server/   HTTP/HTTPS サーバー、過負荷保護、設定読み込み、`s3d` CLI バイナリ
  s3d-check/    HTTP レベルのキー単位並行負荷生成と WGL（Wing & Gong / Lowe）線形化可能性チェッカー（VR-4）
  s3d-bench/    エンドツーエンドの受け入れベンチマーク：スループット、メモリ、100 万オブジェクトの一覧、kill -9 後のコールドリカバリ（VR-9）
  s3d-fuzz/     構造化ファジングのコアとコーパス回帰ドライバ（fuzz/ 配下の libFuzzer 8 ターゲットで使用、VR-7）
docs/
  01-architecture.md      全体アーキテクチャと境界の契約
  02-storage-engine.md    ディスク上のフォーマット、WAL/チェックポイント、クラッシュリカバリ、並行性プロトコル
  03-protocol-and-api.md  S3 プロトコルスタック、SigV4、エラーコード、P0/P1/P2 操作の対応表
  04-verification.md      10 層検証スイート（VR-1..VR-10）の設計
  05-roadmap.md           マイルストーンの納品記録と Q1..Q6 の解決台帳
  deviations.md           ceph/s3-tests 相違点の登録表（ゲート G1 で検査）
scripts/
  ci_gate.sh              ローカル/CI 用のワンショット・ブロッキングゲート（G4）
  run_s3tests_gate.py     s3-tests の起動・実行・オフライン fsck チェックを自己完結で行うランナー（VR-5）
  vr6_real_clients.py     boto3 1.44 + awscli v1 + 1 GiB マルチパートのエンドツーエンド受け入れテスト（VR-6）
  run_libfuzzer_gate.py   8 ターゲット並列の cargo-fuzz (libFuzzer) ゲート（VR-7）
  verify_fr_traceability.py 要件 ID の 100% 追跡可能性スキャナ（VR-1）
  verify_p0_ceiling.py    P0 上限のパケットキャプチャ・ソースレベルでの証明（G1）
```

---

## クイックスタート

### 1. ビルド

Rust `1.85+` が必要です（最新の `stable`、Edition 2024 を推奨）：

```bash
cargo build --release -p s3d-server --bin s3d
```

### 2. アカウントとサーバーの設定

パーミッション `0600` の認証情報ファイル `credentials.toml` を作成します（パーミッションが緩すぎると `s3d` は起動を拒否します）：

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

任意の設定ファイル `s3d.toml` を作成します（未知のフィールドはエラーとして拒否されます。主要な項目はすべて CLI 引数で上書き可能です）：

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
# ネイティブ HTTPS (TLS 1.2 / 1.3) を有効にするには、次の 2 項目を両方設定します：
# tls_cert_file = "./cert.pem"
# tls_key_file  = "./key.pem"
```

### 3. 起動と運用

```bash
# S3 サービスを起動（S3 はポート 8000、管理ポート 9000 で /health と /metrics を提供）
./target/release/s3d serve --config s3d.toml

# awscli で操作
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE \
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY \
aws --endpoint-url http://127.0.0.1:8000 --region us-east-1 s3 mb s3://my-bucket

# オフライン完全整合性チェック（サーバー停止中に FORMAT、チェックポイント、WAL、全セグメントブロックの CRC32C を検証）
./target/release/s3d fsck --data-dir ./data

# セグメントコンパクションを手動で実行
./target/release/s3d compact --data-dir ./data --gc-live-ratio 0.5
```

---

## 検証ゲートの実行

```bash
# PR ブロッキングゲートを一括実行（unsafe・禁止依存の監査 + FR 追跡 + clippy + release テスト + Miri + VR-6 + s3-tests P0）
bash scripts/ci_gate.sh

# ceph/s3-tests 全 545 ケースのゲートとラチェット方式の回帰チェック
.venv/bin/python scripts/run_s3tests_gate.py --select ALL --junitxml reports/m4-junit.xml
.venv/bin/python scripts/check_junit.py reports/m4-junit.xml --min-passed 526

# VR-9 パフォーマンスとコールドリカバリの全ベンチマーク（NFR-1..NFR-6 + fio ベースライン + fsck）
cargo build --release -p s3d-server -p s3d-bench
./target/release/s3d-bench --s3d-bin ./target/release/s3d --put-get-secs 300 --report reports/m3-bench.json

# 標準の Linux x86-64 (2 vCPU, 7 GB RAM) 受け入れコンテナで再現
docker build --platform=linux/amd64 -f Dockerfile.linux-accept -t s3d-linux-accept:latest .
```

---

## ライセンス

Apache-2.0
