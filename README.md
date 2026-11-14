# s3d

[简体中文](README.zh-CN.md) | [English](README.en.md) | **日本語**

[![CI](https://github.com/576657922/s3d/actions/workflows/ci.yml/badge.svg?branch=main&event=push)](https://github.com/576657922/s3d/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

単一ノードで動く S3 互換のオブジェクトストレージです。Rust で書いていて、ストレージエンジン（追記型のセグメントファイル + WAL）も自作しています。RocksDB などの既存のキーバリューストアは使っていません。

目標は「プロセスが落ちても電源が切れても、成功を返した書き込みは失わない」ことです。この性質を、電源断を模擬するディスク層での大量のテストや、参照モデルとの差分テストで確かめています。

> **ステータス**：個人の実験的なプロジェクトです。本番環境での運用実績はないので、大切なデータの保存には使わないでください。

## 特徴

- **S3 互換**：[ceph/s3-tests](https://github.com/ceph/s3-tests) の全 808 件から、AWS 本家でも失敗するケース（`fails_on_aws`）と KMS・マルチテナント・SigV2 など対象外の機能を除いた 545 件のうち、526 件に合格しています（除外の内訳は [tests/s3tests-manifest.json](tests/s3tests-manifest.json)、不合格 19 件の理由は [docs/deviations.md](docs/deviations.md)）。awscli や boto3 からそのまま使えます。
- **クラッシュ安全**：電源断を 4 KiB セクタ単位で模擬して 10 万回注入し、成功済みの書き込みが失われないことを確認しています。
- **省メモリ・高速な復旧**：アイドル時のメモリは 11 MiB、10 GiB のアップロード中でもピーク 26 MiB。100 万バージョンを抱えた状態で強制終了しても、1.2 秒で応答を再開します（ローカル計測）。
- **単一バイナリ**：外部のデータベースやサービスは不要です。
- **主な機能**：マルチパートアップロード、バージョニング、バケットポリシーと ACL、オブジェクトロック、ライフサイクル、サーバー側暗号化（SSE-S3 / SSE-C）、TLS など。一覧は[対応機能](#対応機能)。

## 位置づけ

S3 互換ストレージには MinIO、Garage、SeaweedFS、RustFS など実績のある実装があります。s3d は機能の数や分散構成でそれらと競うものではありません。対象を単一ノードに絞り、「落ちても失わない」ことをどこまでテストで裏付けられるかに焦点を当てています。

## クイックスタート

Rust 1.85 以上が必要です。

```bash
# 1. ビルド
cargo build --release -p s3d-server --bin s3d

# 2. 認証情報を作成（パーミッションが 0600 でないと起動を拒否します）
cat > credentials.toml <<'EOF'
[[accounts]]
user_id = "0123456789abcdef"
display_name = "demo"
email = "demo@example.com"
access_key = "AKIAIOSFODNN7EXAMPLE"
secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
EOF
chmod 600 credentials.toml

# 3. 起動（S3 はポート 8000、/health と /metrics は管理用のポート 9000）
./target/release/s3d serve --listen 127.0.0.1:8000 --admin-listen 127.0.0.1:9000 \
  --data-dir ./data --credentials-file ./credentials.toml

# 4. 別のターミナルから awscli で操作
export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
aws --endpoint-url http://127.0.0.1:8000 --region us-east-1 s3 mb s3://my-bucket
aws --endpoint-url http://127.0.0.1:8000 --region us-east-1 s3 cp ./README.md s3://my-bucket/
```

設定ファイル、TLS、運用コマンドは[設定と運用](#設定と運用)を参照してください。

## 仕組み

`PutObject` の流れ：

```mermaid
sequenceDiagram
    participant C as クライアント
    participant S as s3d
    participant Seg as セグメントファイル
    participant W as WAL
    C->>S: PUT（本文をストリーミング）
    S->>Seg: データを追記
    S->>S: チェックサムを検証
    S->>Seg: fdatasync（同時に来た書き込みとまとめて 1 回）
    S->>W: メタデータを追記して fdatasync（ここがコミット点）
    S->>S: メモリ上の索引を更新
    S-->>C: 200 OK
```

- **書き込み**：本文はセグメントファイルに追記し、メタデータを WAL に記録して `fdatasync` した時点で確定します。同時に届いた書き込みは 1 回の `fdatasync` にまとめます（グループコミット）。
- **再起動時の復旧**：最新のチェックポイントを読み込み、それ以降の WAL を再生します。末尾の書きかけのレコードは切り捨て、途中が壊れていれば起動を中止します。
- **読み取りと GC**：読み取り中のセグメントは参照カウントで保護し、不要領域の回収（GC）が使用中のファイルを消さないようにしています。
- **fsync の失敗**：`fsync` がエラーを返したら、それ以降は読み取り専用に切り替えて書き込みを受け付けません。エラー後のディスク上の状態は保証できないためです。

詳細は [docs/02-storage-engine.md](docs/02-storage-engine.md) にあります。

## 検証

| 確かめること | 方法 | 規模 | 実行タイミング |
| --- | --- | --- | --- |
| 仕様どおりに動くか | インメモリの参照モデルとランダムな操作列で結果を比較（proptest） | 100 万操作列 | 毎晩（PR では 1 万） |
| 電源断で失わないか | FaultDisk：未同期の書き込みを 4 KiB セクタ単位で欠落・並べ替え、未同期のディレクトリ変更を欠落させてから再起動 | 10 万回 | 毎晩（PR では 1,000 回） |
| 並行処理 | Loom（セグメント解放とグループコミットの手順を、テスト内の簡略化したモデルで全探索）、Shuttle（実エンジンでのランダムなスケジュール）、HTTP 経由の線形化可能性チェック（WGL） | Shuttle 1 万スケジュール、WGL 1 万履歴 | 毎晩 |
| S3 互換性 | ceph/s3-tests | 545 件中 526 件合格 | 毎晩（PR では P0 の 249 件中 240 件以上） |
| 実際のクライアント | boto3 と awscli で 1 GiB のマルチパートアップロードと SHA-256 照合 | 1 GiB | PR ごと |
| SigV4 署名 | botocore の署名との差分テストと改ざん検出 | 1 万組 | PR ごと |
| 入力処理の堅牢性 | cargo-fuzz（libFuzzer + AddressSanitizer）8 ターゲット | 各 1 時間 | 毎晩 |
| 未定義動作 | Miri | ライブラリのテスト全体 | PR ごと |

CI の実行結果は [GitHub Actions](https://github.com/576657922/s3d/actions/workflows/ci.yml) で確認できます。各テストの設計は [docs/04-verification.md](docs/04-verification.md)、ローカルでの実行記録は [reports/](reports/) にあります。

`unsafe` を使っているのは `crates/s3d-disk/src/os.rs` の 2 つの関数（`statvfs` と `F_NOCACHE` / `posix_fadvise` の呼び出し）だけです。それ以外のクレートは `unsafe_code = "forbid"` でコンパイルしています。

## 性能（ローカル計測）

Linux x86-64、2 vCPU、7 GB RAM で計測しました。生データは [reports/linux-x86_64-bench.json](reports/linux-x86_64-bench.json) にあります。

| シナリオ | 結果 |
| --- | --- |
| 4 KiB の PUT、並列 32、300 秒（応答前にディスクへ永続化） | 3,049 ops/s、p50 4.0 ms、p99 41 ms |
| 4 KiB の GET、並列 32、300 秒 | 31,669 ops/s、p50 0.9 ms、p99 3.6 ms |
| 1 GiB の PUT / GET（単一ストリーム） | PUT 334 MiB/s、GET 1,375 MiB/s（※） |
| 100 万オブジェクトのバケットで ListObjectsV2（1 ページ 1,000 キー、開始位置はランダム） | p50 1.2 ms、p99 1.5 ms |
| メモリ（RSS） | アイドル 11 MiB、10 GiB のアップロード中のピーク 26 MiB |
| 100 万バージョンを持つ状態で SIGKILL → 再起動して応答するまで | 1.2 秒（その後の `s3d fsck` でエラー 0） |

※ GET はページキャッシュに載った状態の値で、ディスクの読み取り速度ではありません。同じマシンで `fio --direct=1` を使ったディスク単体の速度は、書き込み 309 MiB/s、読み取り 350 MiB/s でした。

## 既知の課題

- 4 KiB PUT のベンチマークで、最大レイテンシが 33 秒になる外れ値が出ています（p99 は 41 ms）。原因はまだ調べていません。

## 設定と運用

設定ファイル `s3d.toml` は任意です。未知のフィールドはエラーとして拒否され、主な項目は CLI 引数で上書きできます。

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

```bash
# 設定ファイルを使って起動
./target/release/s3d serve --config s3d.toml

# オフラインの完全整合性チェック（サーバー停止中に FORMAT、チェックポイント、WAL、全セグメントブロックの CRC32C を検証）
./target/release/s3d fsck --data-dir ./data

# セグメントのコンパクションを手動で実行
./target/release/s3d compact --data-dir ./data --gc-live-ratio 0.5
```

## 対応機能

| レベル | 対応機能 |
| --- | --- |
| **P0 コア** | バケット CRUD、パス形式・仮想ホスト形式のアドレッシング、ストリーミングによるオブジェクトの `PUT`/`GET`/`HEAD`/`DELETE`、Range 読み取り、条件付き読み取り・書き込み・削除（`If-Match` / `If-None-Match` / 時刻条件。コミット時点でアトミックに評価）、`CopyObject`、マルチパートアップロード一式（`Create`/`UploadPart`/`UploadPartCopy`/`Complete`/`Abort`/`ListParts`/`ListMultipartUploads`）、`ListObjects` V1 と `ListObjectsV2`（HMAC による改ざん防止カーソル）、一括 `DeleteObjects`、`GetObjectAttributes`、SigV4 ヘッダー認証と署名付き URL、`aws-chunked` ストリーミング署名とトレーラーチェックサム |
| **P1 マルチテナント・バージョニング** | バージョニング（`Enabled`/`Suspended`、削除マーカー、`ListObjectVersions`）、バケット/オブジェクトのタグ（`?tagging`）、Object Ownership（`BucketOwnerEnforced`/`ObjectWriter`/`BucketOwnerPreferred`）、ACL（Canned ACL / Grant ヘッダー / XML）、IAM バケットポリシー（`ExplicitDeny > Allow > ACL`、`PublicAccessBlock`、`?policyStatus`）、CORS と `OPTIONS` プリフライト、ブラウザフォームによる `PostObject` |
| **P2 エンタープライズ・セキュリティ** | オブジェクトロック WORM（`Governance`/`Compliance` の保持期間、`LegalHold`、`x-amz-bypass-governance-retention`）、ライフサイクルによる期限切れのバックグラウンド削除（`?lifecycle`、`x-amz-expiration`）、サーバー側暗号化（`?encryption` によるデフォルト暗号化、`SSE-S3`、シーク可能なストリーミング AES-256-CTR による `SSE-C`。顧客キーを平文で保存しない）、バケットロギング設定（`?logging`）、ネイティブ TLS 1.2/1.3（`tokio-rustls`）、全 **10 種類のチェックサムアルゴリズム**（`CRC32`、`CRC32C`、`CRC64NVME`、`SHA1`、`SHA256`、`MD5`、`SHA512`、`XXHASH64`、`XXHASH3`、`XXHASH128`） |
| **運用・可観測性** | 独立した管理ポートでの `/health` と `/metrics`（Prometheus テキスト形式）、構造化 JSON リクエストログ（キー・署名はマスク）、`SIGTERM` による 30 秒のドレイン付きグレースフルシャットダウン、ディスク残量不足時の `503 SlowDown` 保護、オフライン完全整合性チェック `s3d fsck`、手動/バックグラウンドのセグメントコンパクション `s3d compact` |

## ディレクトリ構成

```text
crates/
  s3d-types/    ドメイン型、エラーコード、ObjectStore トレイト、ストリーミングダイジェストのインターフェース
  s3d-disk/     ディスク抽象化層：本番用 OsDisk と、障害・電源断を注入する FaultDisk
  s3d-model/    インメモリで動く参照モデル（VR-1。全 63 操作、FR-1..FR-51 注釈付き）
  s3d-engine/   ログ構造化ストレージエンジン（セグメント、WAL グループコミット、チェックポイント、GC、fsck）
  s3d-proto/    S3 HTTP/XML コーデック、SigV4 検証、aws-chunked、Policy/CORS/PostObject
  s3d-server/   HTTP/HTTPS サーバー、過負荷保護、設定読み込み、`s3d` CLI バイナリ
  s3d-check/    HTTP レベルのキー単位並行負荷生成と WGL（Wing & Gong / Lowe）線形化可能性チェッカー（VR-4）
  s3d-bench/    エンドツーエンドのベンチマーク：スループット、メモリ、100 万オブジェクトの一覧、kill -9 後のコールドリカバリ（VR-9）
  s3d-fuzz/     構造化ファジングのコアとコーパス回帰ドライバ（fuzz/ 配下の libFuzzer 8 ターゲットで使用、VR-7）
docs/
  00-requirements.md      要件定義書（中国語）
  01-architecture.md      全体アーキテクチャと境界の契約
  02-storage-engine.md    ディスク上のフォーマット、WAL/チェックポイント、クラッシュリカバリ、並行性プロトコル
  03-protocol-and-api.md  S3 プロトコルスタック、SigV4、エラーコード、P0/P1/P2 操作の対応表
  04-verification.md      10 層のテスト（VR-1..VR-10）の設計
  05-roadmap.md           マイルストーンの記録と Q1..Q6 の解決台帳
  deviations.md           ceph/s3-tests の不合格ケースとその理由
scripts/
  ci_gate.sh              ローカル/CI 用のブロッキングゲートを一括実行
  run_s3tests_gate.py     s3d の起動、s3-tests の実行、終了後の fsck までを行うランナー（VR-5）
  vr6_real_clients.py     boto3 + awscli + 1 GiB マルチパートのエンドツーエンドテスト（VR-6）
  run_libfuzzer_gate.py   8 ターゲット並列の cargo-fuzz (libFuzzer) ゲート（VR-7）
  verify_fr_traceability.py 要件 ID がコードに対応付いているかのスキャナ（VR-1）
  verify_p0_ceiling.py    P0 の不合格ケースの根拠チェック（G1）
```

## テストをローカルで実行する

```bash
# PR ブロッキングゲートを一括実行（unsafe・禁止依存の監査 + 要件 ID の追跡 + clippy + release テスト + Miri + 実クライアント + s3-tests P0）
bash scripts/ci_gate.sh

# ceph/s3-tests の対象 545 件と、合格数が後退していないかのチェック
.venv/bin/python scripts/run_s3tests_gate.py --select ALL --junitxml reports/m4-junit.xml
.venv/bin/python scripts/check_junit.py reports/m4-junit.xml --min-passed 526

# 性能とコールドリカバリのベンチマーク（fio のベースラインと fsck を含む）
cargo build --release -p s3d-server -p s3d-bench
./target/release/s3d-bench --s3d-bin ./target/release/s3d --put-get-secs 300 --report reports/m3-bench.json

# Linux x86-64 (2 vCPU, 7 GB RAM) のコンテナで再現
docker build --platform=linux/amd64 -f Dockerfile.linux-accept -t s3d-linux-accept:latest .
```

## ライセンス

[Apache-2.0](LICENSE)
