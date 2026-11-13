#!/usr/bin/env bash
# G4 Local & CI Blocking Regression Gate (VR-1..VR-3, VR-5, VR-6, VR-8, VR-10)
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
export PATH="$HOME/.cargo/bin:$PATH"

echo "=== [1/7] VR-10 Static Unsafe & Forbidden Crate Audit ==="
# Only crates/s3d-disk/src/os.rs may contain #[allow(unsafe_code)]
UNSAFE_FILES="$(grep -rn "allow(unsafe_code)" crates/ | cut -d: -f1 | sort -u)"
if [ "$UNSAFE_FILES" != "crates/s3d-disk/src/os.rs" ]; then
  echo "ERROR: Unexpected #[allow(unsafe_code)] outside crates/s3d-disk/src/os.rs: $UNSAFE_FILES" >&2
  exit 1
fi
for banned in rocksdb sled redb rusqlite sqlite lmdb heed; do
  if grep -qiE "^${banned}\b" Cargo.toml crates/*/Cargo.toml; then
    echo "ERROR: Forbidden embedded database dependency detected: $banned" >&2
    exit 1
  fi
done

echo "=== [2/7] VR-1 Requirement Traceability Check (51/51 FR + 119/119 Spec IDs) ==="
python3 scripts/verify_fr_traceability.py

echo "=== [3/7] Workspace Clippy (-D warnings) ==="
cargo clippy --workspace --all-targets -- -D warnings

echo "=== [4/7] Release Workspace Test Suite (VR-2 10k, VR-3 1k, VR-8 10k, P2 TLS/Checksums) ==="
cargo test --release --workspace
cargo build --release -p s3d-server --bin s3d

echo "=== [5/7] VR-10 Miri Undefined Behavior Check ==="
MIRIFLAGS="-Zmiri-disable-isolation" cargo +nightly miri test --workspace --lib

echo "=== [6/7] VR-6 Real S3 Clients (boto3 1.44 + awscli v1 + 1 GiB Multipart SHA-256 + fsck) ==="
if [ -x ".venv/bin/python" ]; then
  PY=".venv/bin/python"
else
  PY="python3"
fi
"$PY" scripts/vr6_real_clients.py

echo "=== [7/7] VR-5 / G4 s3-tests P0 Regression Gate + P0 Ceiling Proof ==="
"$PY" scripts/run_s3tests_gate.py --select P0 --junitxml reports/ci-p0-junit.xml
"$PY" scripts/check_junit.py \
  reports/ci-p0-junit.xml \
  --baseline tests/s3tests-passed.txt \
  --deviations docs/deviations.md \
  --min-passed 240
"$PY" scripts/verify_p0_ceiling.py

echo "=== ALL CI BLOCKING GATES PASSED ==="
