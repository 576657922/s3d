#!/usr/bin/env python3
"""Self-contained s3-tests runner for s3d milestone gates (`VR-5`).

Starts release `s3d` on 127.0.0.1:28080 with all 6 accounts from `tests/s3test.conf`
and `default_object_ownership = "ObjectWriter"` (per FR-51 / Q2), runs the selected
`ceph/s3-tests` subset, stops `s3d` via SIGTERM, and runs `s3d fsck` verifying 0 errors.
"""

from __future__ import annotations

import argparse
import os
import signal
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

CREDENTIALS_TOML = """\
[[accounts]]
user_id = "testid"
display_name = "M. Tester"
email = "tester@ceph.com"
access_key = "0555b35654ad1656d804"
secret_key = "h7GhxuBLTrlhVUyxSPUKUV8r/2EI4ngqJxD7iBdBYLhwluN30JaT3Q=="

[[accounts]]
user_id = "56789abcdef0123456789abcdef0123456789abcdef0123456789abcdef01234"
display_name = "john.doe"
email = "john.doe@example.com"
access_key = "NOPQRSTUVWXYZABCDEFG"
secret_key = "nopqrstuvwxyzabcdefghijklmnabcdefghijklm"

[[accounts]]
user_id = "9876543210abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
display_name = "testx$tenanteduser"
email = "tenanteduser@example.com"
access_key = "HIJKLMNOPQRSTUVWXYZA"
secret_key = "opqrstuvwxyzabcdefghijklmnopqrstuvwxyzab"

[[accounts]]
user_id = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
display_name = "youruseridhere"
email = "s3@example.com"
access_key = "ABCDEFGHIJKLMNOPQRST"
secret_key = "abcdefghijklmnopqrstuvwxyzabcdefghijklmn"

[[accounts]]
user_id = "RGW11111111111111111"
display_name = "account1"
email = "account1@ceph.com"
access_key = "AAAAAAAAAAAAAAAAAAaa"
secret_key = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

[[accounts]]
user_id = "RGW22222222222222222"
display_name = "account2"
email = "account2@ceph.com"
access_key = "BBBBBBBBBBBBBBBBBBbb"
secret_key = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
"""


def wait_health(url: str, timeout_s: float = 10.0) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=1.0) as resp:
                if resp.status == 200:
                    return
        except Exception:
            time.sleep(0.1)
    raise RuntimeError(f"s3d failed to become healthy at {url}")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--select", default="M2", help="Selector passed to classify_s3tests.py (e.g. P1, M2, ALL) or explicit pytest nodeid")
    ap.add_argument("--nodeids", nargs="*", help="Explicit pytest nodeids instead of --select")
    ap.add_argument("--junitxml", type=Path, default=None)
    args = ap.parse_args()

    s3d_bin = Path(os.environ.get("S3D_BIN", str(ROOT / "target" / "release" / "s3d")))
    if not s3d_bin.exists():
        print(f"Missing release binary: {s3d_bin}", file=sys.stderr)
        return 2

    if args.nodeids:
        nodes = args.nodeids
    else:
        out = subprocess.check_output(
            [sys.executable, str(ROOT / "scripts" / "classify_s3tests.py"), "--select", args.select],
            text=True,
        )
        nodes = [ln.strip() for ln in out.splitlines() if ln.strip()]

    print(f"Selected {len(nodes)} test functions ({args.select if not args.nodeids else 'explicit'})")

    with tempfile.TemporaryDirectory(prefix="s3d-gate-") as tmp:
        tmp_path = Path(tmp)
        data_dir = tmp_path / "data"
        cred_path = tmp_path / "credentials.toml"
        cred_path.write_text(CREDENTIALS_TOML, encoding="utf-8")
        os.chmod(cred_path, 0o600)

        log_file = (tmp_path / "s3d.log").open("w", encoding="utf-8")
        srv = subprocess.Popen(
            [
                str(s3d_bin),
                "serve",
                "--listen",
                "127.0.0.1:28080",
                "--admin-listen",
                "127.0.0.1:29090",
                "--data-dir",
                str(data_dir),
                "--credentials-file",
                str(cred_path),
                "--region",
                "us-east-1",
                "--default-object-ownership",
                "ObjectWriter",
                "--lc-debug-interval",
                "2",
                "--log-format",
                "json",
            ],
            stdout=log_file,
            stderr=subprocess.STDOUT,
        )
        try:
            wait_health("http://127.0.0.1:29090/health")
            pytest_args = [
                "-q",
                "-o",
                "junit_family=xunit2",
                "-m",
                "not fails_on_aws and not auth_aws2 and not iam_account and not iam_user and not cloud_transition and not cloud_restore and not lifecycle_transition",
                "-k",
                "not tenant and not kms and not transition and not torrent",
            ]
            if args.junitxml:
                args.junitxml.parent.mkdir(parents=True, exist_ok=True)
                pytest_args.append(f"--junitxml={args.junitxml.resolve()}")
            pytest_args.extend(nodes)

            runner_code = (
                "import sys, pytest, botocore.auth as ba; "
                "ba.AUTH_TYPE_MAPS.update({"
                "'v4': ba.SigV4Auth, 'v4-query': ba.SigV4QueryAuth, "
                "'s3v4': ba.S3SigV4Auth, 's3v4-query': ba.S3SigV4QueryAuth"
                "}); "
                "raise SystemExit(pytest.main(sys.argv[1:]))"
            )
            py_bin = os.environ.get("S3TESTS_PYTHON")
            if not py_bin:
                default_py = ROOT / ".venv" / "bin" / "python"
                if default_py.exists():
                    try:
                        if subprocess.run(
                            [str(default_py), "-c", "import pytest, botocore"],
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL,
                        ).returncode == 0:
                            py_bin = str(default_py)
                    except OSError:
                        py_bin = None
            if not py_bin:
                py_bin = sys.executable
            s3tests_dir = Path(os.environ.get("S3TESTS_DIR", str(ROOT / ".cache" / "s3-tests")))
            pytest_cmd = [
                py_bin,
                "-c",
                runner_code,
                *pytest_args,
            ]

            env = os.environ.copy()
            env["TZ"] = "UTC"
            env["S3TEST_CONF"] = str(ROOT / "tests" / "s3test.conf")
            existing_pp = env.get("PYTHONPATH", "")
            env["PYTHONPATH"] = f"{s3tests_dir}:{existing_pp}" if existing_pp else str(s3tests_dir)
            pytest_res = subprocess.run(
                pytest_cmd,
                cwd=str(s3tests_dir),
                env=env,
            )
        finally:
            srv.send_signal(signal.SIGTERM)
            try:
                srv.wait(timeout=15)
            except subprocess.TimeoutExpired:
                srv.kill()
                srv.wait()
            log_file.close()

        fsck_res = subprocess.run(
            [str(s3d_bin), "fsck", "--data-dir", str(data_dir)],
            capture_output=True,
            text=True,
        )
        if fsck_res.returncode != 0:
            print(f"FSCK FAILED ({fsck_res.returncode}):\n{fsck_res.stdout}\n{fsck_res.stderr}", file=sys.stderr)
            return 3
        print("s3d fsck passed with 0 errors.")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
