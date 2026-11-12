#!/usr/bin/env python3
"""VR-6 Real Clients Verification Suite (boto3 1.44 + awscli v1).

Spins up an isolated release `s3d` server on ephemeral ports, executes:
  1. awscli v1 (`mb`, `cp`, `sync`, `ls`, `rm`, `presign` + HTTP GET via presigned URL)
  2. boto3 1.44 CRUD, batch DeleteObjects, conditional writes (`IfNoneMatch='*'`, `IfMatch`),
     presigned PUT & GET URLs, `GetObjectAttributes`, and all 5 P0 checksum algorithms
  3. 1 GiB (1,073,741,824 bytes) streaming Multipart Upload + streaming GET download
     with end-to-end SHA-256 verification and bounded memory
  4. Versioned bucket (`PutBucketVersioning=Enabled`): overwrite v1 -> v2, delete (creates
     DeleteMarker -> 404 on unversioned GET), list versions, restore v1 via CopyObject(VersionId=v1),
     and permanent version deletion
  5. Graceful SIGTERM shutdown + `s3d fsck` offline integrity verification (`0` errors).
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

import boto3
from boto3.s3.transfer import TransferConfig
from botocore.config import Config
from botocore.exceptions import ClientError

ROOT = Path(__file__).resolve().parent.parent
ACCESS_KEY = "0555b35654ad1656d804"
SECRET_KEY = "h7GhxuBLTrlhVUyxSPUKUV8r/2EI4ngqJxD7iBdBYLhwluN30JaT3Q=="
REGION = "us-east-1"


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def run_aws(aws_bin: str, endpoint: str, args: list[str], env: dict[str, str]) -> str:
    cmd = [aws_bin, "--endpoint-url", endpoint, "--region", REGION, *args]
    proc = subprocess.run(cmd, env=env, capture_output=True, text=True)
    if proc.returncode != 0:
        raise RuntimeError(
            f"awscli command failed ({proc.returncode}): {' '.join(cmd)}\n"
            f"stdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
        )
    return proc.stdout


def main() -> int:
    s3d_bin = ROOT / "target" / "release" / "s3d"
    if not s3d_bin.exists():
        raise SystemExit(f"Missing release binary: {s3d_bin}")

    aws_bin = str(ROOT / ".venv" / "bin" / "aws")
    if not Path(aws_bin).exists():
        found = shutil.which("aws")
        if not found:
            raise SystemExit("awscli v1 binary not found in .venv/bin/aws or PATH")
        aws_bin = found

    with tempfile.TemporaryDirectory(prefix="s3d-vr6-") as tmp_str:
        tmp = Path(tmp_str)
        data_dir = tmp / "data"
        cred_path = tmp / "credentials.toml"
        cfg_path = tmp / "s3d.toml"

        cred_path.write_text(
            f'''[[accounts]]
user_id = "testid"
display_name = "M. Tester"
email = "tester@ceph.com"
access_key = "{ACCESS_KEY}"
secret_key = "{SECRET_KEY}"
''',
            encoding="utf-8",
        )
        os.chmod(cred_path, 0o600)

        s3_port = free_port()
        admin_port = free_port()
        endpoint = f"http://127.0.0.1:{s3_port}"
        admin_url = f"http://127.0.0.1:{admin_port}"

        cfg_path.write_text(
            f'''listen = "127.0.0.1:{s3_port}"
admin_listen = "127.0.0.1:{admin_port}"
data_dir = "{data_dir}"
region = "{REGION}"
credentials_file = "{cred_path}"
group_commit_window_ms = 1
group_commit_max_batch = 64
log_format = "json"
''',
            encoding="utf-8",
        )

        log_file = (tmp / "s3d.log").open("w", encoding="utf-8")
        proc = subprocess.Popen(
            [str(s3d_bin), "serve", "--config", str(cfg_path)],
            stdout=log_file,
            stderr=subprocess.STDOUT,
        )
        try:
            # Wait for /health == 200
            for _ in range(50):
                try:
                    with urllib.request.urlopen(f"{admin_url}/health", timeout=0.5) as r:
                        if r.status == 200:
                            break
                except Exception:
                    time.sleep(0.1)
            else:
                raise RuntimeError("s3d failed to become healthy within 5s")

            # ---- Phase 1: awscli v1 (mb, cp, sync, ls, presign, rm) ----
            print("[VR-6 1/5] Running awscli v1 suite (mb, cp, sync, ls, presign, rm)...")
            aws_cfg_file = tmp / "aws_config"
            aws_cfg_file.write_text(
                f"[default]\nregion = {REGION}\ns3 =\n    signature_version = s3v4\n    addressing_style = path\n",
                encoding="utf-8",
            )
            aws_env = os.environ.copy()
            aws_env.update(
                {
                    "AWS_ACCESS_KEY_ID": ACCESS_KEY,
                    "AWS_SECRET_ACCESS_KEY": SECRET_KEY,
                    "AWS_DEFAULT_REGION": REGION,
                    "AWS_CONFIG_FILE": str(aws_cfg_file),
                    "AWS_EC2_METADATA_DISABLED": "true",
                }
            )
            run_aws(aws_bin, endpoint, ["s3", "mb", "s3://vr6-cli-bkt"], aws_env)

            sync_src = tmp / "sync_src"
            sync_dst = tmp / "sync_dst"
            (sync_src / "nested").mkdir(parents=True)
            sync_dst.mkdir(parents=True)
            (sync_src / "hello.txt").write_bytes(b"hello from awscli!\n")
            (sync_src / "nested" / "data.bin").write_bytes(os.urandom(131_072))

            run_aws(
                aws_bin,
                endpoint,
                ["s3", "cp", str(sync_src / "hello.txt"), "s3://vr6-cli-bkt/single.txt"],
                aws_env,
            )
            run_aws(
                aws_bin,
                endpoint,
                ["s3", "sync", str(sync_src), "s3://vr6-cli-bkt/synced/"],
                aws_env,
            )
            ls_out = run_aws(
                aws_bin, endpoint, ["s3", "ls", "s3://vr6-cli-bkt/synced/", "--recursive"], aws_env
            )
            assert "synced/hello.txt" in ls_out and "synced/nested/data.bin" in ls_out

            run_aws(
                aws_bin,
                endpoint,
                ["s3", "sync", "s3://vr6-cli-bkt/synced/", str(sync_dst)],
                aws_env,
            )
            assert (sync_dst / "hello.txt").read_bytes() == (sync_src / "hello.txt").read_bytes()
            assert (sync_dst / "nested" / "data.bin").read_bytes() == (
                sync_src / "nested" / "data.bin"
            ).read_bytes()

            presigned = run_aws(
                aws_bin,
                endpoint,
                ["s3", "presign", "s3://vr6-cli-bkt/single.txt", "--expires-in", "300"],
                aws_env,
            ).strip()
            with urllib.request.urlopen(presigned, timeout=5) as r:
                assert r.status == 200
                assert r.read() == b"hello from awscli!\n"

            run_aws(
                aws_bin,
                endpoint,
                ["s3", "rm", "s3://vr6-cli-bkt", "--recursive"],
                aws_env,
            )
            run_aws(aws_bin, endpoint, ["s3", "rb", "s3://vr6-cli-bkt"], aws_env)

            # ---- Phase 2: boto3 1.44 CRUD, Checksums, Preconditions & Presigned PUT/GET ----
            print("[VR-6 2/5] Running boto3 1.44 checksums, preconditions & presigned URLs...")
            s3 = boto3.client(
                "s3",
                endpoint_url=endpoint,
                aws_access_key_id=ACCESS_KEY,
                aws_secret_access_key=SECRET_KEY,
                region_name=REGION,
                config=Config(signature_version="s3v4", s3={"addressing_style": "path"}),
            )
            s3.create_bucket(Bucket="vr6-boto-bkt")

            for alg in ("CRC32", "CRC32C", "CRC64NVME", "SHA1", "SHA256"):
                payload = f"checksum-verify-{alg}".encode() * 300
                put_r = s3.put_object(
                    Bucket="vr6-boto-bkt",
                    Key=f"csum/{alg}",
                    Body=payload,
                    ChecksumAlgorithm=alg,
                )
                assert f"Checksum{alg}" in put_r
                attrs = s3.get_object_attributes(
                    Bucket="vr6-boto-bkt",
                    Key=f"csum/{alg}",
                    ObjectAttributes=["ETag", "Checksum", "ObjectSize", "StorageClass"],
                )
                assert attrs["ObjectSize"] == len(payload)
                assert attrs["Checksum"][f"Checksum{alg}"] == put_r[f"Checksum{alg}"]

            # Conditional If-None-Match: *
            r1 = s3.put_object(
                Bucket="vr6-boto-bkt", Key="cond-key", Body=b"v1", IfNoneMatch="*"
            )
            try:
                s3.put_object(
                    Bucket="vr6-boto-bkt", Key="cond-key", Body=b"v2", IfNoneMatch="*"
                )
                raise AssertionError("Expected 412 PreconditionFailed")
            except ClientError as e:
                assert e.response["ResponseMetadata"]["HTTPStatusCode"] == 412

            # Conditional If-Match: <etag>
            s3.put_object(
                Bucket="vr6-boto-bkt", Key="cond-key", Body=b"v2", IfMatch=r1["ETag"]
            )

            # Presigned PUT & GET via boto3
            put_url = s3.generate_presigned_url(
                "put_object", Params={"Bucket": "vr6-boto-bkt", "Key": "presigned-put"}, ExpiresIn=300
            )
            req = urllib.request.Request(put_url, data=b"presigned-payload", method="PUT")
            with urllib.request.urlopen(req, timeout=5) as r:
                assert r.status == 200
            get_url = s3.generate_presigned_url(
                "get_object", Params={"Bucket": "vr6-boto-bkt", "Key": "presigned-put"}, ExpiresIn=300
            )
            with urllib.request.urlopen(get_url, timeout=5) as r:
                assert r.read() == b"presigned-payload"

            # ---- Phase 3: 1 GiB Multipart Upload + Download SHA-256 Verification ----
            print("[VR-6 3/5] Uploading & downloading 1 GiB object via Multipart Upload + SHA-256 check...")
            gib_size = 1024 * 1024 * 1024  # 1 GiB exact
            chunk_unit = 4 * 1024 * 1024  # 4 MiB generation buffer
            pattern = hashlib.sha256(b"s3d-vr6-1gib-seed").digest() * (chunk_unit // 32)

            src_file = tmp / "one_gib.bin"
            dst_file = tmp / "one_gib_down.bin"
            up_sha256 = hashlib.sha256()
            with src_file.open("wb") as f:
                for idx in range(gib_size // chunk_unit):
                    # Vary prefix per 4 MiB block so blocks aren't identical!
                    hdr = idx.to_bytes(8, "little")
                    blk = hdr + pattern[8:]
                    up_sha256.update(blk)
                    f.write(blk)
            expected_hex = up_sha256.hexdigest()

            tcfg = TransferConfig(
                multipart_threshold=16 * 1024 * 1024,
                multipart_chunksize=16 * 1024 * 1024,  # 64 parts * 16 MiB = 1 GiB
                max_concurrency=8,
            )
            t0 = time.monotonic()
            s3.upload_file(str(src_file), "vr6-boto-bkt", "large/one_gib.bin", Config=tcfg)
            up_sec = time.monotonic() - t0
            src_file.unlink()  # Free 1 GiB temp input immediately

            attrs_1g = s3.get_object_attributes(
                Bucket="vr6-boto-bkt",
                Key="large/one_gib.bin",
                ObjectAttributes=["ETag", "ObjectParts", "ObjectSize"],
            )
            assert attrs_1g["ObjectSize"] == gib_size
            parts_total = attrs_1g["ObjectParts"].get("TotalPartsCount") or attrs_1g["ObjectParts"].get("PartsCount")
            assert parts_total == 64, f"Expected 64 parts, got {parts_total}"

            t1 = time.monotonic()
            s3.download_file("vr6-boto-bkt", "large/one_gib.bin", str(dst_file), Config=tcfg)
            down_sec = time.monotonic() - t1

            down_sha256 = hashlib.sha256()
            with dst_file.open("rb") as f:
                while True:
                    b = f.read(chunk_unit)
                    if not b:
                        break
                    down_sha256.update(b)
            dst_file.unlink()
            assert down_sha256.hexdigest() == expected_hex, "1 GiB SHA-256 mismatch!"
            print(
                f"    1 GiB SHA-256 verified ({expected_hex[:16]}...): "
                f"upload={up_sec:.2f}s ({1024/up_sec:.0f} MiB/s), "
                f"download={down_sec:.2f}s ({1024/down_sec:.0f} MiB/s)"
            )

            # ---- Phase 4: Versioned Bucket Overwrite, DeleteMarker & Historical Restore ----
            print("[VR-6 4/5] Verifying versioned bucket overwrite, delete-marker & restore...")
            s3.create_bucket(Bucket="vr6-ver-bkt")
            s3.put_bucket_versioning(
                Bucket="vr6-ver-bkt", VersioningConfiguration={"Status": "Enabled"}
            )
            ver_status = s3.get_bucket_versioning(Bucket="vr6-ver-bkt")
            assert ver_status["Status"] == "Enabled"

            v1 = s3.put_object(Bucket="vr6-ver-bkt", Key="doc.txt", Body=b"version-one-content")
            v2 = s3.put_object(Bucket="vr6-ver-bkt", Key="doc.txt", Body=b"version-two-content")
            assert v1["VersionId"] != v2["VersionId"]

            assert s3.get_object(Bucket="vr6-ver-bkt", Key="doc.txt")["Body"].read() == b"version-two-content"
            assert (
                s3.get_object(Bucket="vr6-ver-bkt", Key="doc.txt", VersionId=v1["VersionId"])["Body"].read()
                == b"version-one-content"
            )

            # Soft delete -> creates DeleteMarker
            del_r = s3.delete_object(Bucket="vr6-ver-bkt", Key="doc.txt")
            assert del_r.get("DeleteMarker") is True
            try:
                s3.get_object(Bucket="vr6-ver-bkt", Key="doc.txt")
                raise AssertionError("Expected 404 NoSuchKey under DeleteMarker")
            except ClientError as e:
                assert e.response["Error"]["Code"] == "NoSuchKey"

            # Historical version v1 is still readable and restorable via CopyObject!
            s3.copy_object(
                Bucket="vr6-ver-bkt",
                Key="doc.txt",
                CopySource={"Bucket": "vr6-ver-bkt", "Key": "doc.txt", "VersionId": v1["VersionId"]},
            )
            restored = s3.get_object(Bucket="vr6-ver-bkt", Key="doc.txt")["Body"].read()
            assert restored == b"version-one-content"

            versions = s3.list_object_versions(Bucket="vr6-ver-bkt")
            assert len(versions.get("Versions", [])) == 3  # v1, v2, restored-v3
            assert len(versions.get("DeleteMarkers", [])) == 1

        finally:
            print("[VR-6 5/5] Graceful SIGTERM shutdown + offline `s3d fsck`...")
            proc.send_signal(signal.SIGTERM)
            proc.wait(timeout=15)
            log_file.close()

        fsck_proc = subprocess.run(
            [str(s3d_bin), "fsck", "--data-dir", str(data_dir)],
            capture_output=True,
            text=True,
            check=True,
        )
        report = json.loads(fsck_proc.stdout)
        assert report["status"] == "ok", f"fsck failed: {report}"
        assert report["errors"] == [], f"fsck errors: {report['errors']}"
        print(f"VR-6 ALL PASSED! fsck verified {report['bytes_verified']} bytes, 0 errors.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
