#!/usr/bin/env python3
"""M0 boto3 smoke test against a running s3d instance."""

from __future__ import annotations

import hashlib
import os
import sys
import urllib.request

import boto3
from botocore.client import Config


def main() -> int:
    endpoint = os.environ.get("S3D_ENDPOINT", "http://127.0.0.1:28080")
    admin_endpoint = os.environ.get("S3D_ADMIN_ENDPOINT", "http://127.0.0.1:29090")

    # 1. Admin /health and /metrics
    with urllib.request.urlopen(f"{admin_endpoint}/health", timeout=5) as resp:
        assert resp.status == 200, f"unexpected /health status: {resp.status}"
    with urllib.request.urlopen(f"{admin_endpoint}/metrics", timeout=5) as resp:
        assert resp.status == 200, f"unexpected /metrics status: {resp.status}"
        metrics_body = resp.read().decode("utf-8")
        assert "s3d_" in metrics_body, f"unexpected /metrics body: {metrics_body[:200]}"

    s3 = boto3.client(
        "s3",
        endpoint_url=endpoint,
        aws_access_key_id="0555b35654ad1656d804",
        aws_secret_access_key="h7GhxuBLTrlhVUyxSPUKUV8r/2EI4ngqJxD7iBdBYLhwluN30JaT3Q==",
        region_name="us-east-1",
        config=Config(signature_version="s3v4", s3={"addressing_style": "path"}),
    )

    bucket = "m0-smoke-bucket"
    # Clean up if left over
    try:
        objs = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
        for o in objs:
            s3.delete_object(Bucket=bucket, Key=o["Key"])
        s3.delete_bucket(Bucket=bucket)
    except Exception:
        pass

    # 2. CreateBucket, HeadBucket, ListBuckets, GetBucketLocation
    s3.create_bucket(Bucket=bucket)
    s3.head_bucket(Bucket=bucket)
    buckets = [b["Name"] for b in s3.list_buckets().get("Buckets", [])]
    assert bucket in buckets, f"{bucket} missing from {buckets}"
    loc = s3.get_bucket_location(Bucket=bucket)
    assert loc.get("LocationConstraint") in (None, ""), f"unexpected location: {loc}"

    # 3. PutObject (streaming/chunked checksum via boto3 1.44 default)
    payload = b"hello-s3d-m0-" * 8192  # ~106 KiB across multiple segment blocks
    expected_md5 = f'"{hashlib.md5(payload).hexdigest()}"'
    put_resp = s3.put_object(
        Bucket=bucket,
        Key="dir/alpha.bin",
        Body=payload,
        ContentType="application/octet-stream",
        Metadata={"Author": "antigravity", "Stage": "m0"},
    )
    assert put_resp["ETag"] == expected_md5, f"ETag mismatch: {put_resp['ETag']} != {expected_md5}"

    # 4. HeadObject
    head_resp = s3.head_object(Bucket=bucket, Key="dir/alpha.bin")
    assert head_resp["ContentLength"] == len(payload)
    assert head_resp["ETag"] == expected_md5
    assert head_resp["ContentType"] == "application/octet-stream"
    assert head_resp["Metadata"] == {"author": "antigravity", "stage": "m0"}, head_resp["Metadata"]

    # 5. GetObject full & Range
    get_resp = s3.get_object(Bucket=bucket, Key="dir/alpha.bin")
    got = get_resp["Body"].read()
    assert got == payload, f"body mismatch: len {len(got)} vs {len(payload)}"

    range_resp = s3.get_object(Bucket=bucket, Key="dir/alpha.bin", Range="bytes=6-11")
    assert range_resp["ResponseMetadata"]["HTTPStatusCode"] == 206
    assert range_resp["Body"].read() == payload[6:12]

    # 6. CopyObject & ListObjectsV2
    s3.copy_object(
        Bucket=bucket,
        Key="dir/beta.bin",
        CopySource={"Bucket": bucket, "Key": "dir/alpha.bin"},
    )
    listed = s3.list_objects_v2(Bucket=bucket, Prefix="dir/")
    keys = [c["Key"] for c in listed.get("Contents", [])]
    assert keys == ["dir/alpha.bin", "dir/beta.bin"], f"unexpected keys: {keys}"

    # 7. Presigned GET URL
    presigned_url = s3.generate_presigned_url(
        "get_object",
        Params={"Bucket": bucket, "Key": "dir/beta.bin"},
        ExpiresIn=300,
    )
    with urllib.request.urlopen(presigned_url, timeout=5) as presigned_resp:
        assert presigned_resp.status == 200
        assert presigned_resp.read() == payload

    # 8. DeleteObject, DeleteObjects, DeleteBucket
    s3.delete_object(Bucket=bucket, Key="dir/alpha.bin")
    del_resp = s3.delete_objects(
        Bucket=bucket,
        Delete={"Objects": [{"Key": "dir/beta.bin"}, {"Key": "dir/nonexistent.bin"}]},
    )
    assert len(del_resp.get("Deleted", [])) == 2
    assert not del_resp.get("Errors")

    s3.delete_bucket(Bucket=bucket)
    print("SMOKE TEST PASSED: all M0 boto3 & admin checks succeeded.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
