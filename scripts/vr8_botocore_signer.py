#!/usr/bin/env python3
"""Batch SigV4 signer using real `botocore.auth` (`SigV4Auth` & `S3SigV4QueryAuth`) for VR-8.

Reads JSON Lines from stdin, signs each request with `botocore`, and writes JSON Lines to stdout.
Each input line:
{
  "mode": "header" | "presign",
  "method": "GET" | "PUT" | ...,
  "url": "http://127.0.0.1:28080/...",
  "headers": [["Host", "127.0.0.1:28080"], ...],
  "body_sha256": "UNSIGNED-PAYLOAD" | "<64-hex>",
  "access_key": "...",
  "secret_key": "...",
  "region": "us-east-1",
  "timestamp": "20261112T030000Z",
  "expires": 300
}
"""

from __future__ import annotations

import datetime
import json
import sys
from unittest.mock import patch

from botocore.auth import S3SigV4Auth, S3SigV4QueryAuth
from botocore.awsrequest import AWSRequest
from botocore.credentials import Credentials


class FixedDatetime(datetime.datetime):
    _fixed_now: datetime.datetime = datetime.datetime(
        2026, 11, 12, 3, 0, 0, tzinfo=datetime.timezone.utc
    )

    @classmethod
    def now(cls, tz=None):
        if tz is None:
            return cls._fixed_now.replace(tzinfo=None)
        return cls._fixed_now.astimezone(tz)

    @classmethod
    def utcnow(cls):
        return cls._fixed_now.replace(tzinfo=None)


def parse_compact_utc(ts: str) -> datetime.datetime:
    return datetime.datetime.strptime(ts, "%Y%m%dT%H%M%SZ").replace(
        tzinfo=datetime.timezone.utc
    )


def sign_one(item: dict) -> dict:
    creds = Credentials(item["access_key"], item["secret_key"])
    FixedDatetime._fixed_now = parse_compact_utc(item["timestamp"])

    req = AWSRequest(method=item["method"], url=item["url"], data=b"")
    for k, v in item["headers"]:
        req.headers.add_header(k, v)

    with patch("botocore.auth.datetime.datetime", FixedDatetime):
        if item["mode"] == "presign":
            signer = S3SigV4QueryAuth(creds, "s3", item["region"], expires=item["expires"])
            signer.add_auth(req)
        else:
            req.context["payload_signing_enabled"] = item["body_sha256"] != "UNSIGNED-PAYLOAD"
            if item["body_sha256"] != "UNSIGNED-PAYLOAD":
                req.headers["x-amz-content-sha256"] = item["body_sha256"]
                signer = S3SigV4Auth(creds, "s3", item["region"])
                # Override payload() so we can test arbitrary precomputed body_sha256 without transferring MBs
                signer.payload = lambda _r: item["body_sha256"]
                signer.add_auth(req)
            else:
                req.headers["x-amz-content-sha256"] = "UNSIGNED-PAYLOAD"
                signer = S3SigV4Auth(creds, "s3", item["region"])
                signer.payload = lambda _r: "UNSIGNED-PAYLOAD"
                signer.add_auth(req)

    out_headers: list[list[str]] = []
    for k in req.headers:
        for val in req.headers.get_all(k):
            out_headers.append([k, val])
    return {"url": req.url, "headers": out_headers}


def main() -> int:
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        req_obj = json.loads(line)
        resp_obj = sign_one(req_obj)
        sys.stdout.write(json.dumps(resp_obj) + "\n")
    sys.stdout.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
