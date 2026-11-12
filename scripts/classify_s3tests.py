#!/usr/bin/env python3
"""Static AST classifier for ceph/s3-tests (commit 5b39871) matching Spec Appendix A.

Parses `test_s3.py` and `test_headers.py` purely via Python `ast` (never importing or
executing tests), verifies exact exclusion & domain counts against Appendix A, and emits
`tests/s3tests-manifest.json` or pytest node ID lists for milestone gates (M0..M4).
"""

from __future__ import annotations

import argparse
import ast
import collections
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
DEFAULT_S3TESTS_DIR = ROOT / ".cache" / "s3-tests"
DEFAULT_MANIFEST = ROOT / "tests" / "s3tests-manifest.json"

EXPECTED_EXCLUSIONS = {
    "fails_on_aws": 200,
    "kms": 27,
    "auth_aws2": 21,
    "tenant": 9,
    "transition": 3,
    "iam": 2,
    "torrent": 1,
}

DOMAIN_META = {
    # P0 (249)
    "auth": {"tier": "P0", "milestone": "M1", "expected": 41},
    "list_v2": {"tier": "P0", "milestone": "M1", "expected": 40},
    "list_v1": {"tier": "P0", "milestone": "M1", "expected": 37},
    "object_core": {"tier": "P0", "milestone": "M0", "expected": 33},
    "multipart": {"tier": "P0", "milestone": "M1", "expected": 32},
    "bucket": {"tier": "P0", "milestone": "M0", "expected": 22},
    "copy": {"tier": "P0", "milestone": "M1", "expected": 17},
    "conditional": {"tier": "P0", "milestone": "M1", "expected": 13},
    "checksum": {"tier": "P0", "milestone": "M1", "expected": 10},
    "delete_multi": {"tier": "P0", "milestone": "M1", "expected": 4},
    # P1 (190)
    "policy": {"tier": "P1", "milestone": "M2", "expected": 53},
    "acl": {"tier": "P1", "milestone": "M2", "expected": 44},
    "post_object": {"tier": "P1", "milestone": "M2", "expected": 36},
    "versioning": {"tier": "P1", "milestone": "M2", "expected": 31},
    "tagging": {"tier": "P1", "milestone": "M2", "expected": 17},
    "cors": {"tier": "P1", "milestone": "M2", "expected": 9},
    # P2 (106)
    "encryption": {"tier": "P2", "milestone": "M4", "expected": 41},
    "object_lock": {"tier": "P2", "milestone": "M4", "expected": 39},
    "lifecycle": {"tier": "P2", "milestone": "M4", "expected": 20},
    "logging": {"tier": "P2", "milestone": "M4", "expected": 6},
}


def extract_markers(func_node: ast.FunctionDef) -> set[str]:
    marks: set[str] = set()
    for dec in func_node.decorator_list:
        cur = dec.func if isinstance(dec, ast.Call) else dec
        if isinstance(cur, ast.Attribute) and isinstance(cur.value, ast.Attribute):
            if getattr(cur.value, "attr", None) == "mark":
                marks.add(cur.attr)
    return marks


def exclusion_reason(name: str, marks: set[str]) -> str | None:
    nl = name.lower()
    if "fails_on_aws" in marks:
        return "fails_on_aws"
    if "kms" in nl:
        return "kms"
    if "auth_aws2" in marks:
        return "auth_aws2"
    if "tenant" in nl:
        return "tenant"
    if (
        "cloud_transition" in marks
        or "cloud_restore" in marks
        or "lifecycle_transition" in marks
        or "transition" in nl
    ):
        return "transition"
    if "iam_account" in marks or "iam_user" in marks:
        return "iam"
    if "torrent" in nl:
        return "torrent"
    return None


def classify_domain(file_name: str, name: str, marks: set[str]) -> str:
    # 1. P2 domains (106)
    if "bucket_logging" in marks:
        return "logging"
    if "lifecycle" in marks:
        return "lifecycle"
    if name.startswith("test_object_lock_"):
        return "object_lock"
    if "encryption" in marks or "sse_s3" in marks:
        return "encryption"

    # 2. P1 domains (190)
    if "cors" in name:
        return "cors"
    if name.startswith("test_post_object_"):
        return "post_object"
    if "tagging" in name or "tags" in name:
        return "tagging"
    if (
        "bucket_policy" in marks
        or "policy" in name
        or "public_block" in name
        or name.startswith("test_block_public_")
        or name == "test_ignore_public_acls"
        or name.startswith("test_access_bucket_")
        or ("anonymous" in name and name != "test_bucket_list_objects_anonymous")
        or name in ("test_object_anon_put", "test_object_anon_put_write_access")
    ):
        return "policy"
    if (
        "object_ownership" in marks
        or "acl" in name
        or name
        in (
            "test_bucket_list_objects_anonymous",
            "test_bucket_list_return_data",
            "test_list_multipart_upload_owner",
            "test_100_continue",
            "test_object_raw_get",
            "test_object_raw_authenticated",
        )
    ):
        return "acl"
    if "version" in name or "delete_marker" in marks:
        return "versioning"

    # 3. P0 domains (249)
    if "checksum" in marks:
        return "checksum"
    if file_name == "test_headers.py" or any(
        x in name
        for x in (
            "_raw_",
            "authenticated",
            "presigned",
            "invalid_auth",
            "bad_auth",
            "100_continue",
            "chunked",
        )
    ):
        return "auth"
    if "multi_object" in name and "delete" in name:
        return "delete_multi"
    if "conditional_write" in marks and "multipart" not in name:
        return "conditional"
    if (
        any(
            x in name
            for x in (
                "ifmatch",
                "ifnonematch",
                "ifmodifiedsince",
                "ifunmodifiedsince",
            )
        )
        and "copy" not in name
    ):
        return "conditional"
    if "multipart" in name or "upload_part" in name:
        return "multipart"
    if "copy" in marks or "_copy_" in name:
        return "copy"
    if "list_objects_v2" in marks and (
        "bucket_list" in name or "key_count" in name or "bucketv2_notexist" in name
    ):
        return "list_v2"
    if name.startswith("test_bucket_list"):
        return "list_v1"
    if (
        name.startswith("test_bucket")
        or name.startswith("test_list_buckets")
        or name == "test_expected_bucket_owner"
    ):
        return "bucket"
    return "object_core"


def build_manifest(s3tests_dir: pathlib.Path) -> dict:
    rel_files = [
        "s3tests/functional/test_s3.py",
        "s3tests/functional/test_headers.py",
    ]
    total_defs = 0
    excl_counts: collections.Counter[str] = collections.Counter()
    domain_counts: collections.Counter[str] = collections.Counter()
    entries = []

    for rel in rel_files:
        p = s3tests_dir / rel
        tree = ast.parse(p.read_text(encoding="utf-8"), filename=str(p))
        for node in tree.body:
            if isinstance(node, ast.FunctionDef) and node.name.startswith("test_"):
                total_defs += 1
                marks = extract_markers(node)
                reason = exclusion_reason(node.name, marks)
                if reason is not None:
                    excl_counts[reason] += 1
                    continue
                dom = classify_domain(p.name, node.name, marks)
                domain_counts[dom] += 1
                meta = DOMAIN_META[dom]
                entries.append(
                    {
                        "nodeid": f"{rel}::{node.name}",
                        "file": rel,
                        "name": node.name,
                        "domain": dom,
                        "tier": meta["tier"],
                        "milestone": meta["milestone"],
                        "parametrized": "parametrize" in marks,
                        "markers": sorted(marks),
                    }
                )

    assert total_defs == 808, f"expected 808 test functions, got {total_defs}"
    for k, exp in EXPECTED_EXCLUSIONS.items():
        got = excl_counts[k]
        assert got == exp, f"exclusion '{k}': expected {exp}, got {got}"
    assert sum(excl_counts.values()) == 263
    assert len(entries) == 545

    for dom, meta in DOMAIN_META.items():
        got = domain_counts[dom]
        exp = meta["expected"]
        assert got == exp, f"domain '{dom}': expected {exp}, got {got}"

    return {
        "commit": "5b39871",
        "total_functions": total_defs,
        "excluded_total": sum(excl_counts.values()),
        "exclusions": dict(excl_counts),
        "target_total": len(entries),
        "domains": {dom: domain_counts[dom] for dom in DOMAIN_META},
        "tests": entries,
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--s3tests-dir", type=pathlib.Path, default=DEFAULT_S3TESTS_DIR)
    ap.add_argument("--write-manifest", type=pathlib.Path, default=None)
    ap.add_argument(
        "--select",
        type=str,
        default=None,
        help="Filter selector: M0, P0, P1, P2, ALL, or comma-separated domain names",
    )
    args = ap.parse_args()

    manifest = build_manifest(args.s3tests_dir)

    if args.write_manifest:
        args.write_manifest.parent.mkdir(parents=True, exist_ok=True)
        args.write_manifest.write_text(
            json.dumps(manifest, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )

    if args.select:
        sel = args.select.strip()
        tests = manifest["tests"]
        if sel == "M0":
            picked = [t["nodeid"] for t in tests if t["domain"] in ("bucket", "object_core")]
        elif sel == "M2":
            picked = [t["nodeid"] for t in tests if t["tier"] in ("P0", "P1")]
        elif sel in ("P0", "P1", "P2"):
            picked = [t["nodeid"] for t in tests if t["tier"] == sel]
        elif sel == "ALL":
            picked = [t["nodeid"] for t in tests]
        else:
            doms = {d.strip() for d in sel.split(",")}
            picked = [t["nodeid"] for t in tests if t["domain"] in doms]
        for nid in picked:
            print(nid)
    else:
        p0 = sum(v for k, v in manifest["domains"].items() if DOMAIN_META[k]["tier"] == "P0")
        p1 = sum(v for k, v in manifest["domains"].items() if DOMAIN_META[k]["tier"] == "P1")
        p2 = sum(v for k, v in manifest["domains"].items() if DOMAIN_META[k]["tier"] == "P2")
        print(
            f"Verified s3-tests (5b39871): total={manifest['total_functions']}, "
            f"excluded={manifest['excluded_total']}, target={manifest['target_total']} "
            f"(P0={p0}, P1={p1}, P2={p2}, M0={manifest['domains']['bucket'] + manifest['domains']['object_core']})",
            file=sys.stderr,
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
