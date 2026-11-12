#!/usr/bin/env python3
"""Parse pytest JUnit XML, count passed functions (collapsing parameterized items),
check against tests/s3tests-passed.txt for regressions, and optionally update baseline."""

from __future__ import annotations

import argparse
import sys
import xml.etree.ElementTree as ET
from collections import defaultdict
from pathlib import Path


def parse_junit_functions(xml_path: Path) -> tuple[set[str], dict[str, str]]:
    tree = ET.parse(xml_path)
    items_by_func: dict[str, list[tuple[str, str]]] = defaultdict(list)

    for tc in tree.iter("testcase"):
        cls = tc.attrib.get("classname", "").replace(".", "/") + ".py"
        idx = cls.find("s3tests/")
        if idx >= 0:
            cls = cls[idx:]
        raw_name = tc.attrib["name"]
        base_name = raw_name.split("[", 1)[0]
        func_id = f"{cls}::{base_name}"

        fail = tc.find("failure")
        err = tc.find("error")
        skip = tc.find("skipped")
        if err is not None:
            items_by_func[func_id].append(("ERROR", (err.attrib.get("message") or err.text or "").splitlines()[0] if (err.attrib.get("message") or err.text) else "error"))
        elif fail is not None:
            items_by_func[func_id].append(("FAILED", (fail.attrib.get("message") or fail.text or "").splitlines()[0] if (fail.attrib.get("message") or fail.text) else "failed"))
        elif skip is not None:
            items_by_func[func_id].append(("SKIPPED", skip.attrib.get("message", "skipped")))
        else:
            items_by_func[func_id].append(("PASSED", ""))

    passed: set[str] = set()
    not_passed: dict[str, str] = {}
    for func_id, outcomes in sorted(items_by_func.items()):
        if all(status == "PASSED" for status, _ in outcomes):
            passed.add(func_id)
        else:
            bad = next((f"{st}: {msg}" for st, msg in outcomes if st != "PASSED"), "UNKNOWN")
            not_passed[func_id] = bad
    return passed, not_passed


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("junit_xml", type=Path)
    ap.add_argument("--baseline", type=Path, default=Path("tests/s3tests-passed.txt"))
    ap.add_argument("--deviations", type=Path, default=Path("docs/deviations.md"))
    ap.add_argument("--update-baseline", action="store_true")
    ap.add_argument("--min-passed", type=int, default=0)
    args = ap.parse_args()

    passed, not_passed = parse_junit_functions(args.junit_xml)
    total = len(passed) + len(not_passed)
    print(f"JUnit summary ({args.junit_xml}): {len(passed)} / {total} functions passed ({len(not_passed)} not passed)")

    if args.baseline.exists():
        prev = {
            line.strip()
            for line in args.baseline.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.startswith("#")
        }
        # Only check regressions among functions that were actually executed in this run
        executed = passed | set(not_passed.keys())
        regressed = sorted((prev & executed) - passed)
        if regressed:
            print(f"REGRESSION DETECTED ({len(regressed)} previously passing tests failed):", file=sys.stderr)
            for r in regressed:
                print(f"  - {r}: {not_passed.get(r, '')}", file=sys.stderr)
            return 2

    if len(passed) < args.min_passed:
        print(f"GATE FAILED: passed {len(passed)} < required {args.min_passed}", file=sys.stderr)
        return 1

    if args.update_baseline:
        existing = set()
        if args.baseline.exists():
            existing = {
                line.strip()
                for line in args.baseline.read_text(encoding="utf-8").splitlines()
                if line.strip() and not line.startswith("#")
            }
        merged = sorted(existing | passed)
        args.baseline.write_text("\n".join(merged) + "\n", encoding="utf-8")
        print(f"Updated baseline {args.baseline}: {len(merged)} cumulative passing functions")

    if args.deviations.exists():
        dev_txt = args.deviations.read_text(encoding="utf-8")
        # Extract Section 2 table (before Section 3 if present)
        sec2 = dev_txt.split("## 3.", 1)[0]
        registered: set[str] = set()
        for line in sec2.splitlines():
            if line.startswith("| `s3tests/"):
                cell = line.split("|")[1].strip().strip("`")
                registered.add(cell)
        unregistered = sorted(set(not_passed.keys()) - registered)
        if unregistered:
            print(f"UNREGISTERED DEVIATIONS ({len(unregistered)} unpassed tests missing from {args.deviations}):", file=sys.stderr)
            for u in unregistered:
                print(f"  - {u}", file=sys.stderr)
            return 3
        stale_in_sec2 = sorted(passed & registered)
        if stale_in_sec2:
            print(f"STALE DEVIATIONS ({len(stale_in_sec2)} passing tests still in active table of {args.deviations}):", file=sys.stderr)
            for s in stale_in_sec2:
                print(f"  - {s}", file=sys.stderr)
            return 4

    if not_passed:
        print("\nUnpassed functions in this run (all registered in docs/deviations.md):")
        for fn, reason in sorted(not_passed.items()):
            print(f"  - {fn} -> {reason[:140]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
