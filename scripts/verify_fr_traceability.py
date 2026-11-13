#!/usr/bin/env python3
"""Mechanically verify requirement traceability (`VR-1` & Spec §3-§11).

Checks:
1. All 51 functional requirements (`FR-1` .. `FR-51`) are explicitly annotated in the
   non-test reference model implementation (`crates/s3d-model/src/lib.rs`).
2. All 119 specification requirement IDs (`FR-1..51`, `PR-1..33`, `ST-1..9`, `NFR-1..16`,
   `VR-1..10`) are referenced across the workspace implementation and verification harnesses.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SELF = Path(__file__).resolve()

RANGES = [
    ("FR", 51),
    ("PR", 33),
    ("ST", 9),
    ("NFR", 16),
    ("VR", 10),
]


def find_ids_in_text(text: str, prefix: str, hi: int) -> dict[int, list[int]]:
    hits: dict[int, list[int]] = {}
    pat = re.compile(rf"\b{prefix}-(\d+)\b")
    for lineno, line in enumerate(text.splitlines(), 1):
        for m in pat.finditer(line):
            n = int(m.group(1))
            if 1 <= n <= hi:
                hits.setdefault(n, []).append(lineno)
    return hits


def main() -> int:
    model_path = ROOT / "crates" / "s3d-model" / "src" / "lib.rs"
    model_prod = model_path.read_text(encoding="utf-8").split("#[cfg(test)]")[0]
    model_fr = find_ids_in_text(model_prod, "FR", 51)
    missing_model_fr = [f"FR-{n}" for n in range(1, 52) if n not in model_fr]

    source_files = sorted(
        p
        for p in list((ROOT / "crates").rglob("*.rs"))
        + list((ROOT / "scripts").rglob("*.py"))
        + list((ROOT / "fuzz").rglob("*.rs"))
        if p.resolve() != SELF
    )

    workspace_hits: dict[str, dict[int, list[str]]] = {pfx: {} for pfx, _ in RANGES}
    for path in source_files:
        rel = path.relative_to(ROOT).as_posix()
        txt = path.read_text(encoding="utf-8")
        for pfx, hi in RANGES:
            for n, lines in find_ids_in_text(txt, pfx, hi).items():
                workspace_hits[pfx].setdefault(n, []).append(f"{rel}:{lines[0]}")

    missing_workspace: list[str] = []
    summary: dict[str, str] = {}
    for pfx, hi in RANGES:
        found = len(workspace_hits[pfx])
        summary[pfx] = f"{found}/{hi}"
        for n in range(1, hi + 1):
            if n not in workspace_hits[pfx]:
                missing_workspace.append(f"{pfx}-{n}")

    report = {
        "vr1_model_fr_coverage": f"{len(model_fr)}/51",
        "missing_in_s3d_model": missing_model_fr,
        "workspace_coverage": summary,
        "missing_in_workspace": missing_workspace,
    }
    print(json.dumps(report, indent=2))

    if missing_model_fr or missing_workspace:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
