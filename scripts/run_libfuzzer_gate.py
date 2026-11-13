#!/usr/bin/env python3
"""VR-7 LLVM libFuzzer (`cargo +nightly fuzz`) Parallel Campaign Runner.

Builds all 8 `fuzz/fuzz_targets/*.rs` binaries with SanitizerCoverage + AddressSanitizer
via `cargo +nightly fuzz build`, exports structured S3 protocol/WAL/checkpoint seeds and
dictionary via `s3d-fuzz --export-corpus`, executes all 8 libFuzzer binaries in parallel
for `--seconds` (default 3605s = >1 hour per target per Spec VR-7), verifies 0 crashes /
0 leaks / 0 timeouts, and writes `reports/vr7-cargo-fuzz-report.json`.
"""

from __future__ import annotations

import argparse
import glob
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

TARGETS = [
    "fuzz_auth_header",
    "fuzz_canonical_request",
    "fuzz_aws_chunked",
    "fuzz_xml_requests",
    "fuzz_range_header",
    "fuzz_continuation_token",
    "fuzz_post_policy",
    "fuzz_wal_ckpt_decode",
]

COV_RE = re.compile(r"#(\d+)\s+\S+\s+cov:\s*(\d+)\s+ft:\s*(\d+)\s+corp:\s*(\d+)")
STAT_RE = re.compile(r"^stat::([a-zA-Z0-9_]+):\s+(\d+)")


def find_built_fuzzer(target: str) -> Path:
    matches = glob.glob(str(ROOT / "fuzz" / "target" / "*" / "release" / target))
    matches = [m for m in matches if os.path.isfile(m) and os.access(m, os.X_OK)]
    if not matches:
        raise RuntimeError(f"Could not find compiled libFuzzer binary for {target}")
    matches.sort(key=os.path.getmtime, reverse=True)
    return Path(matches[0])


def parse_libfuzzer_log(log_path: Path) -> dict:
    stats: dict[str, int] = {}
    last_cov = 0
    last_ft = 0
    last_corp = 0
    last_runs = 0
    for line in log_path.read_text(encoding="utf-8", errors="replace").splitlines():
        m_cov = COV_RE.search(line)
        if m_cov:
            last_runs = int(m_cov.group(1))
            last_cov = int(m_cov.group(2))
            last_ft = int(m_cov.group(3))
            last_corp = int(m_cov.group(4))
        m_st = STAT_RE.match(line.strip())
        if m_st:
            stats[m_st.group(1)] = int(m_st.group(2))
    return {
        "executed_units": stats.get("number_of_executed_units", last_runs),
        "average_exec_per_sec": stats.get("average_exec_per_sec", 0),
        "new_units_added": stats.get("new_units_added", 0),
        "peak_rss_mb": stats.get("peak_rss_mb", 0),
        "edge_cov": last_cov,
        "features": last_ft,
        "corpus_entries": last_corp,
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--seconds", type=int, default=3605, help="Per-target libFuzzer duration in seconds (Spec VR-7: >= 3600)")
    ap.add_argument("--report", type=Path, default=ROOT / "reports" / "vr7-cargo-fuzz-report.json")
    args = ap.parse_args()

    env = os.environ.copy()
    cargo_bin = str(Path.home() / ".cargo" / "bin")
    if cargo_bin not in env.get("PATH", ""):
        env["PATH"] = f"{cargo_bin}:{env.get('PATH', '')}"

    corpus_root = ROOT / "fuzz" / "corpus"
    artifacts_root = ROOT / "fuzz" / "artifacts"
    logs_root = ROOT / "fuzz" / "logs"
    logs_root.mkdir(parents=True, exist_ok=True)

    print("[VR-7] Exporting seed corpus & dictionary via s3d-fuzz...", flush=True)
    subprocess.run(
        [
            "cargo",
            "run",
            "--release",
            "-p",
            "s3d-fuzz",
            "--",
            "--export-corpus",
            str(corpus_root),
        ],
        cwd=str(ROOT),
        env=env,
        check=True,
    )

    print("[VR-7] Building all 8 cargo-fuzz (libFuzzer + ASan + SanitizerCoverage) targets...", flush=True)
    subprocess.run(
        ["cargo", "+nightly", "fuzz", "build"],
        cwd=str(ROOT),
        env=env,
        check=True,
    )

    dict_path = corpus_root / "s3d.dict"
    procs: list[tuple[str, subprocess.Popen, Path, object, float]] = []
    wall_t0 = time.monotonic()

    print(f"[VR-7] Launching all {len(TARGETS)} libFuzzer targets in parallel for {args.seconds}s each...", flush=True)
    for t in TARGETS:
        bin_path = find_built_fuzzer(t)
        t_corp = corpus_root / t
        t_art = artifacts_root / t
        t_corp.mkdir(parents=True, exist_ok=True)
        t_art.mkdir(parents=True, exist_ok=True)
        log_path = logs_root / f"{t}.log"
        log_fh = log_path.open("w", encoding="utf-8")
        cmd = [
            str(bin_path),
            str(t_corp),
            f"-artifact_prefix={t_art}/",
            f"-dict={dict_path}",
            f"-max_total_time={args.seconds}",
            "-max_len=65536",
            "-rss_limit_mb=2048",
            "-print_final_stats=1",
        ]
        p = subprocess.Popen(cmd, cwd=str(ROOT), env=env, stdout=log_fh, stderr=subprocess.STDOUT)
        procs.append((t, p, log_path, log_fh, time.monotonic()))

    results = []
    total_crashes = 0
    total_execs = 0
    for t, p, log_path, log_fh, t_start in procs:
        rc = p.wait()
        elapsed = time.monotonic() - t_start
        log_fh.close()
        parsed = parse_libfuzzer_log(log_path)
        artifacts = [
            str(x.relative_to(ROOT))
            for x in (artifacts_root / t).glob("*")
            if x.is_file()
        ]
        crashes = len(artifacts) + (0 if rc == 0 else 1)
        total_crashes += crashes
        total_execs += parsed["executed_units"]
        entry = {
            "target": t,
            "engine": "cargo-fuzz / LLVM libFuzzer + AddressSanitizer",
            "exit_code": rc,
            "duration_secs": round(elapsed, 2),
            "crashes": crashes,
            "artifacts": artifacts,
            **parsed,
            "passed": rc == 0 and len(artifacts) == 0,
        }
        results.append(entry)
        print(
            f"[VR-7 Done] {t}: rc={rc}, duration={elapsed:.1f}s, "
            f"execs={parsed['executed_units']:,} ({parsed['average_exec_per_sec']:,}/s), "
            f"cov={parsed['edge_cov']}, ft={parsed['features']}, corp={parsed['corpus_entries']}, "
            f"crashes={crashes}",
            flush=True,
        )

    wall_secs = time.monotonic() - wall_t0
    all_passed = all(r["passed"] for r in results)
    report = {
        "generated_at_epoch_s": int(time.time()),
        "fuzzer_engine": "cargo-fuzz 0.13 (LLVM libFuzzer + SanitizerCoverage + AddressSanitizer)",
        "per_target_budget_secs": args.seconds,
        "wall_clock_secs": round(wall_secs, 2),
        "targets": results,
        "total_executions": total_execs,
        "total_crashes": total_crashes,
        "all_passed": all_passed,
    }
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"[VR-7 Summary] total_execs={total_execs:,}, total_crashes={total_crashes}, report={args.report}")
    return 0 if all_passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
