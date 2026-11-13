//! Parallel in-process mutational & dictionary fuzz runner (`VR-7`) executing all 8 S3
//! security/protocol/storage fuzz targets concurrently (`>= 1 hour` each for M3 gate).

use std::fs;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use clap::Parser;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use s3d_fuzz::{
    fuzz_auth_header, fuzz_aws_chunked, fuzz_canonical_request, fuzz_continuation_token,
    fuzz_post_policy, fuzz_range_header, fuzz_wal_ckpt_decode, fuzz_xml_requests,
    initial_seed_corpus,
};
use serde::Serialize;

#[derive(Parser, Debug)]
#[command(name = "s3d-fuzz", about = "VR-7 8-target parallel fuzz runner")]
struct Args {
    /// Duration in seconds to run EACH fuzz target (runs all 8 targets in parallel threads).
    #[arg(long, default_value_t = 3605)]
    duration_secs: u64,

    /// Optional single target filter; omit to run all 8 targets in parallel.
    #[arg(long)]
    target: Option<String>,

    /// Output JSON report path.
    #[arg(long, default_value = "reports/m3-fuzz-report.json")]
    report: PathBuf,

    /// Export initial seed corpus and libFuzzer dictionary into `<DIR>/<target>/` and exit.
    #[arg(long)]
    export_corpus: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize)]
struct TargetFuzzStats {
    target: String,
    duration_secs: f64,
    total_executions: u64,
    execs_per_sec: f64,
    crashes: usize,
    passed: bool,
}

#[derive(Debug, Clone, Serialize)]
struct FuzzCampaignReport {
    generated_at_epoch_s: u64,
    per_target_budget_secs: u64,
    wall_clock_secs: f64,
    targets: Vec<TargetFuzzStats>,
    total_executions: u64,
    total_crashes: usize,
    all_passed: bool,
}

const DICT_TOKENS: &[&[u8]] = &[
    b"AWS4-HMAC-SHA256",
    b"Credential=",
    b"SignedHeaders=",
    b"Signature=",
    b"X-Amz-Algorithm",
    b"X-Amz-Credential",
    b"X-Amz-Date",
    b"X-Amz-Expires",
    b"X-Amz-SignedHeaders",
    b"X-Amz-Signature",
    b"UNSIGNED-PAYLOAD",
    b"STREAMING-AWS4-HMAC-SHA256-PAYLOAD",
    b"STREAMING-UNSIGNED-PAYLOAD-TRAILER",
    b";chunk-signature=",
    b"\r\n0\r\n\r\n",
    b"<!DOCTYPE",
    b"<!ENTITY",
    b"bytes=0-",
    b"bytes=-",
    b"multipart/form-data; boundary=",
    b"Content-Disposition: form-data; name=\"",
    b"\"conditions\":",
    b"\"expiration\":",
    b"starts-with",
    b"content-length-range",
    b"S3DFMT01",
    b"S3DSEG01",
    b"S3DWAL01",
    b"S3DCKP01",
    b"S3DCKEND",
];

const INTERESTING_BYTES: &[u8] = &[0x00, 0x01, 0x0a, 0x0d, 0x20, 0x2f, 0x3a, 0x3b, 0x3c, 0x3e, 0x7f, 0x80, 0xff];

fn mutate_havoc(rng: &mut StdRng, corpus: &[Vec<u8>], out: &mut Vec<u8>, max_len: usize) {
    let base = &corpus[rng.gen_range(0..corpus.len())];
    out.clear();
    out.extend_from_slice(base);

    let rounds = rng.gen_range(1..=8);
    for _ in 0..rounds {
        match rng.gen_range(0..8u8) {
            0 if !out.is_empty() => {
                // Single-bit flip
                let idx = rng.gen_range(0..out.len());
                out[idx] ^= 1u8 << rng.gen_range(0..8);
            }
            1 if !out.is_empty() => {
                // Interesting byte overwrite
                let idx = rng.gen_range(0..out.len());
                out[idx] = INTERESTING_BYTES[rng.gen_range(0..INTERESTING_BYTES.len())];
            }
            2 if out.len() >= 4 => {
                // Arithmetic delta on 32-bit word
                let idx = rng.gen_range(0..=out.len() - 4);
                let val = u32::from_le_bytes(out[idx..idx + 4].try_into().unwrap());
                let delta = rng.gen_range(-35i32..=35i32);
                let next = val.wrapping_add(delta as u32);
                out[idx..idx + 4].copy_from_slice(&next.to_le_bytes());
            }
            3 if out.len() > 2 => {
                // Delete random slice
                let start = rng.gen_range(0..out.len());
                let del_len = rng.gen_range(1..=(out.len() - start).min(64));
                out.drain(start..start + del_len);
            }
            4 => {
                // Insert dictionary token
                let tok = DICT_TOKENS[rng.gen_range(0..DICT_TOKENS.len())];
                if out.len() + tok.len() <= max_len {
                    let pos = if out.is_empty() {
                        0
                    } else {
                        rng.gen_range(0..=out.len())
                    };
                    out.splice(pos..pos, tok.iter().copied());
                }
            }
            5 => {
                // Insert random bytes
                let n = rng.gen_range(1..=32);
                if out.len() + n <= max_len {
                    let pos = if out.is_empty() {
                        0
                    } else {
                        rng.gen_range(0..=out.len())
                    };
                    let mut tmp = vec![0u8; n];
                    rng.fill(&mut tmp[..]);
                    out.splice(pos..pos, tmp);
                }
            }
            6 if corpus.len() > 1 => {
                // Crossover / splice with another seed
                let other = &corpus[rng.gen_range(0..corpus.len())];
                if !other.is_empty() && !out.is_empty() {
                    let split_a = rng.gen_range(0..out.len());
                    let split_b = rng.gen_range(0..other.len());
                    out.truncate(split_a);
                    let take = (other.len() - split_b).min(max_len.saturating_sub(out.len()));
                    out.extend_from_slice(&other[split_b..split_b + take]);
                }
            }
            _ => {
                // Duplicate internal chunk (amplifies nested XML / repeated headers)
                if !out.is_empty() && out.len() < max_len {
                    let start = rng.gen_range(0..out.len());
                    let len = rng
                        .gen_range(1..=(out.len() - start).min(64))
                        .min(max_len - out.len());
                    let slice = out[start..start + len].to_vec();
                    let pos = rng.gen_range(0..=out.len());
                    out.splice(pos..pos, slice);
                }
            }
        }
    }
}

fn run_single_target(name: &'static str, func: fn(&[u8]), duration: Duration, seed: u64) -> TargetFuzzStats {
    let mut corpus = initial_seed_corpus(name);
    let mut rng = StdRng::seed_from_u64(seed);
    let mut buf = Vec::with_capacity(16 * 1024);
    let mut execs = 0u64;
    let mut crashes = 0usize;
    let t0 = Instant::now();

    // First execute every seed verbatim
    for s in &corpus {
        if catch_unwind(AssertUnwindSafe(|| func(s))).is_err() {
            crashes += 1;
            let _ = fs::create_dir_all("reports/fuzz-crashes");
            let _ = fs::write(format!("reports/fuzz-crashes/{name}-seed-{execs}.bin"), s);
        }
        execs += 1;
    }

    let mut next_log = Duration::from_secs(300);
    while t0.elapsed() < duration && crashes == 0 {
        for _ in 0..256 {
            mutate_havoc(&mut rng, &corpus, &mut buf, 64 * 1024);
            let res = catch_unwind(AssertUnwindSafe(|| func(&buf)));
            execs += 1;
            if res.is_err() {
                crashes += 1;
                let _ = fs::create_dir_all("reports/fuzz-crashes");
                let crash_path = format!("reports/fuzz-crashes/{name}-crash-{execs}.bin");
                let _ = fs::write(&crash_path, &buf);
                eprintln!("[VR-7 CRASH] {name} panicked at exec #{execs}! Saved to {crash_path}");
                break;
            }
            // Periodically evolve working corpus reservoir (`<= 64` entries)
            if execs.is_multiple_of(8192) && buf.len() <= 8192 {
                if corpus.len() < 64 {
                    corpus.push(buf.clone());
                } else {
                    let keep_seeds = 10.min(corpus.len());
                    let idx = rng.gen_range(keep_seeds..corpus.len());
                    corpus[idx] = buf.clone();
                }
            }
        }
        let el = t0.elapsed();
        if el >= next_log {
            eprintln!(
                "[VR-7 Progress] {name}: {:.0}s / {:.0}s, {} execs ({:.0} exec/s), 0 crashes",
                el.as_secs_f64(),
                duration.as_secs_f64(),
                execs,
                (execs as f64) / el.as_secs_f64().max(0.001)
            );
            next_log += Duration::from_secs(300);
        }
    }

    let elapsed_secs = t0.elapsed().as_secs_f64();
    TargetFuzzStats {
        target: name.to_string(),
        duration_secs: elapsed_secs,
        total_executions: execs,
        execs_per_sec: (execs as f64) / elapsed_secs.max(0.001),
        crashes,
        passed: crashes == 0,
    }
}

type FuzzTargetEntry = (&'static str, fn(&[u8]));

fn main() {
    let args = Args::parse();
    let all_targets: Vec<FuzzTargetEntry> = vec![
        ("fuzz_auth_header", fuzz_auth_header),
        ("fuzz_canonical_request", fuzz_canonical_request),
        ("fuzz_aws_chunked", fuzz_aws_chunked),
        ("fuzz_xml_requests", fuzz_xml_requests),
        ("fuzz_range_header", fuzz_range_header),
        ("fuzz_continuation_token", fuzz_continuation_token),
        ("fuzz_post_policy", fuzz_post_policy),
        ("fuzz_wal_ckpt_decode", fuzz_wal_ckpt_decode),
    ];

    let selected: Vec<FuzzTargetEntry> = match &args.target {
        Some(t) => all_targets
            .into_iter()
            .filter(|(n, _)| *n == t.as_str())
            .collect(),
        None => all_targets,
    };
    assert!(!selected.is_empty(), "unknown --target {:?}", args.target);

    if let Some(corpus_root) = &args.export_corpus {
        fs::create_dir_all(corpus_root).unwrap();
        let mut dict_txt = String::new();
        for (i, tok) in DICT_TOKENS.iter().enumerate() {
            dict_txt.push_str(&format!("tok_{i}=\""));
            for &b in *tok {
                if (0x20..=0x7e).contains(&b) && b != b'"' && b != b'\\' {
                    dict_txt.push(b as char);
                } else {
                    dict_txt.push_str(&format!("\\x{b:02x}"));
                }
            }
            dict_txt.push_str("\"\n");
        }
        fs::write(corpus_root.join("s3d.dict"), dict_txt).unwrap();
        for (name, _) in &selected {
            let dir = corpus_root.join(name);
            fs::create_dir_all(&dir).unwrap();
            for (idx, seed) in initial_seed_corpus(name).into_iter().enumerate() {
                fs::write(dir.join(format!("seed-{idx:03}.bin")), seed).unwrap();
            }
        }
        eprintln!(
            "[VR-7] Exported initial seed corpus & dictionary for {} targets to {}",
            selected.len(),
            corpus_root.display()
        );
        return;
    }

    let budget = Duration::from_secs(args.duration_secs);
    eprintln!(
        "[VR-7] Launching {} fuzz target(s) in parallel for {}s each...",
        selected.len(),
        args.duration_secs
    );

    let wall_t0 = Instant::now();
    let mut handles = Vec::with_capacity(selected.len());
    for (idx, (name, func)) in selected.into_iter().enumerate() {
        let seed = 0x5333_445F_4655_5A5Au64 ^ ((idx as u64 + 1) * 0x9E37_79B9_7F4A_7C15);
        handles.push(std::thread::Builder::new()
            .name(format!("fuzz-{name}"))
            .stack_size(8 * 1024 * 1024)
            .spawn(move || run_single_target(name, func, budget, seed))
            .unwrap());
    }

    let mut stats = Vec::with_capacity(handles.len());
    for h in handles {
        stats.push(h.join().expect("fuzz worker thread panicked outside catch_unwind"));
    }
    let wall_secs = wall_t0.elapsed().as_secs_f64();

    let total_executions: u64 = stats.iter().map(|s| s.total_executions).sum();
    let total_crashes: usize = stats.iter().map(|s| s.crashes).sum();
    let all_passed = total_crashes == 0 && stats.iter().all(|s| s.passed);

    let report = FuzzCampaignReport {
        generated_at_epoch_s: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        per_target_budget_secs: args.duration_secs,
        wall_clock_secs: wall_secs,
        targets: stats,
        total_executions,
        total_crashes,
        all_passed,
    };

    if let Some(parent) = args.report.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    let json = serde_json::to_string_pretty(&report).unwrap();
    fs::write(&args.report, &json).unwrap();
    println!("{json}");

    assert!(
        all_passed,
        "VR-7 fuzzing detected {} crash(es)! Inspect {}",
        total_crashes,
        args.report.display()
    );
}
