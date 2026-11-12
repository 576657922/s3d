//! `VR-4` §3.3 Live HTTP 16-client / 8-key WGL linearizability integration & M3 gate tests.

use s3d_check::run_http_wgl_campaign;

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn wgl_http_ci_smoke_64_histories_and_deep_1000_event_histories() {
    let dir1 = tempfile::tempdir().unwrap();
    let smoke = run_http_wgl_campaign(dir1.path(), 8, 16, 0x2026_1112_0001)
        .await
        .expect("64-history CI smoke campaign must have 0 violations");
    assert_eq!(smoke.total_histories_verified, 64);

    // Also verify deep long-horizon histories (~1,024 HTTP ops per key = 8,192 HTTP ops in 1 round, `04-verification.md` §3.3)
    let dir2 = tempfile::tempdir().unwrap();
    let deep = run_http_wgl_campaign(dir2.path(), 1, 512, 0x2026_1112_0002)
        .await
        .expect("deep ~1024-event-per-key WGL campaign must have 0 violations");
    assert_eq!(deep.total_histories_verified, 8);
    assert_eq!(deep.total_http_ops, 16 * 512);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore]
async fn vr4_wgl_10k_histories_m3_gate() {
    let dir = tempfile::tempdir().unwrap();
    // 1,250 rounds * 8 keys = 10,000 independent concurrent HTTP per-key histories!
    let summary = run_http_wgl_campaign(dir.path(), 1_250, 12, 0x5333_445F_5652_3034)
        .await
        .expect("VR-4 10,000 WGL HTTP histories must pass with 0 linearizability violations");
    assert_eq!(summary.total_histories_verified, 10_000);
    eprintln!(
        "VR-4 WGL HTTP M3 gate passed: {} per-key histories ({} signed HTTP S3 ops across 16 clients / 8 keys + concurrent GC & checkpoints + post-run fsck) verified in {:.2}s, 0 violations.",
        summary.total_histories_verified,
        summary.total_http_ops,
        summary.elapsed_secs
    );
}
