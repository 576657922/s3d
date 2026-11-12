use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use s3d_engine::{EngineMetricsSnapshot, HistogramSnapshot};

/// HTTP request latency histogram upper bounds in microseconds (`0.1ms` .. `2.0s`).
pub const REQ_LATENCY_BUCKETS_US: [u64; 12] = [
    100,
    250,
    500,
    1_000,
    2_500,
    5_000,
    10_000,
    25_000,
    50_000,
    100_000,
    500_000,
    2_000_000,
];

#[derive(Clone)]
struct OpLatencyEntry {
    count: u64,
    sum_us: u64,
    buckets: [u64; REQ_LATENCY_BUCKETS_US.len() + 1], // non-cumulative per-slot counts
}

impl Default for OpLatencyEntry {
    fn default() -> Self {
        Self {
            count: 0,
            sum_us: 0,
            buckets: [0; REQ_LATENCY_BUCKETS_US.len() + 1],
        }
    }
}

/// Prometheus metrics registry covering HTTP & storage engine telemetry (`NFR-11`).
#[derive(Default)]
pub struct ServerMetrics {
    pub requests_total: AtomicU64,
    pub errors_4xx_total: AtomicU64,
    pub errors_5xx_total: AtomicU64,
    pub bytes_in_total: AtomicU64,
    pub bytes_out_total: AtomicU64,
    pub active_connections: AtomicU64,
    by_op_status: Mutex<BTreeMap<(&'static str, u16), OpLatencyEntry>>,
}

impl ServerMetrics {
    pub fn record_request(&self, op: &'static str, status: u16, elapsed_micros: u64) {
        self.requests_total.fetch_add(1, Ordering::Relaxed);
        if (400..500).contains(&status) {
            self.errors_4xx_total.fetch_add(1, Ordering::Relaxed);
        } else if status >= 500 {
            self.errors_5xx_total.fetch_add(1, Ordering::Relaxed);
        }
        let idx = REQ_LATENCY_BUCKETS_US
            .iter()
            .position(|&b| elapsed_micros <= b)
            .unwrap_or(REQ_LATENCY_BUCKETS_US.len());
        let mut map = self.by_op_status.lock().unwrap();
        let entry = map.entry((op, status)).or_default();
        entry.count += 1;
        entry.sum_us += elapsed_micros;
        entry.buckets[idx] += 1;
    }

    pub fn render_prometheus(
        &self,
        read_only_poisoned: bool,
        engine: Option<&EngineMetricsSnapshot>,
    ) -> String {
        let mut out = String::with_capacity(4096);
        let _ = writeln!(out, "# TYPE s3d_requests_total counter");
        let _ = writeln!(
            out,
            "s3d_requests_total {}",
            self.requests_total.load(Ordering::Relaxed)
        );
        let _ = writeln!(out, "# TYPE s3d_errors_4xx_total counter");
        let _ = writeln!(
            out,
            "s3d_errors_4xx_total {}",
            self.errors_4xx_total.load(Ordering::Relaxed)
        );
        let _ = writeln!(out, "# TYPE s3d_errors_5xx_total counter");
        let _ = writeln!(
            out,
            "s3d_errors_5xx_total {}",
            self.errors_5xx_total.load(Ordering::Relaxed)
        );
        let _ = writeln!(out, "# TYPE s3d_bytes_in_total counter");
        let _ = writeln!(
            out,
            "s3d_bytes_in_total {}",
            self.bytes_in_total.load(Ordering::Relaxed)
        );
        let _ = writeln!(out, "# TYPE s3d_bytes_out_total counter");
        let _ = writeln!(
            out,
            "s3d_bytes_out_total {}",
            self.bytes_out_total.load(Ordering::Relaxed)
        );
        let _ = writeln!(out, "# TYPE s3d_active_connections gauge");
        let _ = writeln!(
            out,
            "s3d_active_connections {}",
            self.active_connections.load(Ordering::Relaxed)
        );
        let _ = writeln!(out, "# TYPE s3d_read_only_failed gauge");
        let _ = writeln!(out, "s3d_read_only_failed {}", u8::from(read_only_poisoned));

        let snapshot: Vec<_> = {
            let map = self.by_op_status.lock().unwrap();
            map.iter().map(|(&k, v)| (k, v.clone())).collect()
        };

        let _ = writeln!(out, "# TYPE s3d_operation_requests_total counter");
        for ((op, status), entry) in &snapshot {
            let _ = writeln!(
                out,
                "s3d_operation_requests_total{{op=\"{op}\",status=\"{status}\"}} {}",
                entry.count
            );
        }

        let _ = writeln!(out, "# TYPE s3d_operation_duration_seconds histogram");
        for ((op, status), entry) in &snapshot {
            let mut cum = 0u64;
            for (i, &le_us) in REQ_LATENCY_BUCKETS_US.iter().enumerate() {
                cum += entry.buckets[i];
                let le_sec = (le_us as f64) / 1_000_000.0;
                let _ = writeln!(
                    out,
                    "s3d_operation_duration_seconds_bucket{{op=\"{op}\",status=\"{status}\",le=\"{le_sec}\"}} {cum}"
                );
            }
            cum += entry.buckets[REQ_LATENCY_BUCKETS_US.len()];
            let _ = writeln!(
                out,
                "s3d_operation_duration_seconds_bucket{{op=\"{op}\",status=\"{status}\",le=\"+Inf\"}} {cum}"
            );
            let sum_sec = (entry.sum_us as f64) / 1_000_000.0;
            let _ = writeln!(
                out,
                "s3d_operation_duration_seconds_sum{{op=\"{op}\",status=\"{status}\"}} {sum_sec:.6}"
            );
            let _ = writeln!(
                out,
                "s3d_operation_duration_seconds_count{{op=\"{op}\",status=\"{status}\"}} {}",
                entry.count
            );
        }

        if let Some(eng) = engine {
            let _ = writeln!(out, "# TYPE s3d_fsync_duration_seconds histogram");
            write_us_histogram(
                &mut out,
                "s3d_fsync_duration_seconds",
                "kind=\"wal\"",
                &eng.wal_fsync_us,
            );
            write_us_histogram(
                &mut out,
                "s3d_fsync_duration_seconds",
                "kind=\"seg\"",
                &eng.seg_fsync_us,
            );
            write_us_histogram(
                &mut out,
                "s3d_fsync_duration_seconds",
                "kind=\"ckpt\"",
                &eng.ckpt_fsync_us,
            );

            let _ = writeln!(out, "# TYPE s3d_group_commit_batch_size histogram");
            write_raw_histogram(
                &mut out,
                "s3d_group_commit_batch_size",
                &eng.group_commit_batch_size,
            );

            let _ = writeln!(out, "# TYPE s3d_wal_bytes gauge");
            let _ = writeln!(out, "s3d_wal_bytes {}", eng.wal_bytes);

            let _ = writeln!(out, "# TYPE s3d_segment_live_bytes gauge");
            let _ = writeln!(out, "s3d_segment_live_bytes {}", eng.segment_live_bytes);

            let _ = writeln!(out, "# TYPE s3d_segment_total_bytes gauge");
            let _ = writeln!(out, "s3d_segment_total_bytes {}", eng.segment_total_bytes);

            let _ = writeln!(out, "# TYPE s3d_segment_live_ratio gauge");
            let _ = writeln!(out, "s3d_segment_live_ratio {:.6}", eng.segment_live_ratio);

            let _ = writeln!(out, "# TYPE s3d_gc_runs_total counter");
            let _ = writeln!(out, "s3d_gc_runs_total {}", eng.gc_runs_total);

            let _ = writeln!(out, "# TYPE s3d_gc_compacted_segments_total counter");
            let _ = writeln!(
                out,
                "s3d_gc_compacted_segments_total {}",
                eng.gc_compacted_segments_total
            );

            let _ = writeln!(out, "# TYPE s3d_gc_relocated_bytes_total counter");
            let _ = writeln!(
                out,
                "s3d_gc_relocated_bytes_total {}",
                eng.gc_relocated_bytes_total
            );

            let _ = writeln!(out, "# TYPE s3d_gc_in_progress gauge");
            let _ = writeln!(out, "s3d_gc_in_progress {}", u8::from(eng.gc_in_progress));

            let _ = writeln!(out, "# TYPE s3d_checkpoints_total counter");
            let _ = writeln!(out, "s3d_checkpoints_total {}", eng.checkpoints_total);

            let _ = writeln!(out, "# TYPE s3d_last_checkpoint_lsn gauge");
            let _ = writeln!(out, "s3d_last_checkpoint_lsn {}", eng.last_checkpoint_lsn);

            let _ = writeln!(out, "# TYPE s3d_catalog_buckets gauge");
            let _ = writeln!(out, "s3d_catalog_buckets {}", eng.catalog_buckets);

            let _ = writeln!(out, "# TYPE s3d_catalog_object_versions gauge");
            let _ = writeln!(
                out,
                "s3d_catalog_object_versions {}",
                eng.catalog_object_versions
            );

            let _ = writeln!(out, "# TYPE s3d_catalog_open_uploads gauge");
            let _ = writeln!(out, "s3d_catalog_open_uploads {}", eng.catalog_open_uploads);
        }

        out
    }
}

fn write_us_histogram(out: &mut String, name: &str, label: &str, h: &HistogramSnapshot) {
    for &(le_us, cum) in &h.le_counts {
        let le_sec = (le_us as f64) / 1_000_000.0;
        let _ = writeln!(out, "{name}_bucket{{{label},le=\"{le_sec}\"}} {cum}");
    }
    let _ = writeln!(out, "{name}_bucket{{{label},le=\"+Inf\"}} {}", h.inf_count);
    let sum_sec = (h.sum as f64) / 1_000_000.0;
    let _ = writeln!(out, "{name}_sum{{{label}}} {sum_sec:.6}");
    let _ = writeln!(out, "{name}_count{{{label}}} {}", h.count);
}

fn write_raw_histogram(out: &mut String, name: &str, h: &HistogramSnapshot) {
    for &(le, cum) in &h.le_counts {
        let _ = writeln!(out, "{name}_bucket{{le=\"{le}\"}} {cum}");
    }
    let _ = writeln!(out, "{name}_bucket{{le=\"+Inf\"}} {}", h.inf_count);
    let _ = writeln!(out, "{name}_sum {}", h.sum);
    let _ = writeln!(out, "{name}_count {}", h.count);
}
