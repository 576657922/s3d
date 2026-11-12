use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

pub const FSYNC_LATENCY_BUCKETS_US: [u64; 11] = [
    100, 250, 500, 1_000, 2_500, 5_000, 10_000, 25_000, 50_000, 100_000, 250_000,
];

pub const BATCH_SIZE_BUCKETS: [u64; 7] = [1, 2, 4, 8, 16, 32, 64];

/// Lock-free fixed-bucket Prometheus histogram (`NFR-11`).
pub struct AtomicHistogram<const N: usize> {
    bounds: [u64; N],
    buckets: [AtomicU64; N], // non-cumulative counts per bucket; rendered cumulatively
    inf_bucket: AtomicU64,
    count: AtomicU64,
    sum: AtomicU64,
}

impl<const N: usize> AtomicHistogram<N> {
    pub fn new(bounds: [u64; N]) -> Self {
        Self {
            bounds,
            buckets: std::array::from_fn(|_| AtomicU64::new(0)),
            inf_bucket: AtomicU64::new(0),
            count: AtomicU64::new(0),
            sum: AtomicU64::new(0),
        }
    }

    pub fn observe(&self, val: u64) {
        self.count.fetch_add(1, Ordering::Relaxed);
        self.sum.fetch_add(val, Ordering::Relaxed);
        for (i, &b) in self.bounds.iter().enumerate() {
            if val <= b {
                self.buckets[i].fetch_add(1, Ordering::Relaxed);
                return;
            }
        }
        self.inf_bucket.fetch_add(1, Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> HistogramSnapshot {
        let mut cumulative = 0u64;
        let mut le_counts = Vec::with_capacity(N);
        for i in 0..N {
            cumulative += self.buckets[i].load(Ordering::Relaxed);
            le_counts.push((self.bounds[i], cumulative));
        }
        let inf = cumulative + self.inf_bucket.load(Ordering::Relaxed);
        HistogramSnapshot {
            le_counts,
            inf_count: inf,
            count: self.count.load(Ordering::Relaxed),
            sum: self.sum.load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug, Clone)]
pub struct HistogramSnapshot {
    pub le_counts: Vec<(u64, u64)>,
    pub inf_count: u64,
    pub count: u64,
    pub sum: u64,
}

pub struct EngineTelemetry {
    pub wal_fsync_us: AtomicHistogram<11>,
    pub seg_fsync_us: AtomicHistogram<11>,
    pub ckpt_fsync_us: AtomicHistogram<11>,
    pub group_commit_batch_size: AtomicHistogram<7>,
    pub gc_runs_total: AtomicU64,
    pub gc_compacted_segments_total: AtomicU64,
    pub gc_relocated_bytes_total: AtomicU64,
    pub gc_in_progress: AtomicBool,
    pub checkpoints_total: AtomicU64,
    pub last_checkpoint_lsn: AtomicU64,
}

impl Default for EngineTelemetry {
    fn default() -> Self {
        Self {
            wal_fsync_us: AtomicHistogram::new(FSYNC_LATENCY_BUCKETS_US),
            seg_fsync_us: AtomicHistogram::new(FSYNC_LATENCY_BUCKETS_US),
            ckpt_fsync_us: AtomicHistogram::new(FSYNC_LATENCY_BUCKETS_US),
            group_commit_batch_size: AtomicHistogram::new(BATCH_SIZE_BUCKETS),
            gc_runs_total: AtomicU64::new(0),
            gc_compacted_segments_total: AtomicU64::new(0),
            gc_relocated_bytes_total: AtomicU64::new(0),
            gc_in_progress: AtomicBool::new(false),
            checkpoints_total: AtomicU64::new(0),
            last_checkpoint_lsn: AtomicU64::new(0),
        }
    }
}

#[derive(Debug, Clone)]
pub struct EngineMetricsSnapshot {
    pub wal_fsync_us: HistogramSnapshot,
    pub seg_fsync_us: HistogramSnapshot,
    pub ckpt_fsync_us: HistogramSnapshot,
    pub group_commit_batch_size: HistogramSnapshot,
    pub wal_bytes: u64,
    pub segment_live_bytes: u64,
    pub segment_total_bytes: u64,
    pub segment_live_ratio: f64,
    pub gc_runs_total: u64,
    pub gc_compacted_segments_total: u64,
    pub gc_relocated_bytes_total: u64,
    pub gc_in_progress: bool,
    pub checkpoints_total: u64,
    pub last_checkpoint_lsn: u64,
    pub catalog_buckets: u64,
    pub catalog_object_versions: u64,
    pub catalog_open_uploads: u64,
}
