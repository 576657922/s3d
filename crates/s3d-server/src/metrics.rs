use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

/// Lightweight lock-free/low-overhead Prometheus metrics registry (`NFR-11`).
#[derive(Default)]
pub struct ServerMetrics {
    pub requests_total: AtomicU64,
    pub errors_4xx_total: AtomicU64,
    pub errors_5xx_total: AtomicU64,
    pub bytes_in_total: AtomicU64,
    pub bytes_out_total: AtomicU64,
    pub active_connections: AtomicU64,
    by_op_status: Mutex<HashMap<(&'static str, u16), (u64, u64)>>, // (count, total_micros)
}

impl ServerMetrics {
    pub fn record_request(&self, op: &'static str, status: u16, elapsed_micros: u64) {
        self.requests_total.fetch_add(1, Ordering::Relaxed);
        if (400..500).contains(&status) {
            self.errors_4xx_total.fetch_add(1, Ordering::Relaxed);
        } else if status >= 500 {
            self.errors_5xx_total.fetch_add(1, Ordering::Relaxed);
        }
        let mut map = self.by_op_status.lock().unwrap();
        let entry = map.entry((op, status)).or_insert((0, 0));
        entry.0 += 1;
        entry.1 += elapsed_micros;
    }

    pub fn render_prometheus(&self, read_only_poisoned: bool) -> String {
        let mut out = String::with_capacity(1024);
        out.push_str("# TYPE s3d_requests_total counter\n");
        out.push_str(&format!(
            "s3d_requests_total {}\n",
            self.requests_total.load(Ordering::Relaxed)
        ));
        out.push_str("# TYPE s3d_errors_4xx_total counter\n");
        out.push_str(&format!(
            "s3d_errors_4xx_total {}\n",
            self.errors_4xx_total.load(Ordering::Relaxed)
        ));
        out.push_str("# TYPE s3d_errors_5xx_total counter\n");
        out.push_str(&format!(
            "s3d_errors_5xx_total {}\n",
            self.errors_5xx_total.load(Ordering::Relaxed)
        ));
        out.push_str("# TYPE s3d_active_connections gauge\n");
        out.push_str(&format!(
            "s3d_active_connections {}\n",
            self.active_connections.load(Ordering::Relaxed)
        ));
        out.push_str("# TYPE s3d_read_only_failed gauge\n");
        out.push_str(&format!(
            "s3d_read_only_failed {}\n",
            u8::from(read_only_poisoned)
        ));

        let map = self.by_op_status.lock().unwrap();
        out.push_str("# TYPE s3d_operation_requests_total counter\n");
        for ((op, status), (count, micros)) in map.iter() {
            out.push_str(&format!(
                "s3d_operation_requests_total{{op=\"{op}\",status=\"{status}\"}} {count}\n"
            ));
            out.push_str(&format!(
                "s3d_operation_duration_microseconds_sum{{op=\"{op}\",status=\"{status}\"}} {micros}\n"
            ));
        }
        out
    }
}
