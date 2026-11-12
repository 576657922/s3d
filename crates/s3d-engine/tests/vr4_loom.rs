//! `VR-4` §3.1 `Loom` exhaustive concurrency permutation checks:
//! 1. `loom_segment_pin_vs_delete`: 2 readers acquiring/dropping `SegmentPin` via `seg_mgr` mutex
//!    vs 1 GC worker removing the segment from `seg_mgr`, marking `SEG_STATE_PENDING_DELETE`,
//!    and invoking `try_reclaim_if_unpinned`. Exhaustively proves:
//!    - Segment file is NEVER unlinked while any reader holds a pin (`0` use-after-delete);
//!    - Segment file is ALWAYS unlinked exactly once after GC + last reader release (`0` leaks, `0` double-unlinks).
//! 2. `loom_group_commit_poison`: 2 writer threads enqueuing ops into group-commit queue vs
//!    1 leader encountering `fsync EIO` and setting `read_only_poisoned`. Exhaustively proves:
//!    - Zero deadlocks or lost wakeups;
//!    - Zero uncommitted catalog writes on `EIO`;
//!    - Irreversible `read_only_poisoned` state.

use std::sync::Arc;

use loom::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use loom::sync::{Condvar, Mutex};
use loom::thread;

const PIN_PENDING_DELETE_BIT: usize = 1usize << (usize::BITS - 1);

struct LoomSegmentSlot {
    pin_state: AtomicUsize,
    unlink_count: AtomicUsize,
}

impl LoomSegmentSlot {
    fn new() -> Self {
        Self {
            pin_state: AtomicUsize::new(0),
            unlink_count: AtomicUsize::new(0),
        }
    }

    fn reclaim_now(&self) {
        self.unlink_count.fetch_add(1, Ordering::SeqCst);
    }

    fn mark_pending_delete_and_maybe_reclaim(&self) {
        let prev = self
            .pin_state
            .fetch_or(PIN_PENDING_DELETE_BIT, Ordering::AcqRel);
        if prev == 0 {
            self.reclaim_now();
        }
    }
}

struct LoomSegmentPin {
    slot: Arc<LoomSegmentSlot>,
}

impl LoomSegmentPin {
    fn try_acquire(mgr: &Mutex<Option<Arc<LoomSegmentSlot>>>) -> Option<Self> {
        let guard = mgr.lock().unwrap();
        let slot = guard.as_ref()?.clone();
        let prev = slot.pin_state.fetch_add(1, Ordering::Relaxed);
        assert_eq!(prev & PIN_PENDING_DELETE_BIT, 0);
        Some(Self { slot })
    }

    fn read_assert_alive(&self) {
        assert_eq!(
            self.slot.unlink_count.load(Ordering::SeqCst),
            0,
            "USE-AFTER-DELETE: segment unlinked while reader holds pin!"
        );
    }
}

impl Drop for LoomSegmentPin {
    fn drop(&mut self) {
        let prev = self.slot.pin_state.fetch_sub(1, Ordering::AcqRel);
        if prev == (PIN_PENDING_DELETE_BIT | 1) {
            self.slot.reclaim_now();
        }
    }
}

#[test]
fn loom_segment_pin_vs_delete() {
    loom::model(|| {
        let slot = Arc::new(LoomSegmentSlot::new());
        let mgr = Arc::new(Mutex::new(Some(Arc::clone(&slot))));

        let mgr_r1 = Arc::clone(&mgr);
        let r1 = thread::spawn(move || {
            if let Some(pin) = LoomSegmentPin::try_acquire(&mgr_r1) {
                pin.read_assert_alive();
                drop(pin);
            }
        });

        let mgr_r2 = Arc::clone(&mgr);
        let r2 = thread::spawn(move || {
            if let Some(pin) = LoomSegmentPin::try_acquire(&mgr_r2) {
                pin.read_assert_alive();
                drop(pin);
            }
        });

        let mgr_gc = Arc::clone(&mgr);
        let slot_gc = Arc::clone(&slot);
        let gc = thread::spawn(move || {
            {
                let mut g = mgr_gc.lock().unwrap();
                *g = None;
            }
            slot_gc.mark_pending_delete_and_maybe_reclaim();
        });

        r1.join().unwrap();
        r2.join().unwrap();
        gc.join().unwrap();

        assert_eq!(
            slot.pin_state.load(Ordering::Acquire),
            PIN_PENDING_DELETE_BIT
        );
        assert_eq!(
            slot.unlink_count.load(Ordering::SeqCst),
            1,
            "segment must be unlinked exactly once (0 leaks, 0 double-unlinks)"
        );
    });
}

struct LoomGroupCommit {
    poisoned: AtomicBool,
    catalog_commits: AtomicUsize,
    queue: Mutex<(usize, Option<Result<(), &'static str>>)>, // (queued_writers, batch_result)
    cv: Condvar,
}

impl LoomGroupCommit {
    fn new() -> Self {
        Self {
            poisoned: AtomicBool::new(false),
            catalog_commits: AtomicUsize::new(0),
            queue: Mutex::new((0, None)),
            cv: Condvar::new(),
        }
    }

    fn writer_submit(&self) -> Result<(), &'static str> {
        if self.poisoned.load(Ordering::Acquire) {
            return Err("ReadOnlyPoisoned");
        }
        let mut g = self.queue.lock().unwrap();
        if self.poisoned.load(Ordering::Acquire) {
            return Err("ReadOnlyPoisoned");
        }
        g.0 += 1;
        while g.1.is_none() {
            g = self.cv.wait(g).unwrap();
        }
        let res = g.1.unwrap();
        drop(g);
        if res.is_ok() {
            self.catalog_commits.fetch_add(1, Ordering::SeqCst);
        }
        res
    }

    fn flusher_inject_eio(&self) {
        let mut g = self.queue.lock().unwrap();
        self.poisoned.store(true, Ordering::Release);
        g.1 = Some(Err("EIO_FSYNC_FAILED"));
        self.cv.notify_all();
    }
}

#[test]
fn loom_group_commit_poison() {
    loom::model(|| {
        let gc = Arc::new(LoomGroupCommit::new());

        let gc1 = Arc::clone(&gc);
        let w1 = thread::spawn(move || gc1.writer_submit());

        let gc2 = Arc::clone(&gc);
        let w2 = thread::spawn(move || gc2.writer_submit());

        let gcf = Arc::clone(&gc);
        let flusher = thread::spawn(move || gcf.flusher_inject_eio());

        let res1 = w1.join().unwrap();
        let res2 = w2.join().unwrap();
        flusher.join().unwrap();

        assert!(res1.is_err());
        assert!(res2.is_err());
        assert!(gc.poisoned.load(Ordering::Acquire));
        assert_eq!(
            gc.catalog_commits.load(Ordering::SeqCst),
            0,
            "EIO batch must never apply uncommitted mutations to in-memory catalog!"
        );
        // Subsequent writes after poison must also immediately fail
        assert_eq!(gc.writer_submit(), Err("ReadOnlyPoisoned"));
    });
}
