//! Which span each thread is in, readable from a signal handler and from another thread (Windows
//! sampler): a fixed table of atomics keyed by OS thread id, each slot guarded by a sequence.

use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::task::{Context, Poll};

const SLOTS: usize = 1024;

/// `(span id, trace id)`; zero means no span.
pub type SpanIds = (u64, u128);

struct Slot {
    tid: AtomicU64,
    seq: AtomicU32,
    span: AtomicU64,
    hi: AtomicU64,
    lo: AtomicU64,
}

static TABLE: [Slot; SLOTS] = [const {
    Slot {
        tid: AtomicU64::new(0),
        seq: AtomicU32::new(0),
        span: AtomicU64::new(0),
        hi: AtomicU64::new(0),
        lo: AtomicU64::new(0),
    }
}; SLOTS];

fn start(tid: u64) -> usize {
    (tid.wrapping_mul(0x9E37_79B9_7F4A_7C15) >> 54) as usize % SLOTS
}

/// Async-signal-safe (atomics only). A write in progress reads as no span.
pub(crate) fn current(tid: u64) -> SpanIds {
    let first = start(tid);
    for i in 0..SLOTS {
        let s = &TABLE[(first + i) % SLOTS];
        match s.tid.load(Ordering::Acquire) {
            0 => return (0, 0),
            t if t == tid => {
                let a = s.seq.load(Ordering::Acquire);
                let v = (
                    s.span.load(Ordering::Acquire),
                    (u128::from(s.hi.load(Ordering::Acquire)) << 64)
                        | u128::from(s.lo.load(Ordering::Acquire)),
                );
                return if a & 1 == 0 && s.seq.load(Ordering::Acquire) == a {
                    v
                } else {
                    (0, 0)
                };
            }
            _ => {}
        }
    }
    (0, 0)
}

/// A slot whose thread has exited: free to claim, and probes go on past it.
const TOMBSTONE: u64 = u64::MAX;

/// Sets this thread's span. A full table just leaves the thread unlabeled. A thread's slot is
/// released when the thread exits (see [`Release`]), so churning threads do not fill the table.
fn set(tid: u64, ids: SpanIds) {
    RELEASE.with(|_| {}); // registers this thread's exit hook
    let first = start(tid);
    for _ in 0..4 {
        // This thread's slot, else the first free one along its probe sequence.
        let mut free = None;
        for i in 0..SLOTS {
            let s = &TABLE[(first + i) % SLOTS];
            match s.tid.load(Ordering::Acquire) {
                t if t == tid => return write(s, ids),
                0 => {
                    free = free.or(Some((s, 0)));
                    break;
                }
                TOMBSTONE => free = free.or(Some((s, TOMBSTONE))),
                _ => {}
            }
        }
        let Some((s, was)) = free else { return };
        if ids == (0, 0) {
            return; // nothing to clear on a thread that never had a slot
        }
        if s.tid
            .compare_exchange(was, tid, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            return write(s, ids);
        }
        // another thread claimed it first: look again
    }
}

fn write(s: &Slot, ids: SpanIds) {
    s.seq.fetch_add(1, Ordering::AcqRel);
    s.span.store(ids.0, Ordering::Release);
    s.hi.store((ids.1 >> 64) as u64, Ordering::Release);
    s.lo.store(ids.1 as u64, Ordering::Release);
    s.seq.fetch_add(1, Ordering::AcqRel);
}

/// Frees the exiting thread's slot: its span is cleared first, so a sample never reads it under
/// the next owner.
struct Release;

impl Drop for Release {
    fn drop(&mut self) {
        let tid = super::thread_id();
        let first = start(tid);
        for i in 0..SLOTS {
            let s = &TABLE[(first + i) % SLOTS];
            match s.tid.load(Ordering::Acquire) {
                0 => return,
                t if t == tid => {
                    write(s, (0, 0));
                    s.tid.store(TOMBSTONE, Ordering::Release);
                    return;
                }
                _ => {}
            }
        }
    }
}

thread_local! {
    static RELEASE: Release = const { Release };
}

/// Runs `f` with samples on this thread labeled with the span, restoring the previous one after.
/// For async code use [`with_span_async`], which follows the task across `.await`.
pub fn with_span<R>(span_id: u64, trace_id: u128, f: impl FnOnce() -> R) -> R {
    struct Restore(u64, SpanIds);
    impl Drop for Restore {
        fn drop(&mut self) {
            set(self.0, self.1);
        }
    }
    let tid = super::thread_id();
    let _restore = Restore(tid, current(tid));
    set(tid, (span_id, trace_id));
    f()
}

/// Labels every poll of `fut` with the span, on whichever thread polls it, so an async task stays
/// labeled across `.await`. Time the task spends suspended is not labeled.
pub fn with_span_async<F: Future>(span_id: u64, trace_id: u128, fut: F) -> SpanFuture<F> {
    SpanFuture {
        ids: (span_id, trace_id),
        inner: Box::pin(fut),
    }
}

/// A future whose polls run under a span; see [`with_span_async`].
pub struct SpanFuture<F> {
    ids: SpanIds,
    inner: Pin<Box<F>>,
}

impl<F: Future> Future for SpanFuture<F> {
    type Output = F::Output;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<F::Output> {
        let (span, trace) = self.ids;
        with_span(span, trace, || self.inner.as_mut().poll(cx))
    }
}

/// The `span_id=...,trace_id=...` prefix of a folded line (empty without a span).
pub(crate) fn label_prefix(ids: SpanIds) -> String {
    if ids.0 == 0 {
        return String::new();
    }
    format!("span_id={:016x},trace_id={:032x}\t", ids.0, ids.1)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pending once, then ready.
    struct Yield(bool);

    impl Future for Yield {
        type Output = ();
        fn poll(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<()> {
            if self.0 {
                return Poll::Ready(());
            }
            self.0 = true;
            Poll::Pending
        }
    }

    #[test]
    fn nests_and_restores_per_thread() {
        let me = crate::profiling::thread_id();
        assert_eq!(current(me), (0, 0));
        with_span(7, 9, || {
            assert_eq!(current(me), (7, 9));
            with_span(8, 9, || assert_eq!(current(me), (8, 9)));
            assert_eq!(current(me), (7, 9));
        });
        assert_eq!(current(me), (0, 0));
        // An exited thread's slot is free again.
        let gone = std::thread::spawn(|| {
            let tid = crate::profiling::thread_id();
            with_span(1, 1, || ());
            set(tid, (3, 4));
            tid
        })
        .join()
        .unwrap_or(0);
        assert_eq!(current(gone), (0, 0));
        // Each poll of the future is labeled; between polls the thread is not.
        let mut fut = std::pin::pin!(with_span_async(5, 6, async {
            let first = current(crate::profiling::thread_id());
            Yield(false).await;
            (first, current(crate::profiling::thread_id()))
        }));
        let mut cx = Context::from_waker(std::task::Waker::noop());
        assert!(fut.as_mut().poll(&mut cx).is_pending());
        assert_eq!(current(me), (0, 0));
        assert_eq!(fut.as_mut().poll(&mut cx), Poll::Ready(((5, 6), (5, 6))));
        assert_eq!(
            label_prefix((1, 2)),
            "span_id=0000000000000001,trace_id=00000000000000000000000000000002\t"
        );
    }
}
