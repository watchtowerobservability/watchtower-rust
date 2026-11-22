#![cfg(all(
    feature = "profiling",
    any(target_os = "linux", target_os = "android", target_vendor = "apple")
))]

use std::hint::black_box;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

#[inline(never)]
fn burn_watchtower_marker(stop: &AtomicBool) -> f64 {
    let mut x = 0.0f64;
    while !stop.load(Ordering::Relaxed) {
        for _ in 0..10_000 {
            x = black_box((x + 1.0).sqrt());
        }
    }
    x
}

/// A handler that took a lock (allocator, loader) would hang here: the threads spend nearly all
/// their time inside malloc and free, and SIGPROF lands there at a high rate.
fn allocator_hammer_does_not_hang() {
    let stop = Arc::new(AtomicBool::new(false));
    let workers: Vec<_> = (0..4)
        .map(|_| {
            let stop = stop.clone();
            std::thread::spawn(move || {
                let mut rounds = 0u64;
                while !stop.load(Ordering::Relaxed) {
                    let v: Vec<Vec<u8>> = (1..64).map(|n| vec![0u8; n * 37]).collect();
                    black_box(&v);
                    rounds += 1;
                }
                rounds
            })
        })
        .collect();
    let folded = watchtower_sdk::profiling::capture(Duration::from_secs(3), 1000).expect("capture");
    stop.store(true, Ordering::Relaxed);
    for w in workers {
        // Joining proves no worker is stuck on a lock the handler interrupted.
        assert!(w.join().expect("worker") > 0);
    }
    assert!(folded.values().sum::<u64>() > 100, "{folded:?}");
}

fn samples_this_process() {
    let stop = Arc::new(AtomicBool::new(false));
    let s2 = stop.clone();
    let worker = std::thread::spawn(move || {
        watchtower_sdk::profiling::with_span(0xabc, 0xdef, || burn_watchtower_marker(&s2))
    });
    let folded = watchtower_sdk::profiling::capture(Duration::from_secs(1), 250).expect("capture");
    stop.store(true, Ordering::Relaxed);
    worker.join().expect("worker");
    assert!(
        folded
            .keys()
            .any(|k| k.starts_with("span_id=0000000000000abc,")
                && k.contains("burn_watchtower_marker")),
        "{folded:?}"
    );
}

// One test: the sampler is one per process, and libtest would run two in parallel.
#[test]
fn profiler_is_safe_and_finds_the_busy_function() {
    samples_this_process();
    allocator_hammer_does_not_hang();
}
