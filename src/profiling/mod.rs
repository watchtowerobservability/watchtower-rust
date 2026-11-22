//! Continuous CPU profiler (feature `profiling`), our own sampler, no native agent:
//! - Linux and Apple: `setitimer(ITIMER_PROF)` delivers `SIGPROF` to the thread burning CPU; the
//!   handler walks frame pointers (async-signal-safe, see `unix.rs`) into a lock-free ring.
//! - Windows x86-64 and arm64: a sampler thread suspends each thread that used cycles since the
//!   last round, copies its context and stack, resumes it and unwinds the copy.
//!
//! Every `period`, off the signal path, the stacks are symbolized (`backtrace::resolve`), folded and posted to the
//! gateway's Pyroscope-compatible `/ingest` as `<service>.cpu` (format `folded`). Uploads are best
//! effort. One profiler per process.

#[cfg(all(
    any(target_os = "linux", target_os = "android", target_vendor = "apple"),
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
mod unix;
#[cfg(all(
    any(target_os = "linux", target_os = "android", target_vendor = "apple"),
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
use unix::{Sampler, thread_id};
#[cfg(all(windows, any(target_arch = "x86_64", target_arch = "aarch64")))]
mod windows;
#[cfg(not(any(
    all(
        any(target_os = "linux", target_os = "android", target_vendor = "apple"),
        any(target_arch = "x86_64", target_arch = "aarch64")
    ),
    all(windows, any(target_arch = "x86_64", target_arch = "aarch64"))
)))]
use unsupported::{Sampler, thread_id};
#[cfg(all(windows, any(target_arch = "x86_64", target_arch = "aarch64")))]
use windows::{Sampler, thread_id};
#[cfg(not(any(
    all(
        any(target_os = "linux", target_os = "android", target_vendor = "apple"),
        any(target_arch = "x86_64", target_arch = "aarch64")
    ),
    all(windows, any(target_arch = "x86_64", target_arch = "aarch64"))
)))]
mod unsupported {
    pub(crate) fn thread_id() -> u64 {
        0
    }
    pub(crate) struct Sampler;
    impl Sampler {
        pub(crate) fn new(_: u32) -> std::io::Result<Self> {
            Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "profiling needs Linux, Apple or Windows on x86-64 or aarch64",
            ))
        }
        pub(crate) fn tick(&self) -> std::time::Duration {
            std::time::Duration::from_millis(100)
        }
        pub(crate) fn wait(&self) {
            std::thread::sleep(self.tick());
        }
        pub(crate) fn collect(&mut self, _: &mut super::Stacks) {}
        pub(crate) fn on_sampler_thread(&self) {}
    }
}

mod spans;
pub use spans::{SpanFuture, SpanIds, with_span, with_span_async};

use std::collections::{BTreeMap, HashMap};
use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::thread::JoinHandle;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Frames kept per sample (leaf first).
pub(crate) const DEPTH: usize = 64;

/// Raw stacks (instruction pointers, leaf first) with their span, and their sample counts.
pub type Stacks = HashMap<(Vec<usize>, SpanIds), u64>;

#[derive(Clone)]
pub struct ProfilerConfig {
    api_key: String,
    pub endpoint: String,
    pub service: String,
    pub tags: BTreeMap<String, String>,
    /// Samples per second (per CPU-busy thread), 1..=1000. Default 100.
    pub hz: u32,
    /// Upload interval. Default 15 s.
    pub period: Duration,
}

impl std::fmt::Debug for ProfilerConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProfilerConfig")
            .field("endpoint", &self.endpoint)
            .field("service", &self.service)
            .finish_non_exhaustive()
    }
}

impl ProfilerConfig {
    #[must_use]
    pub fn new(api_key: &str, endpoint: Option<&str>, service: &str) -> Self {
        Self {
            api_key: api_key.to_string(),
            endpoint: endpoint
                .unwrap_or(crate::DEFAULT_ENDPOINT)
                .trim_end_matches('/')
                .to_string(),
            service: service.to_string(),
            tags: BTreeMap::new(),
            hz: 100,
            period: Duration::from_secs(15),
        }
    }

    /// `WT_INGEST_KEY`, `WT_OTLP_ENDPOINT`, `WT_SERVICE` (else `service`), `WT_ENVIRONMENT`, `WT_RELEASE`.
    #[must_use]
    pub fn from_env(service: &str) -> Self {
        let get = |k: &str| std::env::var(k).ok().filter(|v| !v.is_empty());
        let mut c = Self::new(
            &get("WT_INGEST_KEY").unwrap_or_default(),
            get("WT_OTLP_ENDPOINT").as_deref(),
            &get("WT_SERVICE").unwrap_or_else(|| service.to_string()),
        );
        for (tag, var) in [("env", "WT_ENVIRONMENT"), ("version", "WT_RELEASE")] {
            if let Some(v) = get(var) {
                c.tags.insert(tag.into(), v);
            }
        }
        c
    }

    pub(crate) fn ingest_url(&self, from_s: u64, until_s: u64) -> String {
        let labels: Vec<String> = self
            .tags
            .iter()
            .filter(|(_, v)| !v.is_empty())
            .map(|(k, v)| format!("{k}={v}"))
            .collect();
        let name = format!("{}.cpu{{{}}}", self.service, labels.join(","));
        format!(
            "{}/ingest?name={}&from={from_s}&until={until_s}&format=folded&sampleRate={}&units=samples&spyName=watchtower-rust",
            self.endpoint,
            encode(&name),
            self.hz
        )
    }
}

fn encode(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                (b as char).to_string()
            }
            _ => format!("%{b:02X}"),
        })
        .collect()
}

/// Upload counters.
#[derive(Debug, Default)]
pub struct Stats {
    pub uploaded: AtomicU64,
    pub dropped: AtomicU64,
}

/// A running profiler; dropping it stops sampling.
pub struct Profiler {
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
    pub stats: Arc<Stats>,
}

impl Drop for Profiler {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

/// Folds raw stacks into `root;...;leaf` lines.
pub fn fold(
    stacks: &Stacks,
    resolve: &mut dyn FnMut(usize) -> Option<String>,
) -> HashMap<String, u64> {
    let mut names: HashMap<usize, String> = HashMap::new();
    let mut out = HashMap::new();
    for ((ips, ids), n) in stacks {
        let mut frames: Vec<String> = ips
            .iter()
            .enumerate()
            .map(|(i, &ip)| {
                let pc = if i == 0 { ip } else { ip.saturating_sub(1) }; // a return address points past its call
                names
                    .entry(pc)
                    .or_insert_with(|| {
                        resolve(pc)
                            .unwrap_or_else(|| format!("0x{pc:x}"))
                            .replace(';', ":")
                    })
                    .clone()
            })
            .collect();
        if frames.is_empty() {
            continue;
        }
        frames.reverse();
        *out.entry(format!("{}{}", spans::label_prefix(*ids), frames.join(";")))
            .or_insert(0) += n;
    }
    out
}

/// Runs `f` with samples on this thread labeled with the current OpenTelemetry span.
pub fn with_current_span<R>(f: impl FnOnce() -> R) -> R {
    use opentelemetry::trace::TraceContextExt;
    let cx = opentelemetry::Context::current();
    let span = cx.span();
    let sc = span.span_context();
    if !sc.is_valid() {
        return f();
    }
    with_span(
        u64::from_be_bytes(sc.span_id().to_bytes()),
        u128::from_be_bytes(sc.trace_id().to_bytes()),
        f,
    )
}

/// [`with_span_async`] with the current OpenTelemetry span; `fut` runs unlabeled without one.
pub fn with_current_span_async<F: std::future::Future>(fut: F) -> SpanFuture<F> {
    use opentelemetry::trace::TraceContextExt;
    let cx = opentelemetry::Context::current();
    let sc = cx.span().span_context().clone();
    let (span, trace) = if sc.is_valid() {
        (
            u64::from_be_bytes(sc.span_id().to_bytes()),
            u128::from_be_bytes(sc.trace_id().to_bytes()),
        )
    } else {
        (0, 0)
    };
    with_span_async(span, trace, fut)
}

fn resolve(pc: usize) -> Option<String> {
    let mut name = None;
    backtrace::resolve(pc as *mut std::ffi::c_void, |s| {
        if name.is_none() {
            name = s.name().map(|n| format!("{n:#}")); // `{:#}` drops the hash suffix
        }
    });
    name
}

pub(crate) fn body(folded: &HashMap<String, u64>) -> String {
    folded.iter().map(|(k, n)| format!("{k} {n}\n")).collect()
}

fn upload(
    cfg: &ProfilerConfig,
    http: &reqwest::blocking::Client,
    folded: &HashMap<String, u64>,
    from_s: u64,
    stats: &Stats,
) {
    let until = now_s();
    let ok = http
        .post(cfg.ingest_url(from_s, until))
        .bearer_auth(&cfg.api_key)
        .header("content-type", "text/plain")
        .body(body(folded))
        .send()
        .is_ok_and(|r| r.status().is_success());
    (if ok { &stats.uploaded } else { &stats.dropped }).fetch_add(1, Ordering::Relaxed);
}

fn now_s() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Samples this process for `d` and returns the folded stacks.
///
/// # Errors
/// Another profiler runs, the platform is unsupported, or the timer cannot be set.
pub fn capture(d: Duration, hz: u32) -> io::Result<HashMap<String, u64>> {
    let mut s = Sampler::new(hz.clamp(1, 1000))?;
    let mut stacks = Stacks::new();
    let end = Instant::now() + d;
    while Instant::now() < end {
        s.wait();
        s.collect(&mut stacks);
    }
    drop(s);
    Ok(fold(&stacks, &mut resolve))
}

/// Starts the profiler thread.
///
/// # Errors
/// No key, another profiler runs, the platform is unsupported, or the timer cannot be set.
pub fn start(cfg: ProfilerConfig) -> io::Result<Profiler> {
    if cfg.api_key.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "api key is required",
        ));
    }
    let http = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(io::Error::other)?;
    let mut s = Sampler::new(cfg.hz.clamp(1, 1000))?;
    let (stop, stats) = (Arc::new(AtomicBool::new(false)), Arc::new(Stats::default()));
    let (stop2, stats2) = (stop.clone(), stats.clone());
    let thread = std::thread::Builder::new()
        .name("watchtower-profiler".into())
        .spawn(move || {
            s.on_sampler_thread();
            while !stop2.load(Ordering::Relaxed) {
                let (from, began) = (now_s(), Instant::now());
                let mut stacks = Stacks::new();
                while !stop2.load(Ordering::Relaxed) && began.elapsed() < cfg.period {
                    s.wait();
                    s.collect(&mut stacks);
                }
                let folded = fold(&stacks, &mut resolve);
                if !folded.is_empty() {
                    upload(&cfg, &http, &folded, from, &stats2);
                }
            }
        })?;
    Ok(Profiler {
        stop,
        thread: Some(thread),
        stats,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn folds_root_first_with_span_labels() {
        let mut st = Stacks::new();
        st.insert((vec![0x30, 0x41], (0, 0)), 3);
        st.insert((vec![0x30, 0x41], (1, 2)), 4);
        let mut r = |pc: usize| {
            Some(
                match pc {
                    0x30 => "app::leaf",
                    0x40 => "app::main",
                    _ => return None,
                }
                .to_string(),
            )
        };
        assert_eq!(
            fold(&st, &mut r),
            HashMap::from([
                ("app::main;app::leaf".to_string(), 3),
                (
                    "span_id=0000000000000001,trace_id=00000000000000000000000000000002\tapp::main;app::leaf".to_string(),
                    4
                ),
            ])
        );
    }

    #[test]
    fn url_and_body() {
        let mut c =
            ProfilerConfig::new("wtk_example_not_a_real_key", Some("http://gw:4318/"), "api");
        c.tags.insert("env".into(), "prod".into());
        assert!(c.ingest_url(1, 2).starts_with(
            "http://gw:4318/ingest?name=api.cpu%7Benv%3Dprod%7D&from=1&until=2&format=folded"
        ));
        assert!(!format!("{c:?}").contains("wtk_"));
        assert_eq!(body(&HashMap::from([("a;b".to_string(), 2)])), "a;b 2\n");
        assert!(start(ProfilerConfig::new("", None, "x")).is_err());
    }
}
