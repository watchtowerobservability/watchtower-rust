//! Embedded and in-memory datastores (feature `datastores`): client spans with OTel db semconv and
//! `wt.embedded.*` health metrics. Keys, values and raw statements are never recorded.
//!
//! - Any store: wrap a call in [`span`]; report its stats with [`observe`].
//! - SQLite via rusqlite (any version with `Connection::profile`, feature `trace`):
//!   `conn.profile(Some(watchtower_sdk::datastore::sqlite_profile))`. Newer `trace_v2` users call
//!   [`record_statement`] from their callback. File and WAL size: [`observe_files`].
//! - RocksDB (any binding): [`observe_rocksdb`] with a property reader closure.
//! - sled, redb, heed (LMDB) and moka: features of the same names, see [`stores`].

pub mod sqlnorm;
#[cfg(any(feature = "sled", feature = "redb", feature = "heed", feature = "moka"))]
pub mod stores;

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use opentelemetry::metrics::{Meter, ObservableCounter, ObservableGauge};
use opentelemetry::trace::{Span, SpanKind, Status, TraceContextExt, Tracer};
use opentelemetry::{Context, KeyValue, global};

/// Gauges (current value) the backend understands, with units.
pub const GAUGES: &[(&str, &str)] = &[
    ("wt.embedded.file.size", "By"),
    ("wt.embedded.wal.size", "By"),
    ("wt.embedded.map.size", "By"),
    ("wt.embedded.map.used", "By"),
    ("wt.embedded.memory.used", "By"),
    ("wt.embedded.cache.size", "By"),
    ("wt.embedded.keys", "{key}"),
    ("wt.embedded.compaction.pending", "By"),
    ("wt.embedded.transactions.open", "{transaction}"),
    ("wt.embedded.free_pages", "{page}"),
    ("wt.embedded.levels.files", "{file}"),
    ("wt.embedded.snapshots.open", "{snapshot}"),
    ("wt.embedded.iterators.open", "{iterator}"),
    ("wt.embedded.readers", "{reader}"),
];

/// Counters (cumulative since the store opened).
pub const COUNTERS: &[(&str, &str)] = &[
    ("wt.embedded.cache.hits", "{hit}"),
    ("wt.embedded.cache.misses", "{miss}"),
    ("wt.embedded.cache.evictions", "{key}"),
    ("wt.embedded.cache.rejections", "{key}"),
    ("wt.embedded.lock.waits", "{wait}"),
    ("wt.embedded.lock.wait_time", "ms"),
    ("wt.embedded.compactions", "{compaction}"),
    ("wt.embedded.compaction.duration", "ms"),
    ("wt.embedded.flushes", "{flush}"),
    ("wt.embedded.transactions", "{transaction}"),
    ("wt.embedded.bytes.written", "By"),
    ("wt.embedded.bytes.read", "By"),
];

/// One store operation.
#[derive(Debug, Clone, Copy)]
pub struct Op<'a> {
    /// `db.system.name`: "sled", "redb", "lmdb", "rocksdb", "sqlite", ...
    pub system: &'a str,
    /// `db.namespace`: file path or logical name.
    pub namespace: Option<&'a str>,
    /// `db.operation.name`: "get", "insert", "transaction", ...
    pub operation: &'a str,
    /// `db.collection.name`: tree, table, column family.
    pub collection: Option<&'a str>,
}

fn op_attrs(op: &Op<'_>) -> Vec<KeyValue> {
    let mut a = vec![
        KeyValue::new("db.system.name", op.system.to_string()),
        KeyValue::new("db.operation.name", op.operation.to_string()),
    ];
    if let Some(n) = op.namespace {
        a.push(KeyValue::new("db.namespace", n.to_string()));
    }
    if let Some(c) = op.collection {
        a.push(KeyValue::new("db.collection.name", c.to_string()));
    }
    a
}

/// Run `f` inside a client span for `op` (current while `f` runs); an `Err` marks the span failed
/// and is returned unchanged.
pub fn span<T, E: std::fmt::Display>(op: &Op<'_>, f: impl FnOnce() -> Result<T, E>) -> Result<T, E> {
    let tracer = global::tracer("watchtower.datastores");
    let name = match op.collection {
        Some(c) => format!("{} {c}", op.operation),
        None => op.operation.to_string(),
    };
    let s = tracer
        .span_builder(name)
        .with_kind(SpanKind::Client)
        .with_attributes(op_attrs(op))
        .start(&tracer);
    let cx = Context::current_with_span(s);
    let res = {
        let _g = cx.clone().attach();
        f()
    };
    let s = cx.span();
    if let Err(e) = &res {
        s.set_status(Status::error(e.to_string()));
        s.set_attribute(KeyValue::new("error.type", "_OTHER"));
    }
    s.end();
    res
}

/// Record one finished SQL statement as a client span ending now: hash and summary only.
pub fn record_statement(system: &str, namespace: Option<&str>, sql: &str, took: Duration) {
    let tracer = global::tracer("watchtower.datastores");
    let mut attrs = sqlnorm::attributes(system, sql, false);
    let name = attrs
        .iter()
        .find(|kv| kv.key.as_str() == "db.query.summary")
        .map_or_else(|| system.to_string(), |kv| kv.value.as_str().into_owned());
    attrs.push(KeyValue::new("db.system.name", system.to_string()));
    if let Some(n) = namespace {
        attrs.push(KeyValue::new("db.namespace", n.to_string()));
    }
    let end = SystemTime::now();
    let mut s = tracer
        .span_builder(name)
        .with_kind(SpanKind::Client)
        .with_start_time(end.checked_sub(took).unwrap_or(end))
        .with_attributes(attrs)
        .start(&tracer);
    s.end_with_timestamp(end);
}

/// For `rusqlite::Connection::profile(Some(sqlite_profile))`.
pub fn sqlite_profile(sql: &str, took: Duration) {
    record_statement("sqlite", None, sql, took);
}

/// Readings taken by an [`observe`] callback. Names outside [`GAUGES`] and [`COUNTERS`] are ignored.
#[derive(Debug, Default)]
pub struct Readings(Vec<(&'static str, u64)>);

impl Readings {
    pub fn set(&mut self, name: &'static str, v: u64) {
        self.0.push((name, v));
    }
}

type ReadFn = Box<dyn Fn(&mut Readings) + Send>;

struct Source {
    attrs: Vec<KeyValue>,
    read: Mutex<Option<ReadFn>>,
    cache: Mutex<(Option<Instant>, Vec<(&'static str, u64)>)>,
}

impl Source {
    /// One read per collection: the instruments share a reading for a second.
    fn value(&self, name: &str) -> Option<u64> {
        let mut c = self.cache.lock().ok()?;
        if c.0.is_none_or(|t| t.elapsed() > Duration::from_secs(1)) {
            let mut r = Readings::default();
            if let Some(f) = self.read.lock().ok()?.as_ref() {
                f(&mut r);
            }
            *c = (Some(Instant::now()), r.0);
        }
        c.1.iter().find(|(n, _)| *n == name).map(|&(_, v)| v)
    }
}

/// Keeps an [`observe`] registration alive; dropping it stops the readings and frees the store.
pub struct Handle {
    src: Arc<Source>,
    _gauges: Vec<ObservableGauge<u64>>,
    _counters: Vec<ObservableCounter<u64>>,
}

impl Drop for Handle {
    fn drop(&mut self) {
        if let Ok(mut r) = self.src.read.lock() {
            *r = None;
        }
        if let Ok(mut c) = self.src.cache.lock() {
            *c = (None, Vec::new()); // the next read finds no reader and reports nothing
        }
    }
}

/// Call `read` at each metric collection, tagged {db.system.name, db.namespace}. Use the meter of
/// the provider you installed (`global::meter("watchtower")` after `set_meter_provider`).
pub fn observe(
    meter: &Meter,
    system: &str,
    namespace: &str,
    read: impl Fn(&mut Readings) + Send + 'static,
) -> Handle {
    let src = Arc::new(Source {
        attrs: vec![
            KeyValue::new("db.system.name", system.to_string()),
            KeyValue::new("db.namespace", namespace.to_string()),
        ],
        read: Mutex::new(Some(Box::new(read))),
        cache: Mutex::new((None, Vec::new())),
    });
    let gauges = GAUGES
        .iter()
        .map(|&(name, unit)| {
            let s = src.clone();
            meter
                .u64_observable_gauge(name)
                .with_unit(unit)
                .with_callback(move |o| {
                    if let Some(v) = s.value(name) {
                        o.observe(v, &s.attrs);
                    }
                })
                .build()
        })
        .collect();
    let counters = COUNTERS
        .iter()
        .map(|&(name, unit)| {
            let s = src.clone();
            meter
                .u64_observable_counter(name)
                .with_unit(unit)
                .with_callback(move |o| {
                    if let Some(v) = s.value(name) {
                        o.observe(v, &s.attrs);
                    }
                })
                .build()
        })
        .collect();
    Handle { src, _gauges: gauges, _counters: counters }
}

fn file_size(path: &str) -> Option<u64> {
    std::fs::metadata(path).ok().map(|m| m.len())
}

/// File and WAL size of a file-backed store (SQLite: path + "-wal"; DuckDB: path + ".wal").
pub fn observe_files(meter: &Meter, system: &str, path: &str, wal_path: Option<&str>) -> Handle {
    let (p, w) = (path.to_string(), wal_path.map(str::to_string));
    observe(meter, system, path, move |r| {
        if let Some(n) = file_size(&p) {
            r.set("wt.embedded.file.size", n);
        }
        if let Some(n) = w.as_deref().and_then(file_size) {
            r.set("wt.embedded.wal.size", n);
        }
    })
}

/// RocksDB properties as `wt.embedded.*`: pass a reader such as
/// `move |p| db.property_int_value(p).ok().flatten()` (rust-rocksdb), so any binding works.
pub fn observe_rocksdb(
    meter: &Meter,
    namespace: &str,
    prop: impl Fn(&str) -> Option<u64> + Send + 'static,
) -> Handle {
    const PROPS: &[(&str, &str)] = &[
        ("wt.embedded.keys", "rocksdb.estimate-num-keys"),
        ("wt.embedded.cache.size", "rocksdb.block-cache-usage"),
        ("wt.embedded.compaction.pending", "rocksdb.estimate-pending-compaction-bytes"),
        ("wt.embedded.memory.used", "rocksdb.cur-size-all-mem-tables"),
        ("wt.embedded.file.size", "rocksdb.total-sst-files-size"),
        ("wt.embedded.snapshots.open", "rocksdb.num-snapshots"),
    ];
    observe(meter, "rocksdb", namespace, move |r| {
        for &(name, p) in PROPS {
            if let Some(v) = prop(p) {
                r.set(name, v);
            }
        }
    })
}
