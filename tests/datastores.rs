#![cfg(feature = "datastores")]
use opentelemetry::global;
use opentelemetry::metrics::MeterProvider;
use opentelemetry_sdk::metrics::data::{AggregatedMetrics, MetricData};
use opentelemetry_sdk::metrics::{InMemoryMetricExporter, SdkMeterProvider};
use opentelemetry_sdk::trace::{InMemorySpanExporter, SdkTracerProvider};
use watchtower_sdk::datastore::{self, Op, sqlnorm};

#[test]
fn shared_vectors() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../testdata/sql_normalize_vectors.json");
    let Ok(raw) = std::fs::read_to_string(path) else {
        eprintln!("shared vectors not in this checkout; skipped");
        return;
    };
    let v: serde_json::Value = serde_json::from_str(&raw).unwrap();
    let vectors = v["vectors"].as_array().unwrap();
    assert!(!vectors.is_empty());
    for t in vectors {
        let name = t["name"].as_str().unwrap();
        let norm = sqlnorm::normalize(t["input"].as_str().unwrap(), t["pg"].as_bool().unwrap());
        assert_eq!(norm, t["normalized"].as_str().unwrap(), "{name}");
        assert_eq!(sqlnorm::hash(&norm), t["hash"].as_str().unwrap(), "{name}");
    }
}

#[test]
fn summary_like_node() {
    for (text, op, table) in [
        ("SELECT * FROM users WHERE id = ?", "SELECT", "users"),
        ("update \"public\".\"jobs\" set a = ?", "UPDATE", "public.jobs"),
        ("WITH x AS (SELECT ?) DELETE FROM t", "DELETE", "t"),
        ("PRAGMA wal_checkpoint(TRUNCATE)", "PRAGMA", ""),
    ] {
        assert_eq!(sqlnorm::summary(text), (op.to_string(), table.to_string()), "{text}");
    }
}

#[test]
fn span_and_statement_record_no_values() {
    let ex = InMemorySpanExporter::default();
    global::set_tracer_provider(SdkTracerProvider::builder().with_simple_exporter(ex.clone()).build());
    let op = Op { system: "sled", namespace: Some("/d"), operation: "insert", collection: Some("jobs") };
    let r: Result<(), String> = datastore::span(&op, || Err("boom".into()));
    assert!(r.is_err());
    datastore::sqlite_profile("delete from jobs where owner = 'alice@example.com'", std::time::Duration::from_millis(3));
    let spans = ex.get_finished_spans().unwrap();
    let ins = spans.iter().find(|s| s.name == "insert jobs").expect("store span");
    assert!(matches!(ins.status, opentelemetry::trace::Status::Error { .. }));
    let del = spans.iter().find(|s| s.name == "DELETE jobs").expect("statement span");
    assert!(del.attributes.iter().any(|kv| kv.key.as_str() == "db.query.hash"));
    assert!(!format!("{:?}", del.attributes).contains("alice"));
    assert!(del.end_time.duration_since(del.start_time).unwrap() >= std::time::Duration::from_millis(3));
}

fn collect(mp: &SdkMeterProvider, ex: &InMemoryMetricExporter) -> Vec<(String, u64)> {
    mp.force_flush().unwrap();
    ex
        .get_finished_metrics()
        .unwrap()
        .iter()
        .flat_map(|rm| rm.scope_metrics().flat_map(|sm| sm.metrics()))
        .filter_map(|m| match m.data() {
            AggregatedMetrics::U64(MetricData::Sum(s)) => s.data_points().next().map(|p| (m.name().to_string(), p.value())),
            AggregatedMetrics::U64(MetricData::Gauge(g)) => g.data_points().next().map(|p| (m.name().to_string(), p.value())),
            _ => None,
        })
        .collect()
}

#[test]
fn observe_reports_known_names_until_dropped() {
    let ex = InMemoryMetricExporter::default();
    let mp = SdkMeterProvider::builder().with_periodic_exporter(ex.clone()).build();
    let h = datastore::observe(&mp.meter("t"), "custom", "ns", |r| {
        r.set("wt.embedded.cache.hits", 7);
        r.set("not.ours", 1);
    });
    let names = collect(&mp, &ex);
    assert!(names.contains(&("wt.embedded.cache.hits".to_string(), 7)), "{names:?}");
    assert!(!names.iter().any(|(n, _)| n == "not.ours"));
    drop(h);
}

#[cfg(feature = "moka")]
#[test]
fn moka_entry_count() {
    let ex = InMemoryMetricExporter::default();
    let mp = SdkMeterProvider::builder().with_periodic_exporter(ex.clone()).build();
    let c: moka::sync::Cache<u32, u32> = moka::sync::Cache::new(10);
    c.insert(1, 1);
    c.run_pending_tasks();
    let _h = datastore::stores::observe_moka(&mp.meter("t"), &c, "sessions");
    assert!(collect(&mp, &ex).contains(&("wt.embedded.keys".to_string(), 1)));
}

#[cfg(feature = "sled")]
#[test]
fn sled_size_on_disk() {
    let ex = InMemoryMetricExporter::default();
    let mp = SdkMeterProvider::builder().with_periodic_exporter(ex.clone()).build();
    let dir = tempfile::tempdir().unwrap();
    let db = sled::open(dir.path()).unwrap();
    db.insert(b"k", b"v".to_vec()).unwrap();
    db.flush().unwrap();
    let _h = datastore::stores::observe_sled(&mp.meter("t"), &db, "sled");
    assert!(collect(&mp, &ex).iter().any(|(n, v)| n == "wt.embedded.file.size" && *v > 0));
}
