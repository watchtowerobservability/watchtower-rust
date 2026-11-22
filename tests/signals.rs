use opentelemetry_sdk::metrics::Temporality;
use watchtower_sdk::signals::{switch_on, temporality};
use watchtower_sdk::{Config, init_logs, init_metrics};

#[test]
fn delta_unless_the_standard_variable_says_otherwise() {
    assert_eq!(temporality(None), Temporality::Delta);
    assert_eq!(temporality(Some("Cumulative")), Temporality::Cumulative);
    assert_eq!(temporality(Some("lowmemory")), Temporality::LowMemory);
}

#[test]
fn providers_build_and_switches_turn_them_off() {
    // The only test touching these variables, so parallel tests do not race on them.
    let cfg = Config::new("svc", Some("http://127.0.0.1:1"), Some("wtk_fake"));
    let lp = init_logs(&cfg).unwrap().expect("logs are on by default");
    let mp = init_metrics(&cfg).unwrap().expect("metrics are on by default");
    let _ = (lp.shutdown(), mp.shutdown());
    // SAFETY: no other test in this binary reads or writes these variables.
    unsafe {
        std::env::set_var("WATCHTOWER_METRICS", "off");
        std::env::set_var("OTEL_LOGS_EXPORTER", "none");
    }
    assert!(!switch_on("WATCHTOWER_METRICS", "OTEL_METRICS_EXPORTER"));
    assert!(init_metrics(&cfg).unwrap().is_none());
    assert!(init_logs(&cfg).unwrap().is_none());
    unsafe {
        std::env::remove_var("WATCHTOWER_METRICS");
        std::env::remove_var("OTEL_LOGS_EXPORTER");
    }
}

#[cfg(feature = "tracing")]
#[test]
fn tracing_events_become_log_records_with_the_span_ids() {
    use opentelemetry_sdk::logs::{InMemoryLogExporter, SdkLoggerProvider};
    use opentelemetry_sdk::trace::{InMemorySpanExporter, SdkTracerProvider};
    use tracing_subscriber::layer::SubscriberExt;

    let spans = InMemorySpanExporter::default();
    let tp = SdkTracerProvider::builder()
        .with_simple_exporter(spans.clone())
        .build();
    let logs = InMemoryLogExporter::default();
    let lp = SdkLoggerProvider::builder()
        .with_simple_exporter(logs.clone())
        .build();
    let sub = tracing_subscriber::registry()
        .with(watchtower_sdk::tracing_layer::layer(&tp))
        .with(watchtower_sdk::tracing_layer::log_layer(&lp));
    tracing::subscriber::with_default(sub, || {
        tracing::info_span!("op").in_scope(|| tracing::warn!("hello from tracing"));
    });
    let span = spans
        .get_finished_spans()
        .unwrap()
        .into_iter()
        .find(|s| s.name == "op")
        .expect("span");
    let emitted = logs.get_emitted_logs().unwrap();
    let rec = emitted
        .iter()
        .map(|l| &l.record)
        .find(|r| r.body().is_some())
        .expect("log record");
    let tc = rec.trace_context().expect("log record carries the trace context");
    assert_eq!(tc.trace_id, span.span_context.trace_id());
    assert_eq!(tc.span_id, span.span_context.span_id());
}
