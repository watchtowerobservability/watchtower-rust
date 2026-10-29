use opentelemetry::global;
use opentelemetry::trace::{Span, TraceContextExt, Tracer};
use opentelemetry_sdk::trace::{InMemorySpanExporter, SdkTracerProvider};

fn provider() -> (SdkTracerProvider, InMemorySpanExporter) {
    let ex = InMemorySpanExporter::default();
    let p = SdkTracerProvider::builder().with_simple_exporter(ex.clone()).build();
    global::set_tracer_provider(p.clone());
    (p, ex)
}

// The global tracer provider is process-wide, so each test builds its own exporter and only
// looks at spans it caused (distinct names / trace ids).
#[test]
fn panic_hook_links_to_active_span() {
    let (p, ex) = provider();
    watchtower_sdk::capture_panics(&p);
    let span = global::tracer("t").start("request");
    let tid = span.span_context().trace_id();
    let cx = opentelemetry::Context::current_with_span(span);
    let _g = cx.attach();
    let _ = std::panic::catch_unwind(|| panic!("boom"));
    let spans = ex.get_finished_spans().unwrap();
    let s = spans.iter().find(|s| s.name == "panic").expect("panic span");
    assert_eq!(s.span_context.trace_id(), tid);
    assert!(s.events.events.iter().any(|e| e.name == "exception"
        && e.attributes
            .iter()
            .any(|a| a.key.as_str() == "exception.message" && a.value.as_str() == "boom")));
}

#[cfg(feature = "tower")]
#[tokio::test]
async fn tower_layer_marks_5xx() {
    use tower::{ServiceBuilder, ServiceExt, service_fn};
    let (_p, ex) = provider();
    let svc = ServiceBuilder::new()
        .layer(watchtower_sdk::layer::WatchtowerLayer)
        .service(service_fn(|_r: http::Request<()>| async {
            Ok::<_, std::convert::Infallible>(http::Response::builder().status(503).body(()).unwrap())
        }));
    let req = http::Request::get("/x")
        .header("traceparent", "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01")
        .body(())
        .unwrap();
    svc.oneshot(req).await.unwrap();
    let spans = ex.get_finished_spans().unwrap();
    let s = spans.iter().find(|s| s.name == "GET /x").expect("server span");
    assert_eq!(s.span_context.trace_id().to_string(), "0af7651916cd43dd8448eb211c80319c");
    assert!(matches!(s.status, opentelemetry::trace::Status::Error { .. }));
}

#[cfg(feature = "tracing")]
#[test]
fn tracing_layer_exports_spans() {
    use tracing_subscriber::layer::SubscriberExt;
    let (p, ex) = provider();
    let sub = tracing_subscriber::registry().with(watchtower_sdk::tracing_layer::layer(&p));
    tracing::subscriber::with_default(sub, || {
        tracing::info_span!("work").in_scope(|| ());
    });
    assert!(ex.get_finished_spans().unwrap().iter().any(|s| s.name == "work"));
}
