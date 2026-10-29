//! Error and panic capture that attaches to the active trace.

use opentelemetry::trace::{Span, Status, TraceContextExt, Tracer, TracerProvider};
use opentelemetry::{Context, KeyValue};
use opentelemetry_sdk::trace::SdkTracerProvider;

fn exception_attrs(kind: &str, msg: &str, stack: Option<String>) -> Vec<KeyValue> {
    let mut a = vec![
        KeyValue::new("exception.type", kind.to_string()),
        KeyValue::new("exception.message", msg.to_string()),
    ];
    if let Some(s) = stack {
        a.push(KeyValue::new("exception.stacktrace", s));
    }
    a
}

/// Records `err` as an `exception` event on the span active in `cx` and marks it failed, so the
/// error links to its trace and span ids.
pub fn record_error(cx: &Context, err: &(dyn std::error::Error + 'static)) {
    let span = cx.span();
    let msg = err.to_string();
    span.add_event("exception", exception_attrs(std::any::type_name_of_val(err), &msg, None));
    span.set_status(Status::error(msg));
}

/// Installs a panic hook that reports each panic as a `panic` span (child of the active span)
/// with an `exception` event and flushes `provider` before the previous hook runs. Each call
/// chains onto whatever hook was set before.
pub fn capture_panics(provider: &SdkTracerProvider) {
    let provider = provider.clone();
    let prev = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let msg = info
            .payload()
            .downcast_ref::<&str>()
            .map(|s| (*s).to_string())
            .or_else(|| info.payload().downcast_ref::<String>().cloned())
            .unwrap_or_else(|| "panic".to_string());
        let mut attrs = exception_attrs(
            "panic",
            &msg,
            Some(std::backtrace::Backtrace::force_capture().to_string()),
        );
        if let Some(l) = info.location() {
            attrs.push(KeyValue::new("code.file.path", l.file().to_string()));
            attrs.push(KeyValue::new("code.line.number", i64::from(l.line())));
        }
        let tracer = provider.tracer("watchtower");
        let mut span = tracer.start_with_context("panic", &Context::current());
        span.add_event("exception", attrs);
        span.set_status(Status::error(msg));
        span.end();
        let _ = provider.force_flush();
        prev(info);
    }));
}
