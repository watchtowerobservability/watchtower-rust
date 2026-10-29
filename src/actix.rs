//! actix-web middleware: `App::new().wrap(actix_web::middleware::from_fn(watchtower_sdk::actix::trace))`.
//! CI only compiles this (all-features build); it is not exercised against a live actix server.

use actix_web::Error;
use actix_web::body::MessageBody;
use actix_web::dev::{ServiceRequest, ServiceResponse};
use actix_web::middleware::Next;
use opentelemetry::propagation::{Extractor, TextMapPropagator};
use opentelemetry::trace::{FutureExt, Span, SpanKind, Status, TraceContextExt, Tracer};
use opentelemetry::{Context, KeyValue, global};
use opentelemetry_sdk::propagation::TraceContextPropagator;

struct Headers<'a>(&'a actix_web::http::header::HeaderMap);
impl Extractor for Headers<'_> {
    fn get(&self, k: &str) -> Option<&str> {
        self.0.get(k).and_then(|v| v.to_str().ok())
    }
    fn keys(&self) -> Vec<&str> {
        self.0.keys().map(|k| k.as_str()).collect()
    }
}

/// Pass to `actix_web::middleware::from_fn`.
pub async fn trace<B: MessageBody>(
    req: ServiceRequest,
    next: Next<B>,
) -> Result<ServiceResponse<B>, Error> {
    let tracer = global::tracer("watchtower");
    let parent = TraceContextPropagator::new().extract(&Headers(req.headers()));
    let mut span = tracer
        .span_builder(format!("{} {}", req.method(), req.path()))
        .with_kind(SpanKind::Server)
        .start_with_context(&tracer, &parent);
    span.set_attribute(KeyValue::new("http.request.method", req.method().to_string()));
    span.set_attribute(KeyValue::new("url.path", req.path().to_string()));
    let cx = Context::current_with_span(span);
    let res = next.call(req).with_context(cx.clone()).await;
    let span = cx.span();
    match &res {
        Ok(r) => {
            span.set_attribute(KeyValue::new(
                "http.response.status_code",
                i64::from(r.status().as_u16()),
            ));
            if r.status().is_server_error() {
                span.set_status(Status::error(r.status().to_string()));
            }
        }
        Err(e) => {
            span.add_event("exception", vec![KeyValue::new("exception.message", e.to_string())]);
            span.set_status(Status::error(e.to_string()));
        }
    }
    span.end();
    res
}
