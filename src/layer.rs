//! Tower middleware (axum, tonic, hyper): one server span per request, W3C `traceparent`
//! continued, 5xx and service errors recorded on the span.

use std::future::Future;
use std::pin::Pin;
use std::task::{Context as TaskCx, Poll};

use http::{Request, Response};
use opentelemetry::propagation::{Extractor, TextMapPropagator};
use opentelemetry::trace::{FutureExt, Span, SpanKind, Status, TraceContextExt, Tracer};
use opentelemetry::{Context, KeyValue, global};
use opentelemetry_sdk::propagation::TraceContextPropagator;
use tower_layer::Layer;
use tower_service::Service;

struct Headers<'a>(&'a http::HeaderMap);
impl Extractor for Headers<'_> {
    fn get(&self, k: &str) -> Option<&str> {
        self.0.get(k).and_then(|v| v.to_str().ok())
    }
    fn keys(&self) -> Vec<&str> {
        self.0.keys().map(http::HeaderName::as_str).collect()
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct WatchtowerLayer;

impl<S> Layer<S> for WatchtowerLayer {
    type Service = WatchtowerService<S>;
    fn layer(&self, inner: S) -> Self::Service {
        WatchtowerService { inner }
    }
}

#[derive(Clone, Debug)]
pub struct WatchtowerService<S> {
    inner: S,
}

impl<S, B, R> Service<Request<B>> for WatchtowerService<S>
where
    S: Service<Request<B>, Response = Response<R>> + Clone + Send + 'static,
    S::Future: Send + 'static,
    S::Error: std::error::Error + 'static,
    B: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<S::Response, S::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut TaskCx<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<B>) -> Self::Future {
        // Swap in the clone, keeping the instance that was poll_ready'd (tower contract).
        let clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, clone);
        let parent = TraceContextPropagator::new().extract(&Headers(req.headers()));
        let tracer = global::tracer("watchtower");
        let mut span = tracer
            .span_builder(format!("{} {}", req.method(), req.uri().path()))
            .with_kind(SpanKind::Server)
            .start_with_context(&tracer, &parent);
        span.set_attribute(KeyValue::new("http.request.method", req.method().to_string()));
        span.set_attribute(KeyValue::new("url.path", req.uri().path().to_string()));
        let cx = Context::current_with_span(span);
        let fut = inner.call(req);
        let cx2 = cx.clone();
        Box::pin(
            async move {
                let res = fut.await;
                let span = cx2.span();
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
                    Err(e) => crate::record_error(&cx2, e),
                }
                span.end();
                res
            }
            .with_context(cx),
        )
    }
}
