//! `tracing` integration: spans and events become OTel spans; `error!` events become
//! `exception` span events via tracing-opentelemetry.

use opentelemetry::trace::TracerProvider;
use opentelemetry_sdk::trace::{SdkTracer, SdkTracerProvider};
use tracing::Subscriber;
use tracing_opentelemetry::OpenTelemetryLayer;
use tracing_subscriber::registry::LookupSpan;

/// Layer to add to a `tracing_subscriber::Registry`, exporting through `provider`.
pub fn layer<S>(provider: &SdkTracerProvider) -> OpenTelemetryLayer<S, SdkTracer>
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    tracing_opentelemetry::layer().with_tracer(provider.tracer("watchtower"))
}
