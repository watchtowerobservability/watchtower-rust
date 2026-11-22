//! Logs and metrics: the OpenTelemetry Rust logs and metrics SDKs, exported over OTLP/HTTP to the
//! same endpoint with the same key as traces. `tracing` events become log records through
//! `tracing_layer::log_layer` (feature `tracing`).

use opentelemetry_otlp::{ExporterBuildError, WithExportConfig, WithHttpConfig};
use opentelemetry_sdk::Resource;
use opentelemetry_sdk::logs::SdkLoggerProvider;
use opentelemetry_sdk::metrics::{PeriodicReader, SdkMeterProvider, Temporality};

use crate::Config;

/// A `WATCHTOWER_LOGS` / `WATCHTOWER_METRICS` switch: on unless `off`, `false`, `0` or `no`;
/// `otel_exporter` (`OTEL_LOGS_EXPORTER` / `OTEL_METRICS_EXPORTER`) set to `none` also turns it off.
#[must_use]
pub fn switch_on(env: &str, otel_exporter: &str) -> bool {
    let get = |k: &str| std::env::var(k).unwrap_or_default().trim().to_ascii_lowercase();
    get(otel_exporter) != "none" && !matches!(get(env).as_str(), "off" | "false" | "0" | "no")
}

/// Delta (counters and histograms; up-down counters stay cumulative), our ingest default, unless
/// `OTEL_EXPORTER_OTLP_METRICS_TEMPORALITY_PREFERENCE` is `cumulative` or `lowmemory`.
#[must_use]
pub fn temporality(pref: Option<&str>) -> Temporality {
    match pref.map(|p| p.trim().to_ascii_lowercase()).as_deref() {
        Some("cumulative") => Temporality::Cumulative,
        Some("lowmemory") => Temporality::LowMemory,
        _ => Temporality::Delta,
    }
}

fn resource(cfg: &Config) -> Resource {
    Resource::builder_empty()
        .with_attributes(cfg.resource_attributes())
        .build()
}

/// A logger provider exporting OTLP/HTTP logs in batches, or `None` when logs are off.
/// Install it with `opentelemetry::global` or hand it to `tracing_layer::log_layer`.
///
/// # Errors
/// Returns the exporter build error (it never contains the key).
pub fn init_logs(cfg: &Config) -> Result<Option<SdkLoggerProvider>, ExporterBuildError> {
    if !switch_on("WATCHTOWER_LOGS", "OTEL_LOGS_EXPORTER") {
        return Ok(None);
    }
    let ex = opentelemetry_otlp::LogExporter::builder()
        .with_http()
        .with_endpoint(format!("{}/v1/logs", cfg.endpoint))
        .with_headers(cfg.headers().into_iter().collect())
        .build()?;
    Ok(Some(
        SdkLoggerProvider::builder()
            .with_resource(resource(cfg))
            .with_batch_exporter(ex)
            .build(),
    ))
}

/// A meter provider with a periodic OTLP/HTTP reader (`OTEL_METRIC_EXPORT_INTERVAL`), or `None`
/// when metrics are off. Install it with `opentelemetry::global::set_meter_provider`.
///
/// # Errors
/// Returns the exporter build error (it never contains the key).
pub fn init_metrics(cfg: &Config) -> Result<Option<SdkMeterProvider>, ExporterBuildError> {
    if !switch_on("WATCHTOWER_METRICS", "OTEL_METRICS_EXPORTER") {
        return Ok(None);
    }
    let pref = std::env::var("OTEL_EXPORTER_OTLP_METRICS_TEMPORALITY_PREFERENCE").ok();
    let ex = opentelemetry_otlp::MetricExporter::builder()
        .with_http()
        .with_temporality(temporality(pref.as_deref()))
        .with_endpoint(format!("{}/v1/metrics", cfg.endpoint))
        .with_headers(cfg.headers().into_iter().collect())
        .build()?;
    Ok(Some(
        SdkMeterProvider::builder()
            .with_resource(resource(cfg))
            .with_reader(PeriodicReader::builder(ex).build())
            .build(),
    ))
}
