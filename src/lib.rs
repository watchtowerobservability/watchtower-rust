//! Watchtower distribution of the OpenTelemetry Rust SDK: key header, endpoint default,
//! offline buffer, `wt.*`-safe resource attributes and a redaction hook. No product logic.

mod buffer;

use std::sync::{Arc, Mutex};

pub use buffer::OfflineBuffer;
use opentelemetry::KeyValue;
use opentelemetry_otlp::{WithExportConfig, WithHttpConfig};
use opentelemetry_sdk::Resource;
use opentelemetry_sdk::error::OTelSdkResult;
use opentelemetry_sdk::trace::{SdkTracerProvider, SpanData, SpanExporter};

pub const DEFAULT_ENDPOINT: &str = "http://localhost:4318";

/// Called with every attribute of every span before export; return `None` to drop it.
pub type Redactor = Arc<dyn Fn(&KeyValue) -> Option<KeyValue> + Send + Sync>;

#[derive(Clone)]
pub struct Config {
    pub service: String,
    pub endpoint: String,
    key: Option<String>,
    pub resource: Vec<KeyValue>,
    pub redactor: Option<Redactor>,
    pub buffer_batches: usize,
}

impl std::fmt::Debug for Config {
    // The key must never reach logs.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Config")
            .field("service", &self.service)
            .field("endpoint", &self.endpoint)
            .field("key", &self.key.as_ref().map(|_| "***"))
            .finish_non_exhaustive()
    }
}

impl Config {
    /// Reads `WT_ENDPOINT` and `WT_INGEST_KEY`.
    #[must_use]
    pub fn from_env(service: &str) -> Self {
        let get = |k: &str| std::env::var(k).ok().filter(|v| !v.is_empty());
        Self::new(
            service,
            get("WT_ENDPOINT").as_deref(),
            get("WT_INGEST_KEY").as_deref(),
        )
    }

    #[must_use]
    pub fn new(service: &str, endpoint: Option<&str>, key: Option<&str>) -> Self {
        Self {
            service: service.to_string(),
            endpoint: endpoint
                .unwrap_or(DEFAULT_ENDPOINT)
                .trim_end_matches('/')
                .to_string(),
            key: key.map(str::to_string),
            resource: Vec::new(),
            redactor: None,
            buffer_batches: 64,
        }
    }

    #[must_use]
    pub fn with_resource(mut self, attrs: Vec<KeyValue>) -> Self {
        self.resource = attrs;
        self
    }

    #[must_use]
    pub fn with_redactor(mut self, r: Redactor) -> Self {
        self.redactor = Some(r);
        self
    }

    /// `authorization: Bearer <key>` when a key is set.
    #[must_use]
    pub fn headers(&self) -> Vec<(String, String)> {
        self.key
            .iter()
            .map(|k| ("authorization".to_string(), format!("Bearer {k}")))
            .collect()
    }

    /// Service name plus caller attributes, minus any `wt.*` (the gateway strips them anyway).
    #[must_use]
    pub fn resource_attributes(&self) -> Vec<KeyValue> {
        let mut out = vec![KeyValue::new("service.name", self.service.clone())];
        out.extend(
            self.resource
                .iter()
                .filter(|kv| !is_reserved(kv.key.as_str()))
                .cloned(),
        );
        out
    }
}

fn is_reserved(key: &str) -> bool {
    key.starts_with("wt.")
}

/// Applies the redactor to span attributes and drops `wt.*` ones.
#[must_use]
pub fn redact(attrs: Vec<KeyValue>, r: Option<&Redactor>) -> Vec<KeyValue> {
    attrs
        .into_iter()
        .filter(|kv| !is_reserved(kv.key.as_str()))
        .filter_map(|kv| match r {
            Some(f) => f(&kv),
            None => Some(kv),
        })
        .collect()
}

/// Redacts, exports, and keeps failed batches for the next export.
#[derive(Debug)]
pub struct WatchtowerExporter<E> {
    inner: E,
    redactor: Option<Redactor>,
    pending: Mutex<OfflineBuffer<Vec<SpanData>>>,
}

impl<E> WatchtowerExporter<E> {
    pub fn new(inner: E, redactor: Option<Redactor>, buffer_batches: usize) -> Self {
        Self {
            inner,
            redactor,
            pending: Mutex::new(OfflineBuffer::new(buffer_batches)),
        }
    }
}

impl<E: SpanExporter> SpanExporter for WatchtowerExporter<E> {
    async fn export(&self, mut batch: Vec<SpanData>) -> OTelSdkResult {
        for s in &mut batch {
            s.attributes = redact(std::mem::take(&mut s.attributes), self.redactor.as_ref());
        }
        let mut all = self
            .pending
            .lock()
            .map(|mut p| p.drain())
            .unwrap_or_default();
        all.push(batch);
        let mut result = Ok(());
        for b in all {
            if let Err(e) = self.inner.export(b.clone()).await {
                if let Ok(mut p) = self.pending.lock() {
                    p.push(b);
                }
                result = Err(e);
            }
        }
        result
    }

    fn shutdown(&mut self) -> OTelSdkResult {
        self.inner.shutdown()
    }

    fn force_flush(&mut self) -> OTelSdkResult {
        self.inner.force_flush()
    }

    fn set_resource(&mut self, r: &Resource) {
        self.inner.set_resource(r);
    }
}

/// Builds a tracer provider exporting OTLP/HTTP to Watchtower. Install it with
/// `opentelemetry::global::set_tracer_provider`.
///
/// # Errors
/// Returns the exporter build error (it never contains the key).
pub fn init(cfg: &Config) -> Result<SdkTracerProvider, opentelemetry_otlp::ExporterBuildError> {
    let ex = opentelemetry_otlp::SpanExporter::builder()
        .with_http()
        .with_endpoint(format!("{}/v1/traces", cfg.endpoint))
        .with_headers(cfg.headers().into_iter().collect())
        .build()?;
    Ok(SdkTracerProvider::builder()
        .with_resource(
            Resource::builder_empty()
                .with_attributes(cfg.resource_attributes())
                .build(),
        )
        .with_batch_exporter(WatchtowerExporter::new(
            ex,
            cfg.redactor.clone(),
            cfg.buffer_batches,
        ))
        .build())
}
