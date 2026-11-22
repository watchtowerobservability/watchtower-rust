## 0.1.1

- Sync with the monorepo: log bridge metadata attributes, in-app WAF and embedded datastore instrumentation.

- `init_logs` and `init_metrics` (OTLP/HTTP; delta temporality by default), `tracing_layer::log_layer` (opentelemetry-appender-tracing, span ids on every record), `WATCHTOWER_LOGS` / `WATCHTOWER_METRICS` switches.

## 0.1.0

- Tracer provider over OpenTelemetry with key header, offline buffer, redaction hook.
- Panic hook, error recording, `tracing` layer, tower and actix-web middleware.
