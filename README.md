# watchtower-sdk

[![CI](https://github.com/watchtowerobservability/watchtower-rust/actions/workflows/ci.yml/badge.svg)](https://github.com/watchtowerobservability/watchtower-rust/actions/workflows/ci.yml)

Thin Watchtower distribution over the OpenTelemetry Rust SDK: `Authorization: Bearer` key header, endpoint default, `wt.*`-safe attributes, redaction hook, offline buffer.

Status: 0.x, early. APIs may change between minor versions.

## Install

```toml
[dependencies]
watchtower-sdk = { git = "https://github.com/watchtowerobservability/watchtower-rust", tag = "v0.1.1" }
```

## Use

```rust
let provider = watchtower_sdk::init(&watchtower_sdk::Config::from_env("checkout"))?;
```

Quick start:

```rust
let provider = watchtower_sdk::init(&watchtower_sdk::Config::from_env("checkout"))?;
opentelemetry::global::set_tracer_provider(provider.clone());
watchtower_sdk::capture_panics(&provider);
```

## Integrations

| Integration | Enable | Use |
| --- | --- | --- |
| Panic capture | default | `watchtower_sdk::capture_panics(&provider)` |
| Error on span | default | `watchtower_sdk::record_error(&cx, &err)` |
| `tracing` layer | feature `tracing` | `registry().with(watchtower_sdk::tracing_layer::layer(&provider))` |
| `tracing` events as OTLP logs | feature `tracing` | `.with(watchtower_sdk::tracing_layer::log_layer(&logs))`, `logs` from `watchtower_sdk::init_logs(&cfg)?` (records carry the span's trace and span ids) |
| Metrics | default | `watchtower_sdk::init_metrics(&cfg)?` then `opentelemetry::global::set_meter_provider(..)`; delta temporality unless `OTEL_EXPORTER_OTLP_METRICS_TEMPORALITY_PREFERENCE` is set, period `OTEL_METRIC_EXPORT_INTERVAL` |
| axum / tonic / tower | feature `tower` | `.layer(watchtower_sdk::layer::WatchtowerLayer)` |
| actix-web | feature `actix` | `.wrap(actix_web::middleware::from_fn(watchtower_sdk::actix::trace))` |
| SQLite (rusqlite) | feature `datastores` | `conn.profile(Some(watchtower_sdk::datastore::sqlite_profile))`: statement spans with `db.query.hash` and `db.query.summary`, no values; `observe_files` for file and WAL size |
| any embedded store | feature `datastores` | `datastore::span(&Op { .. }, || ...)` spans; `datastore::observe(&meter, system, ns, \|r\| r.set(..))` for `wt.embedded.*` metrics |
| RocksDB (any binding) | feature `datastores` | `observe_rocksdb(&meter, path, move \|p\| db.property_int_value(p).ok().flatten())` |
| sled, redb, heed (LMDB), moka | features `sled`, `redb`, `heed`, `moka` | `datastore::stores::observe_*`: disk size, page cache, map size and readers, entry count |

## Profiling (feature `profiling`)

```rust
let profiler = watchtower_sdk::profiling::start(watchtower_sdk::profiling::ProfilerConfig::from_env("checkout"))?;
// keep `profiler` alive; dropping it stops sampling
```

A CPU profiler with our own sampler, without pprof-rs. Every 15 s it posts folded stacks to `/ingest` as `<service>.cpu`.

- **Linux and macOS (x86-64, aarch64):** `setitimer(ITIMER_PROF)` sends `SIGPROF` at `hz` (default 100) to the thread burning CPU. The handler walks frame pointers from the interrupted registers into a lock-free ring. It takes no lock, allocates nothing and does not call an unwinder, so it cannot deadlock against the allocator or the loader. Bad frame pointers cannot crash the app either: on Linux each read goes through `process_vm_readv`, and on macOS only the thread's own stack is read.
- **Windows x86-64 and arm64:** a sampler thread suspends each thread that used CPU cycles since the last round, copies its registers and stack into preallocated memory, resumes it, then unwinds the copy with `RtlVirtualUnwind`. It never allocates or takes a user-mode lock while a thread is suspended. A stack too large for the buffer is skipped once and the buffer grows (up to 256 MiB) before the next round. Rounds are timed by a high-resolution waitable timer (Windows 10 1803+); older Windows falls back to `Sleep`, which limits the rate to about 64 Hz.

**Stack quality on Linux and macOS depends on frame pointers.** Build with `RUSTFLAGS="-C force-frame-pointers=yes"` for whole stacks. Without them you always get the function that was running (the leaf), but callers are missing or cut short wherever a frame in the chain was compiled without frame pointers, which can include precompiled `std` and C libraries. aarch64 macOS always keeps frame pointers. Windows does not depend on them.

Names are symbolized in-process off the signal path, so ship debug symbols or `debug = "line-tables-only"` to get readable frames. Overhead has not been measured; test it under your own load. Only one profiler runs per process, and it uses `SIGPROF`, so do not combine it with another SIGPROF profiler. `profiling::capture(duration, hz)` returns one window of folded stacks.

`profiling::with_current_span(|| work())` labels samples with the current OpenTelemetry span, so a trace links to its exact profile (`with_span(span_id, trace_id, f)` takes explicit ids). For async code, `with_current_span_async(fut)` (or `with_span_async`) labels every poll of the future on whichever thread runs it, so the task stays labeled across `.await`.

## Configuration

| Variable | Meaning |
| --- | --- |
| `WT_INGEST_KEY` | secret ingest key, sent as `Authorization: Bearer`, masked in debug output; never commit it |
| `WT_OTLP_ENDPOINT` | OTLP/HTTP base, default `http://localhost:4318` |
| `WT_SERVICE` | service name, pass it to `Config::from_env` |
| `WT_ENVIRONMENT`, `WT_RELEASE` | become `deployment.environment.name`, `service.version` |
| `WATCHTOWER_LOGS`, `WATCHTOWER_METRICS` | `off` makes `init_logs` / `init_metrics` return `None` (`OTEL_*_EXPORTER=none` too); default on |

## Provenance

Every release artifact carries a GitHub build attestation. Verify one with
`gh attestation verify <file> --repo watchtowerobservability/watchtower-rust`.

## License

Apache-2.0. Source of truth is the Watchtower monorepo; this repository is a published mirror.
