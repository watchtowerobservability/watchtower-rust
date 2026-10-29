# watchtower-sdk

[![CI](https://github.com/watchtowerobservability/watchtower-rust/actions/workflows/ci.yml/badge.svg)](https://github.com/watchtowerobservability/watchtower-rust/actions/workflows/ci.yml)

Thin Watchtower distribution over the OpenTelemetry Rust SDK: `Authorization: Bearer` key header, endpoint default, `wt.*`-safe attributes, redaction hook, offline buffer.

Status: 0.x, early. APIs may change between minor versions.

## Install

```toml
[dependencies]
watchtower-sdk = { git = "https://github.com/watchtowerobservability/watchtower-rust", tag = "v0.1.0" }
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
| axum / tonic / tower | feature `tower` | `.layer(watchtower_sdk::layer::WatchtowerLayer)` |
| actix-web | feature `actix` | `.wrap(actix_web::middleware::from_fn(watchtower_sdk::actix::trace))` |

## Configuration

| Variable | Meaning |
| --- | --- |
| `WT_INGEST_KEY` | secret ingest key, sent as `Authorization: Bearer`, masked in debug output; never commit it |
| `WT_OTLP_ENDPOINT` | OTLP/HTTP base, default `http://localhost:4318` |
| `WT_SERVICE` | service name, pass it to `Config::from_env` |
| `WT_ENVIRONMENT`, `WT_RELEASE` | become `deployment.environment.name`, `service.version` |

## Provenance

Every release artifact carries a GitHub build attestation. Verify one with
`gh attestation verify <file> --repo watchtowerobservability/watchtower-rust`.

## License

Apache-2.0. Source of truth is the Watchtower monorepo; this repository is a published mirror.
