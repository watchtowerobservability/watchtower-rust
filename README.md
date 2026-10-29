# watchtower-sdk

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

The ingest key is read from the environment (`WT_INGEST_KEY`); never commit it.

## Provenance

Every release artifact carries a GitHub build attestation. Verify one with
`gh attestation verify <file> --repo watchtowerobservability/watchtower-rust`.

## License

Apache-2.0. Source of truth is the Watchtower monorepo; this repository is a published mirror.
