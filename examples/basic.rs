use opentelemetry::trace::{Tracer, TracerProvider};

fn main() {
    // Reads WT_INGEST_KEY, WT_OTLP_ENDPOINT, WT_SERVICE, WT_ENVIRONMENT, WT_RELEASE.
    let provider = watchtower_sdk::init(&watchtower_sdk::Config::from_env("example-rust")).expect("init");
    drop(provider.tracer("example").start("hello"));
    provider.shutdown().expect("flush");
}
