fn main() -> Result<(), Box<dyn std::error::Error>> {
    let provider = watchtower_sdk::init(&watchtower_sdk::Config::from_env("example"))?;
    opentelemetry::global::set_tracer_provider(provider.clone());
    watchtower_sdk::capture_panics(&provider);
    panic!("hello from the example");
}
