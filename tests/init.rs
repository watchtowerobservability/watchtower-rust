use std::sync::Arc;

use opentelemetry::KeyValue;
use watchtower_sdk::{Config, OfflineBuffer, redact};

// Fake key only.
const KEY: &str = "wtk_example_not_a_real_key";

#[test]
fn exports_with_key_header() {
    let c = Config::new("svc", None, Some(KEY));
    assert_eq!(
        c.headers(),
        vec![("authorization".to_string(), format!("Bearer {KEY}"))]
    );
    assert_eq!(c.endpoint, "http://localhost:4318");
    assert!(!format!("{c:?}").contains(KEY));
}

#[test]
fn wt_attributes_dropped_from_resource_and_spans() {
    let c = Config::new("svc", Some("https://x.example/"), None).with_resource(vec![
        KeyValue::new("wt.project_id", "p"),
        KeyValue::new("env", "prod"),
    ]);
    let names: Vec<_> = c
        .resource_attributes()
        .iter()
        .map(|k| k.key.to_string())
        .collect();
    assert_eq!(names, ["service.name", "env"]);
    assert_eq!(c.endpoint, "https://x.example");
    let out = redact(
        vec![KeyValue::new("wt.tenant", "t"), KeyValue::new("a", "b")],
        None,
    );
    assert_eq!(out.len(), 1);
}

#[test]
fn redactor_can_mask_and_drop() {
    let r: watchtower_sdk::Redactor = Arc::new(|kv| match kv.key.as_str() {
        "password" => None,
        "email" => Some(KeyValue::new("email", "[redacted]")),
        _ => Some(kv.clone()),
    });
    let out = redact(
        vec![KeyValue::new("password", "x"), KeyValue::new("email", "a@b.c")],
        Some(&r),
    );
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].value.as_str(), "[redacted]");
}

#[test]
fn buffer_drops_oldest_when_full() {
    let mut b = OfflineBuffer::new(2);
    b.push(1);
    b.push(2);
    b.push(3);
    assert_eq!(b.drain(), vec![2, 3]);
}
