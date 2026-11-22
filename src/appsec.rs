//! App and API Protection in-app WAF (feature `appsec`), the same behavior as the Node, Python and
//! Go agents.
//!
//! [`start`] polls `GET /v1/appsec/ruleset` (an ingestion key with scope `probes:read`, ETag, every
//! `poll_s`): the mode (`monitor` or `block`), the enabled pattern rules and the denylist.
//! [`AppsecLayer`] (a tower layer: axum, hyper, tonic) inspects every request before the app: path,
//! query, User-Agent and the other header values, percent-decoded once, against the rules the
//! worker runs over stored spans. A match is recorded on the current span (`appsec.event`,
//! `appsec.rule_id`, `appsec.category`, `appsec.blocked`); in `block` mode, and for denylisted IPs
//! or users in either mode, the request gets 403 problem+json and the app never runs. Layer it
//! inside [`crate::layer::WatchtowerLayer`] so the server span is current. Rules match
//! case-insensitively. The `regex` crate runs a pattern when it can compile it; look-around and
//! back-references fall back to `fancy-regex` with a backtracking limit. A pattern neither compiles
//! is skipped, and the worker still evaluates it. Nothing happens until [`start`] or [`set_ruleset`].
//!
//! shortcut: trusts X-Forwarded-For for the client IP; run behind a proxy that overwrites it.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock, RwLock};
use std::task::{Context as TaskCx, Poll};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use http::{Request, Response, StatusCode, header};
use opentelemetry::trace::TraceContextExt;
use opentelemetry::{Context, KeyValue};
use regex::{Regex, RegexBuilder};
use serde_json::Value;
use tower_layer::Layer;
use tower_service::Service;

const PROBLEM: &str = r#"{"type":"about:blank","title":"Forbidden","status":403,"detail":"Request blocked by Watchtower App and API Protection"}"#;

/// `regex` when it can compile the pattern (linear time), else `fancy-regex` (look-around and
/// back-references, with a backtracking limit so a runaway pattern counts as no match).
enum Matcher {
    Plain(Regex),
    Fancy(fancy_regex::Regex),
}

impl Matcher {
    fn build(pattern: &str) -> Option<Self> {
        if let Ok(re) = RegexBuilder::new(pattern)
            .case_insensitive(true)
            .size_limit(1 << 20)
            .build()
        {
            return Some(Self::Plain(re));
        }
        fancy_regex::RegexBuilder::new(&format!("(?i){pattern}"))
            .backtrack_limit(100_000)
            .build()
            .ok()
            .map(Self::Fancy) // neither engine can compile it: the worker still evaluates it
    }

    fn find(&self, text: &str) -> Option<String> {
        match self {
            Self::Plain(re) => re.find(text).map(|m| m.as_str().to_owned()),
            Self::Fancy(re) => re.find(text).ok().flatten().map(|m| m.as_str().to_owned()),
        }
    }
}

struct Rule {
    id: String,
    category: String,
    re: Matcher,
    fields: Vec<String>,
}

#[derive(Default)]
struct State {
    block: bool,
    rules: Vec<Rule>,
    ip: HashMap<String, f64>,
    user: HashMap<String, f64>,
}

fn state() -> &'static RwLock<State> {
    static S: OnceLock<RwLock<State>> = OnceLock::new();
    S.get_or_init(|| RwLock::new(State::default()))
}

/// The verdict on one request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decision {
    /// `allow`, `monitor` or `block`.
    pub action: &'static str,
    pub rule_id: String,
    pub category: String,
    pub matched: String,
}

impl Decision {
    fn allow() -> Self {
        Self {
            action: "allow",
            rule_id: String::new(),
            category: String::new(),
            matched: String::new(),
        }
    }
}

fn expiry(v: Option<&Value>) -> HashMap<String, f64> {
    v.and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|e| {
            let value = e.get("value")?.as_str().filter(|s| !s.is_empty())?;
            Some((
                value.to_owned(),
                e.get("expires_at")
                    .and_then(Value::as_f64)
                    .unwrap_or(f64::INFINITY),
            ))
        })
        .collect()
}

/// Replace the active ruleset (the JSON document the edge serves; `Value::Null` clears it).
pub fn set_ruleset(r: &Value) {
    let rules = r
        .get("rules")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|rule| {
            let re = Matcher::build(rule.get("pattern")?.as_str()?)?;
            let text = |k: &str| {
                rule.get(k)
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_owned()
            };
            let fields = rule
                .get("fields")
                .and_then(Value::as_array)
                .map(|f| {
                    f.iter()
                        .filter_map(|x| x.as_str().map(str::to_owned))
                        .collect()
                })
                .unwrap_or_default();
            Some(Rule {
                id: text("id"),
                category: text("category"),
                re,
                fields,
            })
        })
        .collect();
    let deny = r.get("denylist");
    let next = State {
        block: r.get("mode").and_then(Value::as_str) == Some("block"),
        rules,
        ip: expiry(deny.and_then(|d| d.get("ip"))),
        user: expiry(deny.and_then(|d| d.get("user"))),
    };
    if let Ok(mut s) = state().write() {
        *s = next;
    }
}

/// Whether any rule or denylist entry is loaded.
#[must_use]
pub fn active() -> bool {
    state()
        .read()
        .is_ok_and(|s| !(s.rules.is_empty() && s.ip.is_empty() && s.user.is_empty()))
}

fn now_s() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0.0, |d| d.as_secs_f64())
}

/// Whether `user` is denylisted (call after authentication to refuse a listed user).
#[must_use]
pub fn user_blocked(user: &str) -> bool {
    !user.is_empty()
        && state()
            .read()
            .is_ok_and(|s| s.user.get(user).is_some_and(|t| *t > now_s()))
}

/// Judge one request: `fields` holds `path`, `query`, `user_agent`, `headers`, `body`, `ip`, `user`.
#[must_use]
pub fn inspect(fields: &HashMap<&str, String>, now: f64) -> Decision {
    let Ok(s) = state().read() else {
        return Decision::allow();
    };
    let listed = |m: &HashMap<String, f64>, k: &str| {
        fields
            .get(k)
            .is_some_and(|v| m.get(v).is_some_and(|t| *t > now))
    };
    if listed(&s.ip, "ip") || listed(&s.user, "user") {
        return Decision {
            action: "block",
            rule_id: "denylist".into(),
            category: "abuse".into(),
            matched: String::new(),
        };
    }
    for rule in &s.rules {
        for f in &rule.fields {
            if let Some(m) = fields
                .get(f.as_str())
                .filter(|v| !v.is_empty())
                .and_then(|v| rule.re.find(v))
            {
                return Decision {
                    action: if s.block { "block" } else { "monitor" },
                    rule_id: rule.id.clone(),
                    category: rule.category.clone(),
                    matched: m.chars().take(200).collect(),
                };
            }
        }
    }
    Decision::allow()
}

/// Percent-decode once; `+` is a space only in a query. Bad escapes stay as they are.
fn decode(s: &str, plus_is_space: bool) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'%' if b
                .get(i + 1..i + 3)
                .is_some_and(|h| h.iter().all(u8::is_ascii_hexdigit)) =>
            {
                let h = std::str::from_utf8(&b[i + 1..i + 3]).unwrap_or("00");
                out.push(u8::from_str_radix(h, 16).unwrap_or(b'%'));
                i += 3;
            }
            b'+' if plus_is_space => {
                out.push(b' ');
                i += 1;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// The request fields the rules read.
#[must_use]
pub fn fields_of<B>(req: &Request<B>, user: Option<&str>) -> HashMap<&'static str, String> {
    let h = req.headers();
    let text = |k: &str| {
        h.get(k)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_owned()
    };
    let xff = text("x-forwarded-for");
    let ip = if xff.is_empty() {
        text("x-real-ip")
    } else {
        xff.split(',').next().unwrap_or_default().trim().to_owned()
    };
    let others: Vec<&str> = h
        .iter()
        .filter(|(k, _)| **k != header::USER_AGENT)
        .filter_map(|(_, v)| v.to_str().ok())
        .collect();
    let mut m = HashMap::from([
        ("path", decode(req.uri().path(), false)),
        ("query", decode(req.uri().query().unwrap_or_default(), true)),
        ("user_agent", text("user-agent")),
        ("headers", others.join("\n")),
        ("ip", ip),
    ]);
    if let Some(u) = user {
        m.insert("user", u.to_owned());
    }
    m
}

/// Record a decision on the current span.
pub fn annotate(d: &Decision, ip: &str) {
    let cx = Context::current();
    let span = cx.span();
    if !span.is_recording() {
        return;
    }
    if !ip.is_empty() {
        span.set_attribute(KeyValue::new("appsec.client_ip", ip.to_owned()));
    }
    if d.action == "allow" {
        return;
    }
    span.set_attribute(KeyValue::new("appsec.event", true));
    span.set_attribute(KeyValue::new("appsec.rule_id", d.rule_id.clone()));
    span.set_attribute(KeyValue::new("appsec.category", d.category.clone()));
    span.set_attribute(KeyValue::new("appsec.blocked", d.action == "block"));
}

/// Mark the current request as a login attempt; failed ones feed the account-takeover rules.
pub fn track_login(login: &str, success: bool) {
    let cx = Context::current();
    let span = cx.span();
    span.set_attribute(KeyValue::new("appsec.login", login.to_owned()));
    span.set_attribute(KeyValue::new("appsec.login.success", success));
    if success {
        span.set_attribute(KeyValue::new("appsec.auth", true));
    }
}

/// Tower layer: `ServiceBuilder::new().layer(AppsecLayer::default())`. The response body type must
/// convert from `&'static str` (axum's `Body`, `http_body_util::Full`).
#[derive(Clone, Copy, Debug, Default)]
pub struct AppsecLayer;

impl<S> Layer<S> for AppsecLayer {
    type Service = AppsecService<S>;
    fn layer(&self, inner: S) -> Self::Service {
        AppsecService { inner }
    }
}

#[derive(Clone, Debug)]
pub struct AppsecService<S> {
    inner: S,
}

impl<S, B, R> Service<Request<B>> for AppsecService<S>
where
    S: Service<Request<B>, Response = Response<R>> + Clone + Send + 'static,
    S::Future: Send + 'static,
    B: Send + 'static,
    R: From<&'static str> + Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<S::Response, S::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut TaskCx<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<B>) -> Self::Future {
        let clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, clone);
        let judged = active().then(|| {
            let f = fields_of(&req, None);
            (
                inspect(&f, now_s()),
                f.get("ip").cloned().unwrap_or_default(),
            )
        });
        Box::pin(async move {
            if let Some((d, ip)) = judged {
                annotate(&d, &ip);
                if d.action == "block" {
                    let mut r = Response::new(R::from(PROBLEM));
                    *r.status_mut() = StatusCode::FORBIDDEN;
                    r.headers_mut().insert(
                        header::CONTENT_TYPE,
                        header::HeaderValue::from_static("application/problem+json"),
                    );
                    return Ok(r);
                }
            }
            inner.call(req).await
        })
    }
}

/// Stops the polling thread when dropped or when [`Poller::stop`] is called.
pub struct Poller(Arc<AtomicBool>);

impl Poller {
    pub fn stop(&self) {
        self.0.store(true, Ordering::Relaxed);
    }
}

impl Drop for Poller {
    fn drop(&mut self) {
        self.stop();
    }
}

/// One poll: the new ETag when a ruleset arrived, `None` when unchanged or the fetch failed.
fn poll(
    http: &reqwest::blocking::Client,
    endpoint: &str,
    key: &str,
    service: &str,
    etag: &str,
) -> Option<(String, u64)> {
    let mut r = http
        .get(format!(
            "{}/v1/appsec/ruleset",
            endpoint.trim_end_matches('/')
        ))
        .query(&[("service", service)])
        .bearer_auth(key);
    if !etag.is_empty() {
        r = r.header(header::IF_NONE_MATCH, etag);
    }
    let res = r.send().ok().filter(|x| x.status() == StatusCode::OK)?;
    let tag = res
        .headers()
        .get(header::ETAG)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_owned();
    let body: Value =
        serde_json::from_slice(&res.bytes().ok().filter(|b| b.len() <= 4 << 20)?).ok()?;
    set_ruleset(&body);
    Some((
        tag,
        body.get("poll_s")
            .and_then(Value::as_u64)
            .unwrap_or(30)
            .max(10),
    ))
}

/// Fetch the ruleset now and keep polling in a background thread.
#[must_use]
pub fn start(endpoint: &str, key: &str, service: &str) -> Poller {
    let stop = Arc::new(AtomicBool::new(false));
    let (flag, ep, k, svc) = (
        stop.clone(),
        endpoint.to_owned(),
        key.to_owned(),
        service.to_owned(),
    );
    std::thread::Builder::new()
        .name("watchtower-appsec".into())
        .spawn(move || {
            let Ok(http) = reqwest::blocking::Client::builder()
                .timeout(Duration::from_secs(5))
                .build()
            else {
                return;
            };
            let (mut etag, mut every) = (String::new(), 30);
            while !flag.load(Ordering::Relaxed) {
                if let Some((t, p)) = poll(&http, &ep, &k, &svc, &etag) {
                    (etag, every) = (t, p);
                }
                for _ in 0..every {
                    if flag.load(Ordering::Relaxed) {
                        return;
                    }
                    std::thread::sleep(Duration::from_secs(1));
                }
            }
        })
        .ok();
    Poller(stop)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // The ruleset is process-wide, so the cases share one test.
    #[test]
    fn rules_denylist_and_decoding() {
        let doc = |mode: &str| {
            json!({"mode": mode, "rules": [
                {"id": "sqli", "category": "injection", "pattern": "union\\s+select|' or 1=1", "fields": ["path", "query"]},
                {"id": "lookahead", "category": "x", "pattern": "admin(?!istrator)", "fields": ["path"]},
                {"id": "backref", "category": "x", "pattern": "(a)\\1\\1", "fields": ["query"]},
                {"id": "broken", "category": "x", "pattern": "(", "fields": ["path"]}],
                "denylist": {"ip": [{"value": "203.0.113.9", "expires_at": 4_102_444_800.0}], "user": [{"value": "mallory"}]}})
        };
        let get = |uri: &str, xff: Option<&str>| {
            let mut b = Request::builder().uri(uri);
            if let Some(x) = xff {
                b = b.header("x-forwarded-for", x);
            }
            fields_of(&b.body(()).unwrap(), None)
        };
        set_ruleset(&doc("block"));
        assert!(active());
        let d = inspect(&get("/items?q=1%27%20OR%201%3D1", None), 0.0);
        assert_eq!((d.action, d.rule_id.as_str()), ("block", "sqli"));
        assert_eq!(inspect(&get("/items?q=shoes", None), 0.0).action, "allow");
        // look-around and back-references run through fancy-regex; a broken pattern is skipped
        let d = inspect(&get("/admin/x", None), 0.0);
        assert_eq!(d.rule_id, "lookahead");
        assert_eq!(inspect(&get("/administrator", None), 0.0).action, "allow");
        assert_eq!(inspect(&get("/x?q=zaaab", None), 0.0).rule_id, "backref");

        set_ruleset(&doc("monitor"));
        assert_eq!(
            inspect(&get("/items?q=1+union+select+1", None), 0.0).action,
            "monitor"
        );
        let d = inspect(&get("/items?q=ok", Some("203.0.113.9")), 0.0);
        assert_eq!((d.action, d.rule_id.as_str()), ("block", "denylist"));
        assert!(user_blocked("mallory"));

        set_ruleset(&Value::Null);
        assert!(!active());
    }

    #[test]
    fn decode_keeps_bad_escapes_and_plus_only_in_queries() {
        assert_eq!(decode("a%20b+c", false), "a b+c");
        assert_eq!(decode("a%20b+c", true), "a b c");
        assert_eq!(decode("100%", true), "100%");
        assert_eq!(decode("%zz", true), "%zz");
    }
}
