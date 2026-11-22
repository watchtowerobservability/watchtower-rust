//! Copy of the reference `services/worker/src/sqlnorm.rs` (`normalize_with`, `collapse_in`): literal-free
//! statement text plus its XXH3-64 hash as a decimal string, so SDK spans join agent DBM and the
//! worker's `wt.db.query_hash`. Spec: docs/product/instrumentation/sql-normalization.md; contract:
//! testdata/sql_normalize_vectors.json. Keep the scan in sync with the reference.
use opentelemetry::KeyValue;

/// Longest statement looked at; the rest is dropped (an unterminated literal becomes `?`).
pub const MAX_STATEMENT_BYTES: usize = 8 * 1024;
/// Longest `$tag$` of a dollar-quoted string that is recognised.
const MAX_DOLLAR_TAG: usize = 32;

fn cap(s: &str) -> &str {
    let mut end = s.len().min(MAX_STATEMENT_BYTES);
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

fn is_word(c: char) -> bool {
    c.is_alphanumeric() || c == '_' || c == '$'
}

/// Index just past the dollar-quoted string opening at `i` (`$tag$ ... $tag$`), if one opens there.
fn dollar_quoted(cs: &[char], i: usize) -> Option<usize> {
    let tag_len = cs[i + 1..]
        .iter()
        .take(MAX_DOLLAR_TAG + 1)
        .position(|&c| c == '$')?;
    let tag = &cs[i..i + tag_len + 2];
    if !tag[1..=tag_len]
        .iter()
        .all(|&c| c.is_alphanumeric() || c == '_')
        || tag.get(1).is_some_and(char::is_ascii_digit)
    {
        return None;
    }
    let body = i + tag.len();
    Some(
        (body..cs.len())
            .find(|&j| cs[j..].starts_with(tag))
            .map_or(cs.len(), |j| j + tag.len()),
    )
}

/// Normalised statement and its xxh3 hash. Literals (strings, numbers, `$1`) become `?`, comments
/// are dropped, whitespace collapses, and `IN (?, ?, ...)` becomes `IN (?+)`.
/// Whether `db.system.name` uses the Postgres dialect.
#[must_use]
pub fn is_pg(system: &str) -> bool {
    matches!(system, "postgresql" | "cockroachdb" | "redshift")
}

/// Normalised statement. `pg` keeps short `"identifier"` quotes and leaves `#` alone.
#[must_use]
pub fn normalize(stmt: &str, pg: bool) -> String {
    let cs: Vec<char> = cap(stmt).chars().collect();
    let mut out = String::with_capacity(cs.len());
    let mut space = false;
    let mut i = 0;
    while i < cs.len() {
        let c = cs[i];
        let next = cs.get(i + 1).copied();
        if c.is_whitespace() {
            space = true;
            i += 1;
        } else if c == '/' && next == Some('*') {
            // Nested like Postgres; unterminated masks to the end (over-masks MySQL, never leaks).
            let mut depth = 1;
            i += 2;
            while i < cs.len() && depth > 0 {
                match (cs[i], cs.get(i + 1)) {
                    ('/', Some('*')) => (depth, i) = (depth + 1, i + 2),
                    ('*', Some('/')) => (depth, i) = (depth - 1, i + 2),
                    _ => i += 1,
                }
            }
            space = true;
        } else if (c == '-' && next == Some('-')) || (c == '#' && !pg) {
            while i < cs.len() && cs[i] != '\n' {
                i += 1;
            }
            space = true;
        } else {
            if space && !out.is_empty() {
                out.push(' ');
            }
            space = false;
            i = token(&cs, i, pg, &mut out);
        }
    }
    collapse_in(&out)
}

/// Copy or replace the token starting at `i`; returns the index after it.
fn token(cs: &[char], mut i: usize, pg: bool, out: &mut String) -> usize {
    let c = cs[i];
    if c == '\'' {
        i += 1;
        while i < cs.len() {
            if cs[i] == '\'' {
                if cs.get(i + 1) != Some(&'\'') {
                    break;
                }
                i += 1;
            }
            i += 1;
        }
        out.push('?');
        // Standard SQL has no backslash escape, MySQL does. A quote right after a backslash is
        // ambiguous, so mask to the end of the statement rather than risk leaking what follows.
        let ambiguous = i < cs.len() && cs[i - 1] == '\\';
        return if ambiguous { cs.len() } else { i + 1 };
    }
    if c == '"' || c == '`' {
        let close = (i + 1..cs.len()).find(|&j| cs[j] == c).unwrap_or(cs.len());
        let body = &cs[i + 1..close];
        let ident = c == '"'
            && pg
            && close < cs.len()
            && (1..=64).contains(&body.len())
            && body
                .iter()
                .all(|&b| b.is_alphanumeric() || b == '_' || b == '$');
        if ident {
            out.extend(&cs[i..=close]);
        } else {
            out.push('?');
        }
        return close + 1;
    }
    if c == '$' {
        if cs.get(i + 1).is_some_and(char::is_ascii_digit) {
            i += 1;
            while i < cs.len() && cs[i].is_ascii_digit() {
                i += 1;
            }
            out.push('?');
            return i;
        }
        if let Some(end) = dollar_quoted(cs, i) {
            out.push('?');
            return end;
        }
    }
    if c.is_ascii_digit() {
        while i < cs.len() && (is_word(cs[i]) || cs[i] == '.') {
            i += 1;
        }
        out.push('?');
    } else if is_word(c) {
        while i < cs.len() && is_word(cs[i]) {
            out.push(cs[i]);
            i += 1;
        }
    } else {
        out.push(c);
        i += 1;
    }
    i
}

/// `(?, ?, ?)` after `in` -> `(?+)`, so the list length does not split one query into many.
fn collapse_in(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < b.len() {
        let at_word = i == 0 || !is_word(char::from(b[i - 1]));
        if at_word
            && b[i..].len() >= 2
            && b[i..i + 2].eq_ignore_ascii_case(b"in")
            && let Some((open, end)) = in_list(b, i + 2)
        {
            out.push_str(&s[i..open]);
            out.push_str("(?+)");
            i = end;
            continue;
        }
        let ch = s[i..].chars().next().unwrap_or(' ');
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}

/// After `in`: optional space, `(`, `?` items separated by commas, `)`. Returns `(open, end)`.
fn in_list(b: &[u8], mut i: usize) -> Option<(usize, usize)> {
    let skip = |i: &mut usize| {
        while b.get(*i) == Some(&b' ') {
            *i += 1;
        }
    };
    skip(&mut i);
    let open = i;
    (b.get(i) == Some(&b'(')).then_some(())?;
    i += 1;
    loop {
        skip(&mut i);
        (b.get(i) == Some(&b'?')).then_some(())?;
        i += 1;
        skip(&mut i);
        match b.get(i)? {
            b',' => i += 1,
            b')' => return Some((open, i + 1)),
            _ => return None,
        }
    }
}


/// XXH3-64 (seed 0) of the normalized text as an unsigned decimal string.
#[must_use]
pub fn hash(normalized: &str) -> String {
    xxhash_rust::xxh3::xxh3_64(normalized.as_bytes()).to_string()
}

fn ident_end(b: &[u8], mut i: usize) -> usize {
    // `"quoted"` or `[A-Za-z0-9_$]+`, like the Node SDK's TARGET part
    if b.get(i) == Some(&b'"') {
        return b[i + 1..].iter().position(|&c| c == b'"').map_or(i, |p| if p == 0 { i } else { i + p + 2 });
    }
    while b.get(i).is_some_and(|c| c.is_ascii_alphanumeric() || *c == b'_' || *c == b'$') {
        i += 1;
    }
    i
}

/// (OPERATION, first table) of normalized text, like the Node SDK's `querySummary`; either may be empty.
#[must_use]
pub fn summary(normalized: &str) -> (String, String) {
    let b = normalized.as_bytes();
    let alpha_run = |i: usize| {
        let mut j = i;
        while b.get(j).is_some_and(u8::is_ascii_alphabetic) {
            j += 1;
        }
        j
    };
    let skip_ws = |mut i: usize| {
        while b.get(i).is_some_and(u8::is_ascii_whitespace) {
            i += 1;
        }
        i
    };
    let word_at = |i: usize| i < b.len() && (b[i].is_ascii_alphanumeric() || b[i] == b'_');
    let start = skip_ws(0);
    let mut op = String::new();
    let lead = &normalized[start..start + (alpha_run(start) - start)];
    if lead.eq_ignore_ascii_case("with") {
        // the first `)` that is followed by an operation word ends the CTE list
        for (k, _) in normalized.match_indices(')').filter(|(k, _)| *k > start) {
            let s = skip_ws(k + 1);
            if alpha_run(s) > s {
                op = normalized[s..alpha_run(s)].to_ascii_uppercase();
                break;
            }
        }
    }
    if op.is_empty() {
        op = lead.to_ascii_uppercase();
    }
    let mut table = String::new();
    let lower = normalized.to_ascii_lowercase();
    'scan: for kw in 0..b.len() {
        if kw > 0 && word_at(kw - 1) {
            continue;
        }
        for k in ["from", "into", "update", "join", "table"] {
            let e = kw + k.len();
            if lower.as_bytes()[kw..].starts_with(k.as_bytes()) && !word_at(e) {
                let s = skip_ws(e);
                if s == e {
                    continue;
                }
                let mut end = ident_end(b, s);
                if end > s && b.get(end) == Some(&b'.') {
                    let e2 = ident_end(b, end + 1);
                    if e2 > end + 1 {
                        end = e2;
                    }
                }
                if end > s {
                    table = normalized[s..end].replace('"', "");
                    break 'scan;
                }
            }
        }
    }
    (op, table)
}

/// `db.query.hash`, `db.query.summary`, `db.operation.name`, `db.collection.name` and, when
/// `with_text`, the sanitized `db.query.text`.
#[must_use]
pub fn attributes(system: &str, stmt: &str, with_text: bool) -> Vec<KeyValue> {
    if stmt.is_empty() {
        return Vec::new();
    }
    let n = normalize(stmt, is_pg(system));
    let mut a = vec![KeyValue::new("db.query.hash", hash(&n))];
    let (op, table) = summary(&n);
    if !op.is_empty() {
        let s = if table.is_empty() { op.clone() } else { format!("{op} {table}") };
        a.push(KeyValue::new("db.query.summary", s));
        a.push(KeyValue::new("db.operation.name", op));
        if !table.is_empty() {
            a.push(KeyValue::new("db.collection.name", table));
        }
    }
    if with_text {
        a.push(KeyValue::new("db.query.text", n));
    }
    a
}
