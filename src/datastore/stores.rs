//! Stats readers for sled, redb, heed (LMDB) and moka, each behind the feature of the same name.
//! Spans: wrap calls with [`super::span`], e.g.
//! `span(&Op { system: "sled", namespace: Some(path), operation: "insert", collection: None }, || db.insert(k, v))`.
#[cfg(any(feature = "redb", feature = "heed"))]
use super::file_size;
#[allow(unused_imports)]
use super::{Handle, observe};
#[allow(unused_imports)]
use opentelemetry::metrics::Meter;

/// sled: on-disk size (`Db::size_on_disk`) and the number of trees.
#[cfg(feature = "sled")]
pub fn observe_sled(meter: &Meter, db: &sled::Db, namespace: &str) -> Handle {
    let db = db.clone();
    observe(meter, "sled", namespace, move |r| {
        if let Ok(n) = db.size_on_disk() {
            r.set("wt.embedded.file.size", n);
        }
    })
}

/// redb: file size and page-cache hits, misses, evictions and bytes (build redb with the
/// `cache_metrics` feature, which this feature turns on). redb does not expose its path.
#[cfg(feature = "redb")]
pub fn observe_redb(meter: &Meter, db: std::sync::Arc<redb::Database>, path: &str) -> Handle {
    use redb::ReadableDatabase;
    let p = path.to_string();
    observe(meter, "redb", path, move |r| {
        let c = db.cache_stats();
        r.set("wt.embedded.cache.hits", c.read_hits() + c.write_hits());
        r.set("wt.embedded.cache.misses", c.read_misses() + c.write_misses());
        r.set("wt.embedded.cache.evictions", c.evictions());
        r.set("wt.embedded.cache.size", c.used_bytes() as u64);
        if let Some(n) = file_size(&p) {
            r.set("wt.embedded.file.size", n);
        }
    })
}

/// heed (LMDB): map size, data file size, reader slots in use and write transactions committed.
#[cfg(feature = "heed")]
pub fn observe_heed<T: 'static>(meter: &Meter, env: &heed::Env<T>) -> Handle {
    let env = env.clone();
    let ns = env.path().to_string_lossy().into_owned();
    observe(meter, "lmdb", &ns, move |r| {
        let i = env.info();
        r.set("wt.embedded.map.size", i.map_size as u64);
        r.set("wt.embedded.readers", u64::from(i.number_of_readers));
        r.set("wt.embedded.transactions", i.last_txn_id as u64);
        if let Ok(n) = env.real_disk_size() {
            r.set("wt.embedded.file.size", n);
        }
    })
}

/// moka (sync cache): entry count and weighted size. moka keeps no hit/miss counters; count them
/// at the call site if you need a ratio.
#[cfg(feature = "moka")]
pub fn observe_moka<K, V, S>(meter: &Meter, cache: &moka::sync::Cache<K, V, S>, name: &str) -> Handle
where
    K: Send + Sync + 'static,
    V: Send + Sync + 'static,
    S: Send + Sync + 'static,
    moka::sync::Cache<K, V, S>: Clone,
{
    let c = cache.clone();
    observe(meter, "moka", name, move |r| {
        r.set("wt.embedded.keys", c.entry_count());
        r.set("wt.embedded.memory.used", c.weighted_size());
    })
}
