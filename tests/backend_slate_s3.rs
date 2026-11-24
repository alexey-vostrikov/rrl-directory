//! The directory in an S3 bucket, against a real object store.
//!
//! These run only where a bucket is named: `RRL_S3_TEST_BUCKET`, with `RRL_S3_TEST_ENDPOINT` for
//! anything but Amazon, and `RRL_S3_TEST_KEY` / `RRL_S3_TEST_SECRET` for the credentials. Without
//! them the file returns at its first line and reports nothing, so the plain gates neither need a
//! MinIO nor pass a test they did not run - the same shape `tests/session_setup_kerberos.rs` uses
//! for a KDC.
//!
//! What is asserted is the seam's contract, not SlateDB's behaviour: an entry written comes back
//! byte for byte, a change and its journal record exist in one transaction, the counter moves with
//! the data, a deletion leaves a tombstone, and a store reopened on the same prefix finds
//! everything - which is the whole reason to keep a directory in a bucket.
#![cfg(feature = "slate-s3")]

use rrl_directory::backend::redb_store::ChangeKind;
use rrl_directory::backend::{Backend, EntryChange};
use rrl_directory::model::{Attribute, Attributes, Entry};

/// A prefix no earlier run used.
///
/// The bucket is shared and nothing deletes what a run wrote - a test that expected an empty store
/// checked into an empty bucket, and the second run then failed on the first run's objects, measured.
/// A process id and a nanosecond stamp are enough to keep runs apart; what a run leaves behind is
/// for the operator to drop when the bucket is emptied.
fn prefix(name: &str) -> String {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|since| since.as_nanos())
        .unwrap_or(0);
    format!("t/{name}/{}-{stamp}", std::process::id())
}

/// The store, over a prefix nothing else wrote to.
fn store(prefix: &str) -> Option<Backend> {
    let bucket = std::env::var("RRL_S3_TEST_BUCKET").ok()?;
    let mut config = serde_json::json!({
        "bucket": bucket,
        "prefix": prefix,
        "flush_interval_ms": 50,
        "allow_http": true,
    });
    if let Ok(endpoint) = std::env::var("RRL_S3_TEST_ENDPOINT") {
        config["endpoint"] = serde_json::json!(endpoint);
    }
    if let (Ok(key), Ok(secret)) = (
        std::env::var("RRL_S3_TEST_KEY"),
        std::env::var("RRL_S3_TEST_SECRET"),
    ) {
        config["access_key"] = serde_json::json!(key);
        config["secret_key"] = serde_json::json!(secret);
    }
    Some(Backend::from_config("slate-s3", Some(&config)).expect("slate-s3 backend"))
}

fn person(cn: &str, sn: &str) -> Entry {
    let attributes = Attributes::new()
        .push(Attribute::new(
            "objectClass",
            vec!["top".to_string(), "person".to_string()],
        ))
        .push(Attribute::single("cn", cn))
        .push(Attribute::single("sn", sn));
    Entry::new(format!("cn={cn},ou=users,dc=example,dc=com"), attributes)
}

#[tokio::test]
async fn an_entry_written_reads_back_unchanged() {
    let roundtrip = prefix("roundtrip");
    let Some(backend) = store(&roundtrip) else {
        return;
    };
    let entry = person("alice", "Liddell");

    let sequence = backend
        .apply(&[EntryChange::Upsert {
            entry: entry.clone(),
        }])
        .await
        .expect("apply")
        .expect("a numbered change set");
    assert_eq!(sequence, 1, "the first change set is number one");

    let read = backend.entry(entry.dn()).expect("a record read by key");
    assert_eq!(read, entry, "the entry survives the round trip");

    let all = backend.load().await.expect("load");
    assert_eq!(all.entries, vec![entry]);
    assert_eq!(backend.entry_count(), Some(1));
}

#[tokio::test]
async fn a_change_and_its_journal_record_are_one_transaction() {
    let journal = prefix("journal");
    let Some(backend) = store(&journal) else {
        return;
    };
    backend
        .apply(&[EntryChange::Upsert {
            entry: person("bob", "Barker"),
        }])
        .await
        .expect("apply");

    let records = backend.journal_since(None).expect("journal");
    assert_eq!(records.len(), 1, "one change, one record");
    assert_eq!(records[0].kind, ChangeKind::Add);
    assert!(records[0].entry.is_some(), "the record carries the entry");

    let floor = backend.journal_floor().expect("floor");
    assert_eq!(floor.as_deref(), Some(records[0].csn.as_str()));

    // A second change to the same entry is a modify, and the journal says so.
    backend
        .apply(&[EntryChange::Upsert {
            entry: person("bob", "Barker-Jones"),
        }])
        .await
        .expect("apply");
    let records = backend.journal_since(None).expect("journal");
    assert_eq!(records.len(), 2);
    assert_eq!(
        records.last().map(|record| record.kind),
        Some(ChangeKind::Modify)
    );
}

#[tokio::test]
async fn a_deletion_leaves_a_tombstone_and_drops_the_entry() {
    let tombstone = prefix("tombstone");
    let Some(backend) = store(&tombstone) else {
        return;
    };
    let entry = person("carol", "Churchill");
    backend
        .apply(&[EntryChange::Upsert {
            entry: entry.clone(),
        }])
        .await
        .expect("apply");

    backend
        .apply(&[EntryChange::delete(entry.dn(), None)])
        .await
        .expect("apply");

    assert_eq!(backend.entry(entry.dn()), None, "the entry is gone");
    assert_eq!(backend.entry_count(), Some(0), "and the count knows");
    let records = backend.journal_since(None).expect("journal");
    assert_eq!(records.len(), 2);
    let last = records.last().expect("a delete");
    assert_eq!(last.kind, ChangeKind::Delete);
    assert!(last.entry.is_none(), "a tombstone carries no entry");
}

#[tokio::test]
async fn a_change_set_moves_everything_or_nothing() {
    let atomic = prefix("atomic");
    let Some(backend) = store(&atomic) else {
        return;
    };
    // One change set, three entries: one commit, one counter bump.
    let changes: Vec<EntryChange> = ["d", "e", "f"]
        .iter()
        .map(|name| EntryChange::Upsert {
            entry: person(name, "Batch"),
        })
        .collect();
    let sequence = backend
        .apply(&changes)
        .await
        .expect("apply")
        .expect("numbered");
    assert_eq!(sequence, 1, "three entries, one change set");
    assert_eq!(backend.entry_count(), Some(3));
    assert_eq!(backend.sequence().expect("sequence"), 1);
}

#[tokio::test]
async fn a_reopened_store_finds_everything_where_it_left_it() {
    let reopen = prefix("reopen");
    let Some(backend) = store(&reopen) else {
        return;
    };
    let entry = person("dave", "Darling");
    backend
        .apply(&[EntryChange::Upsert {
            entry: entry.clone(),
        }])
        .await
        .expect("apply");
    // The write is durable before the store is dropped: that is what a caller is promised.
    backend.sync().expect("flush");
    drop(backend);

    let again = store(&reopen).expect("the same prefix");
    assert_eq!(
        again.load().await.expect("load").entries,
        vec![entry],
        "a restart on the same bucket sees the same directory"
    );
    assert_eq!(again.sequence().expect("sequence"), 1);
}

#[tokio::test]
async fn a_value_about_the_server_survives_the_round_trip() {
    let meta = prefix("meta");
    let Some(backend) = store(&meta) else {
        return;
    };
    assert_eq!(backend.meta_get("domain_sid").expect("get"), None);
    backend
        .meta_set("domain_sid", b"S-1-5-21-1-2-3")
        .expect("set");
    assert_eq!(
        backend.meta_get("domain_sid").expect("get"),
        Some(b"S-1-5-21-1-2-3".to_vec())
    );
    assert!(backend.keeps_meta(), "a domain SID outlives the host");
}
