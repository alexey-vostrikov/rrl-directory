//! SlateDB on S3-compatible object storage, behind the same seam as the redb store.
//!
//! # Why this is a backend and not a replacement
//!
//! `redb` on a local file is the fastest store this crate has and the only one that keeps no
//! network in the path: a durable single write there measured at 0.027 ms, and the same write
//! through an object store measured at 11 ms with a 10 ms flush interval. That is not a regression
//! anybody should take for a directory on one host.
//!
//! What it cannot do is be two servers at once. `redb` refuses a second handle on one file - measured:
//! `DatabaseAlreadyOpen` - so a second replica is not a configuration it has, and the disk is a
//! thing to lose. SlateDB is an LSM tree whose durability *is* object storage: every write goes to
//! a WAL object and every flush to an SST object, with fencing through the manifest, so replicas
//! can share a bucket and a host can be replaced without a copy of the data.
//!
//! # The shape of a write here
//!
//! One `apply` is one transaction, and one transaction is one commit: the entries, their journal
//! records, the change counter and the entry count move together or not at all, exactly as they do
//! in the redb store. The caller then waits for the commit to become durable - `await_durable`,
//! not `flush` - so commits made inside one flush window coalesce into one WAL object instead of
//! one each. The window is `flush_interval_ms`, 50 ms by default:
//!
//! * a single awaited write costs about the interval, so 50 ms is the latency floor per commit;
//! * a burst of writes inside the window costs one WAL put between them, not one each.
//!
//! Raising the interval buys fewer requests and costs latency; lowering it inverts that. Both ends
//! were measured on the stand rather than assumed, which is why the knob is exposed with the cost
//! written beside it.
//!
//! # What is not here
//!
//! The search index. `index_store` writes an index snapshot and a chain of deltas beside the store;
//! against a bucket every delta would be a PUT, and a directory written to all day would spend more
//! on deltas than the rebuild costs. A rebuild at start is always correct, so this backend reports
//! no stored index and leaves the caller to build one. That is the same answer the `file` and
//! `rest` backends give, and the seam already allows it.
//!
//! # Threads
//!
//! SlateDB is async and most of this seam is not. The database therefore lives on one worker thread
//! with its own runtime, and every synchronous method is a job sent to it; `apply` and `load`, which
//! are already async, use the shared handle and run on the caller's runtime. The alternative -
//! blocking inside the caller's runtime - would park a runtime worker for the length of a flush
//! window on every call.

use std::future::Future;
use std::sync::Arc;
use std::sync::mpsc::{Receiver, Sender, channel};

use serde::Deserialize;
use serde::Serialize;

use crate::backend::redb_store::{ChangeKind, ChangeRecord, StoredEntry};
use crate::backend::{BackendError, DirectoryData, EntryChange};
use crate::model::Entry;

/// The object the change counter is kept under.
const META_SEQ: &str = "__seq";
/// The object the entry count is kept under, so that a count costs a read and not a scan.
const META_COUNT: &str = "__count";

/// Entries, keyed by distinguished name.
const ENTRY: &[u8] = b"e/";
/// Values the server records about itself: the domain SID, the RID counter.
const META: &[u8] = b"m/";
/// The change journal, keyed by `entryCSN` - fixed width, so a range scan over it is a scan in time.
const CHANGES: &[u8] = b"c/";

fn key_entry(dn: &str) -> Vec<u8> {
    let mut key = Vec::with_capacity(ENTRY.len() + dn.len());
    key.extend_from_slice(ENTRY);
    key.extend_from_slice(dn.as_bytes());
    key
}

fn key_meta(name: &str) -> Vec<u8> {
    let mut key = Vec::with_capacity(META.len() + name.len());
    key.extend_from_slice(META);
    key.extend_from_slice(name.as_bytes());
    key
}

fn key_change(csn: &str) -> Vec<u8> {
    let mut key = Vec::with_capacity(CHANGES.len() + csn.len());
    key.extend_from_slice(CHANGES);
    key.extend_from_slice(csn.as_bytes());
    key
}

/// The upper bound of a prefix scan: the last byte bumped, so `e/` runs to `e0`.
///
/// A prefix scan in an LSM takes a range, and a range whose end is the prefix with its last octet
/// incremented is the whole subtree and nothing beside it - which is why the keys are laid out as
/// `e/`, `m/`, `c/` rather than interleaved.
fn prefix_end(prefix: &[u8]) -> Vec<u8> {
    let mut end = prefix.to_vec();
    let last = end.len() - 1;
    end[last] = end[last].saturating_add(1);
    end
}

/// The configuration named in `backends.<name>`.
///
/// Credentials are taken from the configuration when given and from the environment otherwise, as
/// every S3 client does: a deployment on a host with a role has no reason to write a key into a
/// file that `ps` can read.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SlateS3Config {
    /// The bucket the directory lives in.
    pub bucket: String,
    /// The endpoint of an S3-compatible service. Absent means Amazon's own.
    #[serde(default)]
    pub endpoint: Option<String>,
    /// The region to sign for. Absent means `us-east-1`, which most compatible services accept.
    #[serde(default)]
    pub region: Option<String>,
    /// The path inside the bucket. Absent means `rrl`.
    #[serde(default)]
    pub prefix: Option<String>,
    #[serde(default)]
    pub access_key: Option<String>,
    #[serde(default)]
    pub secret_key: Option<String>,
    /// Whether plain HTTP is allowed. Off by default: an endpoint that answers in the clear is a
    /// deployment decision, not a default.
    #[serde(default)]
    pub allow_http: bool,
    /// Whether changes are written to a journal a replica can follow. On by default, as in redb.
    #[serde(default = "yes")]
    pub journal: bool,
    /// The window in which commits coalesce into one WAL object. 50 ms by default.
    ///
    /// This is the latency floor of a durable write here: a single awaited commit waits for the
    /// next tick. Raising it costs latency and saves requests, and the other way round.
    #[serde(default = "default_flush_ms")]
    pub flush_interval_ms: u64,
}

fn yes() -> bool {
    true
}

fn default_flush_ms() -> u64 {
    50
}

impl SlateS3Config {
    fn flush(&self) -> std::time::Duration {
        std::time::Duration::from_millis(self.flush_interval_ms.max(1))
    }

    fn prefix(&self) -> String {
        self.prefix.clone().unwrap_or_else(|| "rrl".to_string())
    }

    fn region(&self) -> String {
        self.region
            .clone()
            .unwrap_or_else(|| "us-east-1".to_string())
    }
}

/// The database, and the runtime its background work runs on.
///
/// Held by the worker thread only. `db` is `None` until the open job has run, because the database
/// cannot be built without a runtime and the runtime cannot be built on a runtime.
struct Reality {
    runtime: tokio::runtime::Runtime,
    db: Option<slatedb::Db>,
}

impl Reality {
    /// A handle to the database.
    ///
    /// Cloned rather than borrowed: `block` needs the runtime while the caller holds the handle,
    /// and two borrows of the same field is the whole of the conflict. `Db` is a handle already -
    /// cloning it is an `Arc` bump.
    fn db(&self) -> Result<slatedb::Db, BackendError> {
        self.db.clone().ok_or_else(|| BackendError::SlateS3 {
            reason: "the database is not open".to_string(),
        })
    }

    /// Runs one asynchronous call to completion on this thread's runtime.
    fn block<T>(&self, future: impl Future<Output = T>) -> T {
        self.runtime.block_on(future)
    }
}

/// A job for the worker: it owns its reply channel, so the queue carries one type.
type Job = Box<dyn FnOnce(&mut Reality) + Send + 'static>;

/// The handle the backend holds: a queue and the thread that drains it.
struct Worker {
    /// Behind a mutex because a sender is not `Sync` and the seam's store must be: the lock is
    /// held for the length of a queue push, against a call that goes to the network.
    ///
    /// `Option` because closing the channel is how the thread is told to stop: the sender is taken
    /// out and dropped, and the queue's `recv` returns. A sentinel job alone would leave the thread
    /// waiting for a job that never comes, and the join would never return.
    jobs: std::sync::Mutex<Option<Sender<Job>>>,
    thread: std::sync::Mutex<Option<std::thread::JoinHandle<()>>>,
}

impl std::fmt::Debug for Worker {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("Worker")
    }
}

impl Worker {
    /// Starts the thread and the runtime it owns.
    ///
    /// The runtime has two worker threads rather than being a current-thread one: SlateDB's flush
    /// tick, compactor and manifest poll are background tasks, and a runtime that is only polled
    /// while a job runs would stop them between jobs - a 50 ms window that only opens when a caller
    /// asks for something is not a window.
    fn start() -> Result<Self, BackendError> {
        let (jobs, queue): (Sender<Job>, Receiver<Job>) = channel();
        let thread = std::thread::Builder::new()
            .name("slate-s3".to_string())
            .spawn(move || {
                let runtime = match tokio::runtime::Builder::new_multi_thread()
                    .worker_threads(2)
                    .enable_all()
                    .thread_name("slate-s3-rt")
                    .build()
                {
                    Ok(runtime) => runtime,
                    Err(err) => {
                        // Nothing can be answered after this, so the jobs that follow are dropped
                        // with their reply channels, and the caller sees a closed channel rather
                        // than a thread that quietly stopped.
                        eprintln!("slate-s3: no runtime for the worker: {err}");
                        return;
                    }
                };
                let mut reality = Reality { runtime, db: None };
                while let Ok(job) = queue.recv() {
                    job(&mut reality);
                }
                // The queue closed: the backend was dropped. Give the database a moment to close
                // its manifest rather than leaving it to the process exit.
                if let Some(db) = reality.db.take() {
                    let _ = reality.runtime.block_on(db.close());
                }
            })
            .map_err(|err| BackendError::SlateS3 {
                reason: format!("cannot start the worker thread: {err}"),
            })?;
        Ok(Self {
            jobs: std::sync::Mutex::new(Some(jobs)),
            thread: std::sync::Mutex::new(Some(thread)),
        })
    }

    /// Runs `job` on the worker and waits for its answer.
    ///
    /// Waiting is what the seam asks for: every method it calls is synchronous except `apply` and
    /// `load`, and a store that answered "later" would need a second shape for every caller.
    fn call<T, F>(&self, job: F) -> Result<T, BackendError>
    where
        T: Send + 'static,
        F: FnOnce(&mut Reality) -> Result<T, BackendError> + Send + 'static,
    {
        let (reply, answer) = channel();
        let queued = self
            .jobs
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_ref()
            .ok_or_else(|| BackendError::SlateS3 {
                reason: "the worker thread is closing".to_string(),
            })?
            .send(Box::new(move |reality| {
                // The receiver may be gone - a caller that gave up - and then the answer is
                // dropped, which is the whole of what it gets.
                let _ = reply.send(job(reality));
            }));
        queued.map_err(|_| BackendError::SlateS3 {
            reason: "the worker thread is gone".to_string(),
        })?;
        answer.recv().map_err(|_| BackendError::SlateS3 {
            reason: "the worker thread answered nothing".to_string(),
        })?
    }
}

impl Drop for Worker {
    fn drop(&mut self) {
        // Closing the queue is the signal: the thread drains what is queued, closes the database
        // and returns. Joined rather than detached, so a process that exits after a `sync` command
        // does not race the manifest write.
        // The sender is taken out and dropped, and that is the signal: the thread's `recv` returns
        // `Err` once every sender is gone, it closes the database, and the loop ends. Waiting for
        // the answer first means the jobs already queued have run.
        let taken = self
            .jobs
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        if taken.is_some() {
            // One last job, answered: everything queued before it has run by the time it replies.
            let (reply, answer) = channel::<()>();
            if let Some(sender) = &taken {
                let _ = sender.send(Box::new(move |_| {
                    let _ = reply.send(());
                }));
                let _ = answer.recv();
            }
        }
        drop(taken);
        let taken = self
            .thread
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        if let Some(thread) = taken {
            let _ = thread.join();
        }
    }
}

/// The directory in a bucket.
pub struct SlateS3Backend {
    /// The thread, shared by every clone: the seam hands the backend around by value, and a clone
    /// that started a second runtime against the same bucket would fence itself out of the manifest.
    worker: Arc<Worker>,
    /// The database handle, shared with the async paths.
    db: Arc<tokio::sync::Mutex<Option<slatedb::Db>>>,
    bucket: String,
    prefix: String,
    journal: bool,
    flush_interval_ms: u64,
}

impl Clone for SlateS3Backend {
    fn clone(&self) -> Self {
        Self {
            worker: Arc::clone(&self.worker),
            db: Arc::clone(&self.db),
            bucket: self.bucket.clone(),
            prefix: self.prefix.clone(),
            journal: self.journal,
            flush_interval_ms: self.flush_interval_ms,
        }
    }
}

impl std::fmt::Debug for SlateS3Backend {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SlateS3Backend")
            .field("bucket", &self.bucket)
            .field("prefix", &self.prefix)
            .field("journal", &self.journal)
            .field("flush_interval_ms", &self.flush_interval_ms)
            .finish()
    }
}

impl SlateS3Backend {
    /// Builds the store from its configuration section.
    ///
    /// Everything that can be wrong is wrong here, at start: an empty bucket, a credential that
    /// does not answer, an endpoint that is not there. A store that opened anyway would report every
    /// one of those as a failed logon later.
    pub fn from_config(config: &serde_json::Value) -> Result<Self, BackendError> {
        let config: SlateS3Config = serde_json::from_value(config.clone())
            .map_err(|err| BackendError::InvalidConfig(format!("slate-s3: {err}")))?;
        if config.bucket.trim().is_empty() {
            return Err(BackendError::InvalidConfig(
                "slate-s3 backend needs a non-empty 'bucket'".to_string(),
            ));
        }

        // The store is built here and handed to the worker: `AmazonS3::build` is synchronous, and
        // the first call to it is what proves the endpoint exists.
        let mut builder = slatedb::object_store::aws::AmazonS3Builder::new()
            .with_bucket_name(config.bucket.clone())
            .with_region(config.region())
            .with_allow_http(config.allow_http);
        if let Some(endpoint) = &config.endpoint {
            builder = builder.with_endpoint(endpoint.clone());
        }
        match (&config.access_key, &config.secret_key) {
            (Some(key), Some(secret)) => {
                builder = builder.with_access_key_id(key.clone());
                builder = builder.with_secret_access_key(secret.clone());
            }
            // No key in the configuration: the environment, or the host's role, as every S3 client
            // reads it. `from_env` fills what it finds and leaves the rest to the builder.
            (None, None) => {
                if let Ok(key) = std::env::var("AWS_ACCESS_KEY_ID") {
                    builder = builder.with_access_key_id(key);
                }
                if let Ok(secret) = std::env::var("AWS_SECRET_ACCESS_KEY") {
                    builder = builder.with_secret_access_key(secret);
                }
                if let Ok(token) = std::env::var("AWS_SESSION_TOKEN") {
                    builder = builder.with_token(token);
                }
            }
            _ => {
                return Err(BackendError::InvalidConfig(
                    "slate-s3 backend needs both 'access_key' and 'secret_key', or neither"
                        .to_string(),
                ));
            }
        }
        let store: Arc<dyn slatedb::object_store::ObjectStore> =
            Arc::new(builder.build().map_err(|err| BackendError::SlateS3 {
                reason: format!("cannot build the S3 client for '{}': {err}", config.bucket),
            })?);

        let worker = Worker::start()?;
        let settings = slatedb::Settings {
            flush_interval: Some(config.flush()),
            ..slatedb::Settings::default()
        };
        let prefix = config.prefix();
        let db = worker.call({
            let prefix = prefix.clone();
            move |reality| {
                let db = reality
                    .block(
                        slatedb::Db::builder(prefix.clone(), store)
                            .with_settings(settings)
                            .build(),
                    )
                    .map_err(|err| BackendError::SlateS3 {
                        reason: format!("cannot open the store at '{prefix}': {err}"),
                    })?;
                reality.db = Some(db.clone());
                Ok(db)
            }
        })?;

        Ok(Self {
            worker: Arc::new(worker),
            db: Arc::new(tokio::sync::Mutex::new(Some(db))),
            bucket: config.bucket,
            prefix,
            journal: config.journal,
            flush_interval_ms: config.flush_interval_ms,
        })
    }

    /// Where the store keeps its objects, for an operator who has to find them.
    pub fn location(&self) -> String {
        format!("s3://{}/{}", self.bucket, self.prefix)
    }

    /// The database, for the asynchronous paths.
    async fn database(&self) -> Result<slatedb::Db, BackendError> {
        self.db
            .lock()
            .await
            .clone()
            .ok_or_else(|| BackendError::SlateS3 {
                reason: "the store is closed".to_string(),
            })
    }

    /// Every entry, as the directory needs them.
    pub async fn directory_data(&self) -> Result<DirectoryData, BackendError> {
        let db = self.database().await?;
        let mut entries = Vec::new();
        let mut iter = db
            .scan(ENTRY.to_vec()..prefix_end(ENTRY))
            .await
            .map_err(slate)?;
        while let Some(item) = iter.next().await.map_err(slate)? {
            let stored: StoredEntry =
                serde_json::from_slice(&item.value).map_err(|err| BackendError::Parse {
                    path: String::from_utf8_lossy(&item.key).to_string(),
                    source: err,
                })?;
            let dn = String::from_utf8_lossy(&item.key[ENTRY.len()..]).to_string();
            entries.push(stored.into_entry(&dn));
        }
        Ok(DirectoryData {
            users: Vec::new(),
            groups: Vec::new(),
            entries,
        })
    }

    /// One entry, by DN.
    pub async fn entry(&self, dn: &str) -> Result<Option<Entry>, BackendError> {
        let db = self.database().await?;
        let found = db.get(key_entry(dn)).await.map_err(slate)?;
        match found {
            None => Ok(None),
            Some(bytes) => {
                let stored: StoredEntry =
                    serde_json::from_slice(&bytes).map_err(|err| BackendError::Parse {
                        path: dn.to_string(),
                        source: err,
                    })?;
                Ok(Some(stored.into_entry(dn)))
            }
        }
    }

    /// One entry, by DN, for the synchronous seam.
    ///
    /// The seam's `entry` is synchronous and this store is not, so the read happens on the worker
    /// thread and the caller waits. `None` for a missing entry and for a failed read alike: the
    /// caller treats both as "not readable here" and reads the store properly.
    pub fn entry_blocking(&self, dn: &str) -> Result<Option<Entry>, BackendError> {
        let key = key_entry(dn);
        let value = self.worker.call(move |reality| {
            let db = reality.db()?;
            let found = reality.block(db.get(key)).map_err(slate)?;
            Ok(found.map(|bytes| bytes.to_vec()))
        })?;
        match value {
            None => Ok(None),
            Some(bytes) => {
                let stored: StoredEntry =
                    serde_json::from_slice(&bytes).map_err(|err| BackendError::Parse {
                        path: dn.to_string(),
                        source: err,
                    })?;
                Ok(Some(stored.into_entry(dn)))
            }
        }
    }

    /// How many entries the store holds.
    ///
    /// Read from the counter the transaction keeps, not by scanning: this answers a status request,
    /// and a scan of a directory of a hundred thousand entries to answer one is a page of L0 read
    /// for nothing.
    pub fn entry_count(&self) -> Result<u64, BackendError> {
        let count = self.meta_get(META_COUNT)?;
        Ok(count
            .map(|bytes| {
                let mut array = [0_u8; 8];
                let take = bytes.len().min(8);
                array[..take].copy_from_slice(&bytes[..take]);
                u64::from_le_bytes(array)
            })
            .unwrap_or(0))
    }

    /// Applies one change set as one transaction.
    ///
    /// The order is the redb store's, because a replica reads both: entries, then their journal
    /// records, then the counter - one commit, so a replica sees the change and its record together
    /// or neither.
    pub async fn apply(&self, changes: &[EntryChange]) -> Result<u64, BackendError> {
        if changes.is_empty() {
            return self.sequence();
        }
        let db = self.database().await?;
        // `put` and `delete` take `&self`; only `commit` consumes the transaction.
        let transaction = db.begin(slatedb::IsolationLevel::Snapshot).map_err(slate)?;

        // Read first and write after: a transaction in SlateDB tracks what it read, and a write
        // made before the read of the same key would not be part of that tracking.
        let current = transaction.get(key_meta(META_SEQ)).await.map_err(slate)?;
        let mut sequence = current
            .as_ref()
            .map(|bytes| {
                let mut array = [0_u8; 8];
                let take = bytes.len().min(8);
                array[..take].copy_from_slice(&bytes[..take]);
                u64::from_le_bytes(array)
            })
            .unwrap_or(0);
        let counted = transaction.get(key_meta(META_COUNT)).await.map_err(slate)?;
        let mut count = counted
            .as_ref()
            .map(|bytes| {
                let mut array = [0_u8; 8];
                let take = bytes.len().min(8);
                array[..take].copy_from_slice(&bytes[..take]);
                u64::from_le_bytes(array)
            })
            .unwrap_or(0);

        for change in changes {
            match change {
                EntryChange::Upsert { entry } => {
                    // `add` or `modify` is decided here, in the transaction: asking the directory
                    // in memory would be a second source of truth, and the two disagree exactly
                    // when a reload has not happened yet.
                    let existed = transaction
                        .get(key_entry(entry.dn()))
                        .await
                        .map_err(slate)?
                        .is_some();
                    let stored = StoredEntry::from_entry(entry);

                    if self.journal {
                        let record = ChangeRecord {
                            csn: csn_of(entry),
                            kind: if existed {
                                ChangeKind::Modify
                            } else {
                                ChangeKind::Add
                            },
                            dn: entry.dn().to_string(),
                            uuid: uuid_of(entry),
                            entry: Some(stored.clone()),
                        };
                        let bytes =
                            serde_json::to_vec(&record).map_err(|err| BackendError::SlateS3 {
                                reason: format!(
                                    "cannot serialize the journal record for '{}': {err}",
                                    entry.dn()
                                ),
                            })?;
                        transaction
                            .put(key_change(&record.csn), bytes)
                            .map_err(slate)?;
                    }

                    let bytes =
                        serde_json::to_vec(&stored).map_err(|err| BackendError::SlateS3 {
                            reason: format!("cannot serialize '{}': {err}", entry.dn()),
                        })?;
                    transaction
                        .put(key_entry(entry.dn()), bytes)
                        .map_err(slate)?;
                    if !existed {
                        count += 1;
                    }
                }
                EntryChange::Delete { dn, .. } => {
                    // The tombstone is written even when the entry was already gone: a replica that
                    // never learned about the deletion still has to.
                    if self.journal {
                        let record = ChangeRecord {
                            csn: crate::operational::next_csn(),
                            kind: ChangeKind::Delete,
                            dn: dn.clone(),
                            uuid: String::new(),
                            entry: None,
                        };
                        let bytes =
                            serde_json::to_vec(&record).map_err(|err| BackendError::SlateS3 {
                                reason: format!(
                                    "cannot serialize the journal record for '{dn}': {err}"
                                ),
                            })?;
                        transaction
                            .put(key_change(&record.csn), bytes)
                            .map_err(slate)?;
                    }
                    let existed = transaction
                        .get(key_entry(dn))
                        .await
                        .map_err(slate)?
                        .is_some();
                    if existed {
                        count = count.saturating_sub(1);
                    }
                    transaction.delete(key_entry(dn)).map_err(slate)?;
                }
                other => {
                    return Err(BackendError::InvalidConfig(format!(
                        "the slate-s3 backend stores whole entries; got {}",
                        other.kind()
                    )));
                }
            }
        }

        // The counter moves with the data, in the same transaction: a start compares it with what
        // the index chain covers, and a counter that could lag the data would let a stale index
        // look current.
        sequence += 1;
        transaction
            .put(key_meta(META_SEQ), sequence.to_le_bytes())
            .map_err(slate)?;
        transaction
            .put(key_meta(META_COUNT), count.to_le_bytes())
            .map_err(slate)?;

        // `commit`, then wait for it to be durable - not `flush`. A flush forces the window shut
        // for this write alone, which is one WAL object per commit; waiting lets commits made
        // inside the same window share one. That is the whole reason the interval exists.
        if let Some(handle) = transaction.commit().await.map_err(slate)? {
            handle.await_durable().await.map_err(slate)?;
        }
        Ok(sequence)
    }

    /// The change counter, or zero for a store nothing has been written to.
    pub fn sequence(&self) -> Result<u64, BackendError> {
        let found = self.meta_get(META_SEQ)?;
        Ok(found
            .map(|bytes| {
                let mut array = [0_u8; 8];
                let take = bytes.len().min(8);
                array[..take].copy_from_slice(&bytes[..take]);
                u64::from_le_bytes(array)
            })
            .unwrap_or(0))
    }

    pub fn meta_get(&self, key: &str) -> Result<Option<Vec<u8>>, BackendError> {
        self.worker.call({
            let key = key_meta(key);
            move |reality| {
                let db = reality.db()?;
                let found = reality.block(db.get(key)).map_err(slate)?;
                Ok(found.map(|bytes| bytes.to_vec()))
            }
        })
    }

    pub fn meta_set(&self, key: &str, value: &[u8]) -> Result<(), BackendError> {
        let value = value.to_vec();
        self.worker.call({
            let key = key_meta(key);
            move |reality| {
                let db = reality.db()?;
                let handle = reality.block(db.put(key, value)).map_err(slate)?;
                reality.block(handle.await_durable()).map_err(slate)?;
                Ok(())
            }
        })
    }

    /// Journal records after `csn`, oldest first.
    pub fn journal_since(&self, csn: Option<&str>) -> Result<Vec<ChangeRecord>, BackendError> {
        if !self.journal {
            return Ok(Vec::new());
        }
        let from = match csn {
            // `entryCSN` is fixed width, so a range from the last-seen stamp is a range in time.
            Some(csn) => key_change(&format!("{csn}\0")),
            None => CHANGES.to_vec(),
        };
        self.worker.call(move |reality| {
            let db = reality.db()?;
            let mut records = Vec::new();
            let mut iter = reality
                .block(db.scan(from..prefix_end(CHANGES)))
                .map_err(slate)?;
            while let Some(item) = reality.block(iter.next()).map_err(slate)? {
                let record: ChangeRecord =
                    serde_json::from_slice(&item.value).map_err(|err| BackendError::Parse {
                        path: String::from_utf8_lossy(&item.key).to_string(),
                        source: err,
                    })?;
                records.push(record);
            }
            Ok(records)
        })
    }

    pub fn journal_floor(&self) -> Result<Option<String>, BackendError> {
        if !self.journal {
            return Ok(None);
        }
        self.worker.call(|reality| {
            let db = reality.db()?;
            let mut iter = reality
                .block(db.scan(CHANGES.to_vec()..prefix_end(CHANGES)))
                .map_err(slate)?;
            match reality.block(iter.next()).map_err(slate)? {
                None => Ok(None),
                Some(item) => Ok(Some(
                    String::from_utf8_lossy(&item.key[CHANGES.len()..]).to_string(),
                )),
            }
        })
    }

    pub fn journal_head(&self) -> Result<Option<String>, BackendError> {
        if !self.journal {
            return Ok(None);
        }
        self.worker.call(|reality| {
            let db = reality.db()?;
            let mut last: Option<String> = None;
            let mut iter = reality
                .block(db.scan(CHANGES.to_vec()..prefix_end(CHANGES)))
                .map_err(slate)?;
            while let Some(item) = reality.block(iter.next()).map_err(slate)? {
                last = Some(String::from_utf8_lossy(&item.key[CHANGES.len()..]).to_string());
            }
            Ok(last)
        })
    }

    /// Drops the oldest records, keeping the newest `keep`.
    pub fn journal_prune(&self, keep: usize) -> Result<usize, BackendError> {
        let records = self.journal_since(None)?;
        if records.len() <= keep {
            return Ok(0);
        }
        let doomed: Vec<String> = records[..records.len() - keep]
            .iter()
            .map(|record| record.csn.clone())
            .collect();
        self.remove_changes(&doomed)
    }

    /// Drops the records stamped before `cutoff`.
    ///
    /// The CSN is read for its time, not compared as text, for the reason the redb store does the
    /// same: a record whose CSN cannot be read is not evidence that it is old, and dropping one a
    /// peer still needs costs that peer a full resynchronisation.
    pub fn journal_prune_before(
        &self,
        cutoff: std::time::SystemTime,
    ) -> Result<usize, BackendError> {
        let records = self.journal_since(None)?;
        let doomed: Vec<String> = records
            .iter()
            .filter(|record| {
                crate::operational::csn_time(&record.csn)
                    .map(|stamp| stamp < cutoff)
                    .unwrap_or(false)
            })
            .map(|record| record.csn.clone())
            .collect();
        self.remove_changes(&doomed)
    }

    fn remove_changes(&self, doomed: &[String]) -> Result<usize, BackendError> {
        if doomed.is_empty() {
            return Ok(0);
        }
        let keys: Vec<Vec<u8>> = doomed.iter().map(|csn| key_change(csn)).collect();
        let removed = keys.len();
        self.worker.call(move |reality| {
            let db = reality.db()?;
            let transaction = reality
                .block(async { db.begin(slatedb::IsolationLevel::Snapshot) })
                .map_err(slate)?;
            for key in keys {
                transaction.delete(key).map_err(slate)?;
            }
            if let Some(handle) = reality.block(transaction.commit()).map_err(slate)? {
                reality.block(handle.await_durable()).map_err(slate)?;
            }
            Ok(())
        })?;
        Ok(removed)
    }

    /// Writes every pending commit down now, rather than at the next tick.
    ///
    /// For a `sync` command or a shutdown: the interval is a latency trade, and an operator asking
    /// for the data to be in the bucket means now.
    pub fn sync(&self) -> Result<(), BackendError> {
        self.worker.call(|reality| {
            let db = reality.db()?;
            reality.block(db.flush()).map_err(slate)?;
            Ok(())
        })
    }
}

/// A SlateDB error, in the shape this crate reports store errors in.
fn slate(err: slatedb::Error) -> BackendError {
    BackendError::SlateS3 {
        reason: err.to_string(),
    }
}

/// The `entryCSN` an entry carries, or a fresh one.
///
/// One function for both stores: a journal record written by one backend and read by a replica of
/// the other has to name the same moment, and a second spelling of "which stamp" is a second place
/// to be wrong.
fn csn_of(entry: &Entry) -> String {
    crate::backend::redb_store::csn_of(entry)
}

/// The entry's `entryUUID`, or one derived from the DN.
fn uuid_of(entry: &Entry) -> String {
    crate::backend::redb_store::uuid_of(entry)
}
