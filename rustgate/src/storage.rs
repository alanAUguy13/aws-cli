//! Durable storage: a hash-chained write-ahead journal.
//!
//! Every state change in [`crate::RustGate`] is expressed as a
//! [`JournalRecord`], durably appended to a [`Journal`] *before* it is
//! applied in memory, and applied through the same code path on restart.
//! Recovery is therefore a replay of exactly the writes that happened, and
//! the in-memory stores stay the query layer.
//!
//! Each [`JournalEntry`] commits to its predecessor's hash, independent of
//! the hashes inside the records themselves, so dropping, reordering or
//! editing any entry (even one that carries no hash of its own, such as an
//! enforcement receipt) is detected when the journal is loaded.
//!
//! Backends:
//! * [`MemoryJournal`]: tests and ephemeral instances.
//! * [`FileJournal`]: append-only JSON lines with optional fsync per entry and
//!   torn-write recovery. Pair it with `chattr +a` or a WORM volume.
//! * [`postgres::PostgresJournal`] (feature `postgres`): one table whose
//!   triggers reject UPDATE, DELETE and TRUNCATE and enforce chain linkage.

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::canonical::{domain, hash_canonical, Digest};
use crate::decision::DecisionRecord;
use crate::enforcement::Receipt;
use crate::error::{GovError, Result};
use crate::evidence::EvidenceRecord;
use crate::fact::{Fact, MappingRule};
use crate::ledger::{AuditEvent, DomainEvent, LedgerEntry};
use crate::observation::StoredObservation;
use crate::policy::{Approval, CompiledPolicy, PolicyRecord};

/// One durable state change.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum JournalRecord {
    MappingRegistered { rule: MappingRule },
    ObservationStored { observation: StoredObservation },
    FactStored { fact: Fact },
    PolicySubmitted { record: PolicyRecord },
    PolicyApproved { policy_id: String, version: u32, approval: Approval },
    PolicyCompiled { policy: CompiledPolicy },
    PolicyActivated { policy_hash: Digest },
    DecisionRecorded { decision: DecisionRecord },
    EvidenceSealed { evidence: EvidenceRecord },
    AuditAppended { entry: LedgerEntry<AuditEvent> },
    EventAppended { entry: LedgerEntry<DomainEvent> },
    ActionCompleted { idempotency_key: Digest, receipt: Receipt },
}

impl JournalRecord {
    pub fn kind(&self) -> &'static str {
        match self {
            JournalRecord::MappingRegistered { .. } => "mapping_registered",
            JournalRecord::ObservationStored { .. } => "observation_stored",
            JournalRecord::FactStored { .. } => "fact_stored",
            JournalRecord::PolicySubmitted { .. } => "policy_submitted",
            JournalRecord::PolicyApproved { .. } => "policy_approved",
            JournalRecord::PolicyCompiled { .. } => "policy_compiled",
            JournalRecord::PolicyActivated { .. } => "policy_activated",
            JournalRecord::DecisionRecorded { .. } => "decision_recorded",
            JournalRecord::EvidenceSealed { .. } => "evidence_sealed",
            JournalRecord::AuditAppended { .. } => "audit_appended",
            JournalRecord::EventAppended { .. } => "event_appended",
            JournalRecord::ActionCompleted { .. } => "action_completed",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JournalEntry {
    pub seq: u64,
    pub prev_hash: Digest,
    pub record: JournalRecord,
    pub entry_hash: Digest,
}

#[derive(Serialize)]
struct EntryPreimage<'a> {
    seq: u64,
    prev_hash: &'a Digest,
    record: &'a JournalRecord,
}

impl JournalEntry {
    pub fn seal(seq: u64, prev_hash: Digest, record: JournalRecord) -> Result<Self> {
        let entry_hash = hash_canonical(domain::JOURNAL_ENTRY, &EntryPreimage { seq, prev_hash: &prev_hash, record: &record })?;
        Ok(Self { seq, prev_hash, record, entry_hash })
    }

    /// Check this entry's own hash and that it follows `(seq, prev)`.
    pub fn verify_follows(&self, seq: u64, prev: &Digest) -> Result<()> {
        let computed =
            hash_canonical(domain::JOURNAL_ENTRY, &EntryPreimage { seq: self.seq, prev_hash: &self.prev_hash, record: &self.record })?;
        if self.seq != seq || self.prev_hash != *prev || computed != self.entry_hash {
            return Err(GovError::Storage(format!("journal chain broken at entry #{seq}")));
        }
        Ok(())
    }
}

/// Verify a loaded journal and return its head `(next_seq, last_hash)`.
pub fn verify_chain(entries: &[JournalEntry]) -> Result<(u64, Digest)> {
    let mut prev = Digest::ZERO;
    for (i, e) in entries.iter().enumerate() {
        e.verify_follows(i as u64, &prev)?;
        prev = e.entry_hash;
    }
    Ok((entries.len() as u64, prev))
}

/// A durable, append-only log of [`JournalEntry`]s.
pub trait Journal {
    /// Append one entry. Must not return `Ok` until the entry is as durable
    /// as the backend promises.
    fn append(&mut self, entry: &JournalEntry) -> Result<()>;
    /// Every entry, in order.
    fn load(&mut self) -> Result<Vec<JournalEntry>>;
    fn describe(&self) -> String;
}

#[derive(Debug, Default)]
pub struct MemoryJournal {
    entries: Vec<JournalEntry>,
}

impl MemoryJournal {
    pub fn entries(&self) -> &[JournalEntry] {
        &self.entries
    }
}

impl Journal for MemoryJournal {
    fn append(&mut self, entry: &JournalEntry) -> Result<()> {
        self.entries.push(entry.clone());
        Ok(())
    }

    fn load(&mut self) -> Result<Vec<JournalEntry>> {
        Ok(self.entries.clone())
    }

    fn describe(&self) -> String {
        format!("memory ({} entries)", self.entries.len())
    }
}

/// Append-only JSON-lines journal file.
///
/// A crash can leave at most one partially written final line; [`load`]
/// truncates that torn tail (it was never acknowledged) and reports it via
/// [`FileJournal::recovered_bytes`]. A malformed *complete* line is
/// corruption, not a crash artefact, and fails the load.
///
/// [`load`]: Journal::load
#[derive(Debug)]
pub struct FileJournal {
    path: PathBuf,
    file: File,
    fsync: bool,
    recovered_bytes: u64,
}

fn io_err(path: &Path, e: std::io::Error) -> GovError {
    GovError::Storage(format!("{}: {e}", path.display()))
}

impl FileJournal {
    /// Open (creating if needed). `fsync = true` syncs every append to disk
    /// before acknowledging it.
    pub fn open(path: impl AsRef<Path>, fsync: bool) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        let file = OpenOptions::new().create(true).read(true).append(true).open(&path).map_err(|e| io_err(&path, e))?;
        Ok(Self { path, file, fsync, recovered_bytes: 0 })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Bytes of torn final line discarded by the last load.
    pub fn recovered_bytes(&self) -> u64 {
        self.recovered_bytes
    }
}

impl Journal for FileJournal {
    fn append(&mut self, entry: &JournalEntry) -> Result<()> {
        let mut line = serde_json::to_vec(entry).map_err(|e| GovError::Storage(e.to_string()))?;
        line.push(b'\n');
        self.file.write_all(&line).map_err(|e| io_err(&self.path, e))?;
        if self.fsync {
            self.file.sync_data().map_err(|e| io_err(&self.path, e))?;
        }
        Ok(())
    }

    fn load(&mut self) -> Result<Vec<JournalEntry>> {
        let mut bytes = Vec::new();
        self.file.seek(SeekFrom::Start(0)).map_err(|e| io_err(&self.path, e))?;
        self.file.read_to_end(&mut bytes).map_err(|e| io_err(&self.path, e))?;

        let complete = bytes.iter().rposition(|b| *b == b'\n').map_or(0, |i| i + 1);
        self.recovered_bytes = (bytes.len() - complete) as u64;
        if self.recovered_bytes > 0 {
            self.file.set_len(complete as u64).map_err(|e| io_err(&self.path, e))?;
            self.file.sync_all().map_err(|e| io_err(&self.path, e))?;
        }

        bytes[..complete]
            .split(|b| *b == b'\n')
            .filter(|l| !l.is_empty())
            .enumerate()
            .map(|(i, line)| {
                serde_json::from_slice(line).map_err(|e| GovError::Storage(format!("{}: entry #{i} is corrupt: {e}", self.path.display())))
            })
            .collect()
    }

    fn describe(&self) -> String {
        format!("file {} (fsync={})", self.path.display(), self.fsync)
    }
}

#[cfg(feature = "postgres")]
pub mod postgres {
    //! PostgreSQL journal backend. Schema: `sql/postgres.sql`.

    use ::postgres::{Client, NoTls};

    use super::{Journal, JournalEntry};
    use crate::error::{GovError, Result};

    pub const SCHEMA: &str = include_str!("../sql/postgres.sql");

    pub struct PostgresJournal {
        client: Client,
        stream: String,
    }

    fn pg_err(e: ::postgres::Error) -> GovError {
        let detail = match (e.as_db_error(), std::error::Error::source(&e)) {
            (Some(db), _) => db.message().to_string(),
            (None, Some(cause)) => format!("{e}: {cause}"),
            (None, None) => e.to_string(),
        };
        GovError::Storage(format!("postgres: {detail}"))
    }

    impl PostgresJournal {
        /// Connect and install the schema idempotently. `stream` names this
        /// instance's journal, so several instances can share one database.
        /// Use TLS (e.g. `postgres-native-tls`) through [`Self::from_client`]
        /// for anything beyond a local socket.
        pub fn connect(url: &str, stream: &str) -> Result<Self> {
            let client = Client::connect(url, NoTls).map_err(pg_err)?;
            Self::from_client(client, stream)
        }

        pub fn from_client(mut client: Client, stream: &str) -> Result<Self> {
            client.batch_execute(SCHEMA).map_err(pg_err)?;
            Ok(Self { client, stream: stream.to_string() })
        }

        pub fn client(&mut self) -> &mut Client {
            &mut self.client
        }
    }

    impl Journal for PostgresJournal {
        fn append(&mut self, entry: &JournalEntry) -> Result<()> {
            let text = serde_json::to_string(entry).map_err(|e| GovError::Storage(e.to_string()))?;
            let seq = i64::try_from(entry.seq).map_err(|_| GovError::Storage("sequence overflow".into()))?;
            self.client
                .execute(
                    "INSERT INTO rustgate_journal (stream, seq, prev_hash, entry_hash, kind, entry) VALUES ($1, $2, $3, $4, $5, $6)",
                    &[&self.stream, &seq, &entry.prev_hash.to_hex(), &entry.entry_hash.to_hex(), &entry.record.kind(), &text],
                )
                .map_err(pg_err)?;
            Ok(())
        }

        fn load(&mut self) -> Result<Vec<JournalEntry>> {
            let rows =
                self.client.query("SELECT entry FROM rustgate_journal WHERE stream = $1 ORDER BY seq", &[&self.stream]).map_err(pg_err)?;
            rows.iter()
                .map(|r| {
                    let text: String = r.get(0);
                    serde_json::from_str(&text).map_err(|e| GovError::Storage(format!("corrupt journal row: {e}")))
                })
                .collect()
        }

        fn describe(&self) -> String {
            format!("postgres stream '{}'", self.stream)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::enforcement::Receipt;

    fn record(n: u8) -> JournalRecord {
        JournalRecord::ActionCompleted {
            idempotency_key: crate::canonical::hash_bytes("t", &[n]),
            receipt: Receipt { connector: "c".into(), external_ref: format!("R-{n}") },
        }
    }

    fn write(j: &mut dyn Journal, n: u8) -> Vec<JournalEntry> {
        let mut prev = Digest::ZERO;
        (0..n)
            .map(|i| {
                let e = JournalEntry::seal(i as u64, prev, record(i)).unwrap();
                j.append(&e).unwrap();
                prev = e.entry_hash;
                e
            })
            .collect()
    }

    fn tmp(name: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!("rustgate-{}-{name}.jsonl", std::process::id()));
        let _ = std::fs::remove_file(&p);
        p
    }

    #[test]
    fn file_journal_roundtrip_and_chain() {
        let p = tmp("roundtrip");
        write(&mut FileJournal::open(&p, true).unwrap(), 5);
        let loaded = FileJournal::open(&p, true).unwrap().load().unwrap();
        assert_eq!(verify_chain(&loaded).unwrap().0, 5);
        std::fs::remove_file(p).unwrap();
    }

    #[test]
    fn torn_tail_is_truncated_but_corruption_fails() {
        let p = tmp("torn");
        write(&mut FileJournal::open(&p, false).unwrap(), 3);
        OpenOptions::new().append(true).open(&p).unwrap().write_all(b"{\"seq\":3,\"prev_h").unwrap();
        let mut j = FileJournal::open(&p, false).unwrap();
        assert_eq!(j.load().unwrap().len(), 3);
        assert_eq!(j.recovered_bytes(), 16);
        assert_eq!(FileJournal::open(&p, false).unwrap().load().unwrap().len(), 3, "truncation persisted");

        let text = std::fs::read_to_string(&p).unwrap().replacen("R-1", "R-9", 1);
        std::fs::write(&p, text).unwrap();
        let loaded = FileJournal::open(&p, false).unwrap().load().unwrap();
        assert!(verify_chain(&loaded).is_err(), "edited entry breaks the chain");

        std::fs::write(&p, "not json\n").unwrap();
        assert!(FileJournal::open(&p, false).unwrap().load().is_err());
        std::fs::remove_file(p).unwrap();
    }

    #[test]
    fn dropped_or_reordered_entries_break_the_chain() {
        let mut j = MemoryJournal::default();
        let mut entries = write(&mut j, 4);
        entries.remove(1);
        assert!(verify_chain(&entries).is_err());
        let mut entries = j.load().unwrap();
        entries.swap(1, 2);
        assert!(verify_chain(&entries).is_err());
    }
}
