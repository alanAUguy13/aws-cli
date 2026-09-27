//! Audit and event ledgers: append-only, hash-chained, correlation-aware.
//!
//! * The **audit ledger** answers "who did what, and was it allowed":
//!   security, policy, decision, enforcement and replay events.
//! * The **event ledger** is the domain event stream (observation ingested,
//!   facts derived, decision made, evidence sealed, action dispatched) with
//!   correlation ids and causation links forming a traceable DAG.
//!
//! Each entry commits to its predecessor's hash; [`Ledger::verify`] detects
//! any edit, deletion, insertion or reordering. Publishing `head()` to an
//! external witness (transparency log, WORM bucket, another org) extends
//! this to detecting wholesale rewrites.

use serde::{Deserialize, Serialize};

use crate::canonical::{domain, hash_canonical, Digest};
use crate::error::{GovError, Result};
use crate::policy::Effect;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LedgerEntry<T> {
    pub seq: u64,
    pub at: u64,
    pub correlation_id: String,
    pub causation: Option<Digest>,
    pub event: T,
    pub prev_hash: Digest,
    pub entry_hash: Digest,
}

#[derive(Serialize)]
struct EntryPreimage<'a, T> {
    seq: u64,
    at: u64,
    correlation_id: &'a str,
    causation: &'a Option<Digest>,
    event: &'a T,
    prev_hash: &'a Digest,
}

#[derive(Debug, Clone)]
pub struct Ledger<T> {
    entries: Vec<LedgerEntry<T>>,
}

impl<T> Default for Ledger<T> {
    fn default() -> Self {
        Self { entries: Vec::new() }
    }
}

impl<T: Serialize + Clone> Ledger<T> {
    pub fn head(&self) -> Digest {
        self.entries.last().map(|e| e.entry_hash).unwrap_or(Digest::ZERO)
    }

    pub fn append(&mut self, at: u64, correlation_id: &str, causation: Option<Digest>, event: T) -> Result<Digest> {
        let seq = self.entries.len() as u64;
        let prev_hash = self.head();
        let entry_hash = hash_canonical(
            domain::LEDGER_ENTRY,
            &EntryPreimage { seq, at, correlation_id, causation: &causation, event: &event, prev_hash: &prev_hash },
        )?;
        self.entries.push(LedgerEntry { seq, at, correlation_id: correlation_id.to_string(), causation, event, prev_hash, entry_hash });
        Ok(entry_hash)
    }

    pub fn verify(&self) -> Result<()> {
        let mut prev = Digest::ZERO;
        for (i, e) in self.entries.iter().enumerate() {
            let computed = hash_canonical(
                domain::LEDGER_ENTRY,
                &EntryPreimage {
                    seq: e.seq,
                    at: e.at,
                    correlation_id: &e.correlation_id,
                    causation: &e.causation,
                    event: &e.event,
                    prev_hash: &e.prev_hash,
                },
            )?;
            if e.seq != i as u64 || e.prev_hash != prev || computed != e.entry_hash {
                return Err(GovError::Integrity(format!("ledger chain broken at entry #{i}")));
            }
            prev = e.entry_hash;
        }
        Ok(())
    }

    pub fn entries(&self) -> &[LedgerEntry<T>] {
        &self.entries
    }

    /// All entries sharing a correlation id, in order.
    pub fn correlated<'a>(&'a self, correlation_id: &'a str) -> impl Iterator<Item = &'a LedgerEntry<T>> + 'a {
        self.entries.iter().filter(move |e| e.correlation_id == correlation_id)
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    #[doc(hidden)]
    pub fn get_mut_unchecked(&mut self, idx: usize) -> Option<&mut LedgerEntry<T>> {
        self.entries.get_mut(idx)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "category", rename_all = "snake_case")]
pub enum AuditEvent {
    Security { action: String, principal: Option<String>, allowed: bool, detail: String },
    Policy { action: String, policy_id: String, version: u32, actor: String, policy_hash: Option<Digest> },
    Decision { decision_hash: Digest, subject: String, effect: Effect, policy_hash: Digest, principal: String },
    Enforcement { decision_hash: Digest, connector: String, operation: String, outcome: String },
    Replay { decision_hash: Digest, verdict: String, report_hash: Digest, principal: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum DomainEvent {
    ObservationIngested { observation_hash: Digest, source_id: String, schema: String, duplicate: bool },
    FactsDerived { observation_hash: Digest, fact_hashes: Vec<Digest>, rejections: Vec<String> },
    DecisionMade { decision_hash: Digest, effect: Effect },
    EvidenceSealed { decision_hash: Digest, evidence_hash: Digest },
    ActionDispatched { idempotency_key: Digest, connector: String, operation: String, external_ref: String },
    ActionFailed { idempotency_key: Digest, connector: String, operation: String, error: String },
}

pub type AuditLedger = Ledger<AuditEvent>;
pub type EventLedger = Ledger<DomainEvent>;
