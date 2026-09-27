//! Decision service: decision records, explanations and decision hashing.
//!
//! The decision hash is a pure function of (tenant, subject, as_of, the fact
//! hashes the policy used, the policy hash, the engine version) and the
//! outcome derived from them. Correlation ids and requester identity are
//! envelope metadata and deliberately excluded, so an identical question
//! asked twice yields the identical decision hash.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::canonical::{domain, hash_canonical, Digest};
use crate::engine::{Evaluation, RuleTrace, ENGINE_VERSION};
use crate::error::{GovError, Result};
use crate::fact::FactSnapshot;
use crate::policy::{ActionTemplate, CompiledPolicy, Effect};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecisionRequest {
    pub tenant: String,
    pub subject: String,
    pub policy_id: String,
    /// The instant the decision is about. Must not be in the future.
    pub as_of: u64,
    pub correlation_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecisionBody {
    pub tenant: String,
    pub subject: String,
    pub as_of: u64,
    pub policy_id: String,
    pub policy_version: u32,
    pub policy_hash: Digest,
    pub engine_version: String,
    pub fact_hashes: BTreeMap<String, Digest>,
    pub effect: Effect,
    pub decisive_rule: Option<String>,
    pub matched_rules: Vec<String>,
    pub actions: Vec<ActionTemplate>,
    pub explanation: String,
    pub trace: Vec<RuleTrace>,
}

impl DecisionBody {
    pub fn build(policy: &CompiledPolicy, snapshot: &FactSnapshot, eval: Evaluation) -> Self {
        DecisionBody {
            tenant: snapshot.tenant.clone(),
            subject: snapshot.subject.clone(),
            as_of: snapshot.as_of,
            policy_id: policy.program.policy_id.clone(),
            policy_version: policy.program.version,
            policy_hash: policy.policy_hash,
            engine_version: ENGINE_VERSION.to_string(),
            fact_hashes: eval.used_facts,
            effect: eval.effect,
            decisive_rule: eval.decisive_rule,
            matched_rules: eval.matched_rules,
            actions: eval.actions,
            explanation: eval.explanation,
            trace: eval.trace,
        }
    }

    pub fn hash(&self) -> Result<Digest> {
        hash_canonical(domain::DECISION, self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecisionRecord {
    pub body: DecisionBody,
    pub decision_hash: Digest,
    pub correlation_id: String,
    pub requested_by: String,
    pub decided_at: u64,
}

impl DecisionRecord {
    pub fn verify(&self) -> Result<()> {
        if self.body.hash()? != self.decision_hash {
            return Err(GovError::Integrity(format!("decision {} content does not match its hash", self.decision_hash.short())));
        }
        Ok(())
    }
}

/// Authority of record for decisions. Append-only; the first record for a
/// given decision hash wins (a repeat request is served from the record).
#[derive(Debug, Default)]
pub struct DecisionService {
    records: BTreeMap<Digest, DecisionRecord>,
}

impl DecisionService {
    /// Returns `(record, is_new)`.
    pub fn record(
        &mut self,
        body: DecisionBody,
        correlation_id: &str,
        requested_by: &str,
        decided_at: u64,
    ) -> Result<(DecisionRecord, bool)> {
        let decision_hash = body.hash()?;
        if let Some(existing) = self.records.get(&decision_hash) {
            return Ok((existing.clone(), false));
        }
        let rec = DecisionRecord {
            body,
            decision_hash,
            correlation_id: correlation_id.to_string(),
            requested_by: requested_by.to_string(),
            decided_at,
        };
        self.records.insert(decision_hash, rec.clone());
        Ok((rec, true))
    }

    pub fn get(&self, hash: &Digest) -> Result<&DecisionRecord> {
        self.records.get(hash).ok_or_else(|| GovError::DecisionNotFound(hash.short()))
    }

    pub fn verify_integrity(&self) -> Result<()> {
        self.records.values().try_for_each(DecisionRecord::verify)
    }

    pub fn len(&self) -> usize {
        self.records.len()
    }

    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    #[doc(hidden)]
    pub fn get_mut_unchecked(&mut self, hash: &Digest) -> Option<&mut DecisionRecord> {
        self.records.get_mut(hash)
    }
}
