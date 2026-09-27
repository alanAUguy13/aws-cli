//! Evidence domain: provenance, hash chain and signatures.
//!
//! Trust chain per decision:
//!
//! ```text
//! observation hash -> fact hash -> policy hash -> decision hash -> evidence hash -> ECDSA signature
//! ```
//!
//! Evidence records are additionally chained to each other (`prev_evidence_hash`)
//! so deleting or reordering a record is as detectable as editing one.
//! [`EvidenceBundle`] packages everything needed to verify a decision offline,
//! with no access to RustGate's stores, including the mapping rules, so
//! the verifier re-derives every fact from its signed observation rather
//! than trusting the fact records.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::canonical::{domain, hash_canonical, Digest};
use crate::decision::{DecisionBody, DecisionRecord};
use crate::engine::{self, ENGINE_VERSION};
use crate::error::{GovError, Result};
use crate::fact::{verify_derivation, Fact, FactSnapshot, MappingRule};
use crate::keys::{EvidenceSigner, KeyPurpose, SignatureEnvelope, TrustStore};
use crate::observation::{ObservationEnvelope, SourceRef};
use crate::policy::CompiledPolicy;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProvenanceLink {
    pub fact_name: String,
    pub fact_hash: Digest,
    pub observation_hash: Digest,
    pub source: SourceRef,
    pub schema: String,
    pub mapping_id: String,
    pub mapping_hash: Digest,
    pub observed_at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceBody {
    pub seq: u64,
    pub tenant: String,
    pub decision_hash: Digest,
    pub policy_hash: Digest,
    pub policy_approvers: Vec<String>,
    pub engine_version: String,
    pub provenance: Vec<ProvenanceLink>,
    pub sealed_at: u64,
    pub prev_evidence_hash: Digest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceRecord {
    pub body: EvidenceBody,
    pub evidence_hash: Digest,
    pub signature: SignatureEnvelope,
}

impl EvidenceRecord {
    pub fn verify(&self, trust: &TrustStore) -> Result<()> {
        let computed = hash_canonical(domain::EVIDENCE, &self.body)?;
        if computed != self.evidence_hash {
            return Err(GovError::Integrity(format!("evidence #{} content does not match its hash", self.body.seq)));
        }
        trust.verify(computed.as_bytes(), &self.signature, KeyPurpose::Evidence, None, self.body.sealed_at)?;
        Ok(())
    }
}

pub struct EvidenceGenerator;

impl EvidenceGenerator {
    /// Build provenance (fact -> observation -> source) for every fact the
    /// decision relied on, link to the previous record, hash and sign.
    #[allow(clippy::too_many_arguments)]
    pub fn seal(
        decision: &DecisionRecord,
        policy: &CompiledPolicy,
        facts: &[&Fact],
        observations: &BTreeMap<Digest, &ObservationEnvelope>,
        seq: u64,
        prev_evidence_hash: Digest,
        sealed_at: u64,
        signer: &dyn EvidenceSigner,
    ) -> Result<EvidenceRecord> {
        let mut provenance = Vec::with_capacity(facts.len());
        for f in facts {
            let obs =
                observations.get(&f.body.observation_hash).ok_or_else(|| GovError::ObservationNotFound(f.body.observation_hash.short()))?;
            provenance.push(ProvenanceLink {
                fact_name: f.body.name.clone(),
                fact_hash: f.fact_hash,
                observation_hash: f.body.observation_hash,
                source: obs.body.source.clone(),
                schema: obs.body.schema.clone(),
                mapping_id: f.body.mapping_id.clone(),
                mapping_hash: f.body.mapping_hash,
                observed_at: f.body.observed_at,
            });
        }
        provenance.sort_by(|a, b| a.fact_name.cmp(&b.fact_name));
        let body = EvidenceBody {
            seq,
            tenant: decision.body.tenant.clone(),
            decision_hash: decision.decision_hash,
            policy_hash: policy.policy_hash,
            policy_approvers: policy.approvers.clone(),
            engine_version: decision.body.engine_version.clone(),
            provenance,
            sealed_at,
            prev_evidence_hash,
        };
        let evidence_hash = hash_canonical(domain::EVIDENCE, &body)?;
        let signature = signer.sign(evidence_hash.as_bytes());
        Ok(EvidenceRecord { body, evidence_hash, signature })
    }
}

/// Append-only, hash-chained evidence repository.
#[derive(Debug, Default)]
pub struct EvidenceRepository {
    records: Vec<EvidenceRecord>,
    by_decision: BTreeMap<Digest, usize>,
}

impl EvidenceRepository {
    pub fn head(&self) -> (u64, Digest) {
        match self.records.last() {
            Some(r) => (r.body.seq + 1, r.evidence_hash),
            None => (0, Digest::ZERO),
        }
    }

    pub fn append(&mut self, record: EvidenceRecord) -> Result<()> {
        let (seq, prev) = self.head();
        if record.body.seq != seq || record.body.prev_evidence_hash != prev {
            return Err(GovError::Integrity("evidence record does not extend the chain head".into()));
        }
        if hash_canonical(domain::EVIDENCE, &record.body)? != record.evidence_hash {
            return Err(GovError::Integrity(format!("evidence #{} content does not match its hash", record.body.seq)));
        }
        self.by_decision.entry(record.body.decision_hash).or_insert(self.records.len());
        self.records.push(record);
        Ok(())
    }

    pub fn for_decision(&self, decision_hash: &Digest) -> Option<&EvidenceRecord> {
        self.by_decision.get(decision_hash).map(|i| &self.records[*i])
    }

    pub fn len(&self) -> usize {
        self.records.len()
    }

    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    pub fn verify_chain(&self, trust: &TrustStore) -> Result<()> {
        let mut prev = Digest::ZERO;
        for (i, r) in self.records.iter().enumerate() {
            if r.body.seq != i as u64 || r.body.prev_evidence_hash != prev {
                return Err(GovError::Integrity(format!("evidence chain broken at #{i}")));
            }
            r.verify(trust)?;
            prev = r.evidence_hash;
        }
        Ok(())
    }

    #[doc(hidden)]
    pub fn get_mut_unchecked(&mut self, idx: usize) -> Option<&mut EvidenceRecord> {
        self.records.get_mut(idx)
    }
}

/// Everything needed to verify one decision offline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceBundle {
    pub evidence: EvidenceRecord,
    pub decision: DecisionRecord,
    pub policy: CompiledPolicy,
    pub facts: Vec<Fact>,
    pub observations: Vec<ObservationEnvelope>,
    /// The exact mapping rule versions that derived `facts`.
    pub mappings: Vec<MappingRule>,
}

impl EvidenceBundle {
    /// Independent verification of the complete trust chain:
    /// signatures on observations and evidence, every hash link, and a full
    /// deterministic re-execution of the decision.
    pub fn verify(&self, trust: &TrustStore) -> Result<()> {
        let obs_by_hash: BTreeMap<Digest, &ObservationEnvelope> = self.observations.iter().map(|o| (o.content_hash, o)).collect();

        // 1. Observation hashes + source signatures.
        for o in &self.observations {
            if o.body.content_hash()? != o.content_hash {
                return Err(GovError::Integrity(format!("bundle observation {} altered", o.content_hash.short())));
            }
            trust.verify(
                o.content_hash.as_bytes(),
                &o.signature,
                KeyPurpose::ObservationSource,
                Some(&o.body.source.id),
                o.body.observed_at,
            )?;
        }
        // 2. Facts: re-run normalisation. Each fact must be exactly what its
        //    named mapping rule produces from its signed observation.
        let mappings: BTreeMap<Digest, &MappingRule> = self.mappings.iter().map(|m| m.hash().map(|h| (h, m))).collect::<Result<_>>()?;
        for f in &self.facts {
            f.verify()?;
            let o = obs_by_hash
                .get(&f.body.observation_hash)
                .ok_or_else(|| GovError::Integrity(format!("fact {} references missing observation", f.fact_hash.short())))?;
            let rule = mappings
                .get(&f.body.mapping_hash)
                .ok_or_else(|| GovError::Integrity(format!("fact {} references a mapping not in the bundle", f.fact_hash.short())))?;
            verify_derivation(rule, f, o)?;
        }
        // 3. Policy hash.
        self.policy.verify()?;
        // 4. Decision hash, and deterministic re-execution.
        self.decision.verify()?;
        let d = &self.decision.body;
        if d.policy_hash != self.policy.policy_hash {
            return Err(GovError::Integrity("decision references a different policy".into()));
        }
        if d.engine_version != ENGINE_VERSION {
            return Err(GovError::Integrity(format!("bundle engine {} cannot be re-executed by {ENGINE_VERSION}", d.engine_version)));
        }
        let facts: BTreeMap<String, Fact> = self.facts.iter().map(|f| (f.body.name.clone(), f.clone())).collect();
        let snapshot = FactSnapshot { tenant: d.tenant.clone(), subject: d.subject.clone(), as_of: d.as_of, facts };
        let eval = engine::evaluate(&self.policy.program, &snapshot)?;
        let recomputed = DecisionBody::build(&self.policy, &snapshot, eval).hash()?;
        if recomputed != self.decision.decision_hash {
            return Err(GovError::Integrity("re-execution produced a different decision".into()));
        }
        // 5. Evidence hash + signature, and its links to everything above.
        self.evidence.verify(trust)?;
        let e = &self.evidence.body;
        if e.decision_hash != self.decision.decision_hash || e.policy_hash != self.policy.policy_hash {
            return Err(GovError::Integrity("evidence does not reference this decision/policy".into()));
        }
        let linked: BTreeMap<&str, (Digest, Digest)> =
            e.provenance.iter().map(|p| (p.fact_name.as_str(), (p.fact_hash, p.observation_hash))).collect();
        let expected: BTreeMap<&str, (Digest, Digest)> =
            self.facts.iter().map(|f| (f.body.name.as_str(), (f.fact_hash, f.body.observation_hash))).collect();
        if linked != expected || d.fact_hashes.len() != expected.len() {
            return Err(GovError::Integrity("evidence provenance does not match the decision's facts".into()));
        }
        Ok(())
    }
}
