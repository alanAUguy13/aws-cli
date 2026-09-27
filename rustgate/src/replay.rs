//! Replay and verification.
//!
//! Two different questions, deliberately kept apart:
//!
//! 1. **Replay** — "given exactly what we knew then, do we get exactly what
//!    we decided then?" Loads the recorded facts and the recorded compiled
//!    policy by hash, re-executes, and compares hashes. Anything other than
//!    `Match` means tampering or a non-deterministic engine.
//! 2. **Re-decision** — "knowing what we know *now* (late-arriving facts,
//!    today's active policy), would we decide the same about that instant?"
//!    Differences here are legitimate drift, classified by cause.

use serde::{Deserialize, Serialize};

use crate::canonical::{domain, hash_canonical, Digest};
use crate::decision::{DecisionBody, DecisionService};
use crate::engine::{self, ENGINE_VERSION};
use crate::error::Result;
use crate::evidence::EvidenceRepository;
use crate::fact::{FactNormalizer, FactSnapshot, FactStore};
use crate::keys::TrustStore;
use crate::observation::ObservationStore;
use crate::policy::{CompiledPolicyStore, Effect};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "verdict", rename_all = "snake_case")]
pub enum ReplayVerdict {
    Match,
    Drift { differences: Vec<String> },
    EngineMismatch { recorded: String, current: String },
    Unverifiable { reason: String },
}

impl ReplayVerdict {
    pub fn label(&self) -> &'static str {
        match self {
            ReplayVerdict::Match => "match",
            ReplayVerdict::Drift { .. } => "drift",
            ReplayVerdict::EngineMismatch { .. } => "engine_mismatch",
            ReplayVerdict::Unverifiable { .. } => "unverifiable",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReDecision {
    pub policy_hash: Digest,
    pub effect: Effect,
    pub policy_changed: bool,
    pub facts_changed: bool,
    pub outcome_changed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplayReport {
    pub decision_hash: Digest,
    pub replayed_hash: Option<Digest>,
    pub verdict: ReplayVerdict,
    pub evidence_verified: std::result::Result<(), String>,
    pub re_decision: Option<ReDecision>,
    pub report_hash: Digest,
}

pub struct ReplayEngine<'a> {
    pub decisions: &'a DecisionService,
    pub facts: &'a FactStore,
    pub normalizer: &'a FactNormalizer,
    pub observations: &'a ObservationStore,
    pub policies: &'a CompiledPolicyStore,
    pub evidence: &'a EvidenceRepository,
    pub trust: &'a TrustStore,
}

impl ReplayEngine<'_> {
    pub fn replay(&self, decision_hash: &Digest) -> Result<ReplayReport> {
        let record = self.decisions.get(decision_hash)?;
        let d = &record.body;

        let evidence_verified = match self.evidence.for_decision(decision_hash) {
            Some(e) if e.body.decision_hash == *decision_hash => e.verify(self.trust).map_err(|e| e.to_string()),
            Some(_) => Err("evidence index points at another decision".into()),
            None => Err("no evidence sealed".into()),
        };

        let (verdict, replayed_hash) = self.reexecute(record.decision_hash, d);

        // Re-decision with present knowledge.
        let re_decision = self.policies.active(&d.tenant, &d.policy_id).ok().and_then(|active| {
            let snapshot = self.facts.snapshot(&d.tenant, &d.subject, d.as_of);
            let eval = engine::evaluate(&active.program, &snapshot).ok()?;
            let facts_changed = eval.used_facts != d.fact_hashes;
            Some(ReDecision {
                policy_hash: active.policy_hash,
                effect: eval.effect,
                policy_changed: active.policy_hash != d.policy_hash,
                facts_changed,
                outcome_changed: eval.effect != d.effect,
            })
        });

        #[derive(Serialize)]
        struct Preimage<'a> {
            decision_hash: &'a Digest,
            replayed_hash: &'a Option<Digest>,
            verdict: &'a ReplayVerdict,
            evidence_verified: &'a std::result::Result<(), String>,
            re_decision: &'a Option<ReDecision>,
        }
        let report_hash = hash_canonical(
            domain::REPLAY_REPORT,
            &Preimage {
                decision_hash,
                replayed_hash: &replayed_hash,
                verdict: &verdict,
                evidence_verified: &evidence_verified,
                re_decision: &re_decision,
            },
        )?;
        Ok(ReplayReport { decision_hash: *decision_hash, replayed_hash, verdict, evidence_verified, re_decision, report_hash })
    }

    fn reexecute(&self, recorded_hash: Digest, d: &DecisionBody) -> (ReplayVerdict, Option<Digest>) {
        if d.engine_version != ENGINE_VERSION {
            return (ReplayVerdict::EngineMismatch { recorded: d.engine_version.clone(), current: ENGINE_VERSION.into() }, None);
        }
        // Policy reconstruction (verifies the compiled binary's hash).
        let policy = match self.policies.get(&d.policy_hash) {
            Ok(p) => p,
            Err(e) => return (ReplayVerdict::Unverifiable { reason: e.to_string() }, None),
        };
        // Historical retrieval: exactly the facts the decision used.
        let mut facts = std::collections::BTreeMap::new();
        for (name, h) in &d.fact_hashes {
            match self.facts.get(h) {
                Some(f) if f.verify().is_ok() => {
                    // Re-run normalisation: the fact must be exactly what its
                    // mapping rule derives from its signed observation.
                    let derived = self
                        .observations
                        .get(&f.body.observation_hash)
                        .ok_or_else(|| format!("observation {} missing", f.body.observation_hash.short()))
                        .and_then(|o| self.normalizer.rederive(f, &o.envelope).map_err(|e| e.to_string()));
                    if let Err(reason) = derived {
                        return (ReplayVerdict::Unverifiable { reason }, None);
                    }
                    facts.insert(name.clone(), f.clone());
                }
                Some(_) => return (ReplayVerdict::Unverifiable { reason: format!("fact {} fails integrity check", h.short()) }, None),
                None => return (ReplayVerdict::Unverifiable { reason: format!("fact {} missing", h.short()) }, None),
            }
        }
        let snapshot = FactSnapshot { tenant: d.tenant.clone(), subject: d.subject.clone(), as_of: d.as_of, facts };
        let eval = match engine::evaluate(&policy.program, &snapshot) {
            Ok(e) => e,
            Err(e) => return (ReplayVerdict::Unverifiable { reason: e.to_string() }, None),
        };
        let replayed = DecisionBody::build(policy, &snapshot, eval);
        let replayed_hash = match replayed.hash() {
            Ok(h) => h,
            Err(e) => return (ReplayVerdict::Unverifiable { reason: e.to_string() }, None),
        };
        if replayed_hash == recorded_hash && replayed == *d {
            return (ReplayVerdict::Match, Some(replayed_hash));
        }
        let mut differences = Vec::new();
        if replayed_hash != recorded_hash {
            differences.push(format!("decision hash: recorded {} replayed {}", recorded_hash.short(), replayed_hash.short()));
        }
        if replayed.effect != d.effect {
            differences.push(format!("effect: recorded {:?} replayed {:?}", d.effect, replayed.effect));
        }
        if replayed.decisive_rule != d.decisive_rule {
            differences.push(format!("decisive rule: recorded {:?} replayed {:?}", d.decisive_rule, replayed.decisive_rule));
        }
        if replayed.actions != d.actions {
            differences.push("actions differ".into());
        }
        if replayed.explanation != d.explanation {
            differences.push("explanation differs".into());
        }
        if replayed.trace != d.trace {
            differences.push("execution trace differs".into());
        }
        (ReplayVerdict::Drift { differences }, Some(replayed_hash))
    }
}
