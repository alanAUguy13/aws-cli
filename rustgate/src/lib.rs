//! # RustGate — deterministic governance core
//!
//! ```text
//! External Actor -> Identity/Authentication -> Authorization -> API & Security Edge
//!   -> Observation Gateway -> Observation Store -> Fact Normalization -> Fact Store
//!   -> Governed Policy -> Compiled Policy -> Deterministic Decision Engine -> Decision Service
//!        ├─> Evidence Generator -> Evidence Repository -> Audit Ledger -> Event Ledger
//!        │                                                  -> Replay Engine -> Replay Validation
//!        └─> Action Authorization -> Enforcement
//! ```
//!
//! The invariant: **same facts + same policy + same engine = same decision
//! hash**, and every decision carries a signed, hash-linked chain back to the
//! signed observations it was derived from.
//!
//! [`RustGate`] wires the components together. Each stage is also usable on
//! its own through its module.

pub mod canonical;
pub mod decision;
pub mod enforcement;
pub mod engine;
pub mod error;
pub mod evidence;
pub mod fact;
pub mod identity;
pub mod keys;
pub mod ledger;
pub mod observation;
pub mod policy;
pub mod replay;
pub mod scenario;

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

pub use canonical::Digest;
pub use error::{GovError, Result};

use decision::{DecisionBody, DecisionRecord, DecisionRequest, DecisionService};
use enforcement::{ActionAuthorizer, DispatchOutcome, EnforcementService};
use evidence::{EvidenceBundle, EvidenceGenerator, EvidenceRecord, EvidenceRepository};
use fact::{Fact, FactNormalizer, FactStore};
use identity::{Authorizer, EdgeConfig, IdentityProvider, Permission, Principal, SecurityEdge};
use keys::{EvidenceSigner, TrustStore};
use ledger::{AuditEvent, AuditLedger, DomainEvent, EventLedger};
use observation::{Appended, ObservationEnvelope, ObservationGateway, ObservationStore};
use policy::{CompiledPolicyStore, PolicyCompiler, PolicyRepository, PolicySource};
use replay::{ReplayEngine, ReplayReport};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IngestReceipt {
    pub observation_hash: Digest,
    pub duplicate: bool,
    pub fact_hashes: Vec<Digest>,
    pub rejections: Vec<fact::QualityViolation>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecisionOutcome {
    pub decision: DecisionRecord,
    pub evidence: EvidenceRecord,
    pub dispatches: Vec<DispatchOutcome>,
    /// Set when action authorisation refused the decision's actions.
    pub actions_refused: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrityReport {
    pub observations: usize,
    pub facts: usize,
    pub decisions: usize,
    pub evidence_records: usize,
    pub audit_entries: usize,
    pub event_entries: usize,
    pub audit_head: Digest,
    pub event_head: Digest,
    pub evidence_head: Digest,
}

pub struct Config {
    pub required_policy_approvals: usize,
    pub max_future_skew_ms: u64,
    pub max_actions_per_decision: usize,
    pub edge: EdgeConfig,
}

impl Default for Config {
    fn default() -> Self {
        Self { required_policy_approvals: 2, max_future_skew_ms: 5_000, max_actions_per_decision: 8, edge: EdgeConfig::default() }
    }
}

/// The assembled platform. Every mutating call takes an explicit timestamp:
/// RustGate never reads a clock, which is what makes it replayable.
pub struct RustGate {
    pub trust: TrustStore,
    pub identity: IdentityProvider,
    pub authorizer: Authorizer,
    pub edge: SecurityEdge,
    pub gateway: ObservationGateway,
    pub observations: ObservationStore,
    pub normalizer: FactNormalizer,
    pub facts: FactStore,
    pub policy_repo: PolicyRepository,
    pub policies: CompiledPolicyStore,
    pub decisions: DecisionService,
    pub evidence: EvidenceRepository,
    pub action_authorizer: ActionAuthorizer,
    pub enforcement: EnforcementService,
    pub audit: AuditLedger,
    pub events: EventLedger,
    evidence_signer: Box<dyn EvidenceSigner>,
}

impl RustGate {
    pub fn new(config: Config, evidence_signer: Box<dyn EvidenceSigner>) -> Self {
        Self {
            trust: TrustStore::new(),
            identity: IdentityProvider::default(),
            authorizer: Authorizer::default(),
            edge: SecurityEdge::new(config.edge),
            gateway: ObservationGateway::new(config.max_future_skew_ms),
            observations: ObservationStore::default(),
            normalizer: FactNormalizer::default(),
            facts: FactStore::default(),
            policy_repo: PolicyRepository::new(config.required_policy_approvals),
            policies: CompiledPolicyStore::default(),
            decisions: DecisionService::default(),
            evidence: EvidenceRepository::default(),
            action_authorizer: ActionAuthorizer::new(config.max_actions_per_decision),
            enforcement: EnforcementService::default(),
            audit: AuditLedger::default(),
            events: EventLedger::default(),
            evidence_signer,
        }
    }

    pub fn evidence_signer(&self) -> &dyn EvidenceSigner {
        self.evidence_signer.as_ref()
    }

    /// Authentication + authorisation, with the outcome written to the
    /// audit ledger whether it succeeds or not.
    fn admit(
        &mut self,
        token: &str,
        permission: Permission,
        tenant: &str,
        resource: Option<&str>,
        correlation: &str,
        at: u64,
    ) -> Result<Principal> {
        let result =
            self.identity.authenticate(token, at).and_then(|p| self.authorizer.authorize(&p, permission, tenant, resource).map(|_| p));
        let (principal, allowed, detail) = match &result {
            Ok(p) => (Some(p.id.clone()), true, format!("{permission} on tenant '{tenant}'")),
            Err(e) => (None, false, e.to_string()),
        };
        self.audit.append(at, correlation, None, AuditEvent::Security { action: permission.to_string(), principal, allowed, detail })?;
        result
    }

    fn audit_security_failure(&mut self, principal: &Principal, action: &str, err: &GovError, correlation: &str, at: u64) -> Result<()> {
        self.audit.append(
            at,
            correlation,
            None,
            AuditEvent::Security { action: action.into(), principal: Some(principal.id.clone()), allowed: false, detail: err.to_string() },
        )?;
        Ok(())
    }

    /// Full ingestion path: authn -> authz -> edge -> gateway -> store -> facts.
    pub fn ingest(&mut self, token: &str, nonce: &str, envelope: ObservationEnvelope, received_at: u64) -> Result<IngestReceipt> {
        let correlation = envelope.content_hash.to_hex();
        let body = &envelope.body;
        let principal = self.admit(token, Permission::SubmitObservation, &body.tenant, Some(&body.schema), &correlation, received_at)?;

        let checked: Result<Digest> = (|| {
            // Bind the authenticated caller to the claimed source: a principal
            // can only speak for itself.
            if principal.id != body.source.id || principal.kind != body.source.kind {
                return Err(GovError::Forbidden {
                    principal: principal.id.clone(),
                    permission: Permission::SubmitObservation.to_string(),
                    reason: format!("cannot submit on behalf of source '{}'", body.source.id),
                });
            }
            let size = canonical::canonical_json(&envelope)?.len();
            self.edge.admit(&principal, size, nonce, received_at)?;
            self.gateway.validate(&envelope, &self.trust, received_at)
        })();
        let obs_hash = match checked {
            Ok(h) => h,
            Err(e) => {
                self.audit_security_failure(&principal, "observation_rejected", &e, &correlation, received_at)?;
                return Err(e);
            }
        };

        let source_id = envelope.body.source.id.clone();
        let schema = envelope.body.schema.clone();
        let duplicate = matches!(self.observations.append(envelope, received_at, &principal.id), Appended::Duplicate(_));
        let ingested = self.events.append(
            received_at,
            &correlation,
            None,
            DomainEvent::ObservationIngested { observation_hash: obs_hash, source_id, schema, duplicate },
        )?;
        if duplicate {
            return Ok(IngestReceipt { observation_hash: obs_hash, duplicate, fact_hashes: vec![], rejections: vec![] });
        }

        let stored = self.observations.get(&obs_hash).expect("just appended");
        let outcome = self.normalizer.normalize(stored);
        let fact_hashes: Vec<Digest> = outcome.facts.iter().map(|f| f.fact_hash).collect();
        for f in outcome.facts {
            self.facts.insert(f);
        }
        self.events.append(
            received_at,
            &correlation,
            Some(ingested),
            DomainEvent::FactsDerived {
                observation_hash: obs_hash,
                fact_hashes: fact_hashes.clone(),
                rejections: outcome.rejections.iter().map(|r| format!("{}: {}", r.mapping_id, r.reason)).collect(),
            },
        )?;
        Ok(IngestReceipt { observation_hash: obs_hash, duplicate, fact_hashes, rejections: outcome.rejections })
    }

    pub fn submit_policy(&mut self, source: PolicySource, author: &dyn EvidenceSigner, at: u64) -> Result<Digest> {
        let (id, version) = (source.id.clone(), source.version);
        let h = self.policy_repo.submit(source, author, &self.trust, at)?;
        self.audit.append(
            at,
            &format!("policy:{id}@{version}"),
            None,
            AuditEvent::Policy { action: "submitted".into(), policy_id: id, version, actor: author.key_id().into(), policy_hash: Some(h) },
        )?;
        Ok(h)
    }

    pub fn approve_policy(&mut self, id: &str, version: u32, approver: &dyn EvidenceSigner, at: u64) -> Result<usize> {
        let result = self.policy_repo.approve(id, version, approver, &self.trust, at);
        self.audit.append(
            at,
            &format!("policy:{id}@{version}"),
            None,
            AuditEvent::Policy {
                action: match &result {
                    Ok(_) => "approved".into(),
                    Err(e) => format!("approval_rejected: {e}"),
                },
                policy_id: id.into(),
                version,
                actor: approver.key_id().into(),
                policy_hash: None,
            },
        )?;
        result
    }

    /// Verify approvals, compile against the current fact catalog, store the
    /// binary and make it the active version.
    pub fn compile_and_activate(&mut self, id: &str, version: u32, actor: &str, at: u64) -> Result<policy::CompiledPolicy> {
        let correlation = format!("policy:{id}@{version}");
        let result = (|| {
            let record = self.policy_repo.get(id, version).ok_or_else(|| GovError::PolicyNotFound(format!("{id}@{version}")))?;
            let approvers = self.policy_repo.verify_approved(record, &self.trust)?;
            let catalog = self.normalizer.catalog();
            PolicyCompiler { catalog: &catalog }.compile(record, approvers)
        })();
        let (action, hash) = match &result {
            Ok(c) => ("compiled_and_activated".to_string(), Some(c.policy_hash)),
            Err(e) => (format!("compile_rejected: {e}"), None),
        };
        self.audit.append(
            at,
            &correlation,
            None,
            AuditEvent::Policy { action, policy_id: id.into(), version, actor: actor.into(), policy_hash: hash },
        )?;
        let compiled = result?;
        let h = self.policies.insert(compiled.clone());
        self.policies.activate(h)?;
        Ok(compiled)
    }

    /// Decide, seal evidence, authorise and dispatch actions.
    pub fn decide(&mut self, token: &str, request: &DecisionRequest, at: u64) -> Result<DecisionOutcome> {
        let principal = self.admit(token, Permission::RequestDecision, &request.tenant, None, &request.correlation_id, at)?;
        if request.as_of > at {
            let e = GovError::InvalidProgram(format!(
                "as_of {} is in the future (now {at}); decisions about the future are not replayable",
                request.as_of
            ));
            self.audit_security_failure(&principal, "decision_rejected", &e, &request.correlation_id, at)?;
            return Err(e);
        }

        let policy = self.policies.active(&request.tenant, &request.policy_id)?.clone();
        let snapshot = self.facts.snapshot(&request.tenant, &request.subject, request.as_of);
        let eval = engine::evaluate(&policy.program, &snapshot)?;
        let body = DecisionBody::build(&policy, &snapshot, eval);
        let (decision, is_new) = self.decisions.record(body, &request.correlation_id, &principal.id, at)?;
        let dh = decision.decision_hash;

        if is_new {
            self.audit.append(
                at,
                &request.correlation_id,
                None,
                AuditEvent::Decision {
                    decision_hash: dh,
                    subject: decision.body.subject.clone(),
                    effect: decision.body.effect,
                    policy_hash: policy.policy_hash,
                    principal: principal.id.clone(),
                },
            )?;
        }
        let made = self.events.append(
            at,
            &request.correlation_id,
            None,
            DomainEvent::DecisionMade { decision_hash: dh, effect: decision.body.effect },
        )?;

        // Evidence (sealed once per decision hash).
        let evidence = match self.evidence.for_decision(&dh) {
            Some(e) => e.clone(),
            None => {
                let used: Vec<&Fact> = decision.body.fact_hashes.values().filter_map(|h| self.facts.get(h)).collect();
                let obs: BTreeMap<Digest, &ObservationEnvelope> =
                    used.iter().filter_map(|f| self.observations.get(&f.body.observation_hash)).map(|o| (o.hash(), &o.envelope)).collect();
                let (seq, prev) = self.evidence.head();
                let rec = EvidenceGenerator::seal(&decision, &policy, &used, &obs, seq, prev, at, self.evidence_signer.as_ref())?;
                self.evidence.append(rec.clone())?;
                rec
            }
        };
        let sealed = self.events.append(
            at,
            &request.correlation_id,
            Some(made),
            DomainEvent::EvidenceSealed { decision_hash: dh, evidence_hash: evidence.evidence_hash },
        )?;

        // Action authorisation -> enforcement.
        let (dispatches, actions_refused) = match self.action_authorizer.authorize(&decision, Some(&evidence), &self.trust) {
            Ok(reqs) => (self.enforcement.dispatch(reqs), None),
            Err(e) => {
                self.audit.append(
                    at,
                    &request.correlation_id,
                    None,
                    AuditEvent::Enforcement { decision_hash: dh, connector: "*".into(), operation: "*".into(), outcome: e.to_string() },
                )?;
                (Vec::new(), Some(e.to_string()))
            }
        };
        for d in &dispatches {
            let (event, outcome) = match &d.result {
                Ok(r) => (
                    DomainEvent::ActionDispatched {
                        idempotency_key: d.request.idempotency_key,
                        connector: d.request.connector.clone(),
                        operation: d.request.operation.clone(),
                        external_ref: r.external_ref.clone(),
                    },
                    if d.deduplicated { format!("deduplicated:{}", r.external_ref) } else { format!("dispatched:{}", r.external_ref) },
                ),
                Err(e) => (
                    DomainEvent::ActionFailed {
                        idempotency_key: d.request.idempotency_key,
                        connector: d.request.connector.clone(),
                        operation: d.request.operation.clone(),
                        error: e.clone(),
                    },
                    format!("failed:{e}"),
                ),
            };
            if !d.deduplicated {
                self.events.append(at, &request.correlation_id, Some(sealed), event)?;
            }
            self.audit.append(
                at,
                &request.correlation_id,
                None,
                AuditEvent::Enforcement {
                    decision_hash: dh,
                    connector: d.request.connector.clone(),
                    operation: d.request.operation.clone(),
                    outcome,
                },
            )?;
        }

        Ok(DecisionOutcome { decision, evidence, dispatches, actions_refused })
    }

    pub fn replay(&mut self, token: &str, tenant: &str, decision_hash: &Digest, at: u64) -> Result<ReplayReport> {
        let correlation = format!("replay:{}", decision_hash.to_hex());
        let principal = self.admit(token, Permission::Replay, tenant, None, &correlation, at)?;
        let record_tenant = self.decisions.get(decision_hash)?.body.tenant.clone();
        if record_tenant != tenant {
            let e = GovError::Forbidden {
                principal: principal.id.clone(),
                permission: "replay".into(),
                reason: "decision belongs to another tenant".into(),
            };
            self.audit_security_failure(&principal, "replay_rejected", &e, &correlation, at)?;
            return Err(e);
        }
        let report = ReplayEngine {
            decisions: &self.decisions,
            facts: &self.facts,
            policies: &self.policies,
            evidence: &self.evidence,
            trust: &self.trust,
        }
        .replay(decision_hash)?;
        self.audit.append(
            at,
            &correlation,
            None,
            AuditEvent::Replay {
                decision_hash: *decision_hash,
                verdict: report.verdict.label().into(),
                report_hash: report.report_hash,
                principal: principal.id,
            },
        )?;
        Ok(report)
    }

    /// Self-contained package for offline verification by an auditor,
    /// regulator or court, using only the bundle and the public keys.
    pub fn export_bundle(&self, decision_hash: &Digest) -> Result<EvidenceBundle> {
        let decision = self.decisions.get(decision_hash)?.clone();
        let evidence = self.evidence.for_decision(decision_hash).ok_or_else(|| GovError::EvidenceNotFound(decision_hash.short()))?.clone();
        let policy = self.policies.get(&decision.body.policy_hash)?.clone();
        let facts: Vec<Fact> = decision
            .body
            .fact_hashes
            .values()
            .map(|h| self.facts.get(h).cloned().ok_or_else(|| GovError::FactNotFound(h.short())))
            .collect::<Result<_>>()?;
        let mut observations: Vec<ObservationEnvelope> = Vec::new();
        for f in &facts {
            let o = self
                .observations
                .get(&f.body.observation_hash)
                .ok_or_else(|| GovError::ObservationNotFound(f.body.observation_hash.short()))?;
            if !observations.iter().any(|x| x.content_hash == o.hash()) {
                observations.push(o.envelope.clone());
            }
        }
        observations.sort_by_key(|o| o.content_hash);
        Ok(EvidenceBundle { evidence, decision, policy, facts, observations })
    }

    /// Recompute every hash and chain in every store.
    pub fn verify_integrity(&self) -> Result<IntegrityReport> {
        self.observations.verify_integrity()?;
        self.facts.verify_integrity()?;
        self.policies.verify_integrity()?;
        self.decisions.verify_integrity()?;
        self.evidence.verify_chain(&self.trust)?;
        self.audit.verify()?;
        self.events.verify()?;
        Ok(IntegrityReport {
            observations: self.observations.len(),
            facts: self.facts.len(),
            decisions: self.decisions.len(),
            evidence_records: self.evidence.len(),
            audit_entries: self.audit.len(),
            event_entries: self.events.len(),
            audit_head: self.audit.head(),
            event_head: self.events.head(),
            evidence_head: self.evidence.head().1,
        })
    }
}
