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
//!
//! State is durable through a write-ahead [`storage::Journal`]: every change
//! is appended to the journal before it is applied in memory, and
//! [`RustGate::open`] rebuilds the stores by applying the same records.

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
pub mod storage;

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

pub use canonical::Digest;
pub use error::{GovError, Result};

use decision::{DecisionBody, DecisionRecord, DecisionRequest, DecisionService};
use enforcement::{ActionAuthorizer, DispatchOutcome, EnforcementService};
use evidence::{EvidenceBundle, EvidenceGenerator, EvidenceRecord, EvidenceRepository};
use fact::{Fact, FactNormalizer, FactStore, MappingRule};
use identity::{Authorizer, EdgeConfig, IdentityProvider, Permission, Principal, SecurityEdge};
use keys::{EvidenceSigner, TrustStore};
use ledger::{AuditEvent, AuditLedger, DomainEvent, EventLedger};
use observation::{ObservationEnvelope, ObservationGateway, ObservationStore, StoredObservation};
use policy::{CompiledPolicyStore, PolicyCompiler, PolicyRepository, PolicySource};
use replay::{ReplayEngine, ReplayReport};
use storage::{Journal, JournalEntry, JournalRecord, MemoryJournal};

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
    pub journal_entries: u64,
    pub journal_head: Digest,
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
///
/// Durable state (observations, facts, mappings, policies, decisions,
/// evidence, ledgers, enforcement receipts) lives in the journal.
/// Configuration (trust store, identities, roles, schemas, connectors and
/// grants) is supplied by the deployment on every start, from its key
/// management and identity systems.
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
    journal: Box<dyn Journal>,
    journal_head: (u64, Digest),
    /// Set if a durably journaled record failed to apply in memory; the
    /// instance then refuses further writes until restarted from the journal.
    poisoned: Option<String>,
}

impl RustGate {
    /// An ephemeral instance backed by an in-memory journal.
    pub fn new(config: Config, evidence_signer: Box<dyn EvidenceSigner>) -> Self {
        Self::open(config, evidence_signer, Box::new(MemoryJournal::default())).expect("an empty in-memory journal always opens")
    }

    /// Open an instance over `journal`, verifying the journal's hash chain
    /// and rebuilding every store from it. Signature checks need the trust
    /// store, so call [`RustGate::verify_integrity`] once configuration has
    /// been loaded.
    pub fn open(config: Config, evidence_signer: Box<dyn EvidenceSigner>, mut journal: Box<dyn Journal>) -> Result<Self> {
        let entries = journal.load()?;
        let head = storage::verify_chain(&entries)?;
        let mut gate = Self {
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
            journal,
            journal_head: head,
            poisoned: None,
        };
        for e in entries {
            let seq = e.seq;
            gate.apply(e.record).map_err(|err| GovError::Storage(format!("journal entry #{seq} cannot be applied: {err}")))?;
        }
        Ok(gate)
    }

    pub fn evidence_signer(&self) -> &dyn EvidenceSigner {
        self.evidence_signer.as_ref()
    }

    pub fn journal_description(&self) -> String {
        self.journal.describe()
    }

    /// `(entries, last entry hash)`: publish this to an external witness to
    /// make wholesale rewrites of the journal detectable too.
    pub fn journal_head(&self) -> (u64, Digest) {
        self.journal_head
    }

    /// Write-ahead: durably journal the change, then apply it.
    fn commit(&mut self, record: JournalRecord) -> Result<()> {
        if let Some(reason) = &self.poisoned {
            return Err(GovError::Storage(format!("instance is read-only after a failed apply: {reason}")));
        }
        let (seq, prev) = self.journal_head;
        let entry = JournalEntry::seal(seq, prev, record)?;
        self.journal.append(&entry)?;
        self.journal_head = (seq + 1, entry.entry_hash);
        self.apply(entry.record).inspect_err(|e| self.poisoned = Some(format!("entry #{seq}: {e}")))
    }

    /// The single path by which state changes, live or during recovery.
    fn apply(&mut self, record: JournalRecord) -> Result<()> {
        match record {
            JournalRecord::MappingRegistered { rule } => {
                self.normalizer.register(rule)?;
            }
            JournalRecord::ObservationStored { observation } => self.observations.restore(observation)?,
            JournalRecord::FactStored { fact } => {
                self.facts.restore(fact)?;
            }
            JournalRecord::PolicySubmitted { record } => self.policy_repo.restore_submitted(record)?,
            JournalRecord::PolicyApproved { policy_id, version, approval } => {
                self.policy_repo.restore_approval(&policy_id, version, approval)?;
            }
            JournalRecord::PolicyCompiled { policy } => {
                self.policies.insert(policy)?;
            }
            JournalRecord::PolicyActivated { policy_hash } => self.policies.activate(policy_hash)?,
            JournalRecord::DecisionRecorded { decision } => self.decisions.restore(decision)?,
            JournalRecord::EvidenceSealed { evidence } => self.evidence.append(evidence)?,
            JournalRecord::AuditAppended { entry } => {
                self.audit.push(entry)?;
            }
            JournalRecord::EventAppended { entry } => {
                self.events.push(entry)?;
            }
            JournalRecord::ActionIntent { request } => self.enforcement.restore_intent(request),
            JournalRecord::ActionCompleted { idempotency_key, receipt } => self.enforcement.restore_receipt(idempotency_key, receipt),
        }
        Ok(())
    }

    fn audit(&mut self, at: u64, correlation: &str, causation: Option<Digest>, event: AuditEvent) -> Result<Digest> {
        let entry = self.audit.prepare(at, correlation, causation, event)?;
        let h = entry.entry_hash;
        self.commit(JournalRecord::AuditAppended { entry })?;
        Ok(h)
    }

    fn event(&mut self, at: u64, correlation: &str, causation: Option<Digest>, event: DomainEvent) -> Result<Digest> {
        let entry = self.events.prepare(at, correlation, causation, event)?;
        let h = entry.entry_hash;
        self.commit(JournalRecord::EventAppended { entry })?;
        Ok(h)
    }

    /// Register a fact mapping rule. Registering the version that is
    /// already active is a no-op, so deployments can re-apply their mapping
    /// configuration on every start.
    pub fn register_mapping(&mut self, rule: MappingRule) -> Result<Digest> {
        if self.normalizer.is_active(&rule)? {
            return rule.hash();
        }
        let h = self.normalizer.check(&rule)?;
        self.commit(JournalRecord::MappingRegistered { rule })?;
        Ok(h)
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
        self.audit(at, correlation, None, AuditEvent::Security { action: permission.to_string(), principal, allowed, detail })?;
        result
    }

    fn audit_security_failure(&mut self, principal: &Principal, action: &str, err: &GovError, correlation: &str, at: u64) -> Result<()> {
        self.audit(
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
        let duplicate = self.observations.contains(&obs_hash);
        if !duplicate {
            let stored =
                StoredObservation { envelope, received_at, ingest_seq: self.observations.next_seq(), submitted_by: principal.id.clone() };
            self.commit(JournalRecord::ObservationStored { observation: stored })?;
        }
        let ingested = self.event(
            received_at,
            &correlation,
            None,
            DomainEvent::ObservationIngested { observation_hash: obs_hash, source_id, schema, duplicate },
        )?;
        if duplicate {
            return Ok(IngestReceipt { observation_hash: obs_hash, duplicate, fact_hashes: vec![], rejections: vec![] });
        }

        let outcome = self.normalizer.normalize(self.observations.get(&obs_hash).expect("just stored"));
        let fact_hashes: Vec<Digest> = outcome.facts.iter().map(|f| f.fact_hash).collect();
        for fact in outcome.facts {
            if !self.facts.contains(&fact.fact_hash) {
                self.commit(JournalRecord::FactStored { fact })?;
            }
        }
        self.event(
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
        let record = self.policy_repo.prepare_submit(source, author, &self.trust, at)?;
        let h = record.source_hash;
        self.commit(JournalRecord::PolicySubmitted { record })?;
        self.audit(
            at,
            &format!("policy:{id}@{version}"),
            None,
            AuditEvent::Policy { action: "submitted".into(), policy_id: id, version, actor: author.key_id().into(), policy_hash: Some(h) },
        )?;
        Ok(h)
    }

    pub fn approve_policy(&mut self, id: &str, version: u32, approver: &dyn EvidenceSigner, at: u64) -> Result<usize> {
        let result = match self.policy_repo.prepare_approval(id, version, approver, &self.trust, at) {
            Ok(approval) => self
                .commit(JournalRecord::PolicyApproved { policy_id: id.into(), version, approval })
                .map(|_| self.policy_repo.get(id, version).map_or(0, |r| r.approvals.len())),
            Err(e) => Err(e),
        };
        self.audit(
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
    /// binary and make it the active version. The caller must authenticate
    /// and hold [`Permission::ActivatePolicy`] in the policy's tenant; the
    /// audit record names the authenticated principal.
    pub fn compile_and_activate(&mut self, token: &str, id: &str, version: u32, at: u64) -> Result<policy::CompiledPolicy> {
        let correlation = format!("policy:{id}@{version}");
        let tenant = self
            .policy_repo
            .get(id, version)
            .map(|r| r.source.tenant.clone())
            .ok_or_else(|| GovError::PolicyNotFound(format!("{id}@{version}")))?;
        let principal = self.admit(token, Permission::ActivatePolicy, &tenant, None, &correlation, at)?;
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
        self.audit(
            at,
            &correlation,
            None,
            AuditEvent::Policy { action, policy_id: id.into(), version, actor: principal.id, policy_hash: hash },
        )?;
        let compiled = result?;
        if !self.policies.contains(&compiled.policy_hash) {
            self.commit(JournalRecord::PolicyCompiled { policy: compiled.clone() })?;
        }
        self.commit(JournalRecord::PolicyActivated { policy_hash: compiled.policy_hash })?;
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
        let (decision, is_new) = self.decisions.prepare(body, &request.correlation_id, &principal.id, at)?;
        let dh = decision.decision_hash;

        if is_new {
            self.commit(JournalRecord::DecisionRecorded { decision: decision.clone() })?;
            self.audit(
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
        let made =
            self.event(at, &request.correlation_id, None, DomainEvent::DecisionMade { decision_hash: dh, effect: decision.body.effect })?;

        // Evidence (sealed once per decision hash).
        let evidence = match self.evidence.for_decision(&dh) {
            Some(e) => e.clone(),
            None => {
                let used: Vec<&Fact> = decision.body.fact_hashes.values().filter_map(|h| self.facts.get(h)).collect();
                let obs: BTreeMap<Digest, &ObservationEnvelope> =
                    used.iter().filter_map(|f| self.observations.get(&f.body.observation_hash)).map(|o| (o.hash(), &o.envelope)).collect();
                let (seq, prev) = self.evidence.head();
                let rec = EvidenceGenerator::seal(&decision, &policy, &used, &obs, seq, prev, at, self.evidence_signer.as_ref())?;
                self.commit(JournalRecord::EvidenceSealed { evidence: rec.clone() })?;
                rec
            }
        };
        let sealed = self.event(
            at,
            &request.correlation_id,
            Some(made),
            DomainEvent::EvidenceSealed { decision_hash: dh, evidence_hash: evidence.evidence_hash },
        )?;

        // Action authorisation -> enforcement.
        let (dispatches, actions_refused) = match self.action_authorizer.authorize(&decision, Some(&evidence), &self.trust) {
            Ok(reqs) => (self.dispatch_durably(reqs)?, None),
            Err(e) => {
                self.audit(
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
                    match (d.deduplicated, d.reconciled) {
                        (true, _) => format!("deduplicated:{}", r.external_ref),
                        (false, true) => format!("reconciled:{}", r.external_ref),
                        (false, false) => format!("dispatched:{}", r.external_ref),
                    },
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
                self.event(at, &request.correlation_id, Some(sealed), event)?;
            }
            self.audit(
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

    /// Intent/receipt protocol: journal the intent, call the connector
    /// (reconciling first if a previous attempt left the action in doubt),
    /// journal the receipt. A crash at any point is recoverable without
    /// executing an action twice, given a connector that honours the
    /// [`enforcement::Connector`] idempotency contract.
    fn dispatch_durably(&mut self, requests: Vec<enforcement::DispatchRequest>) -> Result<Vec<DispatchOutcome>> {
        let mut outcomes = Vec::with_capacity(requests.len());
        for request in requests {
            let key = request.idempotency_key;
            if let Some(r) = self.enforcement.completed(&key) {
                outcomes.push(DispatchOutcome { result: Ok(r.clone()), request, deduplicated: true, reconciled: false });
                continue;
            }
            let in_doubt = self.enforcement.is_in_doubt(&key);
            if !in_doubt {
                self.commit(JournalRecord::ActionIntent { request: request.clone() })?;
            }
            match self.enforcement.execute(&request, in_doubt) {
                Ok((receipt, reconciled)) => {
                    self.commit(JournalRecord::ActionCompleted { idempotency_key: key, receipt: receipt.clone() })?;
                    outcomes.push(DispatchOutcome { result: Ok(receipt), request, deduplicated: false, reconciled });
                }
                Err(e) => outcomes.push(DispatchOutcome { result: Err(e), request, deduplicated: false, reconciled: false }),
            }
        }
        Ok(outcomes)
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
            normalizer: &self.normalizer,
            observations: &self.observations,
            policies: &self.policies,
            evidence: &self.evidence,
            trust: &self.trust,
        }
        .replay(decision_hash)?;
        self.audit(
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
        let mut observations: BTreeMap<Digest, ObservationEnvelope> = BTreeMap::new();
        let mut mappings: BTreeMap<Digest, MappingRule> = BTreeMap::new();
        for f in &facts {
            let o = self
                .observations
                .get(&f.body.observation_hash)
                .ok_or_else(|| GovError::ObservationNotFound(f.body.observation_hash.short()))?;
            observations.insert(o.hash(), o.envelope.clone());
            let m = self
                .normalizer
                .mapping(&f.body.mapping_hash)
                .ok_or_else(|| GovError::Integrity(format!("mapping {} not found", f.body.mapping_hash.short())))?;
            mappings.insert(f.body.mapping_hash, m.clone());
        }
        Ok(EvidenceBundle {
            evidence,
            decision,
            policy,
            facts,
            observations: observations.into_values().collect(),
            mappings: mappings.into_values().collect(),
        })
    }

    /// Recompute every hash, chain and signature in every in-memory store.
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
            journal_entries: self.journal_head.0,
            journal_head: self.journal_head.1,
        })
    }

    /// Re-read the durable journal and check its chain ends exactly where
    /// this instance believes it does (detects out-of-band edits, deletions
    /// and appends by another writer).
    pub fn verify_journal(&mut self) -> Result<(u64, Digest)> {
        let entries = self.journal.load()?;
        let head = storage::verify_chain(&entries)?;
        if head != self.journal_head {
            return Err(GovError::Storage(format!(
                "journal head {}#{} differs from in-memory head {}#{}",
                head.1.short(),
                head.0,
                self.journal_head.1.short(),
                self.journal_head.0
            )));
        }
        Ok(head)
    }
}
