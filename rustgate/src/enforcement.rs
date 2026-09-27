//! Action authorisation and enforcement.
//!
//! Enforcement is the one place RustGate touches the outside world, so it is
//! guarded twice: an action is dispatched only if (1) the decision's evidence
//! is sealed and its signature verifies, and (2) the tenant holds an explicit
//! grant for that connector + operation. Dispatch is idempotent per
//! (decision, action index), so retries never double-create tickets.
//!
//! Connectors (ServiceNow, Dynamics, SAP, webhooks, ...) implement
//! [`Connector`]; [`RecordingConnector`] is the in-memory stand-in.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::canonical::{domain, hash_canonical, Digest};
use crate::decision::DecisionRecord;
use crate::error::{GovError, Result};
use crate::evidence::EvidenceRecord;
use crate::keys::TrustStore;
use crate::policy::Effect;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DispatchRequest {
    pub idempotency_key: Digest,
    pub decision_hash: Digest,
    pub evidence_hash: Digest,
    pub tenant: String,
    pub subject: String,
    pub effect: Effect,
    pub connector: String,
    pub operation: String,
    pub params: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Receipt {
    pub connector: String,
    pub external_ref: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DispatchOutcome {
    pub request: DispatchRequest,
    pub result: std::result::Result<Receipt, String>,
    pub deduplicated: bool,
}

pub trait Connector {
    fn execute(&mut self, req: &DispatchRequest) -> std::result::Result<Receipt, String>;
}

/// In-memory connector that records every request and returns a
/// deterministic external reference (e.g. `INC-3fa2b1c0`).
#[derive(Debug, Default)]
pub struct RecordingConnector {
    pub name: String,
    pub ref_prefix: String,
    pub log: Vec<DispatchRequest>,
}

impl RecordingConnector {
    pub fn new(name: &str, ref_prefix: &str) -> Self {
        Self { name: name.into(), ref_prefix: ref_prefix.into(), log: Vec::new() }
    }
}

impl Connector for RecordingConnector {
    fn execute(&mut self, req: &DispatchRequest) -> std::result::Result<Receipt, String> {
        self.log.push(req.clone());
        Ok(Receipt { connector: self.name.clone(), external_ref: format!("{}-{}", self.ref_prefix, &req.idempotency_key.to_hex()[..8]) })
    }
}

#[derive(Debug, Default)]
pub struct ActionAuthorizer {
    grants: BTreeMap<(String, String), BTreeSet<String>>,
    pub max_actions_per_decision: usize,
}

fn render(template: &str, d: &DecisionRecord) -> String {
    template
        .replace("{subject}", &d.body.subject)
        .replace("{tenant}", &d.body.tenant)
        .replace("{effect}", &format!("{:?}", d.body.effect))
        .replace("{decision}", &d.decision_hash.to_hex())
        .replace("{rule}", d.body.decisive_rule.as_deref().unwrap_or("default"))
}

impl ActionAuthorizer {
    pub fn new(max_actions_per_decision: usize) -> Self {
        Self { grants: BTreeMap::new(), max_actions_per_decision }
    }

    pub fn grant(&mut self, tenant: &str, connector: &str, operation: &str) {
        self.grants.entry((tenant.into(), connector.into())).or_default().insert(operation.into());
    }

    /// Turn a decision's action templates into authorised dispatch requests.
    /// Any unauthorised action rejects the whole set: partial enforcement of
    /// a decision is worse than none.
    pub fn authorize(
        &self,
        decision: &DecisionRecord,
        evidence: Option<&EvidenceRecord>,
        trust: &TrustStore,
    ) -> Result<Vec<DispatchRequest>> {
        let evidence = evidence.ok_or_else(|| GovError::ActionNotAuthorised("evidence not sealed".into()))?;
        evidence.verify(trust).map_err(|e| GovError::ActionNotAuthorised(format!("evidence invalid: {e}")))?;
        if evidence.body.decision_hash != decision.decision_hash {
            return Err(GovError::ActionNotAuthorised("evidence belongs to another decision".into()));
        }
        decision.verify().map_err(|e| GovError::ActionNotAuthorised(e.to_string()))?;
        let actions = &decision.body.actions;
        if actions.len() > self.max_actions_per_decision {
            return Err(GovError::ActionNotAuthorised(format!("{} actions exceed limit {}", actions.len(), self.max_actions_per_decision)));
        }
        actions
            .iter()
            .enumerate()
            .map(|(i, a)| {
                let allowed =
                    self.grants.get(&(decision.body.tenant.clone(), a.connector.clone())).is_some_and(|ops| ops.contains(&a.operation));
                if !allowed {
                    return Err(GovError::ActionNotAuthorised(format!(
                        "tenant '{}' has no grant for {}:{}",
                        decision.body.tenant, a.connector, a.operation
                    )));
                }
                Ok(DispatchRequest {
                    idempotency_key: hash_canonical(domain::IDEMPOTENCY, &(decision.decision_hash, i as u64))?,
                    decision_hash: decision.decision_hash,
                    evidence_hash: evidence.evidence_hash,
                    tenant: decision.body.tenant.clone(),
                    subject: decision.body.subject.clone(),
                    effect: decision.body.effect,
                    connector: a.connector.clone(),
                    operation: a.operation.clone(),
                    params: a.params.iter().map(|(k, v)| (k.clone(), render(v, decision))).collect(),
                })
            })
            .collect()
    }
}

#[derive(Default)]
pub struct EnforcementService {
    connectors: BTreeMap<String, Box<dyn Connector>>,
    completed: BTreeMap<Digest, Receipt>,
}

impl EnforcementService {
    pub fn register(&mut self, name: &str, connector: Box<dyn Connector>) {
        self.connectors.insert(name.into(), connector);
    }

    /// Record a completed dispatch (journal recovery) so a restarted
    /// instance never re-executes an action that already succeeded.
    pub fn restore_receipt(&mut self, idempotency_key: Digest, receipt: Receipt) {
        self.completed.entry(idempotency_key).or_insert(receipt);
    }

    pub fn dispatch(&mut self, requests: Vec<DispatchRequest>) -> Vec<DispatchOutcome> {
        requests
            .into_iter()
            .map(|request| {
                if let Some(r) = self.completed.get(&request.idempotency_key) {
                    return DispatchOutcome { result: Ok(r.clone()), request, deduplicated: true };
                }
                let result = match self.connectors.get_mut(&request.connector) {
                    Some(c) => c.execute(&request),
                    None => Err(GovError::UnknownConnector(request.connector.clone()).to_string()),
                };
                if let Ok(r) = &result {
                    self.completed.insert(request.idempotency_key, r.clone());
                }
                DispatchOutcome { request, result, deduplicated: false }
            })
            .collect()
    }
}
