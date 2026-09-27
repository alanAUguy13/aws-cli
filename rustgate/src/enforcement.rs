//! Action authorisation and enforcement.
//!
//! Enforcement is the one place RustGate touches the outside world, so it is
//! guarded twice: an action is dispatched only if (1) the decision's evidence
//! is sealed and its signature verifies, and (2) the tenant holds an explicit
//! grant for that connector + operation. Dispatch is idempotent per
//! (decision, action index), so retries never double-create tickets.
//!
//! Crash safety uses an intent/receipt protocol. Before a connector is
//! called, the request is made durable as an *intent*; after it succeeds,
//! the *receipt* is made durable. A crash in between leaves the action *in
//! doubt*: on the next attempt it is first reconciled with
//! [`Connector::lookup`], and only re-executed if the external system has no
//! record of it. Connectors must also be idempotent on the idempotency key,
//! which closes the remaining window (a crash during the external call).
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
    /// Served from a durable receipt; the connector was not called.
    pub deduplicated: bool,
    /// An in-doubt action whose receipt was recovered from the external
    /// system via [`Connector::lookup`]; it was not executed again.
    pub reconciled: bool,
}

/// An external system RustGate can act on.
///
/// Contract: `execute` must be idempotent on `req.idempotency_key`. A second
/// call with the same key must not create a second external effect and must
/// return the original receipt (map the key to the system's own mechanism:
/// a ServiceNow correlation id, an HTTP `Idempotency-Key` header, an SAP
/// document reference).
pub trait Connector {
    fn execute(&mut self, req: &DispatchRequest) -> std::result::Result<Receipt, String>;

    /// Return the receipt of an action previously executed under `key`, if
    /// the external system has one. Used to reconcile in-doubt actions after
    /// a crash; `Ok(None)` means "never executed".
    fn lookup(&mut self, key: &Digest) -> std::result::Result<Option<Receipt>, String>;
}

/// In-memory connector that records every request and returns a
/// deterministic external reference (e.g. `INC-3fa2b1c0`). Idempotent on the
/// idempotency key, as the [`Connector`] contract requires.
#[derive(Debug, Default)]
pub struct RecordingConnector {
    pub name: String,
    pub ref_prefix: String,
    /// Requests that caused an external effect (duplicates excluded).
    pub log: Vec<DispatchRequest>,
    receipts: BTreeMap<Digest, Receipt>,
}

impl RecordingConnector {
    pub fn new(name: &str, ref_prefix: &str) -> Self {
        Self { name: name.into(), ref_prefix: ref_prefix.into(), ..Default::default() }
    }
}

impl Connector for RecordingConnector {
    fn execute(&mut self, req: &DispatchRequest) -> std::result::Result<Receipt, String> {
        if let Some(r) = self.receipts.get(&req.idempotency_key) {
            return Ok(r.clone());
        }
        self.log.push(req.clone());
        let r =
            Receipt { connector: self.name.clone(), external_ref: format!("{}-{}", self.ref_prefix, &req.idempotency_key.to_hex()[..8]) };
        self.receipts.insert(req.idempotency_key, r.clone());
        Ok(r)
    }

    fn lookup(&mut self, key: &Digest) -> std::result::Result<Option<Receipt>, String> {
        Ok(self.receipts.get(key).cloned())
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
    in_doubt: BTreeMap<Digest, DispatchRequest>,
}

impl EnforcementService {
    pub fn register(&mut self, name: &str, connector: Box<dyn Connector>) {
        self.connectors.insert(name.into(), connector);
    }

    /// Durable receipt for `key`, if the action completed.
    pub fn completed(&self, key: &Digest) -> Option<&Receipt> {
        self.completed.get(key)
    }

    /// True if an intent for `key` is durable but no receipt is.
    pub fn is_in_doubt(&self, key: &Digest) -> bool {
        self.in_doubt.contains_key(key)
    }

    /// Actions that may or may not have happened externally.
    pub fn in_doubt(&self) -> impl Iterator<Item = &DispatchRequest> {
        self.in_doubt.values()
    }

    /// Apply a durable intent (live path or journal recovery).
    pub fn restore_intent(&mut self, request: DispatchRequest) {
        if !self.completed.contains_key(&request.idempotency_key) {
            self.in_doubt.insert(request.idempotency_key, request);
        }
    }

    /// Apply a durable receipt (live path or journal recovery) so a
    /// restarted instance never re-executes an action that succeeded.
    pub fn restore_receipt(&mut self, idempotency_key: Digest, receipt: Receipt) {
        self.in_doubt.remove(&idempotency_key);
        self.completed.entry(idempotency_key).or_insert(receipt);
    }

    /// Perform one action whose intent is already durable. With `reconcile`
    /// (the action was in doubt), ask the external system first and only
    /// execute if it has no record. Returns the receipt and whether it was
    /// recovered by reconciliation. Does not record completion; the caller
    /// makes the receipt durable and then applies it.
    pub fn execute(&mut self, request: &DispatchRequest, reconcile: bool) -> std::result::Result<(Receipt, bool), String> {
        let connector =
            self.connectors.get_mut(&request.connector).ok_or_else(|| GovError::UnknownConnector(request.connector.clone()).to_string())?;
        if reconcile {
            if let Some(r) = connector.lookup(&request.idempotency_key)? {
                return Ok((r, true));
            }
        }
        connector.execute(request).map(|r| (r, false))
    }

    /// Non-durable convenience for standalone use: dispatch and record
    /// completions in memory only. [`crate::RustGate`] instead journals an
    /// intent before and a receipt after each call.
    pub fn dispatch(&mut self, requests: Vec<DispatchRequest>) -> Vec<DispatchOutcome> {
        requests
            .into_iter()
            .map(|request| {
                if let Some(r) = self.completed.get(&request.idempotency_key) {
                    return DispatchOutcome { result: Ok(r.clone()), request, deduplicated: true, reconciled: false };
                }
                let reconcile = self.is_in_doubt(&request.idempotency_key);
                match self.execute(&request, reconcile) {
                    Ok((r, reconciled)) => {
                        self.restore_receipt(request.idempotency_key, r.clone());
                        DispatchOutcome { result: Ok(r), request, deduplicated: false, reconciled }
                    }
                    Err(e) => DispatchOutcome { result: Err(e), request, deduplicated: false, reconciled: false },
                }
            })
            .collect()
    }
}
