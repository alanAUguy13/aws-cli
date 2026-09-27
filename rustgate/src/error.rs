//! Error type shared by every RustGate component.
//!
//! Errors are deliberately specific: in a governance system "why was this
//! rejected" is itself evidence, so every rejection carries enough context to
//! be written to the audit ledger verbatim.

use thiserror::Error;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum GovError {
    #[error("authentication failed: {0}")]
    Unauthenticated(String),
    #[error("principal '{principal}' is not permitted to {permission} ({reason})")]
    Forbidden { principal: String, permission: String, reason: String },
    #[error("rejected at security edge: {0}")]
    EdgeRejected(String),
    #[error("action not authorised: {0}")]
    ActionNotAuthorised(String),
    #[error("unknown tenant '{0}'")]
    UnknownTenant(String),
    #[error("source '{source_id}' is not authorised for tenant '{tenant}'")]
    SourceNotAuthorised { tenant: String, source_id: String },
    #[error("unknown observation schema '{0}'")]
    UnknownSchema(String),
    #[error("schema '{schema}' violation: {reason}")]
    SchemaViolation { schema: String, reason: String },
    #[error("content hash mismatch: claimed {claimed}, computed {computed}")]
    HashMismatch { claimed: String, computed: String },
    #[error("signature rejected: {0}")]
    SignatureRejected(String),
    #[error("unknown key '{0}'")]
    UnknownKey(String),
    #[error("observation timestamp {observed_at} is later than receipt {received_at} plus allowed skew")]
    FutureObservation { observed_at: u64, received_at: u64 },
    #[error("canonicalisation failed: {0}")]
    Canonicalisation(String),
    #[error("policy '{0}' not found")]
    PolicyNotFound(String),
    #[error("policy {id}@{version} already exists")]
    PolicyVersionExists { id: String, version: u32 },
    #[error("policy {id}@{version} is not approved ({have}/{need} approvals)")]
    PolicyNotApproved { id: String, version: u32, have: usize, need: usize },
    #[error("separation of duties: {0}")]
    SeparationOfDuties(String),
    #[error("policy compilation failed:\n  {}", .0.join("\n  "))]
    Compilation(Vec<String>),
    #[error("compiled policy {0} failed integrity check")]
    CompiledPolicyTampered(String),
    #[error("no facts for subject '{subject}' in tenant '{tenant}'")]
    NoFacts { tenant: String, subject: String },
    #[error("fact {0} not found")]
    FactNotFound(String),
    #[error("observation {0} not found")]
    ObservationNotFound(String),
    #[error("decision {0} not found")]
    DecisionNotFound(String),
    #[error("evidence for decision {0} not found")]
    EvidenceNotFound(String),
    #[error("unknown connector '{0}'")]
    UnknownConnector(String),
    #[error("integrity violation: {0}")]
    Integrity(String),
    #[error("engine program invalid: {0}")]
    InvalidProgram(String),
}

pub type Result<T> = std::result::Result<T, GovError>;
