//! Observation layer: gateway validation and the immutable observation store.
//!
//! An observation is a signed claim by one source ("sensor s-17 read 7.2 C at
//! t"). The gateway accepts it only if the tenant resolves, the source is
//! authorised for the tenant, the payload matches a registered schema, the
//! claimed content hash is correct, and the signature verifies against a key
//! owned by that source and valid at the observation time.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::canonical::{domain, hash_canonical, Digest};
use crate::error::{GovError, Result};
use crate::identity::ActorKind;
use crate::keys::{EvidenceSigner, KeyPurpose, SignatureEnvelope, TrustStore};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceRef {
    pub kind: ActorKind,
    pub id: String,
}

/// The signed content of an observation. Its canonical hash is the
/// observation hash.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ObservationBody {
    pub tenant: String,
    pub source: SourceRef,
    pub schema: String,
    /// Unix milliseconds, asserted by the source.
    pub observed_at: u64,
    pub payload: Value,
}

impl ObservationBody {
    pub fn content_hash(&self) -> Result<Digest> {
        hash_canonical(domain::OBSERVATION, self)
    }

    /// Hash and sign; what a well-behaved device SDK does before sending.
    pub fn seal(self, signer: &dyn EvidenceSigner) -> Result<ObservationEnvelope> {
        let content_hash = self.content_hash()?;
        let signature = signer.sign(content_hash.as_bytes());
        Ok(ObservationEnvelope { body: self, content_hash, signature })
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ObservationEnvelope {
    pub body: ObservationBody,
    pub content_hash: Digest,
    pub signature: SignatureEnvelope,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FieldType {
    Number,
    Integer,
    String,
    Bool,
}

impl FieldType {
    fn matches(self, v: &Value) -> bool {
        match self {
            FieldType::Number => v.is_number(),
            FieldType::Integer => v.is_i64() || v.is_u64(),
            FieldType::String => v.is_string(),
            FieldType::Bool => v.is_boolean(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObservationSchema {
    pub id: String,
    pub required: BTreeMap<String, FieldType>,
    pub optional: BTreeMap<String, FieldType>,
    /// Reject payload fields not declared above.
    pub closed: bool,
}

impl ObservationSchema {
    pub fn validate(&self, payload: &Value) -> Result<()> {
        let violation = |reason: String| GovError::SchemaViolation { schema: self.id.clone(), reason };
        let obj = payload.as_object().ok_or_else(|| violation("payload must be a JSON object".into()))?;
        for (field, ty) in &self.required {
            match obj.get(field) {
                None => return Err(violation(format!("missing required field '{field}'"))),
                Some(v) if !ty.matches(v) => return Err(violation(format!("field '{field}' must be {ty:?}"))),
                _ => {}
            }
        }
        for (field, v) in obj {
            match (self.required.get(field), self.optional.get(field)) {
                (Some(_), _) => {}
                (None, Some(ty)) if !ty.matches(v) => return Err(violation(format!("field '{field}' must be {ty:?}"))),
                (None, Some(_)) => {}
                (None, None) if self.closed => return Err(violation(format!("undeclared field '{field}'"))),
                (None, None) => {}
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredObservation {
    pub envelope: ObservationEnvelope,
    /// Provenance metadata recorded by the gateway (not part of the hash).
    pub received_at: u64,
    pub ingest_seq: u64,
    pub submitted_by: String,
}

impl StoredObservation {
    pub fn hash(&self) -> Digest {
        self.envelope.content_hash
    }
}

#[derive(Debug, Default)]
pub struct ObservationGateway {
    tenants: BTreeMap<String, BTreeSet<String>>,
    schemas: BTreeMap<String, ObservationSchema>,
    /// Tolerated clock skew between a source and the gateway.
    pub max_future_skew_ms: u64,
}

impl ObservationGateway {
    pub fn new(max_future_skew_ms: u64) -> Self {
        Self { max_future_skew_ms, ..Default::default() }
    }

    pub fn register_tenant(&mut self, tenant: impl Into<String>) {
        self.tenants.entry(tenant.into()).or_default();
    }

    pub fn authorise_source(&mut self, tenant: &str, source_id: impl Into<String>) -> Result<()> {
        self.tenants.get_mut(tenant).ok_or_else(|| GovError::UnknownTenant(tenant.into()))?.insert(source_id.into());
        Ok(())
    }

    pub fn register_schema(&mut self, schema: ObservationSchema) {
        self.schemas.insert(schema.id.clone(), schema);
    }

    pub fn schema(&self, id: &str) -> Option<&ObservationSchema> {
        self.schemas.get(id)
    }

    /// Validate an envelope. Pure: does not store anything.
    pub fn validate(&self, env: &ObservationEnvelope, trust: &TrustStore, received_at: u64) -> Result<Digest> {
        let body = &env.body;
        // Tenant resolver
        let sources = self.tenants.get(&body.tenant).ok_or_else(|| GovError::UnknownTenant(body.tenant.clone()))?;
        if !sources.contains(&body.source.id) {
            return Err(GovError::SourceNotAuthorised { tenant: body.tenant.clone(), source_id: body.source.id.clone() });
        }
        // Schema validator
        self.schemas.get(&body.schema).ok_or_else(|| GovError::UnknownSchema(body.schema.clone()))?.validate(&body.payload)?;
        if body.observed_at > received_at.saturating_add(self.max_future_skew_ms) {
            return Err(GovError::FutureObservation { observed_at: body.observed_at, received_at });
        }
        // Hash verifier
        let computed = body.content_hash()?;
        if computed != env.content_hash {
            return Err(GovError::HashMismatch { claimed: env.content_hash.to_hex(), computed: computed.to_hex() });
        }
        // Signature validator: key must be owned by the claimed source.
        trust.verify(computed.as_bytes(), &env.signature, KeyPurpose::ObservationSource, Some(&body.source.id), body.observed_at)?;
        Ok(computed)
    }
}

/// Append-only, content-addressed observation store.
#[derive(Debug, Default)]
pub struct ObservationStore {
    records: BTreeMap<Digest, StoredObservation>,
    next_seq: u64,
}

pub enum Appended {
    New(u64),
    Duplicate(u64),
}

impl ObservationStore {
    /// Idempotent: re-submitting the same observation returns the original
    /// sequence number and does not create a second record.
    pub fn append(&mut self, envelope: ObservationEnvelope, received_at: u64, submitted_by: &str) -> Appended {
        let hash = envelope.content_hash;
        if let Some(existing) = self.records.get(&hash) {
            return Appended::Duplicate(existing.ingest_seq);
        }
        let seq = self.next_seq;
        self.next_seq += 1;
        self.records.insert(hash, StoredObservation { envelope, received_at, ingest_seq: seq, submitted_by: submitted_by.to_string() });
        Appended::New(seq)
    }

    pub fn get(&self, hash: &Digest) -> Option<&StoredObservation> {
        self.records.get(hash)
    }

    pub fn len(&self) -> usize {
        self.records.len()
    }

    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = &StoredObservation> {
        self.records.values()
    }

    /// Recompute every content hash; detects in-place tampering.
    pub fn verify_integrity(&self) -> Result<()> {
        for (key, rec) in &self.records {
            let computed = rec.envelope.body.content_hash()?;
            if computed != *key || rec.envelope.content_hash != *key {
                return Err(GovError::Integrity(format!("observation {} content does not match its hash", key.short())));
            }
        }
        Ok(())
    }

    /// Test/forensics hook: mutable access, used to prove tamper detection.
    #[doc(hidden)]
    pub fn get_mut_unchecked(&mut self, hash: &Digest) -> Option<&mut StoredObservation> {
        self.records.get_mut(hash)
    }
}
