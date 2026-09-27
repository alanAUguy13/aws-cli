//! Canonical serialisation and domain-separated hashing.
//!
//! Every hash in RustGate is `SHA-256(domain || 0x00 || canonical_json(value))`.
//!
//! * **Canonical JSON**: object keys sorted by byte order, no insignificant
//!   whitespace, strings escaped by serde_json. Independent of struct field
//!   order and of whether `serde_json/preserve_order` is enabled anywhere in the
//!   dependency graph, because we sort explicitly.
//! * **Domain separation**: an observation hash can never collide with a fact
//!   or decision hash that happens to share the same JSON body.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;
use sha2::{Digest as _, Sha256};

use crate::error::{GovError, Result};

/// Hash domains. Versioned so that a future change to any record layout
/// produces visibly different hashes instead of silently colliding.
pub mod domain {
    pub const OBSERVATION: &str = "rustgate.observation.v1";
    pub const FACT: &str = "rustgate.fact.v1";
    pub const POLICY_SOURCE: &str = "rustgate.policy.source.v1";
    pub const POLICY_COMPILED: &str = "rustgate.policy.compiled.v1";
    pub const DECISION: &str = "rustgate.decision.v1";
    pub const EVIDENCE: &str = "rustgate.evidence.v1";
    pub const LEDGER_ENTRY: &str = "rustgate.ledger.entry.v1";
    pub const IDEMPOTENCY: &str = "rustgate.enforcement.idempotency.v1";
    pub const REPLAY_REPORT: &str = "rustgate.replay.report.v1";
    pub const POLICY_APPROVAL: &str = "rustgate.policy.approval.v1";
}

/// A SHA-256 digest. Serialises as lowercase hex.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Digest(pub [u8; 32]);

impl Digest {
    pub const ZERO: Digest = Digest([0u8; 32]);

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// First 12 hex chars, for logs and human-facing output only.
    pub fn short(&self) -> String {
        self.to_hex()[..12].to_string()
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl fmt::Debug for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Digest({})", self.short())
    }
}

impl FromStr for Digest {
    type Err = GovError;
    fn from_str(s: &str) -> Result<Self> {
        let bytes = hex::decode(s).map_err(|e| GovError::Canonicalisation(e.to_string()))?;
        let arr: [u8; 32] = bytes.try_into().map_err(|_| GovError::Canonicalisation("digest must be 32 bytes".into()))?;
        Ok(Digest(arr))
    }
}

impl Serialize for Digest {
    fn serialize<S: Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for Digest {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

/// Canonical JSON text for any serialisable value.
pub fn canonical_json<T: Serialize + ?Sized>(value: &T) -> Result<String> {
    let v = serde_json::to_value(value).map_err(|e| GovError::Canonicalisation(e.to_string()))?;
    let mut out = String::new();
    write_canonical(&v, &mut out)?;
    Ok(out)
}

fn write_canonical(v: &Value, out: &mut String) -> Result<()> {
    match v {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => {
            if let Some(f) = n.as_f64().filter(|_| n.is_f64()) {
                if !f.is_finite() {
                    return Err(GovError::Canonicalisation("non-finite number".into()));
                }
            }
            out.push_str(&n.to_string());
        }
        Value::String(s) => out.push_str(&serde_json::to_string(s).expect("string serialisation is infallible")),
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_canonical(item, out)?;
            }
            out.push(']');
        }
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            out.push('{');
            for (i, k) in keys.into_iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&serde_json::to_string(k).expect("string serialisation is infallible"));
                out.push(':');
                write_canonical(&map[k], out)?;
            }
            out.push('}');
        }
    }
    Ok(())
}

/// Raw domain-separated SHA-256.
pub fn hash_bytes(domain: &str, bytes: &[u8]) -> Digest {
    let mut h = Sha256::new();
    h.update(domain.as_bytes());
    h.update([0u8]);
    h.update(bytes);
    let out = h.finalize();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&out);
    Digest(arr)
}

/// Domain-separated hash of the canonical JSON form of `value`.
pub fn hash_canonical<T: Serialize + ?Sized>(domain: &str, value: &T) -> Result<Digest> {
    Ok(hash_bytes(domain, canonical_json(value)?.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn key_order_does_not_affect_hash() {
        let a = json!({"b": 1, "a": {"y": [1, 2], "x": "s"}});
        let b: Value = serde_json::from_str(r#"{"a":{"x":"s","y":[1,2]},"b":1}"#).unwrap();
        assert_eq!(canonical_json(&a).unwrap(), r#"{"a":{"x":"s","y":[1,2]},"b":1}"#);
        assert_eq!(hash_canonical("d", &a).unwrap(), hash_canonical("d", &b).unwrap());
    }

    #[test]
    fn domains_separate() {
        let v = json!({"k": 1});
        assert_ne!(hash_canonical("a", &v).unwrap(), hash_canonical("b", &v).unwrap());
    }

    #[test]
    fn digest_hex_roundtrip() {
        let d = hash_bytes("x", b"y");
        let s = serde_json::to_string(&d).unwrap();
        let back: Digest = serde_json::from_str(&s).unwrap();
        assert_eq!(d, back);
    }
}
