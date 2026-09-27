//! Key management: signers, the trust store, and key lifecycle.
//!
//! Signing is abstracted behind [`EvidenceSigner`] so that production
//! deployments can back it with an HSM, AWS KMS, Azure Key Vault or a TPM
//! without touching the decision path. [`LocalP256Signer`] is the in-process
//! implementation.
//!
//! ECDSA P-256 / SHA-256 with RFC 6979 deterministic nonces: signing the same
//! evidence twice with the same key produces the same signature, which keeps
//! the whole pipeline bit-for-bit reproducible.

use std::collections::BTreeMap;

use p256::ecdsa::signature::{Signer, Verifier};
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::canonical::hash_bytes;
use crate::error::{GovError, Result};

pub const ALGORITHM: &str = "ECDSA_P256_SHA256";

/// What a key is allowed to sign. A key registered for one purpose is
/// rejected for every other, so a compromised camera key cannot approve
/// policies or seal evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyPurpose {
    ObservationSource,
    PolicyAuthor,
    PolicyApprover,
    Evidence,
}

/// A detached signature plus the key that produced it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignatureEnvelope {
    pub key_id: String,
    pub algorithm: String,
    /// Fixed-size (r || s) signature, hex encoded.
    pub signature: String,
}

pub trait EvidenceSigner {
    fn key_id(&self) -> &str;
    /// SEC1 uncompressed public key.
    fn public_key_sec1(&self) -> Vec<u8>;
    fn sign(&self, message: &[u8]) -> SignatureEnvelope;
}

pub struct LocalP256Signer {
    key_id: String,
    key: SigningKey,
}

impl LocalP256Signer {
    pub fn from_secret_bytes(key_id: impl Into<String>, secret: &[u8; 32]) -> Result<Self> {
        let key = SigningKey::from_slice(secret).map_err(|e| GovError::SignatureRejected(format!("invalid secret scalar: {e}")))?;
        Ok(Self { key_id: key_id.into(), key })
    }

    /// Derive a key deterministically from a seed string. For demos, tests
    /// and reproducible fixtures only: never use in production.
    pub fn from_seed(key_id: &str, seed: &str) -> Self {
        (0u32..)
            .find_map(|counter| {
                let material = hash_bytes("rustgate.test-key-derivation.v1", format!("{seed}/{counter}").as_bytes());
                Self::from_secret_bytes(key_id, material.as_bytes()).ok()
            })
            .expect("a valid scalar is found within a few attempts")
    }
}

impl EvidenceSigner for LocalP256Signer {
    fn key_id(&self) -> &str {
        &self.key_id
    }

    fn public_key_sec1(&self) -> Vec<u8> {
        self.key.verifying_key().to_sec1_bytes().to_vec()
    }

    fn sign(&self, message: &[u8]) -> SignatureEnvelope {
        let sig: Signature = self.key.sign(message);
        SignatureEnvelope { key_id: self.key_id.clone(), algorithm: ALGORITHM.to_string(), signature: hex::encode(sig.to_bytes()) }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustedKey {
    pub key_id: String,
    pub purpose: KeyPurpose,
    /// Who the key belongs to: a source id, a person, or a service.
    pub owner: String,
    pub public_key_sec1: String,
    pub not_before: u64,
    pub not_after: Option<u64>,
    pub revoked_at: Option<u64>,
}

impl TrustedKey {
    pub fn active_at(&self, at: u64) -> bool {
        at >= self.not_before && self.not_after.is_none_or(|end| at < end) && self.revoked_at.is_none_or(|rev| at < rev)
    }
}

/// Registry of public keys the platform trusts, with validity windows.
///
/// Validity is evaluated at the *time of the signed event* (observation time,
/// approval time, sealing time), never at wall-clock "now": a replay years
/// later must reach the same verdict even after the key has been rotated.
/// Revocation is the exception by design: a key revoked at `t` invalidates
/// everything it signed at or after `t`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TrustStore {
    keys: BTreeMap<String, TrustedKey>,
}

impl TrustStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(
        &mut self,
        signer_public_sec1: &[u8],
        key_id: impl Into<String>,
        purpose: KeyPurpose,
        owner: impl Into<String>,
        not_before: u64,
    ) {
        let key_id = key_id.into();
        self.keys.insert(
            key_id.clone(),
            TrustedKey {
                key_id,
                purpose,
                owner: owner.into(),
                public_key_sec1: hex::encode(signer_public_sec1),
                not_before,
                not_after: None,
                revoked_at: None,
            },
        );
    }

    pub fn register_signer(&mut self, signer: &dyn EvidenceSigner, purpose: KeyPurpose, owner: impl Into<String>, not_before: u64) {
        self.register(&signer.public_key_sec1(), signer.key_id(), purpose, owner, not_before);
    }

    /// Stop accepting new signatures from `key_id` after `at` (rotation).
    pub fn retire(&mut self, key_id: &str, at: u64) -> Result<()> {
        let k = self.keys.get_mut(key_id).ok_or_else(|| GovError::UnknownKey(key_id.into()))?;
        k.not_after = Some(at);
        Ok(())
    }

    pub fn revoke(&mut self, key_id: &str, at: u64) -> Result<()> {
        let k = self.keys.get_mut(key_id).ok_or_else(|| GovError::UnknownKey(key_id.into()))?;
        k.revoked_at = Some(at);
        Ok(())
    }

    pub fn get(&self, key_id: &str) -> Option<&TrustedKey> {
        self.keys.get(key_id)
    }

    /// Verify `sig` over `message`, requiring the key to have `purpose`,
    /// belong to `expected_owner` (when given) and be active at `at`.
    pub fn verify(
        &self,
        message: &[u8],
        sig: &SignatureEnvelope,
        purpose: KeyPurpose,
        expected_owner: Option<&str>,
        at: u64,
    ) -> Result<&TrustedKey> {
        let key = self.keys.get(&sig.key_id).ok_or_else(|| GovError::UnknownKey(sig.key_id.clone()))?;
        if sig.algorithm != ALGORITHM {
            return Err(GovError::SignatureRejected(format!("unsupported algorithm '{}'", sig.algorithm)));
        }
        if key.purpose != purpose {
            return Err(GovError::SignatureRejected(format!("key '{}' has purpose {:?}, required {:?}", key.key_id, key.purpose, purpose)));
        }
        if let Some(owner) = expected_owner {
            if key.owner != owner {
                return Err(GovError::SignatureRejected(format!("key '{}' belongs to '{}', not '{}'", key.key_id, key.owner, owner)));
            }
        }
        if !key.active_at(at) {
            return Err(GovError::SignatureRejected(format!("key '{}' not active at {}", key.key_id, at)));
        }
        let pk = hex::decode(&key.public_key_sec1).map_err(|e| GovError::SignatureRejected(e.to_string()))?;
        let vk = VerifyingKey::from_sec1_bytes(&pk).map_err(|e| GovError::SignatureRejected(e.to_string()))?;
        let raw = hex::decode(&sig.signature).map_err(|e| GovError::SignatureRejected(e.to_string()))?;
        let signature = Signature::from_slice(&raw).map_err(|e| GovError::SignatureRejected(e.to_string()))?;
        vk.verify(message, &signature).map_err(|_| GovError::SignatureRejected(format!("bad signature from key '{}'", key.key_id)))?;
        Ok(key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_signatures_and_purpose_binding() {
        let s = LocalP256Signer::from_seed("k1", "seed");
        let a = s.sign(b"msg");
        assert_eq!(a, s.sign(b"msg"), "RFC 6979 signatures must be deterministic");

        let mut ts = TrustStore::new();
        ts.register_signer(&s, KeyPurpose::Evidence, "svc", 0);
        assert!(ts.verify(b"msg", &a, KeyPurpose::Evidence, Some("svc"), 10).is_ok());
        assert!(ts.verify(b"msg", &a, KeyPurpose::PolicyApprover, None, 10).is_err());
        assert!(ts.verify(b"other", &a, KeyPurpose::Evidence, None, 10).is_err());
        ts.revoke("k1", 5).unwrap();
        assert!(ts.verify(b"msg", &a, KeyPurpose::Evidence, None, 4).is_ok());
        assert!(ts.verify(b"msg", &a, KeyPurpose::Evidence, None, 5).is_err());
    }
}
