//! Identity / Authentication -> Authorization -> API & Security Edge.
//!
//! These three stages sit in front of the Observation Gateway: nothing reaches
//! the evidentiary pipeline unless the caller is authenticated, holds a role
//! that grants the requested permission within its own tenant, and passes the
//! edge controls (payload size, nonce replay protection, rate limiting).
//!
//! All checks take an explicit timestamp instead of reading a clock, so the
//! admission decision itself is deterministic and testable.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::canonical::{hash_bytes, Digest};
use crate::error::{GovError, Result};

/// The kinds of external actor shown in the architecture.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActorKind {
    AiModel,
    Camera,
    Sensor,
    Robot,
    ErpSystem,
    MobileApp,
    User,
    Service,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Principal {
    pub id: String,
    pub tenant: String,
    pub kind: ActorKind,
    pub roles: BTreeSet<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Permission {
    SubmitObservation,
    AuthorPolicy,
    ApprovePolicy,
    ActivatePolicy,
    RequestDecision,
    Replay,
    ReadEvidence,
}

impl fmt::Display for Permission {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = serde_json::to_value(self).ok().and_then(|v| v.as_str().map(str::to_owned)).unwrap_or_default();
        f.write_str(&s)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Credential {
    principal_id: String,
    not_after: Option<u64>,
    revoked: bool,
}

/// Authenticates bearer credentials. Only the SHA-256 of each token is
/// stored, so a leaked credential table does not leak usable tokens.
#[derive(Debug, Default)]
pub struct IdentityProvider {
    principals: BTreeMap<String, Principal>,
    credentials: BTreeMap<Digest, Credential>,
}

fn token_digest(token: &str) -> Digest {
    hash_bytes("rustgate.credential.v1", token.as_bytes())
}

impl IdentityProvider {
    pub fn register_principal(&mut self, principal: Principal) {
        self.principals.insert(principal.id.clone(), principal);
    }

    pub fn issue_credential(&mut self, principal_id: &str, token: &str, not_after: Option<u64>) -> Result<()> {
        if !self.principals.contains_key(principal_id) {
            return Err(GovError::Unauthenticated(format!("unknown principal '{principal_id}'")));
        }
        self.credentials.insert(token_digest(token), Credential { principal_id: principal_id.to_string(), not_after, revoked: false });
        Ok(())
    }

    pub fn revoke_credential(&mut self, token: &str) {
        if let Some(c) = self.credentials.get_mut(&token_digest(token)) {
            c.revoked = true;
        }
    }

    pub fn authenticate(&self, token: &str, at: u64) -> Result<Principal> {
        let cred = self.credentials.get(&token_digest(token)).ok_or_else(|| GovError::Unauthenticated("unknown credential".into()))?;
        if cred.revoked {
            return Err(GovError::Unauthenticated("credential revoked".into()));
        }
        if cred.not_after.is_some_and(|end| at >= end) {
            return Err(GovError::Unauthenticated("credential expired".into()));
        }
        self.principals.get(&cred.principal_id).cloned().ok_or_else(|| GovError::Unauthenticated("principal removed".into()))
    }

    pub fn principal(&self, id: &str) -> Option<&Principal> {
        self.principals.get(id)
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Role {
    pub permissions: BTreeSet<Permission>,
    /// ABAC restriction for `SubmitObservation`: schemas this role may
    /// submit. `None` means any registered schema.
    pub allowed_schemas: Option<BTreeSet<String>>,
}

/// RBAC with tenant isolation and attribute (schema) restrictions.
#[derive(Debug, Default)]
pub struct Authorizer {
    roles: BTreeMap<String, Role>,
}

impl Authorizer {
    pub fn define_role(&mut self, name: impl Into<String>, role: Role) {
        self.roles.insert(name.into(), role);
    }

    /// `resource` is the schema id for `SubmitObservation`, ignored otherwise.
    pub fn authorize(&self, principal: &Principal, permission: Permission, tenant: &str, resource: Option<&str>) -> Result<()> {
        let deny = |reason: String| GovError::Forbidden { principal: principal.id.clone(), permission: permission.to_string(), reason };
        if principal.tenant != tenant {
            return Err(deny(format!("principal belongs to tenant '{}', not '{tenant}'", principal.tenant)));
        }
        let granted = principal.roles.iter().filter_map(|r| self.roles.get(r)).any(|role| {
            role.permissions.contains(&permission)
                && match (&role.allowed_schemas, resource) {
                    (Some(allowed), Some(schema)) if permission == Permission::SubmitObservation => allowed.contains(schema),
                    _ => true,
                }
        });
        if granted {
            Ok(())
        } else {
            Err(deny("no role grants this permission for this resource".into()))
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EdgeConfig {
    pub max_payload_bytes: usize,
    pub rate_limit_requests: u32,
    pub rate_limit_window_ms: u64,
    /// How long a nonce is remembered for replay protection.
    pub nonce_ttl_ms: u64,
}

impl Default for EdgeConfig {
    fn default() -> Self {
        Self { max_payload_bytes: 64 * 1024, rate_limit_requests: 1_000, rate_limit_window_ms: 60_000, nonce_ttl_ms: 300_000 }
    }
}

/// API & security edge: size limits, per-principal fixed-window rate
/// limiting and request-nonce replay protection.
#[derive(Debug, Default)]
pub struct SecurityEdge {
    config: EdgeConfig,
    seen_nonces: BTreeMap<(String, String), u64>,
    windows: BTreeMap<String, (u64, u32)>,
}

impl SecurityEdge {
    pub fn new(config: EdgeConfig) -> Self {
        Self { config, ..Default::default() }
    }

    pub fn admit(&mut self, principal: &Principal, payload_bytes: usize, nonce: &str, at: u64) -> Result<()> {
        if payload_bytes > self.config.max_payload_bytes {
            return Err(GovError::EdgeRejected(format!("payload {payload_bytes} bytes exceeds limit {}", self.config.max_payload_bytes)));
        }
        if nonce.is_empty() || nonce.len() > 128 {
            return Err(GovError::EdgeRejected("nonce must be 1..=128 bytes".into()));
        }

        let ttl = self.config.nonce_ttl_ms;
        self.seen_nonces.retain(|_, seen_at| at.saturating_sub(*seen_at) < ttl);
        let key = (principal.id.clone(), nonce.to_string());
        if self.seen_nonces.contains_key(&key) {
            return Err(GovError::EdgeRejected(format!("replayed nonce '{nonce}'")));
        }

        let window = self.config.rate_limit_window_ms.max(1);
        let window_start = at - at % window;
        let entry = self.windows.entry(principal.id.clone()).or_insert((window_start, 0));
        if entry.0 != window_start {
            *entry = (window_start, 0);
        }
        if entry.1 >= self.config.rate_limit_requests {
            return Err(GovError::EdgeRejected(format!("rate limit exceeded for '{}'", principal.id)));
        }
        entry.1 += 1;
        self.seen_nonces.insert(key, at);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn principal(tenant: &str, role: &str) -> Principal {
        Principal { id: "cam-1".into(), tenant: tenant.into(), kind: ActorKind::Camera, roles: [role.to_string()].into() }
    }

    #[test]
    fn authn_authz_edge() {
        let mut idp = IdentityProvider::default();
        idp.register_principal(principal("t1", "camera"));
        idp.issue_credential("cam-1", "secret", Some(100)).unwrap();
        assert!(idp.authenticate("secret", 50).is_ok());
        assert!(idp.authenticate("secret", 100).is_err());
        assert!(idp.authenticate("wrong", 50).is_err());

        let mut az = Authorizer::default();
        az.define_role(
            "camera",
            Role { permissions: [Permission::SubmitObservation].into(), allowed_schemas: Some(["shelf.stock/v1".to_string()].into()) },
        );
        let p = principal("t1", "camera");
        assert!(az.authorize(&p, Permission::SubmitObservation, "t1", Some("shelf.stock/v1")).is_ok());
        assert!(az.authorize(&p, Permission::SubmitObservation, "t1", Some("pos.sale/v1")).is_err());
        assert!(az.authorize(&p, Permission::SubmitObservation, "t2", Some("shelf.stock/v1")).is_err());
        assert!(az.authorize(&p, Permission::ApprovePolicy, "t1", None).is_err());

        let mut edge = SecurityEdge::new(EdgeConfig { rate_limit_requests: 2, ..Default::default() });
        assert!(edge.admit(&p, 10, "n1", 0).is_ok());
        assert!(edge.admit(&p, 10, "n1", 1).is_err(), "nonce replay");
        assert!(edge.admit(&p, 10, "n2", 2).is_ok());
        assert!(edge.admit(&p, 10, "n3", 3).is_err(), "rate limit");
        assert!(edge.admit(&p, 10, "n3", 60_000).is_ok(), "new window");
        assert!(edge.admit(&p, 1 << 20, "n4", 60_001).is_err(), "payload size");
    }
}
