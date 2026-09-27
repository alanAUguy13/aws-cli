//! Governed policy: repository, approvals, compiler and compiled store.
//!
//! Policies follow a software-release lifecycle. Authors submit signed
//! source; a quorum of *other* approvers signs off; only approved source can
//! be compiled; compilation validates syntax and semantics against the fact
//! catalog, detects conflicts, and emits a content-addressed program whose
//! hash is what every decision references.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::canonical::{domain, hash_bytes, hash_canonical, Digest};
use crate::engine::ENGINE_ABI;
use crate::error::{GovError, Result};
use crate::fact::{FactCatalog, FactType, FactValue};
use crate::keys::{EvidenceSigner, KeyPurpose, SignatureEnvelope, TrustStore};

/// Decision outcomes, in increasing severity. Severity breaks priority ties.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Effect {
    Allow,
    Escalate,
    Deny,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CmpOp {
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Condition {
    Always,
    All {
        of: Vec<Condition>,
    },
    Any {
        of: Vec<Condition>,
    },
    Not {
        cond: Box<Condition>,
    },
    Compare {
        fact: String,
        cmp: CmpOp,
        value: FactValue,
    },
    Exists {
        fact: String,
    },
    /// Temporal: fact observed no more than `max_age_ms` before `as_of`.
    FreshWithin {
        fact: String,
        max_age_ms: u64,
    },
    /// Temporal: fact older than `min_age_ms` (e.g. "out of stock for 2h").
    OlderThan {
        fact: String,
        min_age_ms: u64,
    },
    ConfidenceAtLeast {
        fact: String,
        min_bp: u32,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActionTemplate {
    pub connector: String,
    pub operation: String,
    #[serde(default)]
    pub params: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RuleSource {
    pub id: String,
    pub priority: u32,
    pub when: Condition,
    pub effect: Effect,
    #[serde(default)]
    pub actions: Vec<ActionTemplate>,
    pub explain: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PolicySource {
    pub id: String,
    pub version: u32,
    pub tenant: String,
    pub description: String,
    pub default_effect: Effect,
    pub rules: Vec<RuleSource>,
}

impl PolicySource {
    pub fn source_hash(&self) -> Result<Digest> {
        hash_canonical(domain::POLICY_SOURCE, self)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Approval {
    pub approver: String,
    pub approved_at: u64,
    pub signature: SignatureEnvelope,
}

fn approval_message(source_hash: &Digest, approved_at: u64) -> Digest {
    let mut msg = source_hash.0.to_vec();
    msg.extend_from_slice(&approved_at.to_be_bytes());
    hash_bytes(domain::POLICY_APPROVAL, &msg)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRecord {
    pub source: PolicySource,
    pub source_hash: Digest,
    pub author: String,
    pub submitted_at: u64,
    pub author_signature: SignatureEnvelope,
    pub approvals: Vec<Approval>,
}

/// Versioned, signed, approval-gated policy source repository.
#[derive(Debug)]
pub struct PolicyRepository {
    records: BTreeMap<(String, u32), PolicyRecord>,
    pub required_approvals: usize,
}

impl PolicyRepository {
    pub fn new(required_approvals: usize) -> Self {
        Self { records: BTreeMap::new(), required_approvals }
    }

    pub fn submit(&mut self, source: PolicySource, author: &dyn EvidenceSigner, trust: &TrustStore, at: u64) -> Result<Digest> {
        let record = self.prepare_submit(source, author, trust, at)?;
        let h = record.source_hash;
        self.restore_submitted(record)?;
        Ok(h)
    }

    fn check_new_version(&self, id: &str, version: u32) -> Result<()> {
        let latest = self.records.range((id.to_string(), 0)..=(id.to_string(), u32::MAX)).next_back();
        if latest.is_some_and(|((_, v), _)| version <= *v) {
            return Err(GovError::PolicyVersionExists { id: id.into(), version });
        }
        Ok(())
    }

    /// Sign and validate a submission without storing it.
    pub fn prepare_submit(&self, source: PolicySource, author: &dyn EvidenceSigner, trust: &TrustStore, at: u64) -> Result<PolicyRecord> {
        self.check_new_version(&source.id, source.version)?;
        let source_hash = source.source_hash()?;
        let author_signature = author.sign(source_hash.as_bytes());
        let key_info = trust.verify(source_hash.as_bytes(), &author_signature, KeyPurpose::PolicyAuthor, None, at)?;
        Ok(PolicyRecord { author: key_info.owner.clone(), source, source_hash, submitted_at: at, author_signature, approvals: Vec::new() })
    }

    /// Store a submission (live path or journal recovery). Signatures are
    /// re-checked by [`PolicyRepository::verify_approved`] before compiling.
    pub fn restore_submitted(&mut self, record: PolicyRecord) -> Result<()> {
        self.check_new_version(&record.source.id, record.source.version)?;
        if record.source.source_hash()? != record.source_hash || !record.approvals.is_empty() {
            return Err(GovError::Integrity(format!("policy {} submission record is inconsistent", record.source.id)));
        }
        self.records.insert((record.source.id.clone(), record.source.version), record);
        Ok(())
    }

    pub fn approve(&mut self, id: &str, version: u32, approver: &dyn EvidenceSigner, trust: &TrustStore, at: u64) -> Result<usize> {
        let approval = self.prepare_approval(id, version, approver, trust, at)?;
        self.restore_approval(id, version, approval)
    }

    /// Sign and validate an approval without storing it.
    pub fn prepare_approval(&self, id: &str, version: u32, approver: &dyn EvidenceSigner, trust: &TrustStore, at: u64) -> Result<Approval> {
        let record = self.records.get(&(id.to_string(), version)).ok_or_else(|| GovError::PolicyNotFound(format!("{id}@{version}")))?;
        let msg = approval_message(&record.source_hash, at);
        let signature = approver.sign(msg.as_bytes());
        let key = trust.verify(msg.as_bytes(), &signature, KeyPurpose::PolicyApprover, None, at)?;
        let approval = Approval { approver: key.owner.clone(), approved_at: at, signature };
        Self::check_approval(record, &approval)?;
        Ok(approval)
    }

    fn check_approval(record: &PolicyRecord, approval: &Approval) -> Result<()> {
        if approval.approver == record.author {
            return Err(GovError::SeparationOfDuties(format!("author '{}' cannot approve their own policy", approval.approver)));
        }
        if record.approvals.iter().any(|a| a.approver == approval.approver) {
            return Err(GovError::SeparationOfDuties(format!("'{}' has already approved", approval.approver)));
        }
        Ok(())
    }

    pub fn restore_approval(&mut self, id: &str, version: u32, approval: Approval) -> Result<usize> {
        let record = self.records.get_mut(&(id.to_string(), version)).ok_or_else(|| GovError::PolicyNotFound(format!("{id}@{version}")))?;
        Self::check_approval(record, &approval)?;
        record.approvals.push(approval);
        Ok(record.approvals.len())
    }

    pub fn get(&self, id: &str, version: u32) -> Option<&PolicyRecord> {
        self.records.get(&(id.to_string(), version))
    }

    /// Re-verify author and every approval signature, and the quorum.
    pub fn verify_approved(&self, record: &PolicyRecord, trust: &TrustStore) -> Result<Vec<String>> {
        let computed = record.source.source_hash()?;
        if computed != record.source_hash {
            return Err(GovError::Integrity(format!("policy {} source altered after submission", record.source.id)));
        }
        trust.verify(computed.as_bytes(), &record.author_signature, KeyPurpose::PolicyAuthor, Some(&record.author), record.submitted_at)?;
        let mut approvers = BTreeSet::new();
        for a in &record.approvals {
            let msg = approval_message(&computed, a.approved_at);
            trust.verify(msg.as_bytes(), &a.signature, KeyPurpose::PolicyApprover, Some(&a.approver), a.approved_at)?;
            if a.approver != record.author {
                approvers.insert(a.approver.clone());
            }
        }
        if approvers.len() < self.required_approvals {
            return Err(GovError::PolicyNotApproved {
                id: record.source.id.clone(),
                version: record.source.version,
                have: approvers.len(),
                need: self.required_approvals,
            });
        }
        Ok(approvers.into_iter().collect())
    }
}

/// One instruction of the compiled condition program (postfix stack code).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "i", rename_all = "snake_case")]
pub enum Op {
    True,
    Cmp { fact: u16, cmp: CmpOp, konst: u16 },
    Exists { fact: u16 },
    Fresh { fact: u16, max_age_ms: u64 },
    Older { fact: u16, min_age_ms: u64 },
    Conf { fact: u16, min_bp: u32 },
    Not,
    And { n: u16 },
    Or { n: u16 },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompiledRule {
    pub id: String,
    pub priority: u32,
    pub effect: Effect,
    pub code: Vec<Op>,
    pub actions: Vec<ActionTemplate>,
    pub explain: String,
}

/// The executable, content-addressed form of a policy. Everything that can
/// influence a decision is inside `program` and therefore inside the hash.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyProgram {
    pub policy_id: String,
    pub version: u32,
    pub tenant: String,
    pub source_hash: Digest,
    pub engine_abi: u32,
    pub default_effect: Effect,
    pub fact_table: Vec<String>,
    pub constants: Vec<FactValue>,
    /// Pre-sorted by the priority resolver: priority desc, severity desc, id.
    pub rules: Vec<CompiledRule>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompiledPolicy {
    pub program: PolicyProgram,
    pub policy_hash: Digest,
    pub approvers: Vec<String>,
    pub warnings: Vec<String>,
}

impl CompiledPolicy {
    pub fn verify(&self) -> Result<()> {
        if hash_canonical(domain::POLICY_COMPILED, &self.program)? != self.policy_hash {
            return Err(GovError::CompiledPolicyTampered(self.policy_hash.short()));
        }
        Ok(())
    }

    /// The canonical "binary": the bytes the policy hash is computed over.
    pub fn binary(&self) -> Result<Vec<u8>> {
        Ok(crate::canonical::canonical_json(&self.program)?.into_bytes())
    }
}

pub struct PolicyCompiler<'a> {
    pub catalog: &'a FactCatalog,
}

struct Emitter<'a> {
    catalog: &'a FactCatalog,
    facts: Vec<String>,
    constants: Vec<FactValue>,
    errors: Vec<String>,
}

impl Emitter<'_> {
    fn fact(&mut self, rule: &str, name: &str) -> (u16, Option<FactType>) {
        let ty = self.catalog.get(name).copied();
        if ty.is_none() {
            self.errors.push(format!("rule '{rule}': unknown fact '{name}' (not produced by any mapping)"));
        }
        let idx = match self.facts.iter().position(|f| f == name) {
            Some(i) => i,
            None => {
                self.facts.push(name.to_string());
                self.facts.len() - 1
            }
        };
        (idx as u16, ty)
    }

    fn konst(&mut self, v: &FactValue) -> u16 {
        match self.constants.iter().position(|c| c == v) {
            Some(i) => i as u16,
            None => {
                self.constants.push(v.clone());
                (self.constants.len() - 1) as u16
            }
        }
    }

    fn emit(&mut self, rule: &str, c: &Condition, out: &mut Vec<Op>) {
        match c {
            Condition::Always => out.push(Op::True),
            Condition::All { of } | Condition::Any { of } => {
                if of.is_empty() {
                    self.errors.push(format!("rule '{rule}': empty all/any"));
                }
                for sub in of {
                    self.emit(rule, sub, out);
                }
                let n = of.len() as u16;
                out.push(if matches!(c, Condition::All { .. }) { Op::And { n } } else { Op::Or { n } });
            }
            Condition::Not { cond } => {
                self.emit(rule, cond, out);
                out.push(Op::Not);
            }
            Condition::Compare { fact, cmp, value } => {
                let (f, ty) = self.fact(rule, fact);
                if let Some(ty) = ty {
                    if ty != value.fact_type() {
                        self.errors.push(format!("rule '{rule}': fact '{fact}' is {ty:?}, compared with {:?}", value.fact_type()));
                    } else if ty != FactType::Int && !matches!(cmp, CmpOp::Eq | CmpOp::Ne) {
                        self.errors.push(format!("rule '{rule}': ordering comparison on non-integer fact '{fact}'"));
                    }
                }
                let k = self.konst(value);
                out.push(Op::Cmp { fact: f, cmp: *cmp, konst: k });
            }
            Condition::Exists { fact } => {
                let (f, _) = self.fact(rule, fact);
                out.push(Op::Exists { fact: f });
            }
            Condition::FreshWithin { fact, max_age_ms } => {
                if *max_age_ms == 0 {
                    self.errors.push(format!("rule '{rule}': fresh_within max_age_ms must be > 0"));
                }
                let (f, _) = self.fact(rule, fact);
                out.push(Op::Fresh { fact: f, max_age_ms: *max_age_ms });
            }
            Condition::OlderThan { fact, min_age_ms } => {
                let (f, _) = self.fact(rule, fact);
                out.push(Op::Older { fact: f, min_age_ms: *min_age_ms });
            }
            Condition::ConfidenceAtLeast { fact, min_bp } => {
                if *min_bp > 10_000 {
                    self.errors.push(format!("rule '{rule}': min_bp {min_bp} exceeds 10000"));
                }
                let (f, _) = self.fact(rule, fact);
                out.push(Op::Conf { fact: f, min_bp: *min_bp });
            }
        }
    }
}

fn valid_ident(s: &str) -> bool {
    !s.is_empty() && s.len() <= 64 && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.')
}

impl PolicyCompiler<'_> {
    /// Compile an approved record. `approvers` comes from
    /// [`PolicyRepository::verify_approved`], so unapproved source can never
    /// reach this point through the public facade.
    pub fn compile(&self, record: &PolicyRecord, approvers: Vec<String>) -> Result<CompiledPolicy> {
        let src = &record.source;
        let mut em = Emitter { catalog: self.catalog, facts: Vec::new(), constants: Vec::new(), errors: Vec::new() };
        let mut warnings = Vec::new();

        // Syntax validation
        if !valid_ident(&src.id) {
            em.errors.push(format!("invalid policy id '{}'", src.id));
        }
        if src.rules.is_empty() {
            em.errors.push("policy has no rules".into());
        }
        let mut seen = BTreeSet::new();
        for r in &src.rules {
            if !valid_ident(&r.id) {
                em.errors.push(format!("invalid rule id '{}'", r.id));
            }
            if !seen.insert(r.id.as_str()) {
                em.errors.push(format!("duplicate rule id '{}'", r.id));
            }
            if r.explain.trim().is_empty() {
                em.errors.push(format!("rule '{}': explanation is required", r.id));
            }
            for a in &r.actions {
                if a.connector.is_empty() || a.operation.is_empty() {
                    em.errors.push(format!("rule '{}': action needs connector and operation", r.id));
                }
            }
        }

        // Semantic validation + code generation
        let mut rules: Vec<CompiledRule> = src
            .rules
            .iter()
            .map(|r| {
                let mut code = Vec::new();
                em.emit(&r.id, &r.when, &mut code);
                CompiledRule {
                    id: r.id.clone(),
                    priority: r.priority,
                    effect: r.effect,
                    code,
                    actions: r.actions.clone(),
                    explain: r.explain.clone(),
                }
            })
            .collect();

        // Conflict detection
        for (i, a) in src.rules.iter().enumerate() {
            for b in &src.rules[i + 1..] {
                if a.priority == b.priority && a.effect != b.effect {
                    em.errors.push(format!(
                        "conflict: rules '{}' ({:?}) and '{}' ({:?}) share priority {}; give them distinct priorities",
                        a.id, a.effect, b.id, b.effect, a.priority
                    ));
                }
                if a.when == b.when && a.effect != b.effect {
                    em.errors.push(format!("conflict: rules '{}' and '{}' have identical conditions but different effects", a.id, b.id));
                }
            }
        }

        // Priority resolver (ahead of time)
        rules.sort_by(|a, b| b.priority.cmp(&a.priority).then(b.effect.cmp(&a.effect)).then(a.id.cmp(&b.id)));

        // Reachability
        if let Some(pos) = rules.iter().position(|r| r.code == [Op::True]) {
            for shadowed in &rules[pos + 1..] {
                warnings.push(format!("rule '{}' is unreachable: shadowed by unconditional rule '{}'", shadowed.id, rules[pos].id));
            }
        }

        if em.facts.len() > u16::MAX as usize || em.constants.len() > u16::MAX as usize {
            em.errors.push("policy too large".into());
        }
        if !em.errors.is_empty() {
            return Err(GovError::Compilation(em.errors));
        }

        let program = PolicyProgram {
            policy_id: src.id.clone(),
            version: src.version,
            tenant: src.tenant.clone(),
            source_hash: record.source_hash,
            engine_abi: ENGINE_ABI,
            default_effect: src.default_effect,
            fact_table: em.facts,
            constants: em.constants,
            rules,
        };
        crate::engine::check_program(&program)?;
        let policy_hash = hash_canonical(domain::POLICY_COMPILED, &program)?;
        Ok(CompiledPolicy { program, policy_hash, approvers, warnings })
    }
}

/// Content-addressed store of compiled policies plus the active pointer per
/// (tenant, policy id). Old binaries are never removed: replay needs them.
#[derive(Debug, Default)]
pub struct CompiledPolicyStore {
    by_hash: BTreeMap<Digest, CompiledPolicy>,
    active: BTreeMap<(String, String), Digest>,
}

impl CompiledPolicyStore {
    pub fn insert(&mut self, policy: CompiledPolicy) -> Result<Digest> {
        policy.verify()?;
        let h = policy.policy_hash;
        self.by_hash.entry(h).or_insert(policy);
        Ok(h)
    }

    pub fn contains(&self, hash: &Digest) -> bool {
        self.by_hash.contains_key(hash)
    }

    pub fn activate(&mut self, hash: Digest) -> Result<()> {
        let p = self.by_hash.get(&hash).ok_or_else(|| GovError::PolicyNotFound(hash.short()))?;
        self.active.insert((p.program.tenant.clone(), p.program.policy_id.clone()), hash);
        Ok(())
    }

    pub fn active(&self, tenant: &str, policy_id: &str) -> Result<&CompiledPolicy> {
        let h = self
            .active
            .get(&(tenant.to_string(), policy_id.to_string()))
            .ok_or_else(|| GovError::PolicyNotFound(format!("{tenant}/{policy_id} (no active version)")))?;
        self.get(h)
    }

    pub fn get(&self, hash: &Digest) -> Result<&CompiledPolicy> {
        let p = self.by_hash.get(hash).ok_or_else(|| GovError::PolicyNotFound(hash.short()))?;
        p.verify()?;
        Ok(p)
    }

    pub fn verify_integrity(&self) -> Result<()> {
        self.by_hash.values().try_for_each(CompiledPolicy::verify)
    }

    #[doc(hidden)]
    pub fn get_mut_unchecked(&mut self, hash: &Digest) -> Option<&mut CompiledPolicy> {
        self.by_hash.get_mut(hash)
    }
}
