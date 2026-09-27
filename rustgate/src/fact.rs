//! Fact normalisation and the deterministic fact store.
//!
//! Raw observations are noisy, source-specific and may carry floats. Facts
//! are canonical: a fixed vocabulary of names, integer/boolean/text values
//! (decimals become fixed-point integers via exact decimal-string parsing,
//! never float arithmetic), integer confidence in basis points, and a hash
//! that links back to the originating observation.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::canonical::{domain, hash_canonical, Digest};
use crate::error::{GovError, Result};
use crate::observation::{ObservationEnvelope, StoredObservation};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "type", content = "value", rename_all = "snake_case")]
pub enum FactValue {
    Bool(bool),
    Int(i64),
    Text(String),
}

impl FactValue {
    pub fn fact_type(&self) -> FactType {
        match self {
            FactValue::Bool(_) => FactType::Bool,
            FactValue::Int(_) => FactType::Int,
            FactValue::Text(_) => FactType::Text,
        }
    }
}

impl fmt::Display for FactValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FactValue::Bool(b) => write!(f, "{b}"),
            FactValue::Int(i) => write!(f, "{i}"),
            FactValue::Text(s) => write!(f, "{s:?}"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FactType {
    Bool,
    Int,
    Text,
}

/// Content of a fact; its canonical hash is the fact hash.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FactBody {
    pub tenant: String,
    pub subject: String,
    pub name: String,
    pub value: FactValue,
    pub observed_at: u64,
    /// 0..=10_000 basis points.
    pub confidence_bp: u32,
    pub observation_hash: Digest,
    pub mapping_id: String,
    /// Content hash of the exact mapping rule version that derived this fact.
    pub mapping_hash: Digest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Fact {
    pub body: FactBody,
    pub fact_hash: Digest,
}

impl Fact {
    pub fn new(body: FactBody) -> Result<Self> {
        let fact_hash = hash_canonical(domain::FACT, &body)?;
        Ok(Self { body, fact_hash })
    }

    pub fn verify(&self) -> Result<()> {
        let computed = hash_canonical(domain::FACT, &self.body)?;
        if computed != self.fact_hash {
            return Err(GovError::Integrity(format!("fact {} content does not match its hash", self.fact_hash.short())));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ValueMapping {
    Bool,
    Text,
    /// Decimal -> integer scaled by 10^scale, rounded half-to-even.
    FixedPoint {
        scale: u32,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "rule", rename_all = "snake_case")]
pub enum QualityRule {
    MinInt { min: i64 },
    MaxInt { max: i64 },
    NonEmptyText,
    OneOf { values: Vec<String> },
}

/// Canonical mapping: one payload field of one schema -> one named fact.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MappingRule {
    pub id: String,
    pub schema: String,
    /// Payload field whose value names the subject (e.g. `shelf_id`).
    pub subject_field: String,
    pub fact_name: String,
    pub value_field: String,
    pub mapping: ValueMapping,
    #[serde(default)]
    pub quality: Vec<QualityRule>,
    /// Optional payload field holding a 0..1 confidence (AI models, vision).
    pub confidence_field: Option<String>,
    /// Facts below this confidence are rejected, not stored.
    #[serde(default)]
    pub min_confidence_bp: u32,
}

impl MappingRule {
    pub fn fact_type(&self) -> FactType {
        match self.mapping {
            ValueMapping::Bool => FactType::Bool,
            ValueMapping::Text => FactType::Text,
            ValueMapping::FixedPoint { .. } => FactType::Int,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QualityViolation {
    pub mapping_id: String,
    pub observation_hash: Digest,
    pub reason: String,
}

#[derive(Debug, Default, Clone)]
pub struct NormalizationOutcome {
    pub facts: Vec<Fact>,
    pub rejections: Vec<QualityViolation>,
}

/// The fact vocabulary: every fact name with its type. Derived from the
/// mapping rules and handed to the policy compiler for semantic validation.
pub type FactCatalog = BTreeMap<String, FactType>;

/// Canonical mapping registry.
///
/// Every version of every mapping rule ever registered is kept, addressed by
/// its content hash, and each fact records the hash of the exact rule that
/// derived it. That makes normalisation itself re-executable: replay and
/// offline bundle verification re-derive each fact from its signed
/// observation and require a bit-identical result.
#[derive(Debug, Default)]
pub struct FactNormalizer {
    /// schema -> active rules, sorted by id.
    active: BTreeMap<String, Vec<(Digest, MappingRule)>>,
    history: BTreeMap<Digest, MappingRule>,
}

impl MappingRule {
    pub fn hash(&self) -> Result<Digest> {
        hash_canonical(domain::MAPPING, self)
    }
}

impl FactNormalizer {
    /// Validate a rule against the current vocabulary without registering it.
    pub fn check(&self, rule: &MappingRule) -> Result<Digest> {
        let clash = self
            .active
            .values()
            .flatten()
            .find(|(_, r)| r.fact_name == rule.fact_name && r.id != rule.id && r.fact_type() != rule.fact_type());
        if let Some((_, existing)) = clash {
            return Err(GovError::Compilation(vec![format!(
                "fact '{}' already produced as {:?} by mapping '{}', mapping '{}' produces {:?}",
                rule.fact_name,
                existing.fact_type(),
                existing.id,
                rule.id,
                rule.fact_type()
            )]));
        }
        rule.hash()
    }

    /// True if `rule` is already the active version of its id.
    pub fn is_active(&self, rule: &MappingRule) -> Result<bool> {
        let h = rule.hash()?;
        Ok(self.active.get(&rule.schema).is_some_and(|list| list.iter().any(|(ah, _)| *ah == h)))
    }

    /// Register (or supersede, by id) a rule. Superseded versions stay in
    /// the history so facts they derived remain re-derivable.
    pub fn register(&mut self, rule: MappingRule) -> Result<Digest> {
        let h = self.check(&rule)?;
        for list in self.active.values_mut() {
            list.retain(|(_, r)| r.id != rule.id);
        }
        let list = self.active.entry(rule.schema.clone()).or_default();
        list.push((h, rule.clone()));
        list.sort_by(|a, b| a.1.id.cmp(&b.1.id));
        self.history.insert(h, rule);
        Ok(h)
    }

    pub fn mapping(&self, hash: &Digest) -> Option<&MappingRule> {
        self.history.get(hash)
    }

    pub fn catalog(&self) -> FactCatalog {
        self.active.values().flatten().map(|(_, r)| (r.fact_name.clone(), r.fact_type())).collect()
    }

    pub fn normalize(&self, obs: &StoredObservation) -> NormalizationOutcome {
        let mut out = NormalizationOutcome::default();
        for (h, rule) in self.active.get(&obs.envelope.body.schema).into_iter().flatten() {
            match derive_fact(rule, *h, &obs.envelope) {
                Ok(fact) => out.facts.push(fact),
                Err(reason) => out.rejections.push(QualityViolation { mapping_id: rule.id.clone(), observation_hash: obs.hash(), reason }),
            }
        }
        out
    }

    /// Re-derive `fact` from `envelope` with the rule it names and require
    /// a bit-identical result.
    pub fn rederive(&self, fact: &Fact, envelope: &ObservationEnvelope) -> Result<()> {
        let rule = self.mapping(&fact.body.mapping_hash).ok_or_else(|| {
            GovError::Integrity(format!("fact {} names unknown mapping {}", fact.fact_hash.short(), fact.body.mapping_hash.short()))
        })?;
        verify_derivation(rule, fact, envelope)
    }
}

/// Check that `rule` applied to `envelope` produces exactly `fact`.
pub fn verify_derivation(rule: &MappingRule, fact: &Fact, envelope: &ObservationEnvelope) -> Result<()> {
    let h = rule.hash()?;
    if h != fact.body.mapping_hash {
        return Err(GovError::Integrity(format!("fact {} was not derived by mapping {}", fact.fact_hash.short(), h.short())));
    }
    match derive_fact(rule, h, envelope) {
        Ok(derived) if derived == *fact => Ok(()),
        Ok(_) => Err(GovError::Integrity(format!(
            "fact {} does not match re-derivation from observation {} by mapping '{}'",
            fact.fact_hash.short(),
            envelope.content_hash.short(),
            rule.id
        ))),
        Err(reason) => Err(GovError::Integrity(format!("fact {} cannot be re-derived: {reason}", fact.fact_hash.short()))),
    }
}

/// Apply one mapping rule to one observation. Pure and deterministic.
pub fn derive_fact(rule: &MappingRule, mapping_hash: Digest, envelope: &ObservationEnvelope) -> std::result::Result<Fact, String> {
    let body = &envelope.body;
    if rule.schema != body.schema {
        return Err(format!("mapping '{}' is for schema '{}', observation is '{}'", rule.id, rule.schema, body.schema));
    }
    let payload = &body.payload;
    let subject = payload
        .get(&rule.subject_field)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| format!("subject field '{}' missing or not a non-empty string", rule.subject_field))?;
    let raw = payload.get(&rule.value_field).ok_or_else(|| format!("value field '{}' missing", rule.value_field))?;

    let value = match &rule.mapping {
        ValueMapping::Bool => FactValue::Bool(raw.as_bool().ok_or("expected boolean")?),
        ValueMapping::Text => FactValue::Text(raw.as_str().ok_or("expected string")?.to_string()),
        ValueMapping::FixedPoint { scale } => {
            let n = raw.as_number().ok_or("expected number")?;
            FactValue::Int(parse_scaled(&n.to_string(), *scale).ok_or_else(|| format!("number {n} out of range"))?)
        }
    };

    for q in &rule.quality {
        match (q, &value) {
            (QualityRule::MinInt { min }, FactValue::Int(v)) if v < min => return Err(format!("{v} below minimum {min}")),
            (QualityRule::MaxInt { max }, FactValue::Int(v)) if v > max => return Err(format!("{v} above maximum {max}")),
            (QualityRule::NonEmptyText, FactValue::Text(s)) if s.trim().is_empty() => return Err("empty text".into()),
            (QualityRule::OneOf { values }, FactValue::Text(s)) if !values.contains(s) => return Err(format!("{s:?} not in allowed set")),
            _ => {}
        }
    }

    let confidence_bp = match &rule.confidence_field {
        None => 10_000,
        Some(field) => {
            let n = payload.get(field).and_then(Value::as_number).ok_or_else(|| format!("confidence field '{field}' missing"))?;
            let bp = parse_scaled(&n.to_string(), 4).ok_or("confidence out of range")?;
            if !(0..=10_000).contains(&bp) {
                return Err(format!("confidence {n} outside 0..1"));
            }
            bp as u32
        }
    };
    if confidence_bp < rule.min_confidence_bp {
        return Err(format!("confidence {confidence_bp}bp below required {}bp", rule.min_confidence_bp));
    }

    Fact::new(FactBody {
        tenant: body.tenant.clone(),
        subject: subject.to_string(),
        name: rule.fact_name.clone(),
        value,
        observed_at: body.observed_at,
        confidence_bp,
        observation_hash: envelope.content_hash,
        mapping_id: rule.id.clone(),
        mapping_hash,
    })
    .map_err(|e| e.to_string())
}

/// Parse a JSON decimal literal into `value * 10^scale` exactly, rounding
/// half-to-even. No floating point is involved, so results are identical on
/// every platform and compiler.
pub fn parse_scaled(literal: &str, scale: u32) -> Option<i64> {
    let (mantissa, exp) = match literal.find(['e', 'E']) {
        Some(i) => (&literal[..i], literal[i + 1..].parse::<i32>().ok()?),
        None => (literal, 0),
    };
    let (neg, mantissa) = match mantissa.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, mantissa),
    };
    let (int_part, frac_part) = mantissa.split_once('.').unwrap_or((mantissa, ""));
    if int_part.is_empty() && frac_part.is_empty() {
        return None;
    }
    let digits: String = format!("{int_part}{frac_part}");
    if !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    // value = digits * 10^(exp - frac_len); we want value * 10^scale.
    let shift = exp.checked_sub(frac_part.len() as i32)?.checked_add(scale as i32)?;
    let digits = digits.trim_start_matches('0');
    let digits = if digits.is_empty() { "0" } else { digits };

    let result: i128 = if shift >= 0 {
        let mut v: i128 = digits.parse().ok()?;
        for _ in 0..shift {
            v = v.checked_mul(10)?;
        }
        v
    } else {
        let cut = (-shift) as usize;
        let (keep, dropped) = if cut >= digits.len() {
            ("0".to_string(), format!("{}{}", "0".repeat(cut - digits.len()), digits))
        } else {
            (digits[..digits.len() - cut].to_string(), digits[digits.len() - cut..].to_string())
        };
        let mut v: i128 = keep.parse().ok()?;
        let first = dropped.as_bytes()[0] - b'0';
        let rest_nonzero = dropped.bytes().skip(1).any(|b| b != b'0');
        let round_up = first > 5 || (first == 5 && (rest_nonzero || v % 2 == 1));
        if round_up {
            v += 1;
        }
        v
    };
    let signed = if neg { -result } else { result };
    i64::try_from(signed).ok()
}

/// All facts a subject had as of an instant: the latest value of each name.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FactSnapshot {
    pub tenant: String,
    pub subject: String,
    pub as_of: u64,
    pub facts: BTreeMap<String, Fact>,
}

/// Deterministic fact store and registry.
#[derive(Debug, Default)]
pub struct FactStore {
    by_hash: BTreeMap<Digest, Fact>,
    /// (tenant, subject, name) -> [(observed_at, fact_hash)] kept sorted.
    index: BTreeMap<(String, String, String), Vec<(u64, Digest)>>,
}

impl FactStore {
    /// Idempotent insert. Returns true if the fact is new.
    pub fn insert(&mut self, fact: Fact) -> bool {
        if self.by_hash.contains_key(&fact.fact_hash) {
            return false;
        }
        let key = (fact.body.tenant.clone(), fact.body.subject.clone(), fact.body.name.clone());
        let series = self.index.entry(key).or_default();
        let entry = (fact.body.observed_at, fact.fact_hash);
        let pos = series.binary_search(&entry).unwrap_or_else(|p| p);
        series.insert(pos, entry);
        self.by_hash.insert(fact.fact_hash, fact);
        true
    }

    pub fn get(&self, hash: &Digest) -> Option<&Fact> {
        self.by_hash.get(hash)
    }

    pub fn contains(&self, hash: &Digest) -> bool {
        self.by_hash.contains_key(hash)
    }

    /// Verified insert, for the journal path.
    pub fn restore(&mut self, fact: Fact) -> Result<bool> {
        fact.verify()?;
        Ok(self.insert(fact))
    }

    pub fn len(&self) -> usize {
        self.by_hash.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_hash.is_empty()
    }

    /// Latest fact per name with `observed_at <= as_of`. Ties at the same
    /// millisecond are broken by the larger fact hash: arbitrary but total,
    /// and therefore reproducible.
    pub fn snapshot(&self, tenant: &str, subject: &str, as_of: u64) -> FactSnapshot {
        let lo = (tenant.to_string(), subject.to_string(), String::new());
        let facts = self
            .index
            .range(lo..)
            .take_while(|((t, s, _), _)| t == tenant && s == subject)
            .filter_map(|((_, _, name), series)| {
                let idx = series.partition_point(|(at, _)| *at <= as_of);
                (idx > 0).then(|| (name.clone(), self.by_hash[&series[idx - 1].1].clone()))
            })
            .collect();
        FactSnapshot { tenant: tenant.into(), subject: subject.into(), as_of, facts }
    }

    pub fn verify_integrity(&self) -> Result<()> {
        for (k, f) in &self.by_hash {
            f.verify()?;
            if *k != f.fact_hash {
                return Err(GovError::Integrity(format!("fact index key {} mismatch", k.short())));
            }
        }
        Ok(())
    }

    #[doc(hidden)]
    pub fn get_mut_unchecked(&mut self, hash: &Digest) -> Option<&mut Fact> {
        self.by_hash.get_mut(hash)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_decimal_scaling() {
        assert_eq!(parse_scaled("7.2", 3), Some(7200));
        assert_eq!(parse_scaled("-0.5", 0), Some(0), "half to even");
        assert_eq!(parse_scaled("1.5", 0), Some(2));
        assert_eq!(parse_scaled("2.5", 0), Some(2));
        assert_eq!(parse_scaled("2.5000001", 0), Some(3));
        assert_eq!(parse_scaled("0.9731", 4), Some(9731));
        assert_eq!(parse_scaled("1e-7", 4), Some(0));
        assert_eq!(parse_scaled("1.25E2", 1), Some(1250));
        assert_eq!(parse_scaled("42", 2), Some(4200));
        assert_eq!(parse_scaled("99999999999999999999", 0), None);
        assert_eq!(parse_scaled("abc", 0), None);
    }
}
