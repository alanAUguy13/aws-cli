//! Deterministic runtime engine.
//!
//! A pure function: `(PolicyProgram, FactSnapshot) -> Evaluation`. No clock,
//! no randomness, no I/O, no hash-map iteration, no floating point. Time
//! enters only as the snapshot's `as_of`. Every rule is evaluated in full
//! (no short-circuiting) so the execution trace is complete even for rules
//! that did not decide the outcome.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::canonical::Digest;
use crate::error::{GovError, Result};
use crate::fact::{Fact, FactSnapshot, FactValue};
use crate::policy::{ActionTemplate, CmpOp, Effect, Op, PolicyProgram};

/// Bumped whenever evaluation semantics change. A decision records the
/// engine version; replay under a different version reports the mismatch
/// instead of silently comparing apples to oranges.
pub const ENGINE_VERSION: &str = "rustgate-engine/1.0.0";
/// Program format the engine executes.
pub const ENGINE_ABI: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpTrace {
    pub op: String,
    pub result: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleTrace {
    pub rule_id: String,
    pub priority: u32,
    pub effect: Effect,
    pub matched: bool,
    pub steps: Vec<OpTrace>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Evaluation {
    pub effect: Effect,
    /// Rule that decided the outcome; `None` means the default applied.
    pub decisive_rule: Option<String>,
    pub matched_rules: Vec<String>,
    pub actions: Vec<ActionTemplate>,
    pub explanation: String,
    /// Facts the program referenced that were present, by name.
    pub used_facts: BTreeMap<String, Digest>,
    pub trace: Vec<RuleTrace>,
}

/// Static check that every rule's code is well-formed: indices in range and
/// the stack ends with exactly one boolean.
pub fn check_program(p: &PolicyProgram) -> Result<()> {
    if p.engine_abi != ENGINE_ABI {
        return Err(GovError::InvalidProgram(format!("program ABI {} != engine ABI {ENGINE_ABI}", p.engine_abi)));
    }
    for r in &p.rules {
        let mut depth: usize = 0;
        for op in &r.code {
            let fact_ok = |f: u16| (f as usize) < p.fact_table.len();
            let (pops, ok) = match op {
                Op::True => (0, true),
                Op::Cmp { fact, konst, .. } => (0, fact_ok(*fact) && (*konst as usize) < p.constants.len()),
                Op::Exists { fact } | Op::Fresh { fact, .. } | Op::Older { fact, .. } | Op::Conf { fact, .. } => (0, fact_ok(*fact)),
                Op::Not => (1, true),
                Op::And { n } | Op::Or { n } => (*n as usize, *n > 0),
            };
            if !ok || depth < pops {
                return Err(GovError::InvalidProgram(format!("rule '{}': malformed op {op:?}", r.id)));
            }
            depth = depth - pops + 1;
        }
        if depth != 1 {
            return Err(GovError::InvalidProgram(format!("rule '{}': stack depth {depth} at end", r.id)));
        }
    }
    Ok(())
}

fn compare(cmp: CmpOp, a: &FactValue, b: &FactValue) -> bool {
    match (cmp, a, b) {
        (CmpOp::Eq, _, _) => a == b,
        (CmpOp::Ne, _, _) => a != b,
        (_, FactValue::Int(x), FactValue::Int(y)) => match cmp {
            CmpOp::Lt => x < y,
            CmpOp::Le => x <= y,
            CmpOp::Gt => x > y,
            CmpOp::Ge => x >= y,
            CmpOp::Eq | CmpOp::Ne => unreachable!(),
        },
        _ => false,
    }
}

fn cmp_symbol(c: CmpOp) -> &'static str {
    match c {
        CmpOp::Eq => "==",
        CmpOp::Ne => "!=",
        CmpOp::Lt => "<",
        CmpOp::Le => "<=",
        CmpOp::Gt => ">",
        CmpOp::Ge => ">=",
    }
}

/// Evaluate `program` against `snapshot`.
pub fn evaluate(program: &PolicyProgram, snapshot: &FactSnapshot) -> Result<Evaluation> {
    check_program(program)?;
    if program.tenant != snapshot.tenant {
        return Err(GovError::InvalidProgram(format!(
            "policy tenant '{}' does not match snapshot tenant '{}'",
            program.tenant, snapshot.tenant
        )));
    }
    let as_of = snapshot.as_of;
    let resolved: Vec<Option<&Fact>> = program.fact_table.iter().map(|n| snapshot.facts.get(n)).collect();
    let used_facts: BTreeMap<String, Digest> = resolved.iter().flatten().map(|f| (f.body.name.clone(), f.fact_hash)).collect();

    let mut trace = Vec::with_capacity(program.rules.len());
    let mut matched_rules = Vec::new();
    let mut decisive: Option<usize> = None;

    for (idx, rule) in program.rules.iter().enumerate() {
        let mut stack: Vec<bool> = Vec::new();
        let mut steps = Vec::with_capacity(rule.code.len());
        for op in &rule.code {
            let name = |f: u16| program.fact_table[f as usize].as_str();
            let fact = |f: u16| resolved[f as usize];
            let age = |f: &Fact| as_of.saturating_sub(f.body.observed_at);
            let (desc, result) = match op {
                Op::True => ("always".to_string(), true),
                Op::Cmp { fact: f, cmp, konst } => {
                    let k = &program.constants[*konst as usize];
                    match fact(*f) {
                        Some(x) => (format!("{} ({}) {} {k}", name(*f), x.body.value, cmp_symbol(*cmp)), compare(*cmp, &x.body.value, k)),
                        None => (format!("{} (missing) {} {k}", name(*f), cmp_symbol(*cmp)), false),
                    }
                }
                Op::Exists { fact: f } => (format!("exists({})", name(*f)), fact(*f).is_some()),
                Op::Fresh { fact: f, max_age_ms } => match fact(*f) {
                    Some(x) => (format!("age({}) = {}ms <= {max_age_ms}ms", name(*f), age(x)), age(x) <= *max_age_ms),
                    None => (format!("age({}) (missing) <= {max_age_ms}ms", name(*f)), false),
                },
                Op::Older { fact: f, min_age_ms } => match fact(*f) {
                    Some(x) => (format!("age({}) = {}ms > {min_age_ms}ms", name(*f), age(x)), age(x) > *min_age_ms),
                    None => (format!("age({}) (missing) > {min_age_ms}ms", name(*f)), false),
                },
                Op::Conf { fact: f, min_bp } => match fact(*f) {
                    Some(x) => {
                        (format!("confidence({}) = {}bp >= {min_bp}bp", name(*f), x.body.confidence_bp), x.body.confidence_bp >= *min_bp)
                    }
                    None => (format!("confidence({}) (missing) >= {min_bp}bp", name(*f)), false),
                },
                Op::Not => {
                    let v = stack.pop().expect("checked");
                    ("not".to_string(), !v)
                }
                Op::And { n } | Op::Or { n } => {
                    let args = stack.split_off(stack.len() - *n as usize);
                    if matches!(op, Op::And { .. }) {
                        (format!("all({n})"), args.iter().all(|b| *b))
                    } else {
                        (format!("any({n})"), args.iter().any(|b| *b))
                    }
                }
            };
            stack.push(result);
            steps.push(OpTrace { op: desc, result });
        }
        let matched = stack.pop().expect("checked");
        if matched {
            matched_rules.push(rule.id.clone());
            decisive.get_or_insert(idx);
        }
        trace.push(RuleTrace { rule_id: rule.id.clone(), priority: rule.priority, effect: rule.effect, matched, steps });
    }

    let (effect, decisive_rule, actions, explanation) = match decisive {
        Some(i) => {
            let r = &program.rules[i];
            let why = trace[i]
                .steps
                .iter()
                .filter(|s| s.result && !s.op.starts_with("all(") && !s.op.starts_with("any("))
                .map(|s| s.op.as_str())
                .collect::<Vec<_>>()
                .join("; ");
            (
                r.effect,
                Some(r.id.clone()),
                r.actions.clone(),
                format!(
                    "{:?} for subject '{}' by rule '{}' (priority {}) of policy {}@{}: {} [evidence: {}]",
                    r.effect, snapshot.subject, r.id, r.priority, program.policy_id, program.version, r.explain, why
                ),
            )
        }
        None => (
            program.default_effect,
            None,
            Vec::new(),
            format!(
                "{:?} for subject '{}': no rule of policy {}@{} matched; default effect applied",
                program.default_effect, snapshot.subject, program.policy_id, program.version
            ),
        ),
    };

    Ok(Evaluation { effect, decisive_rule, matched_rules, actions, explanation, used_facts, trace })
}
