//! Walk the full RustGate pipeline on the ShelfCat reference scenario.
//!
//!     cargo run --bin rustgate-demo [-- --bundle out.json]

use rustgate::policy::Effect;
use rustgate::scenario::*;

const SHELF: &str = "cooler-3/shelf-2";

fn step(title: &str) {
    println!("\n== {title}");
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let bundle_path = std::env::args().skip_while(|a| a != "--bundle").nth(1);
    let mut s = ShelfCat::new();

    step("Governed policy: author -> dual approval -> compile -> activate");
    let v1 = s.publish_policy(1, 5_000, T0 - 10 * MINUTE)?;
    println!("policy {POLICY_ID}@1  hash {}  approvers {:?}", v1.policy_hash.short(), v1.approvers);

    step("Observations: authn -> authz -> edge -> gateway -> store -> facts");
    let obs = [
        s.observe_temperature(SHELF, 3.9, T0)?,
        s.observe_stock(SHELF, "SKU-MILK-2L", 0, 0.93, T0 + MINUTE)?,
        s.observe_temperature(SHELF, 7.2, T0 + 2 * MINUTE)?,
    ];
    for r in &obs {
        println!("observation {} -> {} fact(s)", r.observation_hash.short(), r.fact_hashes.len());
    }

    step("Decisions: deterministic engine -> decision service -> evidence -> action authz -> enforcement");
    let mut decisions = Vec::new();
    for (i, as_of) in [T0 + 30_000, T0 + 90_000, T0 + 150_000].into_iter().enumerate() {
        let d = s.decide(SHELF, as_of, &format!("shift-7/check-{i}"))?;
        println!(
            "\n{:?}  decision {}  evidence {}",
            d.decision.body.effect,
            d.decision.decision_hash.short(),
            d.evidence.evidence_hash.short()
        );
        println!("  {}", d.decision.body.explanation);
        for x in &d.dispatches {
            match &x.result {
                Ok(r) => println!("  -> {}:{} => {}", x.request.connector, x.request.operation, r.external_ref),
                Err(e) => println!("  -> {}:{} FAILED {e}", x.request.connector, x.request.operation),
            }
        }
        decisions.push(d);
    }
    let breach = decisions.last().unwrap();
    assert_eq!(breach.decision.body.effect, Effect::Deny);

    step("Trust chain for the cold-chain denial");
    for p in &breach.evidence.body.provenance {
        println!(
            "observation {} ({} {}) -> fact {} [{}]",
            p.observation_hash.short(),
            p.source.id,
            p.schema,
            p.fact_hash.short(),
            p.fact_name
        );
    }
    println!(
        "-> policy {} -> decision {} -> evidence {} -> {} sig by {}",
        breach.evidence.body.policy_hash.short(),
        breach.decision.decision_hash.short(),
        breach.evidence.evidence_hash.short(),
        breach.evidence.signature.algorithm,
        breach.evidence.signature.key_id
    );

    step("Replay & verification");
    let first = decisions[0].decision.decision_hash;
    let r = s.gate.replay(AUDITOR_TOKEN, TENANT, &breach.decision.decision_hash, T0 + 3 * MINUTE)?;
    println!("replay of denial: {:?}, evidence verified: {:?}", r.verdict, r.evidence_verified);

    let v2 = s.publish_policy(2, 3_500, T0 + 4 * MINUTE)?;
    println!("activated {POLICY_ID}@2 (threshold 3.5 C)  hash {}", v2.policy_hash.short());
    let r = s.gate.replay(AUDITOR_TOKEN, TENANT, &first, T0 + 5 * MINUTE)?;
    println!("replay of first decision under its original policy: {:?}", r.verdict);
    println!("re-decision with today's policy: {:?}", r.re_decision);

    step("Offline evidence bundle");
    let bundle = s.gate.export_bundle(&breach.decision.decision_hash)?;
    bundle.verify(&s.gate.trust)?;
    println!("bundle verified offline: {} observation(s), {} fact(s)", bundle.observations.len(), bundle.facts.len());
    if let Some(path) = bundle_path {
        std::fs::write(&path, serde_json::to_string_pretty(&bundle)?)?;
        println!("written to {path}");
    }

    step("Integrity");
    let report = s.gate.verify_integrity()?;
    println!("{}", serde_json::to_string_pretty(&report)?);

    step("Tamper: rewrite the denial as an allow");
    s.gate.decisions.get_mut_unchecked(&breach.decision.decision_hash).unwrap().body.effect = Effect::Allow;
    println!("integrity check: {}", s.gate.verify_integrity().err().map(|e| e.to_string()).unwrap_or_else(|| "passed?!".into()));
    let r = s.gate.replay(AUDITOR_TOKEN, TENANT, &breach.decision.decision_hash, T0 + 6 * MINUTE)?;
    println!("replay: {:?}", r.verdict);
    Ok(())
}
