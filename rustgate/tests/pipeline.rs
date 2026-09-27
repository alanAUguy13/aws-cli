//! End-to-end tests of the governance pipeline against the ShelfCat scenario.

use rustgate::decision::DecisionRequest;
use rustgate::error::GovError;
use rustgate::fact::FactValue;
use rustgate::identity::ActorKind;
use rustgate::keys::LocalP256Signer;
use rustgate::observation::{ObservationBody, SourceRef};
use rustgate::policy::{CmpOp, Condition, Effect, RuleSource};
use rustgate::replay::ReplayVerdict;
use rustgate::scenario::*;
use serde_json::json;

const SHELF: &str = "cooler-3/shelf-2";

fn store_with_policy() -> ShelfCat {
    let mut s = ShelfCat::new();
    s.publish_policy(1, 5_000, T0 - 10 * MINUTE).expect("policy publishes");
    s
}

#[test]
fn full_pipeline_allow_escalate_deny() {
    let mut s = store_with_policy();

    let r = s.observe_temperature(SHELF, 3.9, T0).unwrap();
    assert_eq!(r.fact_hashes.len(), 1);
    let d1 = s.decide(SHELF, T0 + 30_000, "c1").unwrap();
    assert_eq!(d1.decision.body.effect, Effect::Allow);
    assert!(d1.dispatches.is_empty());

    s.observe_stock(SHELF, "SKU-MILK-2L", 0, 0.93, T0 + MINUTE).unwrap();
    let d2 = s.decide(SHELF, T0 + 90_000, "c2").unwrap();
    assert_eq!(d2.decision.body.effect, Effect::Escalate);
    assert_eq!(d2.decision.body.decisive_rule.as_deref(), Some("out-of-stock"));
    assert_eq!(d2.dispatches.len(), 1);
    assert!(d2.dispatches[0].result.as_ref().unwrap().external_ref.starts_with("TASK-"));

    s.observe_temperature(SHELF, 7.2, T0 + 2 * MINUTE).unwrap();
    let d3 = s.decide(SHELF, T0 + 150_000, "c3").unwrap();
    assert_eq!(d3.decision.body.effect, Effect::Deny, "{}", d3.decision.body.explanation);
    assert_eq!(d3.decision.body.decisive_rule.as_deref(), Some("cold-chain-breach"));
    assert_eq!(d3.decision.body.matched_rules, vec!["cold-chain-breach", "out-of-stock"]);
    assert_eq!(d3.dispatches.len(), 2);
    assert!(d3.dispatches[0].request.params["reason"].contains(&d3.decision.decision_hash.to_hex()));

    let report = s.gate.verify_integrity().unwrap();
    assert_eq!(report.decisions, 3);
    assert_eq!(report.evidence_records, 3);
}

#[test]
fn decisions_are_deterministic_across_independent_instances() {
    let run = || {
        let mut s = store_with_policy();
        s.observe_temperature(SHELF, 7.2, T0).unwrap();
        s.observe_stock(SHELF, "SKU-MILK-2L", 3, 0.99, T0 + 1).unwrap();
        let d = s.decide(SHELF, T0 + 5_000, "c").unwrap();
        (d.decision.decision_hash, d.evidence.evidence_hash, d.evidence.signature.signature, s.gate.audit.head(), s.gate.events.head())
    };
    assert_eq!(run(), run());
}

#[test]
fn repeated_request_is_idempotent() {
    let mut s = store_with_policy();
    s.observe_temperature(SHELF, 9.0, T0).unwrap();
    let a = s.decide(SHELF, T0 + 1_000, "first").unwrap();
    let b = s.decide(SHELF, T0 + 1_000, "retry").unwrap();
    assert_eq!(a.decision.decision_hash, b.decision.decision_hash);
    assert_eq!(a.evidence, b.evidence);
    assert_eq!(s.gate.evidence.len(), 1);
    assert!(b.dispatches.iter().all(|d| d.deduplicated), "no duplicate tickets on retry");
}

#[test]
fn temporal_staleness_escalates() {
    let mut s = store_with_policy();
    s.observe_temperature(SHELF, 3.0, T0).unwrap();
    let fresh = s.decide(SHELF, T0 + 14 * MINUTE, "a").unwrap();
    assert_eq!(fresh.decision.body.effect, Effect::Allow);
    let stale = s.decide(SHELF, T0 + 16 * MINUTE, "b").unwrap();
    assert_eq!(stale.decision.body.effect, Effect::Escalate);
    assert_eq!(stale.decision.body.decisive_rule.as_deref(), Some("telemetry-stale"));
    // Unknown shelf: no telemetry at all is also stale, not "allow".
    let unknown = s.decide("cooler-9/shelf-1", T0, "c").unwrap();
    assert_eq!(unknown.decision.body.effect, Effect::Escalate);
}

#[test]
fn decisions_about_the_future_are_rejected() {
    let mut s = store_with_policy();
    let req = DecisionRequest {
        tenant: TENANT.into(),
        subject: SHELF.into(),
        policy_id: POLICY_ID.into(),
        as_of: T0 + 10,
        correlation_id: "f".into(),
    };
    assert!(s.gate.decide(OPS_TOKEN, &req, T0).is_err());
}

#[test]
fn replay_matches_and_detects_policy_and_fact_drift() {
    let mut s = store_with_policy();
    s.observe_temperature(SHELF, 4.5, T0).unwrap();
    let d = s.decide(SHELF, T0 + 1_000, "c").unwrap();
    assert_eq!(d.decision.body.effect, Effect::Allow);
    let h = d.decision.decision_hash;

    let r = s.gate.replay(AUDITOR_TOKEN, TENANT, &h, T0 + 2_000).unwrap();
    assert_eq!(r.verdict, ReplayVerdict::Match);
    assert_eq!(r.evidence_verified, Ok(()));
    let rd = r.re_decision.unwrap();
    assert!(!rd.policy_changed && !rd.facts_changed && !rd.outcome_changed);

    // Tighten the threshold to 4.0 C: replay still matches (the historical
    // policy is used), but re-decision flags the outcome would change.
    s.publish_policy(2, 4_000, T0 + 3_000).unwrap();
    let r = s.gate.replay(AUDITOR_TOKEN, TENANT, &h, T0 + 10_000).unwrap();
    assert_eq!(r.verdict, ReplayVerdict::Match);
    let rd = r.re_decision.unwrap();
    assert!(rd.policy_changed && rd.outcome_changed && !rd.facts_changed);
    assert_eq!(rd.effect, Effect::Deny);

    // A late-arriving reading observed before as_of is fact drift.
    s.observe_temperature(SHELF, 4.2, T0 + 500).unwrap();
    let r = s.gate.replay(AUDITOR_TOKEN, TENANT, &h, T0 + 20_000).unwrap();
    assert_eq!(r.verdict, ReplayVerdict::Match);
    assert!(r.re_decision.unwrap().facts_changed);
}

#[test]
fn tampering_is_detected_everywhere() {
    let build = || {
        let mut s = store_with_policy();
        s.observe_temperature(SHELF, 7.2, T0).unwrap();
        let d = s.decide(SHELF, T0 + 1_000, "c").unwrap();
        (s, d.decision.decision_hash, d.decision.body.fact_hashes.values().next().copied().unwrap())
    };

    // Decision record edited: integrity check fails, replay reports drift.
    let (mut s, h, _) = build();
    s.gate.decisions.get_mut_unchecked(&h).unwrap().body.effect = Effect::Allow;
    assert!(s.gate.verify_integrity().is_err());
    let r = s.gate.replay(AUDITOR_TOKEN, TENANT, &h, T0 + 5_000).unwrap();
    assert!(matches!(r.verdict, ReplayVerdict::Drift { .. }), "{:?}", r.verdict);

    // Fact edited: integrity fails and replay cannot verify.
    let (mut s, h, fh) = build();
    s.gate.facts.get_mut_unchecked(&fh).unwrap().body.value = FactValue::Int(1_000);
    assert!(s.gate.verify_integrity().is_err());
    let r = s.gate.replay(AUDITOR_TOKEN, TENANT, &h, T0 + 5_000).unwrap();
    assert!(matches!(r.verdict, ReplayVerdict::Unverifiable { .. }));

    // Observation payload edited.
    let (mut s, _, fh) = build();
    let oh = s.gate.facts.get(&fh).unwrap().body.observation_hash;
    s.gate.observations.get_mut_unchecked(&oh).unwrap().envelope.body.payload["temperature_c"] = json!(2.0);
    assert!(s.gate.verify_integrity().is_err());

    // Compiled policy binary edited.
    let (mut s, h, _) = build();
    let ph = s.gate.decisions.get(&h).unwrap().body.policy_hash;
    s.gate.policies.get_mut_unchecked(&ph).unwrap().program.rules[1].priority = 1;
    assert!(s.gate.verify_integrity().is_err());
    let r = s.gate.replay(AUDITOR_TOKEN, TENANT, &h, T0 + 5_000).unwrap();
    assert!(matches!(r.verdict, ReplayVerdict::Unverifiable { .. }));

    // Evidence edited.
    let (mut s, _, _) = build();
    s.gate.evidence.get_mut_unchecked(0).unwrap().body.sealed_at += 1;
    assert!(s.gate.verify_integrity().is_err());

    // Ledger entry edited.
    let (mut s, _, _) = build();
    s.gate.audit.get_mut_unchecked(0).unwrap().at += 1;
    assert!(s.gate.verify_integrity().is_err());
}

#[test]
fn offline_bundle_verification() {
    let mut s = store_with_policy();
    s.observe_temperature(SHELF, 7.2, T0).unwrap();
    s.observe_stock(SHELF, "SKU-MILK-2L", 0, 0.95, T0 + 10).unwrap();
    let d = s.decide(SHELF, T0 + 1_000, "c").unwrap();
    let bundle = s.gate.export_bundle(&d.decision.decision_hash).unwrap();

    // Round-trip through JSON: the auditor only has the file and public keys.
    let json = serde_json::to_string(&bundle).unwrap();
    let back: rustgate::evidence::EvidenceBundle = serde_json::from_str(&json).unwrap();
    back.verify(&s.gate.trust).expect("bundle verifies offline");
    assert_eq!(back.facts.len(), 2);
    assert_eq!(back.observations.len(), 2);

    let mut forged = back.clone();
    forged.decision.body.effect = Effect::Allow;
    assert!(forged.verify(&s.gate.trust).is_err());

    let mut forged = back.clone();
    forged.facts[0].body.value = FactValue::Int(1_000);
    forged.facts[0].fact_hash = rustgate::fact::Fact::new(forged.facts[0].body.clone()).unwrap().fact_hash;
    assert!(forged.verify(&s.gate.trust).is_err(), "re-hashing a forged fact still breaks the chain");
}

#[test]
fn identity_authorization_and_edge() {
    let mut s = store_with_policy();
    let body = |source: &str, kind: ActorKind, schema: &str, payload: serde_json::Value| ObservationBody {
        tenant: TENANT.into(),
        source: SourceRef { kind, id: source.into() },
        schema: schema.into(),
        observed_at: T0,
        payload,
    };
    let temp = json!({"shelf_id": SHELF, "temperature_c": 4.0});

    // Bad token.
    let env = body(SENSOR, ActorKind::Sensor, "cooler.temperature/v1", temp.clone()).seal(&s.sensor_key).unwrap();
    assert!(matches!(s.gate.ingest("nope", "n1", env.clone(), T0), Err(GovError::Unauthenticated(_))));
    // Camera role may not submit temperature (ABAC schema restriction).
    assert!(matches!(s.gate.ingest(CAMERA_TOKEN, "n2", env.clone(), T0), Err(GovError::Forbidden { .. })));
    // Decider can't submit observations at all.
    assert!(matches!(s.gate.ingest(OPS_TOKEN, "n3", env.clone(), T0), Err(GovError::Forbidden { .. })));
    // Nonce replay at the edge.
    s.gate.ingest(SENSOR_TOKEN, "n4", env.clone(), T0).unwrap();
    assert!(matches!(s.gate.ingest(SENSOR_TOKEN, "n4", env.clone(), T0), Err(GovError::EdgeRejected(_))));
    // Identical observation with a fresh nonce is an idempotent duplicate.
    assert!(s.gate.ingest(SENSOR_TOKEN, "n5", env, T0).unwrap().duplicate);

    // Signed with someone else's key.
    let env = body(SENSOR, ActorKind::Sensor, "cooler.temperature/v1", temp.clone()).seal(&s.camera_key).unwrap();
    assert!(matches!(s.gate.ingest(SENSOR_TOKEN, "n6", env, T0), Err(GovError::SignatureRejected(_))));
    // Unregistered key.
    let rogue = LocalP256Signer::from_seed("rogue", "rogue");
    let env = body(SENSOR, ActorKind::Sensor, "cooler.temperature/v1", temp.clone()).seal(&rogue).unwrap();
    assert!(matches!(s.gate.ingest(SENSOR_TOKEN, "n7", env, T0), Err(GovError::UnknownKey(_))));
    // Payload changed after signing.
    let mut env = body(SENSOR, ActorKind::Sensor, "cooler.temperature/v1", temp.clone()).seal(&s.sensor_key).unwrap();
    env.body.payload["temperature_c"] = json!(2.0);
    assert!(matches!(s.gate.ingest(SENSOR_TOKEN, "n8", env, T0), Err(GovError::HashMismatch { .. })));
    // Schema violations.
    let env = body(SENSOR, ActorKind::Sensor, "cooler.temperature/v1", json!({"shelf_id": SHELF})).seal(&s.sensor_key).unwrap();
    assert!(matches!(s.gate.ingest(SENSOR_TOKEN, "n9", env, T0), Err(GovError::SchemaViolation { .. })));
    let env = body(SENSOR, ActorKind::Sensor, "cooler.temperature/v1", json!({"shelf_id": SHELF, "temperature_c": 1, "x": 1}))
        .seal(&s.sensor_key)
        .unwrap();
    assert!(matches!(s.gate.ingest(SENSOR_TOKEN, "n10", env, T0), Err(GovError::SchemaViolation { .. })));
    // Far-future timestamp.
    let mut b = body(SENSOR, ActorKind::Sensor, "cooler.temperature/v1", temp);
    b.observed_at = T0 + MINUTE;
    let env = b.seal(&s.sensor_key).unwrap();
    assert!(matches!(s.gate.ingest(SENSOR_TOKEN, "n11", env, T0), Err(GovError::FutureObservation { .. })));

    // Every rejection is on the audit ledger.
    let denials =
        s.gate.audit.entries().iter().filter(|e| matches!(&e.event, rustgate::ledger::AuditEvent::Security { allowed: false, .. })).count();
    assert_eq!(denials, 10);
    s.gate.verify_integrity().unwrap();
}

#[test]
fn quality_rules_reject_low_confidence_and_out_of_range() {
    let mut s = store_with_policy();
    let r = s.observe_stock(SHELF, "SKU-1", 0, 0.42, T0).unwrap();
    assert!(r.fact_hashes.is_empty());
    assert_eq!(r.rejections.len(), 2);
    let r = s.observe_temperature(SHELF, 75.0, T0 + 1).unwrap();
    assert!(r.fact_hashes.is_empty() && r.rejections[0].reason.contains("above maximum"));
}

#[test]
fn policy_governance() {
    let mut s = ShelfCat::new();
    s.gate.submit_policy(ShelfCat::policy(1, 5_000), &s.alice, T0).unwrap();
    // Not approved yet.
    assert!(matches!(
        s.gate.compile_and_activate(RELEASE_TOKEN, POLICY_ID, 1, T0),
        Err(GovError::PolicyNotApproved { have: 0, need: 2, .. })
    ));
    // Author can't approve own policy, even with an approver key.
    let alice_approver = LocalP256Signer::from_seed("alice/approver", "alice-approver");
    assert!(matches!(s.gate.approve_policy(POLICY_ID, 1, &alice_approver, T0), Err(GovError::SeparationOfDuties(_))));
    // Author key can't be used as an approver key.
    assert!(matches!(s.gate.approve_policy(POLICY_ID, 1, &s.alice, T0), Err(GovError::SignatureRejected(_))));
    s.gate.approve_policy(POLICY_ID, 1, &s.bob, T0 + 1).unwrap();
    assert!(matches!(s.gate.approve_policy(POLICY_ID, 1, &s.bob, T0 + 2), Err(GovError::SeparationOfDuties(_))));
    assert!(s.gate.compile_and_activate(RELEASE_TOKEN, POLICY_ID, 1, T0).is_err());
    s.gate.approve_policy(POLICY_ID, 1, &s.carol, T0 + 3).unwrap();
    // Activation needs an authenticated principal holding ActivatePolicy.
    assert!(matches!(s.gate.compile_and_activate(OPS_TOKEN, POLICY_ID, 1, T0 + 4), Err(GovError::Forbidden { .. })));
    assert!(matches!(s.gate.compile_and_activate("forged", POLICY_ID, 1, T0 + 4), Err(GovError::Unauthenticated(_))));
    assert!(s.gate.policies.active(TENANT, POLICY_ID).is_err(), "nothing activated by refused callers");
    let compiled = s.gate.compile_and_activate(RELEASE_TOKEN, POLICY_ID, 1, T0 + 4).unwrap();
    let activation = s.gate.audit.entries().iter().rev().find_map(|e| match &e.event {
        rustgate::ledger::AuditEvent::Policy { actor, policy_hash: Some(h), .. } if *h == compiled.policy_hash => Some(actor.clone()),
        _ => None,
    });
    assert_eq!(activation.as_deref(), Some("release-pipeline"), "audit names the authenticated principal");
    // Versions are monotonic and immutable.
    assert!(matches!(s.gate.submit_policy(ShelfCat::policy(1, 1), &s.alice, T0), Err(GovError::PolicyVersionExists { .. })));
}

#[test]
fn compiler_semantic_and_conflict_checks() {
    let mut s = ShelfCat::new();
    let mut src = ShelfCat::policy(1, 5_000);
    src.rules.push(RuleSource {
        id: "bad-fact".into(),
        priority: 50,
        when: Condition::Compare { fact: "cooler.humidity".into(), cmp: CmpOp::Gt, value: FactValue::Int(1) },
        effect: Effect::Deny,
        actions: vec![],
        explain: "x".into(),
    });
    src.rules.push(RuleSource {
        id: "bad-type".into(),
        priority: 40,
        when: Condition::Compare { fact: "shelf.sku".into(), cmp: CmpOp::Gt, value: FactValue::Text("a".into()) },
        effect: Effect::Deny,
        actions: vec![],
        explain: "x".into(),
    });
    src.rules.push(RuleSource {
        id: "conflicting".into(),
        priority: 100,
        when: Condition::Always,
        effect: Effect::Deny,
        actions: vec![],
        explain: "x".into(),
    });
    s.gate.submit_policy(src, &s.alice, T0).unwrap();
    s.gate.approve_policy(POLICY_ID, 1, &s.bob, T0).unwrap();
    s.gate.approve_policy(POLICY_ID, 1, &s.carol, T0).unwrap();
    match s.gate.compile_and_activate(RELEASE_TOKEN, POLICY_ID, 1, T0) {
        Err(GovError::Compilation(errs)) => {
            let all = errs.join("\n");
            assert!(all.contains("unknown fact 'cooler.humidity'"), "{all}");
            assert!(all.contains("ordering comparison on non-integer fact 'shelf.sku'"), "{all}");
            assert!(all.contains("conflict: rules 'out-of-stock'"), "{all}");
        }
        other => panic!("expected compilation errors, got {other:?}"),
    }
}

#[test]
fn action_authorization_blocks_ungranted_operations() {
    let mut s = ShelfCat::new();
    let mut src = ShelfCat::policy(1, 5_000);
    src.rules[1].actions.push(rustgate::policy::ActionTemplate {
        connector: "sap".into(),
        operation: "write_off_inventory".into(),
        params: Default::default(),
    });
    s.gate.submit_policy(src, &s.alice, T0).unwrap();
    s.gate.approve_policy(POLICY_ID, 1, &s.bob, T0).unwrap();
    s.gate.approve_policy(POLICY_ID, 1, &s.carol, T0).unwrap();
    s.gate.compile_and_activate(RELEASE_TOKEN, POLICY_ID, 1, T0).unwrap();
    s.observe_temperature(SHELF, 9.0, T0).unwrap();
    let d = s.decide(SHELF, T0 + 1_000, "c").unwrap();
    assert_eq!(d.decision.body.effect, Effect::Deny, "decision and evidence still stand");
    assert!(d.dispatches.is_empty(), "no partial enforcement");
    assert!(d.actions_refused.unwrap().contains("sap:write_off_inventory"));
}

#[test]
fn cross_tenant_replay_is_forbidden() {
    let mut s = store_with_policy();
    s.observe_temperature(SHELF, 3.0, T0).unwrap();
    let d = s.decide(SHELF, T0 + 1_000, "c").unwrap();
    assert!(matches!(s.gate.replay(AUDITOR_TOKEN, "other-tenant", &d.decision.decision_hash, T0 + 2_000), Err(GovError::Forbidden { .. })));
}

#[test]
fn re_decision_separates_policy_drift_from_fact_drift_and_sees_action_changes() {
    let mut s = store_with_policy();
    s.observe_temperature(SHELF, 7.2, T0).unwrap();
    s.observe_stock(SHELF, "SKU-MILK-2L", 4, 0.99, T0 + 10).unwrap();
    let d = s.decide(SHELF, T0 + 1_000, "c").unwrap();
    assert_eq!(d.decision.body.effect, Effect::Deny);
    assert_eq!(d.decision.body.fact_hashes.len(), 2);

    // v2: still denies the breach, but no longer places a POS hold, and no
    // longer reads shelf facings at all. No new facts arrive.
    let mut v2 = ShelfCat::policy(2, 5_000);
    v2.rules.retain(|r| r.id != "out-of-stock");
    v2.rules[1].actions.retain(|a| a.connector != "pos");
    s.gate.submit_policy(v2, &s.alice, T0 + 2_000).unwrap();
    s.gate.approve_policy(POLICY_ID, 2, &s.bob, T0 + 2_001).unwrap();
    s.gate.approve_policy(POLICY_ID, 2, &s.carol, T0 + 2_002).unwrap();
    s.gate.compile_and_activate(RELEASE_TOKEN, POLICY_ID, 2, T0 + 2_003).unwrap();

    let r = s.gate.replay(AUDITOR_TOKEN, TENANT, &d.decision.decision_hash, T0 + 3_000).unwrap();
    assert_eq!(r.verdict, ReplayVerdict::Match);
    let rd = r.re_decision.unwrap();
    assert!(rd.policy_changed);
    assert!(!rd.facts_changed, "dropping a fact reference is policy drift, not fact drift");
    assert!(!rd.effect_changed);
    assert!(rd.actions_changed && rd.outcome_changed, "same effect, different enforcement");
    assert_eq!(rd.decisive_rule.as_deref(), Some("cold-chain-breach"));
}
