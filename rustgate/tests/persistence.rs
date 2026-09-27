//! Durability: restart from a journal, tamper detection on the journal
//! itself, mapping versioning, and bundle re-derivation of facts.

use std::path::PathBuf;

use rustgate::error::GovError;
use rustgate::fact::{MappingRule, QualityRule, ValueMapping};
use rustgate::policy::Effect;
use rustgate::replay::ReplayVerdict;
use rustgate::scenario::*;
use rustgate::storage::FileJournal;

const SHELF: &str = "cooler-3/shelf-2";

fn tmp(name: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!("rustgate-it-{}-{name}.jsonl", std::process::id()));
    let _ = std::fs::remove_file(&p);
    p
}

fn open(path: &PathBuf) -> rustgate::Result<ShelfCat> {
    ShelfCat::with_journal(Box::new(FileJournal::open(path, true)?))
}

/// Run a workload that touches every record kind.
fn workload(s: &mut ShelfCat) -> rustgate::Digest {
    s.publish_policy(1, 5_000, T0 - 10 * MINUTE).unwrap();
    s.observe_temperature(SHELF, 7.2, T0).unwrap();
    s.observe_stock(SHELF, "SKU-MILK-2L", 0, 0.95, T0 + 10).unwrap();
    let d = s.decide(SHELF, T0 + 1_000, "c1").unwrap();
    assert_eq!(d.decision.body.effect, Effect::Deny);
    assert_eq!(d.dispatches.len(), 2);
    s.gate.replay(AUDITOR_TOKEN, TENANT, &d.decision.decision_hash, T0 + 2_000).unwrap();
    d.decision.decision_hash
}

#[test]
fn restart_restores_every_store_exactly() {
    let path = tmp("restart");
    let (before, head, h) = {
        let mut s = open(&path).unwrap();
        let h = workload(&mut s);
        (serde_json::to_value(s.gate.verify_integrity().unwrap()).unwrap(), s.gate.journal_head(), h)
    };

    let mut s = open(&path).unwrap();
    assert_eq!(s.gate.journal_head(), head, "re-applying configuration journals nothing");
    assert_eq!(serde_json::to_value(s.gate.verify_integrity().unwrap()).unwrap(), before);
    s.gate.verify_journal().unwrap();

    // Replay works on recovered state.
    let r = s.gate.replay(AUDITOR_TOKEN, TENANT, &h, T0 + 3_000).unwrap();
    assert_eq!(r.verdict, ReplayVerdict::Match);
    assert_eq!(r.evidence_verified, Ok(()));

    // Repeating the decision after restart must not re-execute actions.
    let again = s.decide(SHELF, T0 + 1_000, "c1-retry").unwrap();
    assert_eq!(again.decision.decision_hash, h);
    assert!(again.dispatches.iter().all(|d| d.deduplicated), "enforcement receipts survived the restart");

    // New work after restart persists too.
    s.observe_temperature(SHELF, 3.0, T0 + MINUTE).unwrap();
    let d2 = s.decide(SHELF, T0 + MINUTE + 1_000, "c2").unwrap();
    let head2 = s.gate.journal_head();
    drop(s);
    let s = open(&path).unwrap();
    assert_eq!(s.gate.journal_head(), head2);
    // Cooler is back to 3.0 C but the shelf is still empty.
    assert_eq!(s.gate.decisions.get(&d2.decision.decision_hash).unwrap().body.effect, Effect::Escalate);
    s.gate.verify_integrity().unwrap();
    std::fs::remove_file(path).unwrap();
}

#[test]
fn edited_deleted_or_reordered_journal_entries_refuse_to_open() {
    let path = tmp("tamper");
    {
        let mut s = open(&path).unwrap();
        workload(&mut s);
    }
    let original = std::fs::read_to_string(&path).unwrap();

    // Rewrite the denial as an allow, everywhere it appears in the file.
    std::fs::write(&path, original.replace("\"effect\":\"deny\"", "\"effect\":\"allow\"")).unwrap();
    assert!(matches!(open(&path), Err(GovError::Storage(_))));

    // Delete one line (an enforcement receipt: carries no hash of its own).
    let lines: Vec<&str> = original.lines().collect();
    let idx = lines.iter().position(|l| l.contains("\"kind\":\"action_completed\"")).unwrap();
    let mut dropped = lines.clone();
    dropped.remove(idx);
    std::fs::write(&path, dropped.join("\n") + "\n").unwrap();
    assert!(matches!(open(&path), Err(GovError::Storage(_))));

    // Swap two lines.
    let mut swapped = lines.clone();
    swapped.swap(5, 6);
    std::fs::write(&path, swapped.join("\n") + "\n").unwrap();
    assert!(matches!(open(&path), Err(GovError::Storage(_))));

    // Truncate to a prefix: a valid (shorter) chain. Opens, but the head no
    // longer matches a published witness value.
    std::fs::write(&path, lines[..10].join("\n") + "\n").unwrap();
    let s = open(&path).unwrap();
    assert_eq!(s.gate.journal_head().0, 10);
    std::fs::remove_file(path).unwrap();
}

#[test]
fn torn_final_write_is_recovered() {
    let path = tmp("torn");
    let head = {
        let mut s = open(&path).unwrap();
        workload(&mut s);
        s.gate.journal_head()
    };
    let mut bytes = std::fs::read(&path).unwrap();
    bytes.extend_from_slice(b"{\"seq\":999,\"prev_hash\":\"00");
    std::fs::write(&path, bytes).unwrap();
    let mut s = open(&path).unwrap();
    assert_eq!(s.gate.journal_head(), head);
    s.gate.verify_journal().unwrap();
    s.gate.verify_integrity().unwrap();
    std::fs::remove_file(path).unwrap();
}

#[test]
fn another_writer_is_detected() {
    let path = tmp("two-writers");
    let mut a = open(&path).unwrap();
    a.publish_policy(1, 5_000, T0).unwrap();
    let mut b = open(&path).unwrap();
    b.observe_temperature(SHELF, 4.0, T0 + 1).unwrap();
    assert!(matches!(a.gate.verify_journal(), Err(GovError::Storage(_))));
    std::fs::remove_file(path).unwrap();
}

fn temperature_mapping(max: i64) -> MappingRule {
    MappingRule {
        id: "cooler.temperature.v1".into(),
        schema: "cooler.temperature/v1".into(),
        subject_field: "shelf_id".into(),
        fact_name: "cooler.temperature_mc".into(),
        value_field: "temperature_c".into(),
        mapping: ValueMapping::FixedPoint { scale: 3 },
        quality: vec![QualityRule::MinInt { min: -40_000 }, QualityRule::MaxInt { max }],
        confidence_field: None,
        min_confidence_bp: 0,
    }
}

#[test]
fn superseded_mappings_stay_rederivable() {
    let path = tmp("mapping-versions");
    let (h, old_mapping) = {
        let mut s = open(&path).unwrap();
        s.publish_policy(1, 5_000, T0 - MINUTE).unwrap();
        s.observe_temperature(SHELF, 7.2, T0).unwrap();
        let h = s.decide(SHELF, T0 + 1_000, "c").unwrap().decision.decision_hash;
        // Tighten the plausibility range: a new mapping version.
        let new = s.gate.register_mapping(temperature_mapping(30_000)).unwrap();
        let old = temperature_mapping(60_000).hash().unwrap();
        assert_ne!(new, old);
        (h, old)
    };
    // After restart the deployment re-applies its *original* configuration
    // (the scenario registers the 60 C version), which supersedes again.
    let mut s = open(&path).unwrap();
    assert!(s.gate.normalizer.mapping(&temperature_mapping(30_000).hash().unwrap()).is_some());
    let r = s.gate.replay(AUDITOR_TOKEN, TENANT, &h, T0 + 2_000).unwrap();
    assert_eq!(r.verdict, ReplayVerdict::Match);
    let bundle = s.gate.export_bundle(&h).unwrap();
    assert_eq!(bundle.mappings.len(), 1);
    assert_eq!(bundle.mappings[0].hash().unwrap(), old_mapping);
    bundle.verify(&s.gate.trust).unwrap();
    std::fs::remove_file(path).unwrap();
}

#[test]
fn bundle_rederives_facts_from_observations() {
    let mut s = ShelfCat::new();
    s.publish_policy(1, 5_000, T0 - MINUTE).unwrap();
    s.observe_temperature(SHELF, 7.2, T0).unwrap();
    s.observe_stock(SHELF, "SKU-MILK-2L", 0, 0.95, T0 + 10).unwrap();
    let h = s.decide(SHELF, T0 + 1_000, "c").unwrap().decision.decision_hash;
    let bundle = s.gate.export_bundle(&h).unwrap();
    bundle.verify(&s.gate.trust).unwrap();
    assert_eq!(bundle.mappings.len(), 2, "one mapping per fact the policy used");

    // Forged confidence, re-hashed so the fact's own hash is consistent:
    // re-derivation from the signed observation exposes it.
    let mut forged = bundle.clone();
    let f = forged.facts.iter_mut().find(|f| f.body.name == "shelf.facing_count").unwrap();
    f.body.confidence_bp = 10_000;
    *f = rustgate::fact::Fact::new(f.body.clone()).unwrap();
    let err = forged.verify(&s.gate.trust).unwrap_err().to_string();
    assert!(err.contains("does not match re-derivation"), "{err}");

    // Swapping in a different mapping rule is caught by its hash.
    let mut forged = bundle.clone();
    forged.mappings[0].min_confidence_bp = 0;
    assert!(forged.verify(&s.gate.trust).unwrap_err().to_string().contains("mapping not in the bundle"));

    // Dropping the mapping rules makes the bundle unverifiable.
    let mut forged = bundle;
    forged.mappings.clear();
    assert!(forged.verify(&s.gate.trust).is_err());
}

#[cfg(feature = "postgres")]
mod postgres {
    use super::*;
    use rustgate::storage::postgres::PostgresJournal;

    /// Runs only when RUSTGATE_TEST_POSTGRES_URL is set, e.g.
    /// `host=/tmp port=5432 user=postgres dbname=rustgate`.
    fn url() -> Option<String> {
        std::env::var("RUSTGATE_TEST_POSTGRES_URL").ok()
    }

    fn open_pg(url: &str, stream: &str) -> rustgate::Result<ShelfCat> {
        ShelfCat::with_journal(Box::new(PostgresJournal::connect(url, stream)?))
    }

    #[test]
    fn postgres_journal_restart_and_worm() {
        let Some(url) = url() else {
            eprintln!("RUSTGATE_TEST_POSTGRES_URL not set; skipping");
            return;
        };
        let stream = format!("it-{}-{}", std::process::id(), T0);
        let (report, h) = {
            let mut s = open_pg(&url, &stream).unwrap();
            let h = workload(&mut s);
            (serde_json::to_value(s.gate.verify_integrity().unwrap()).unwrap(), h)
        };
        let mut s = open_pg(&url, &stream).unwrap();
        assert_eq!(serde_json::to_value(s.gate.verify_integrity().unwrap()).unwrap(), report);
        s.gate.verify_journal().unwrap();
        assert_eq!(s.gate.replay(AUDITOR_TOKEN, TENANT, &h, T0 + 5_000).unwrap().verdict, ReplayVerdict::Match);

        // The database refuses to rewrite history.
        let mut j = PostgresJournal::connect(&url, &stream).unwrap();
        let c = j.client();
        for sql in ["UPDATE rustgate_journal SET kind = 'x' WHERE stream = $1", "DELETE FROM rustgate_journal WHERE stream = $1"] {
            let e = c.execute(sql, &[&stream]).unwrap_err();
            assert!(e.as_db_error().unwrap().message().contains("append-only"), "{e}");
        }
        assert!(c.batch_execute("TRUNCATE rustgate_journal").is_err());
        // ...and to fork or skip the chain.
        let e = c
            .execute(
                "INSERT INTO rustgate_journal (stream, seq, prev_hash, entry_hash, kind, entry) VALUES ($1, 1000000, $2, $2, 'x', '{}')",
                &[&stream, &"0".repeat(64)],
            )
            .unwrap_err();
        assert!(e.as_db_error().unwrap().message().contains("sequence gap"), "{e}");
    }
}
