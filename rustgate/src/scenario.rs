//! Reference scenario: a ShelfCat store with a cold-chain cooler sensor and
//! a shelf-vision camera, governed by an approved cold-chain + availability
//! policy. Used by the demo binary and the integration tests, and a worked
//! example of wiring every stage.
//!
//! Keys are derived from fixed seeds so the run is reproducible bit for bit.
//! Never derive production keys this way.

use serde_json::json;

use crate::decision::DecisionRequest;
use crate::enforcement::RecordingConnector;
use crate::fact::FactValue;
use crate::fact::{MappingRule, QualityRule, ValueMapping};
use crate::identity::{ActorKind, Permission, Principal, Role};
use crate::keys::{KeyPurpose, LocalP256Signer};
use crate::observation::{FieldType, ObservationBody, ObservationSchema, SourceRef};
use crate::policy::{ActionTemplate, CmpOp, Condition, Effect, PolicySource, RuleSource};
use crate::{Config, DecisionOutcome, IngestReceipt, Result, RustGate};

pub const TENANT: &str = "shelfcat-store-0042";
pub const POLICY_ID: &str = "cold-chain-and-availability";
pub const T0: u64 = 1_790_000_000_000;
pub const MINUTE: u64 = 60_000;

pub const CAMERA: &str = "cam-aisle-7";
pub const SENSOR: &str = "sensor-cooler-3";
pub const OPS_TOKEN: &str = "tok-ops-service";
pub const AUDITOR_TOKEN: &str = "tok-auditor";
pub const CAMERA_TOKEN: &str = "tok-cam-aisle-7";
pub const SENSOR_TOKEN: &str = "tok-sensor-cooler-3";

pub struct ShelfCat {
    pub gate: RustGate,
    pub camera_key: LocalP256Signer,
    pub sensor_key: LocalP256Signer,
    pub alice: LocalP256Signer,
    pub bob: LocalP256Signer,
    pub carol: LocalP256Signer,
    nonce: u64,
}

fn roles(names: &[&str]) -> std::collections::BTreeSet<String> {
    names.iter().map(|s| s.to_string()).collect()
}

impl ShelfCat {
    pub fn new() -> Self {
        let evidence_key = LocalP256Signer::from_seed("rustgate-evidence-2026", "evidence");
        let mut gate = RustGate::new(Config::default(), Box::new(evidence_key));

        // Keys and trust.
        let camera_key = LocalP256Signer::from_seed("cam-aisle-7/k1", "camera");
        let sensor_key = LocalP256Signer::from_seed("sensor-cooler-3/k1", "sensor");
        let alice = LocalP256Signer::from_seed("alice/policy", "alice");
        let bob = LocalP256Signer::from_seed("bob/approver", "bob");
        let carol = LocalP256Signer::from_seed("carol/approver", "carol");
        gate.trust.register_signer(&camera_key, KeyPurpose::ObservationSource, CAMERA, 0);
        gate.trust.register_signer(&sensor_key, KeyPurpose::ObservationSource, SENSOR, 0);
        gate.trust.register_signer(&alice, KeyPurpose::PolicyAuthor, "alice", 0);
        gate.trust.register_signer(&bob, KeyPurpose::PolicyApprover, "bob", 0);
        gate.trust.register_signer(&carol, KeyPurpose::PolicyApprover, "carol", 0);
        // Alice may also approve, but never her own work (separation of duties).
        let alice_approver = LocalP256Signer::from_seed("alice/approver", "alice-approver");
        gate.trust.register_signer(&alice_approver, KeyPurpose::PolicyApprover, "alice", 0);
        let evidence_pub = gate.evidence_signer().public_key_sec1();
        gate.trust.register(&evidence_pub, "rustgate-evidence-2026", KeyPurpose::Evidence, "rustgate", 0);

        // Identity + authorisation.
        let principals = [
            (CAMERA, ActorKind::Camera, "vision-source", CAMERA_TOKEN),
            (SENSOR, ActorKind::Sensor, "telemetry-source", SENSOR_TOKEN),
            ("ops-service", ActorKind::Service, "decider", OPS_TOKEN),
            ("auditor", ActorKind::User, "auditor", AUDITOR_TOKEN),
        ];
        for (id, kind, role, token) in principals {
            gate.identity.register_principal(Principal { id: id.into(), tenant: TENANT.into(), kind, roles: roles(&[role]) });
            gate.identity.issue_credential(id, token, None).expect("principal registered");
        }
        gate.authorizer.define_role(
            "vision-source",
            Role { permissions: [Permission::SubmitObservation].into(), allowed_schemas: Some(roles(&["shelf.stock/v1"])) },
        );
        gate.authorizer.define_role(
            "telemetry-source",
            Role { permissions: [Permission::SubmitObservation].into(), allowed_schemas: Some(roles(&["cooler.temperature/v1"])) },
        );
        gate.authorizer
            .define_role("decider", Role { permissions: [Permission::RequestDecision, Permission::Replay].into(), allowed_schemas: None });
        gate.authorizer
            .define_role("auditor", Role { permissions: [Permission::Replay, Permission::ReadEvidence].into(), allowed_schemas: None });

        // Observation layer.
        gate.gateway.register_tenant(TENANT);
        gate.gateway.authorise_source(TENANT, CAMERA).unwrap();
        gate.gateway.authorise_source(TENANT, SENSOR).unwrap();
        gate.gateway.register_schema(ObservationSchema {
            id: "cooler.temperature/v1".into(),
            required: [("shelf_id".to_string(), FieldType::String), ("temperature_c".to_string(), FieldType::Number)].into(),
            optional: [("firmware".to_string(), FieldType::String)].into(),
            closed: true,
        });
        gate.gateway.register_schema(ObservationSchema {
            id: "shelf.stock/v1".into(),
            required: [
                ("shelf_id".to_string(), FieldType::String),
                ("sku".to_string(), FieldType::String),
                ("facing_count".to_string(), FieldType::Integer),
                ("confidence".to_string(), FieldType::Number),
            ]
            .into(),
            optional: [("model".to_string(), FieldType::String)].into(),
            closed: true,
        });

        // Canonical fact mapping.
        let mappings = [
            MappingRule {
                id: "cooler.temperature.v1".into(),
                schema: "cooler.temperature/v1".into(),
                subject_field: "shelf_id".into(),
                fact_name: "cooler.temperature_mc".into(),
                value_field: "temperature_c".into(),
                mapping: ValueMapping::FixedPoint { scale: 3 },
                quality: vec![QualityRule::MinInt { min: -40_000 }, QualityRule::MaxInt { max: 60_000 }],
                confidence_field: None,
                min_confidence_bp: 0,
            },
            MappingRule {
                id: "shelf.facings.v1".into(),
                schema: "shelf.stock/v1".into(),
                subject_field: "shelf_id".into(),
                fact_name: "shelf.facing_count".into(),
                value_field: "facing_count".into(),
                mapping: ValueMapping::FixedPoint { scale: 0 },
                quality: vec![QualityRule::MinInt { min: 0 }],
                confidence_field: Some("confidence".into()),
                min_confidence_bp: 5_000,
            },
            MappingRule {
                id: "shelf.sku.v1".into(),
                schema: "shelf.stock/v1".into(),
                subject_field: "shelf_id".into(),
                fact_name: "shelf.sku".into(),
                value_field: "sku".into(),
                mapping: ValueMapping::Text,
                quality: vec![QualityRule::NonEmptyText],
                confidence_field: Some("confidence".into()),
                min_confidence_bp: 5_000,
            },
        ];
        for m in mappings {
            gate.normalizer.register(m).unwrap();
        }

        // Enforcement.
        gate.enforcement.register("servicenow", Box::new(RecordingConnector::new("servicenow", "INC")));
        gate.enforcement.register("dynamics", Box::new(RecordingConnector::new("dynamics", "TASK")));
        gate.enforcement.register("pos", Box::new(RecordingConnector::new("pos", "HOLD")));
        gate.action_authorizer.grant(TENANT, "servicenow", "create_incident");
        gate.action_authorizer.grant(TENANT, "dynamics", "create_restock_task");
        gate.action_authorizer.grant(TENANT, "pos", "hold_sku");

        Self { gate, camera_key, sensor_key, alice, bob, carol, nonce: 0 }
    }

    /// The governed policy. `breach_threshold_mc` is in milli-degrees C.
    pub fn policy(version: u32, breach_threshold_mc: i64) -> PolicySource {
        let p = |pairs: &[(&str, &str)]| pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        PolicySource {
            id: POLICY_ID.into(),
            version,
            tenant: TENANT.into(),
            description: "Cold-chain safety and on-shelf availability for refrigerated aisles".into(),
            default_effect: Effect::Allow,
            rules: vec![
                RuleSource {
                    id: "telemetry-stale".into(),
                    priority: 300,
                    when: Condition::Not {
                        cond: Box::new(Condition::FreshWithin { fact: "cooler.temperature_mc".into(), max_age_ms: 15 * MINUTE }),
                    },
                    effect: Effect::Escalate,
                    actions: vec![ActionTemplate {
                        connector: "servicenow".into(),
                        operation: "create_incident".into(),
                        params: p(&[("short_description", "Cooler telemetry stale for {subject}"), ("urgency", "2")]),
                    }],
                    explain: "cannot attest cold-chain without temperature telemetry from the last 15 minutes".into(),
                },
                RuleSource {
                    id: "cold-chain-breach".into(),
                    priority: 200,
                    when: Condition::Compare {
                        fact: "cooler.temperature_mc".into(),
                        cmp: CmpOp::Gt,
                        value: FactValue::Int(breach_threshold_mc),
                    },
                    effect: Effect::Deny,
                    actions: vec![
                        ActionTemplate {
                            connector: "pos".into(),
                            operation: "hold_sku".into(),
                            params: p(&[("shelf", "{subject}"), ("reason", "cold-chain breach, decision {decision}")]),
                        },
                        ActionTemplate {
                            connector: "servicenow".into(),
                            operation: "create_incident".into(),
                            params: p(&[("short_description", "Cold-chain breach on {subject}"), ("urgency", "1")]),
                        },
                    ],
                    explain: "product held above the safe storage temperature".into(),
                },
                RuleSource {
                    id: "out-of-stock".into(),
                    priority: 100,
                    when: Condition::All {
                        of: vec![
                            Condition::Compare { fact: "shelf.facing_count".into(), cmp: CmpOp::Eq, value: FactValue::Int(0) },
                            Condition::ConfidenceAtLeast { fact: "shelf.facing_count".into(), min_bp: 8_000 },
                        ],
                    },
                    effect: Effect::Escalate,
                    actions: vec![ActionTemplate {
                        connector: "dynamics".into(),
                        operation: "create_restock_task".into(),
                        params: p(&[("location", "{subject}")]),
                    }],
                    explain: "shelf observed empty with high confidence".into(),
                },
            ],
        }
    }

    /// Submit, dual-approve, compile and activate a policy version.
    pub fn publish_policy(&mut self, version: u32, threshold_mc: i64, at: u64) -> Result<crate::policy::CompiledPolicy> {
        self.gate.submit_policy(Self::policy(version, threshold_mc), &self.alice, at)?;
        self.gate.approve_policy(POLICY_ID, version, &self.bob, at + 1)?;
        self.gate.approve_policy(POLICY_ID, version, &self.carol, at + 2)?;
        self.gate.compile_and_activate(POLICY_ID, version, "release-pipeline", at + 3)
    }

    fn next_nonce(&mut self) -> String {
        self.nonce += 1;
        format!("n-{}", self.nonce)
    }

    pub fn observe_temperature(&mut self, shelf: &str, celsius: f64, at: u64) -> Result<IngestReceipt> {
        let env = ObservationBody {
            tenant: TENANT.into(),
            source: SourceRef { kind: ActorKind::Sensor, id: SENSOR.into() },
            schema: "cooler.temperature/v1".into(),
            observed_at: at,
            payload: json!({ "shelf_id": shelf, "temperature_c": celsius, "firmware": "3.1.4" }),
        }
        .seal(&self.sensor_key)?;
        let nonce = self.next_nonce();
        self.gate.ingest(SENSOR_TOKEN, &nonce, env, at + 250)
    }

    pub fn observe_stock(&mut self, shelf: &str, sku: &str, facings: i64, confidence: f64, at: u64) -> Result<IngestReceipt> {
        let env = ObservationBody {
            tenant: TENANT.into(),
            source: SourceRef { kind: ActorKind::Camera, id: CAMERA.into() },
            schema: "shelf.stock/v1".into(),
            observed_at: at,
            payload: json!({ "shelf_id": shelf, "sku": sku, "facing_count": facings, "confidence": confidence, "model": "shelfcat-vision-4" }),
        }
        .seal(&self.camera_key)?;
        let nonce = self.next_nonce();
        self.gate.ingest(CAMERA_TOKEN, &nonce, env, at + 400)
    }

    pub fn decide(&mut self, shelf: &str, as_of: u64, correlation_id: &str) -> Result<DecisionOutcome> {
        let req = DecisionRequest {
            tenant: TENANT.into(),
            subject: shelf.into(),
            policy_id: POLICY_ID.into(),
            as_of,
            correlation_id: correlation_id.into(),
        };
        self.gate.decide(OPS_TOKEN, &req, as_of + 1_000)
    }
}

impl Default for ShelfCat {
    fn default() -> Self {
        Self::new()
    }
}
