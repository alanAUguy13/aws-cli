# RustGate: deterministic governance core

RustGate is a Rust reference implementation of the deterministic governance architecture.
It turns signed observations from cameras, sensors, robots, AI models, ERP systems, apps and
users into canonical facts. It then evaluates those facts against governed, compiled policies
and produces decisions that are explainable, signed, hash-chained, and **replayable bit for bit**.

```
External Actor -> Identity/Authentication -> Authorization -> API & Security Edge
  -> Observation Gateway -> Observation Store -> Fact Normalization -> Fact Store
  -> Governed Policy -> Compiled Policy -> Deterministic Decision Engine -> Decision Service
       ├─> Evidence Generator -> Evidence Repository -> Audit Ledger -> Event Ledger
       │                                                 -> Replay Engine -> Replay Validation
       └─> Action Authorization -> Enforcement
```

**Invariant:** same facts + same policy + same engine = same decision hash.

## Stage → module map

| Stage | Module | What it enforces |
|---|---|---|
| Identity / Authentication | `identity::IdentityProvider` | Bearer credentials stored only as SHA-256, with expiry and revocation |
| Authorization | `identity::Authorizer` | RBAC plus tenant isolation plus ABAC schema restrictions (a camera can't submit temperature) |
| API & Security Edge | `identity::SecurityEdge` | Payload size limit, per-principal rate limit, nonce replay protection |
| Observation Gateway | `observation::ObservationGateway` | Tenant resolution, source allow-list, schema validation, hash verification, ECDSA signature bound to the source's own key, clock-skew check |
| Observation Store | `observation::ObservationStore` | Append-only, content-addressed, idempotent, with provenance metadata |
| Fact Normalization | `fact::FactNormalizer` | Canonical mapping, quality rules, confidence thresholds, and exact decimal→fixed-point conversion (no floats) |
| Fact Store | `fact::FactStore` | Fact registry and "as of t" snapshots with a total, reproducible ordering |
| Governed Policy | `policy::PolicyRepository` | Signed authorship, N-of-M approvals, separation of duties, immutable monotonic versions |
| Compiled Policy | `policy::PolicyCompiler`, `CompiledPolicyStore` | Syntax and semantic checks against the fact catalog, conflict detection, reachability warnings, content-addressed stack bytecode |
| Deterministic Decision Engine | `engine::evaluate` | Pure function with no clock, randomness, I/O or floats. Priority and severity resolution, temporal operators, full trace |
| Decision Service | `decision::DecisionService` | Decision records, explanations, decision hashing, authority of record |
| Evidence Generator / Repository | `evidence` | Provenance, the observation→fact→policy→decision→evidence→signature chain, hash-chained records, offline `EvidenceBundle` |
| Audit Ledger / Event Ledger | `ledger` | Hash-chained, correlation- and causation-linked, tamper-evident |
| Replay Engine / Validation | `replay` | Exact replay (match, drift, engine mismatch, unverifiable) and a separate re-decision that classifies policy drift and late-fact drift |
| Action Authorization / Enforcement | `enforcement` | Actions run only after evidence is sealed and verified and an explicit tenant grant exists. No partial enforcement. Idempotent dispatch |

## Design choices worth knowing

- **No clock inside.** Every call takes an explicit timestamp. Decisions about the future (`as_of > now`)
  are rejected because they could change as facts arrive.
- **No floats in the decision path.** Payload decimals become fixed-point integers by parsing the JSON
  literal with round-half-to-even. `7.2` °C at scale 3 is exactly `7200`, on every platform.
- **Domain-separated canonical hashing.** SHA-256 over `domain || 0x00 || canonical_json`. Keys are
  sorted explicitly, and every record type has its own versioned domain.
- **Deterministic signatures.** ECDSA P-256 with RFC 6979 nonces, so the entire run is reproducible,
  signatures included. Signing sits behind `keys::EvidenceSigner`, where an HSM, KMS, Key Vault or TPM can plug in.
- **Key validity is judged at event time.** A rotated key still verifies its historical signatures,
  and a revoked key invalidates everything it signed after revocation.
- **Replay vs. re-decision.** Replay answers "is the record authentic and the engine deterministic?"
  Re-decision answers "would we decide differently today, and is that because of the policy or the facts?"

## Run it

```bash
cd rustgate
cargo test                      # 20 unit and integration tests
cargo run --bin rustgate-demo -- --bundle evidence-bundle.json
```

The demo runs a ShelfCat store (`src/scenario.rs`) with a cooler temperature sensor and a shelf-vision
camera under a dual-approved cold-chain and availability policy. The run goes like this:

1. It produces an Allow, an Escalate (restock task) and a Deny (POS hold plus incident).
2. It replays each decision, activates a stricter policy, and shows the re-decision flag the change.
3. It exports an evidence bundle and verifies it offline.
4. It tampers with a stored decision and shows both the integrity check and replay catching it.

## Not yet included

- Persistent storage. The stores are in-memory behind small APIs, ready for Postgres or an object store with WORM retention.
- Re-running normalization inside offline bundle verification. The bundle would need to carry the mapping rules.
- External anchoring of ledger heads (a transparency log or cross-organization witness).
- OpenTelemetry export of pipeline spans. The correlation ids are already in place.
