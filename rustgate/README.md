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
| Fact Normalization | `fact::FactNormalizer` | Canonical mapping, quality rules, confidence thresholds, and exact decimal→fixed-point conversion (no floats). Mapping rules are content-addressed and every version is kept, so any fact can be re-derived |
| Fact Store | `fact::FactStore` | Fact registry and "as of t" snapshots with a total, reproducible ordering |
| Governed Policy | `policy::PolicyRepository` | Signed authorship, N-of-M approvals, separation of duties, immutable monotonic versions |
| Compiled Policy | `policy::PolicyCompiler`, `CompiledPolicyStore` | Syntax and semantic checks against the fact catalog, conflict detection, reachability warnings, content-addressed stack bytecode |
| Deterministic Decision Engine | `engine::evaluate` | Pure function with no clock, randomness, I/O or floats. Priority and severity resolution, temporal operators, full trace |
| Decision Service | `decision::DecisionService` | Decision records, explanations, decision hashing, authority of record |
| Evidence Generator / Repository | `evidence` | Provenance, the observation→fact→policy→decision→evidence→signature chain, hash-chained records, offline `EvidenceBundle` |
| Audit Ledger / Event Ledger | `ledger` | Hash-chained, correlation- and causation-linked, tamper-evident |
| Replay Engine / Validation | `replay` | Exact replay (match, drift, engine mismatch, unverifiable) and a separate re-decision that classifies policy drift and late-fact drift |
| Action Authorization / Enforcement | `enforcement` | Actions run only after evidence is sealed and verified and an explicit tenant grant exists. No partial enforcement. Idempotent dispatch, including across restarts |
| Durable storage | `storage` | Hash-chained write-ahead journal: in-memory, append-only file, or PostgreSQL with database-enforced WORM |

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
- **Normalization is re-executable.** Each fact records the hash of the exact mapping rule version that
  derived it. Replay and offline bundle verification re-derive every fact from its signed observation
  and require a bit-identical result, so a forged fact is caught even if it was consistently re-hashed.
- **Replay vs. re-decision.** Replay answers "is the record authentic and the engine deterministic?"
  Re-decision answers "would we decide differently today, and is that because of the policy or the facts?"

## Durable storage

Every state change is a `storage::JournalRecord`. It is appended to a `Journal` *before* it is applied
in memory, and `RustGate::open` rebuilds every store by applying the same records through the same
code path. The in-memory stores are the query layer; the journal is the source of truth.

- **Journal chain.** Each entry commits to its predecessor's hash, independent of the hashes inside
  the records. Editing, deleting, reordering or inserting any entry, including enforcement receipts
  that carry no hash of their own, makes the journal refuse to open. `journal_head()` gives the value
  to publish to an external witness, which also makes truncation to a shorter valid prefix detectable.
- **What is journaled:** observations, facts, mapping versions, policy submissions, approvals, compiled
  binaries, activations, decisions, evidence, both ledgers, and enforcement receipts (so a restarted
  instance never re-executes an action).
- **What is configuration:** keys, identities, roles, schemas, connectors and grants. The deployment
  supplies these on every start from its KMS and IdP. Re-registering the active mapping rules is a no-op.
- **Failure handling.** If a record fails to apply after it was made durable, the instance becomes
  read-only until it is restarted from the journal.

| Backend | Use | Guarantees |
|---|---|---|
| `MemoryJournal` | Tests, ephemeral instances | None beyond the process |
| `FileJournal` | Single node, edge devices | Append-only JSON lines, optional fsync per entry, torn final write truncated on open, corrupt complete lines rejected. Pair with `chattr +a` or a WORM volume |
| `postgres::PostgresJournal` (feature `postgres`) | Servers | Schema in `sql/postgres.sql`. Triggers reject UPDATE, DELETE and TRUNCATE and enforce chain linkage and sequence continuity. Many instances share one table by `stream`. Grant the app role only INSERT and SELECT |

Object stores with retention locks (for example S3 Object Lock in compliance mode) fit the same trait:
the file format is already append-only JSON lines, so sealed files can be shipped as immutable objects.

## Run it

```bash
cd rustgate
cargo test                      # unit and integration tests
cargo run --bin rustgate-demo -- --bundle evidence-bundle.json

# Persist to a file, then run again to recover, re-verify and replay everything
cargo run --bin rustgate-demo -- --journal store.jsonl
cargo run --bin rustgate-demo -- --journal store.jsonl

# PostgreSQL backend (tests skip unless the URL is set)
RUSTGATE_TEST_POSTGRES_URL="host=localhost user=postgres password=postgres dbname=rustgate" \
  cargo test --features postgres
```

The demo runs a ShelfCat store (`src/scenario.rs`) with a cooler temperature sensor and a shelf-vision
camera under a dual-approved cold-chain and availability policy. The run goes like this:

1. It produces an Allow, an Escalate (restock task) and a Deny (POS hold plus incident).
2. It replays each decision, activates a stricter policy, and shows the re-decision flag the change.
3. It exports an evidence bundle and verifies it offline.
4. It tampers with a stored decision and shows both the integrity check and replay catching it.

## Not yet included

- External anchoring of journal and ledger heads (a transparency log or cross-organization witness).
  `journal_head()` provides the value to publish.
- Journaling the trust store. Key registrations, rotations and revocations are configuration today, so
  verifying old evidence depends on the deployment keeping retired public keys in its key registry.
- OpenTelemetry export of pipeline spans. The correlation ids are already in place.
