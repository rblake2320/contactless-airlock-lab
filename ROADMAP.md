# Build Roadmap

The repository is built in evidence-gated slices. A checked item means the
behavior exists at the scope stated and has executable evidence. It does not
promote simulator behavior into a production payment claim.

## P0: Protocol foundation

- [x] Separate repository with product boundaries
- [x] P-256 trusted-device signing reference implementation
- [x] Canonical transaction/provisioning challenge payload
- [x] Exact-field and unknown-field rejection
- [x] Versioned canonical binding vectors match exact UTF-8 bytes and SHA-256
      in TypeScript and an independent Python standard-library verifier
- [x] Signed approvals and enrolled keys use one explicit versioned
      P-256/SHA-256/DER profile with runtime and restore downgrade rejection
- [x] One-time challenge consumption in the single-process lab
- [x] Expiry and terminal-state behavior
- [x] Monotonic provisioning and transaction state machines
- [x] In-memory hash-chain audit integrity check
- [ ] Authenticated append-only audit sink with a key or signed chain-tip
      anchor outside the primary database trust boundary
- [x] Fraudulent provisioning, legitimate flow, and reversal/clearing scenarios
- [x] Threat model, security policy, test plan, and partner boundaries

## P1: Durable service

- [x] SQLite durable-store foundation with repeatable migrations, optimistic
      compare-and-swap, idempotency primitives, and transactional outbox tests
- [x] Simulator-only browser-lab snapshots survive process restart and reject
      corrupt, stale-writer, cross-record, and lifecycle-inconsistent state
- [ ] PostgreSQL durable state and schema migrations
- [ ] Transactional compare-and-swap challenge consumption
- [ ] Idempotency records for every external mutation
- [ ] Transactional outbox and at-least-once event consumers
- [x] Barrier-driven separate-process SQLite terminal races with restart proof
      for approval/retry, expiry, and cancellation on one host
- [x] OpenAPI 3.1 contract for the current simulator-only realtime-lab issuer
      surface, with executable route, schema, header, and negative drift tests
- [ ] Production issuer/processor API contract agreed with a partner
- [x] AsyncAPI 3.0 simulator-only SQLite outbox record/lifecycle contract with
      executable source, schema, migration, and runtime drift evidence
- [ ] Partner-agreed AsyncAPI event envelope, topics, payloads, transport,
      authentication, compatibility, and delivery policy
- [ ] Authentication and signed webhook verification
- [x] Closed simulator-domain reason codes on every JSON error and public
      result, with OpenAPI/runtime enum parity and live rejection drift tests
- [ ] Partner-agreed production reason-code mapping and privacy-safe
      observability

## P2: Partner simulators and operator experience

- [ ] Independent merchant/terminal simulator
- [ ] Processor/network authorization, reversal, clearing, and retry simulator
- [ ] Wallet/TSP provisioning simulator
- [ ] Trusted-device web/mobile demonstration using WebAuthn
- [x] WebAuthn credential-verifier boundary and deterministic negative-path
      test double, explicitly not integrated with the live lab
- [ ] Fraud-operations and cardholder activity interfaces
- [ ] Scenario controls for latency, duplication, outage, and reordering
- [ ] Exportable evidence bundle for every partner demonstration

## P3: Security closure

- [ ] Property-based state-machine tests
- [x] Barrier-driven multi-process, single-host SQLite race tests; PostgreSQL
      and multi-host equivalence remain open
- [x] Deterministic seeded property-style canonical binding generation and
      malformed-input mutation run in the dependency-free default test suite
- [ ] Coverage-guided fuzzing of canonical message decoding and schema validation
- [x] Simulator trusted-device key rotation, revocation, and compromise
      exercises with atomic invalidation, cap release, duplicate-key rejection,
      restart durability, rollback, retry, and replay evidence
- [ ] Production-authorized recovery ceremony, hardware-key replacement,
      multi-device policy, and partner-integrated compromise response
- [ ] Push-fatigue and misleading-transaction UX tests
- [x] Single-host SQLite cap reservations are serialized transactionally across
      contending OS processes, including partial-write rollback, expiry release,
      same-key retry, exact replay, aggregate reconciliation, and restart proof
- [ ] PostgreSQL/multi-host cap enforcement and production-ledger
      reconciliation across concurrent authorizations
- [x] Strict TypeScript static checking in the default quality gate
- [x] Secret-free CI runs tests, scenarios, demo, dependency audit,
      and a narrow committed-credential precheck
- [x] Dedicated CodeQL SAST and full-history Gitleaks workflows
- [x] CycloneDX SBOM generated from the checked-out source/dependency tree and
      retained as a workflow artifact
- [x] Bounded release-evidence generator records commit, lockfile digest,
      tool versions, normalized tests/scenarios, and simulator boundaries;
      explicitly unsigned and unattested
- [ ] Dependency-review policy, artifact attestation/signed build provenance,
      and independent CI/action review
- [ ] Container scanning if and when a deployable container image exists
- [ ] Independent application-security review

## P4: Partner pilot

- [ ] Sponsor issuer/processor sandbox access
- [ ] Captured authorization and reversal semantics
- [ ] Wallet/TSP app-to-app provisioning integration
- [ ] Written handling for stand-in, advice, offline, transit, incremental,
      partial, tip-adjusted, duplicate, and late-clearing events
- [ ] Partner-approved liability and customer-recovery policy
- [ ] Controlled pilot with synthetic or authorized test credentials
- [ ] Evidence-based decision on pre-authorization versus deferred completion

## Release language

Before P4 evidence, describe the project as a reference implementation and
partner integration lab. Do not claim production fraud prevention, NFC relay
resistance, wallet integration, issuer certification, or guaranteed settlement
prevention.

The detailed exit criteria and external dependencies are maintained in
[`docs/PRODUCTION_READINESS.md`](docs/PRODUCTION_READINESS.md).
