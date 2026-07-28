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
- [x] Authenticated append-only audit sink: per-event HMAC-SHA256 tags chained
      over the hash chain, keyed by an external key provider and verified on
      restore against an external trust anchor held outside the primary database
      trust boundary; whole-chain recomputation, authenticated-suffix deletion,
      and retired-key rollback are rejected fail-closed
      (`packages/audit/auditLog.ts`, `tests/audit-authentication.test.ts`).
      Binding that key to an HSM/KMS remains a production step (tracked in
      `docs/PRODUCTION_READINESS.md`).
- [x] Fraudulent provisioning, legitimate flow, and reversal/clearing scenarios
- [x] Threat model, security policy, test plan, and partner boundaries

## P1: Durable service

- [x] SQLite durable-store foundation with repeatable migrations, optimistic
      compare-and-swap, idempotency primitives, and transactional outbox tests
- [x] Simulator-only browser-lab snapshots survive process restart and reject
      corrupt, stale-writer, cross-record, and lifecycle-inconsistent state
- [x] WAL-consistent snapshot backup (SQLite Online Backup API) with a
      checksummed, self-describing manifest and a restore-verification drill
      (checksum, byte length, `integrity_check`, application-schema fingerprint,
      and the same deep application-state checks the server runs on restart);
      exclusive-create so nothing is overwritten. Single-host and snapshot-only
      — explicitly NOT continuous point-in-time recovery, off-host replication,
      or DR (`tools/backup-lib.ts`, `tests/backup-restore.test.ts`,
      `docs/BACKUP_RESTORE.md`; PITR/off-host/DR tracked in
      `docs/PRODUCTION_READINESS.md`).
- [ ] PostgreSQL durable state and schema migrations
- [x] Tenant-scoped PostgreSQL adapter contract for optimistic CAS,
      idempotency, transactional outbox leasing, and cap reservations, with an
      opt-in real multi-process test. The real database gate remains unrun
      without `AIRLOCK_POSTGRES_URL`, so this does not close the item above
      (`packages/storage/postgresStore.ts`, `tests/postgres-integration.test.ts`).
- [x] The single-host realtime lab serializes challenge-state mutations through
      a versioned whole-snapshot SQLite compare-and-swap: a stale writer loses
      the swap, reloads authoritative state, and discards its in-memory
      mutation. Generic durable-record tests separately prove exactly one
      terminal transition across contending connections and OS processes
      (`apps/realtime-lab/server.ts`, `tests/durable-storage.test.ts`,
      `tests/durable-terminal-race.test.ts`). This is not per-challenge-row CAS;
      PostgreSQL and multi-host equivalence remain open.
- [x] Idempotency records for every realtime-lab HTTP mutation on a single host:
      the first response is replayed, a same-key request with a different
      canonical body/path is rejected without effect, concurrent duplicates
      across two server processes produce exactly one effect, and records
      survive restart (`tests/server-restart-idempotency.test.ts`,
      `tests/durable-storage.test.ts`). Partner/production "every external
      mutation" scope remains open.
- [x] Transactional outbox with at-least-once lease delivery on a single host:
      claim/lease, retry-delay, wrong-owner rejection, and acknowledgement,
      rolled back atomically with the compare-and-swap that enqueued the event
      (`tests/durable-storage.test.ts`, `tests/asyncapi-outbox.test.ts`).
      Partner-agreed transport and production event consumers remain open.
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
- [x] Authenticated realtime-lab profile with bounded, revocable, role- and
      tenant-scoped sessions, exact Origin/CSRF enforcement, and mutually
      exclusive controlled-demo bootstrap or strict OIDC/JWT identity-provider
      composition. OIDC mode has no bootstrap fallback; distributed session and
      replay storage remain open.
- [x] Candidate partner-transport adapter with raw-body HMAC signing,
      replay/idempotency enforcement, bounded timeout/retry/circuit breaking,
      and durable dead-letter-before-acknowledgement tests. It is not a
      partner-agreed or deployed webhook integration.
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
- [x] Production WebAuthn assertion adapter using the pinned
      `@simplewebauthn/server` implementation and real ES256/COSE fixtures,
      with exact protocol, purpose, RP, origin, UV, counter, algorithm, and
      challenge-ID rejection. Registration, attestation trust, hardware keys,
      and live-lab composition remain open.
- [ ] Fraud-operations and cardholder activity interfaces
- [x] Synthetic customer/fraud operations state machine and evidence contract
      covering device loss, strong-proof recovery, false declines, fraudulent
      approvals, compromise, and dual-control trust reset. Production UI,
      notification delivery, IAM/case integration, and named owners remain open.
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
- [x] Pull-request dependency-review gate failing on newly introduced
      high/critical advisories, action pinned by commit SHA under least
      privilege; an advisory-only PR-diff gate — no license policy, and not a
      runtime or deep-transitive scanner (`.github/workflows/dependency-review.yml`,
      `tests/dependency-review-config.test.ts`,
      `docs/DEPENDENCY_REVIEW_BOUNDARY.md`)
- [x] Process-local per-client mutation rate limiting and SSE connection
      bounding for the simulator realtime-lab (token bucket with fail-closed
      admission that never refunds a penalized bucket, trusted-proxy client
      identity, deterministic stream cleanup); in-process, single-instance only
      — distributed/edge enforcement is external (`apps/realtime-lab/server.ts`,
      `tests/rate-limit.test.ts`, `docs/REALTIME_LAB_RATE_LIMIT.md`)
- [x] Controlled-demo launch policy, privacy-safe bounded service telemetry,
      SLO alert evaluation, incident/rollback runbook, and an opt-in 300-second
      capacity gate that records build, hardware, concurrency, warm/cold, and
      latency evidence. External metrics export, paging, distributed admission,
      and a completed retained capacity run remain open.
- [x] Runtime-coherent static assets and build identity: the server snapshots
      frontend bytes at startup and reports a build ID plus asset digest, with
      tests proving a running backend cannot silently mix with later on-disk
      frontend changes.
- [x] Bounded release-evidence generator records commit, lockfile digest,
      tool versions, normalized tests/scenarios, and simulator boundaries;
      explicitly unsigned and unattested
- [ ] Artifact attestation/signed build provenance and independent CI/action
      review (the PR-time dependency-review policy above is in place; these
      remain open)
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
