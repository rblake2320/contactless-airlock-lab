# Production Readiness

## Current verdict

Contactless Airlock Lab is a testable reference implementation and partner
integration artifact. It is not production-ready and is not approved to carry
real payment credentials or cardholder data.

The repository can independently close engineering quality and simulator
evidence. It cannot independently grant access to payment rails, certify a
wallet integration, decide an issuer's liability policy, or create settlement
semantics that a processor/network/merchant does not enforce.

## Repository-controlled release gate

All items below must be complete before proposing a controlled partner pilot.

### Protocol and cryptography

- [x] Versioned canonical binding encoding has exact-byte and SHA-256 vectors
      verified independently by TypeScript and Python standard-library code.
- [ ] Every security-relevant field is authenticated and unknown fields fail
      closed.
- [ ] Device keys are non-exportable and hardware-backed in the pilot client.
- [ ] Key enrollment, rotation, revocation, recovery, and compromise handling
      are implemented and exercised.
- [x] Approval verification compares issuer-owned stored challenge state before
      one-time consumption: the submitted approval binding is canonicalized and
      timing-safe compared against the issuer's stored challenge, expiry and the
      device signature are checked, and the challenge transitions to a terminal
      state so it cannot be consumed twice (single-host lab —
      `packages/state-machine/challengeStore.ts`, `tests/audit-authentication.test.ts`
      and the challenge lifecycle tests). Production hardware-backed device trust
      remains covered by the device-key items above.
- [x] Approval algorithm profile is versioned and signed; enrollment,
      verification, and restore reject unknown, missing, mismatched, and
      wrong-curve profiles without fallback.
- [ ] An independent cryptographic/protocol review has no unresolved critical
      or high findings.

### State and distributed correctness

- [ ] Durable database migrations are repeatable and reversible under the
      documented policy.
- [x] A tenant-scoped PostgreSQL adapter and forward-only migration contract
      implement optimistic CAS, durable idempotency, atomic outbox enqueue and
      leasing, and cap reservations. Static/contract tests pass; the real
      multi-process integration test is deliberately opt-in and remains
      unexecuted until `AIRLOCK_POSTGRES_URL` names an approved test database
      (`packages/storage/postgresStore.ts`,
      `tests/postgres-integration.test.ts`).
- [x] The live lab serializes state transitions with WHOLE-SNAPSHOT optimistic
      compare-and-swap: the entire engine state persists as one durable record
      with a version, a stale writer's swap is rejected and its in-memory state
      is reloaded-and-discarded, and generic durable-record terminal-race
      evidence exists across contending OS processes (single-host —
      `apps/realtime-lab/server.ts`, `tests/durable-storage.test.ts`,
      `tests/durable-terminal-race.test.ts`). This is NOT per-challenge-row CAS.
- [ ] Per-challenge-row transactional compare-and-set on a production database
      (PostgreSQL) with multi-host/connection-pool correctness.
- [x] Every realtime-lab HTTP mutation has a durable idempotency record on one
      host: the first response is replayed, a same-key request with a divergent
      canonical body/path is rejected without effect, concurrent duplicates
      across two server processes produce exactly one effect, and records
      survive restart (`tests/server-restart-idempotency.test.ts`,
      `tests/durable-storage.test.ts`).
- [ ] Partner/external-system mutations (issuer, processor, wallet/TSP) have
      durable idempotency records under the agreed production contract.
- [x] The single-host SQLite transactional outbox exercises atomic enqueue,
      at-least-once leasing, acknowledgement, retry delay, wrong-owner
      rejection, duplication, and restart behavior, with a simulator-only
      AsyncAPI contract and executable drift tests.
- [ ] Production outbox consumers and partner transport handle duplication,
      delay, reordering, dead-letter policy, failover, and restart.
- [x] A candidate, non-partner-approved transport adapter exercises raw-body
      message signing, bounded replay protection, idempotent receiving,
      timeout/retry/circuit-breaker behavior, and durable dead-letter-before-
      acknowledgement semantics with no configured external destination
      (`packages/partner-transport`, `tests/partner-transport.test.ts`).
- [ ] A partner-agreed event contract defines authenticated transport, envelope
      versioning, topic payloads, correlation/causation, retry/DLQ policy, and
      acknowledgement semantics.
- [x] Barrier-driven separate-process tests on one host prove exactly one
      restart-durable SQLite terminal outcome under competing approval/retry,
      expiry, and cancellation.
- [ ] Equivalent PostgreSQL and multi-host tests cover approval, denial,
      expiry, cancellation, retry, failover, and connection-pool behavior.
- [ ] Clearing, reversal, advice, offline, stand-in, partial, incremental,
      transit, tip-adjustment, and late-arrival behavior is explicit.
- [x] WAL-consistent SQLite snapshot backup and verified restore are exercised
      against live concurrent writers, corruption, wrong-source data, failed
      restore cleanup, and a full application lifecycle.
- [ ] Continuous point-in-time recovery, authenticated/off-host backup
      retention, disaster recovery, and production audit retention are
      exercised under an approved operational policy.
- [ ] The authenticated audit profile is wired to an HSM/KMS-backed key
      provider and independently administered chain-tip anchor with tested
      atomic publication and crash recovery. Direct profile tests alone do not
      close this production gate.

### Application and integration security

- [x] A standalone strict OIDC/JWT access-token verifier boundary validates an
      exact HTTPS issuer, audience, asymmetric algorithm allowlist, bounded
      JWKS rotation/cache, token time claims, signed tenant/principal/roles, and
      optional atomic `jti` replay policy with real-JWT adversarial tests.
      Authenticated server mode composes this verifier without bootstrap
      fallback and caps the resulting process-local session at the signed token
      expiry. A real identity provider, distributed replay/session store, and
      production access audit remain external deployment work.
- [ ] All partner calls and webhooks are mutually authenticated or
      message-signed, authorized, replay-protected, versioned, and size-bounded.
- [ ] Operator access is strongly authenticated, least-privilege, and audited;
      sensitive overrides use dual control.
- [x] The realtime simulator has executable authenticated principals, roles,
      bounded sessions, CSRF/origin enforcement, logout revocation, and
      process-local tenant isolation. Distributed identity/session storage and
      production access auditing remain open.
- [x] The single-process simulator and candidate partner adapter exercise
      bounded request/SSE admission, mutation rate limits, timeouts, retry
      budgets, and circuit breaking under adversarial tests. Distributed edge
      enforcement and production dependency isolation remain open.
- [ ] Logs and errors contain no credentials, PAN, payment-token material,
      notification tokens, signatures, or unnecessary personal data.
- [x] Dedicated CodeQL SAST and full-history Gitleaks scans run in secret-free,
      least-privilege CI.
- [x] CI generates a CycloneDX SBOM of the checked-out repository/dependency
      tree and retains it as a bounded-lifetime workflow artifact.
- [x] A least-privilege, commit-SHA-pinned pull-request dependency-review gate
      fails on newly introduced high/critical advisories. It is explicitly not
      a runtime, baseline, deep-transitive, or license-policy scanner.
- [ ] Artifact attestation, signed-build provenance, and independent review of
      pinned action implementations are complete.
- [ ] Container/image scanning is added if a deployable image becomes part of
      the release; no container exists to scan today.
- [ ] Independent penetration testing has no unresolved critical or high
      findings.

### Privacy, operations, and customer safety

- [x] Current synthetic simulator data has a field-level inventory with purpose,
      location, current retention/deletion limits, and downstream status.
- [ ] Data inventory identifies purpose, lawful basis, location, retention,
      deletion, access, and downstream disclosure for each production data
      class and approved integration.
- [ ] Production, staging, demonstration, and development identities, keys,
      credentials, and telemetry are isolated.
- [ ] Device loss, account recovery, false decline, fraudulent approval, and
      dispute procedures are tested with named owners.
- [x] Synthetic, tenant-scoped customer/fraud workflow state machines exercise
      device loss, strong-proof recovery, false-decline review, fraudulent-
      approval dispute, compromise response, and dual-control destructive reset
      without SMS/typed-code downgrade or direct notification delivery
      (`packages/customer-operations`, `tests/customer-operations.test.ts`).
      Named production owners, real IAM/case systems, and liability procedures
      remain open.
- [ ] Monitoring has service-level objectives, actionable alerts, runbooks,
      escalation paths, and privacy-safe evidence.
- [x] A non-production controlled-demo launch policy, deterministic capacity
      evidence evaluator, bounded privacy-safe telemetry model, and incident/
      rollback runbook exist with executable tests. External telemetry export,
      paging, distributed admission, and completed operational drills remain
      open.
- [ ] Incident response and credential/key compromise exercises are complete.
- [ ] Accessibility and misleading/push-fatigue UX testing is complete.
- [ ] Rollback does not create an authentication downgrade or bypass a required
      airlock decision.

### Evidence and delivery

- [x] The default CI definition verifies a pristine checkout before locked
      `npm ci --ignore-scripts`; a successful hosted run remains release
      evidence rather than an inference from configuration.
- [ ] Live partner tests are isolated, opt-in, and never run on pull requests.
- [x] A bounded machine-readable bundle records commit, lockfile hash, Node and
      Python versions, normalized test/scenario evidence, and simulated versus
      real boundaries from a clean checkout.
- [ ] Signed build provenance and artifact attestation remain unimplemented;
      the release-evidence bundle explicitly claims neither.
- [x] Controlled-demo performance evidence states the tested commit/build,
      hardware, process count, concurrency, warm/cold state, duration, loopback
      simulator involvement, request counts, p95 latencies, and policy result
      (`evidence/capacity/954d7af.json`). It does not authorize public,
      multi-user, partner, or payment traffic.
- [x] The opt-in capacity gate requires and records commit/build identity,
      hardware/process context, concurrency, warm/cold declaration, duration,
      loopback-only scope, latency percentiles, success ratio, and overload
      evidence. No performance claim is made until its full policy window is
      actually run and retained (`tools/capacity-gate.ts`).
- [x] Runtime health exposes an explicit build identifier and startup-snapshotted
      static-asset digest; executable tests prove a running backend cannot serve
      frontend bytes changed on disk after startup.
- [ ] Documentation and demonstrations use the release-language restrictions
      in `ROADMAP.md`.

## External partner blockers

These are not solvable by adding more repository code. Each requires written
access, authority, semantics, or approval from the named external party.

| Blocker | Required owner/evidence | Why it is external |
|---|---|---|
| Sponsor issuer and processor sandbox | Issuer/processor credentials, message contract, certification plan, named technical owners | The lab cannot originate or decide production issuer traffic. |
| Wallet/TSP provisioning integration | Wallet/TSP entitlement, app-to-app verification contract, token lifecycle callbacks, certification fixtures | The lab cannot create or activate a real network token. |
| Authorization decision semantics | Issuer/processor decision codes, timeout/retry behavior, stand-in rules, and liability owner | A simulator cannot define how a production authorization is honored. |
| Deferred-completion guarantee | Written processor/network/merchant enforcement and clearing behavior | Approve-then-reverse does not prevent goods release or late clearing. |
| Network and scheme approval | Applicable network rules, test cases, certification, and change approval | The repository has no authority to change scheme or EMV behavior. |
| PCI and regulatory scope | Qualified legal/compliance assessment, data-flow scope, required audits and registrations | Tests cannot confer compliance or legal authorization. |
| Device attestation and secure keys | Platform entitlements, supported-device policy, attestation trust roots, recovery contract | PEM-based lab keys do not establish production device trust. |
| Fraud, recovery, and liability policy | Issuer fraud, operations, legal, customer-support, and dispute sign-off | Security tradeoffs and customer remedies are business obligations. |
| Production data and privacy approval | Controller/processor roles, regional requirements, retention and subject-rights procedures | Synthetic lab data does not validate real-data handling authority. |
| Controlled pilot approval | Written scope, test accounts, monitoring, stop criteria, rollback, and incident contacts | A real pilot changes operational and customer risk. |

## Partner-entry package

The project is ready to enter partner discovery—not production—when it can
provide:

1. a reproducible clean-checkout build and test report;
2. protocol, threat-model, and adapter-boundary documentation;
3. deterministic test vectors and adversarial scenario evidence;
4. a demonstration that clearly labels simulated systems;
5. a data-flow and integration questionnaire;
6. an open decision log for pre-authorization versus genuinely enforced
   deferred completion; and
7. a gap register mapping every external blocker above to a named partner
   owner, due date, and acceptance artifact.

No unchecked external blocker may be relabeled as an internal engineering task
or silently represented by a simulator in production-readiness claims.
