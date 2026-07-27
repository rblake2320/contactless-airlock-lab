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

- [ ] Versioned canonical encoding has cross-language test vectors.
- [ ] Every security-relevant field is authenticated and unknown fields fail
      closed.
- [ ] Device keys are non-exportable and hardware-backed in the pilot client.
- [ ] Key enrollment, rotation, revocation, recovery, and compromise handling
      are implemented and exercised.
- [ ] Approval verification reconstructs or compares issuer-owned state before
      one-time consumption.
- [ ] Algorithm agility and downgrade rejection are documented and tested.
- [ ] An independent cryptographic/protocol review has no unresolved critical
      or high findings.

### State and distributed correctness

- [ ] Durable database migrations are repeatable and reversible under the
      documented policy.
- [ ] Challenge consumption uses transactional compare-and-set semantics.
- [ ] External mutations have durable idempotency records.
- [ ] Transactional outbox and at-least-once consumers handle duplication,
      delay, reordering, and restart.
- [ ] Barrier-driven multi-process tests prove exactly one terminal outcome
      under competing approval, denial, expiry, cancellation, and retry.
- [ ] Clearing, reversal, advice, offline, stand-in, partial, incremental,
      transit, tip-adjustment, and late-arrival behavior is explicit.
- [ ] Backups, point-in-time recovery, disaster recovery, and audit retention
      are exercised rather than documented only.

### Application and integration security

- [ ] All partner calls and webhooks are mutually authenticated or
      message-signed, authorized, replay-protected, versioned, and size-bounded.
- [ ] Operator access is strongly authenticated, least-privilege, and audited;
      sensitive overrides use dual control.
- [ ] Rate limits, abuse controls, circuit breakers, timeouts, and capacity
      isolation pass adversarial tests.
- [ ] Logs and errors contain no credentials, PAN, payment-token material,
      notification tokens, signatures, or unnecessary personal data.
- [ ] Dedicated SAST, dependency review, full-history secret scanning,
      SBOM/provenance, signed-build, and container/image scans run in CI.
- [ ] Independent penetration testing has no unresolved critical or high
      findings.

### Privacy, operations, and customer safety

- [ ] Data inventory identifies purpose, lawful basis, location, retention,
      deletion, access, and downstream disclosure for each data class.
- [ ] Production, staging, demonstration, and development identities, keys,
      credentials, and telemetry are isolated.
- [ ] Device loss, account recovery, false decline, fraudulent approval, and
      dispute procedures are tested with named owners.
- [ ] Monitoring has service-level objectives, actionable alerts, runbooks,
      escalation paths, and privacy-safe evidence.
- [ ] Incident response and credential/key compromise exercises are complete.
- [ ] Accessibility and misleading/push-fatigue UX testing is complete.
- [ ] Rollback does not create an authentication downgrade or bypass a required
      airlock decision.

### Evidence and delivery

- [ ] The default CI gate passes from a clean checkout using `npm ci` without
      credentials.
- [ ] Live partner tests are isolated, opt-in, and never run on pull requests.
- [ ] A release records commit, lockfile, build provenance, test evidence,
      environment, and all simulated versus real boundaries.
- [ ] Performance evidence states hardware, concurrency, dataset, warm/cold
      state, and partner/simulator involvement.
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
