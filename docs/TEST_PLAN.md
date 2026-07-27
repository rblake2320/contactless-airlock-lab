# Contactless Airlock Lab Test Plan

## 1. Purpose and evidence standard

This plan verifies the standalone protocol core, simulators, and partner
integration boundary. It does not treat a health response, mocked callback, or
successful UI path as proof of payment security. Every acceptance claim must
map to a reproducible test, immutable input fixture, expected state sequence,
and machine-readable audit evidence. Tests use synthetic identifiers only; no
PAN, CVV, production token, biometric template, or production credential is
permitted.

The following claims are expressly outside the test boundary and must never be
inferred from a passing result:

- NFC or RF distance-bounding and relay prevention;
- modification of an EMV kernel, Secure Element, wallet, or payment network;
- a universal guarantee that provisional approvals cannot clear;
- production issuer, TSP, or processor integration before a partner certifies
  its adapter;
- identity proof merely because a device key produced a valid signature.

## 2. Test levels and release gates

| Gate | Level | Required proof | Blocking rule |
|---|---|---|---|
| G0 | Static contract | Schemas, canonical fixtures, transition tables, threat assumptions | Any ambiguous signed field or undocumented transition blocks release |
| G1 | Unit | Deterministic crypto, policy, state-machine, and validation tests | 100% pass; no retries used to obtain green |
| G2 | Property/adversarial | Generated mutations, replay, race, and malformed-message suites | Zero invariant violations across recorded seed set |
| G3 | Integration | Protocol core plus issuer, wallet/TSP, notification, processor, and clearing simulators | Exact event/state trace must match fixture |
| G4 | Resilience | Crash, restart, duplicate delivery, clock, queue, and dependency-failure tests | No unauthorized activation/approval; recovery evidence retained |
| G5 | Security review | Threat-model traceability, dependency scan, secret scan, key-handling review | No unresolved critical/high finding |
| G6 | Partner acceptance | Partner-owned adapter against conformance harness | Partner signs the applicable acceptance matrix |
| G7 | Production-readiness | Sandbox/certification results, operational controls, rollback rehearsal | Required partner and compliance approvals present |

Unit and integration tests must use an injectable clock, deterministic fixture
IDs, and seeded generators. Cryptographic key generation may use fixed
test-only keys from fixtures. Tests of entropy quality use a separate statistical
and platform-validation suite and must never replace cryptographic review.

## 3. System invariants

Each invariant receives a stable ID used in test names, audit events, and
partner conformance reports.

| ID | Invariant |
|---|---|
| INV-01 | A challenge is consumable at most once, including under concurrent requests and retries. |
| INV-02 | Approval is valid only for the exact canonical binding originally issued. |
| INV-03 | Purpose, protocol version, audience, account, subject, token, device, transaction, merchant, amount, currency, issue time, and expiry cannot be substituted. |
| INV-04 | An expired, cancelled, declined, or previously confirmed challenge cannot return to a consumable state. |
| INV-05 | Only the enrolled key for the bound trusted device can approve a challenge. |
| INV-06 | Provisioning cannot activate a token before all policy-required approvals succeed. |
| INV-07 | A capped token cannot exceed its aggregate, velocity, merchant, or transaction controls through concurrency or transaction splitting. |
| INV-08 | Transaction states are monotonic except for explicitly documented clearing/reversal exception paths. |
| INV-09 | Duplicate inbound events are idempotent and do not duplicate financial or security effects. |
| INV-10 | Unknown, unauthenticated, stale, malformed, or unsupported-version events fail closed. |
| INV-11 | Notification delivery is not proof of user approval; only verified challenge consumption is. |
| INV-12 | Biometric/SETI/liveness failure or timeout cannot silently weaken the mandatory device-native control. |
| INV-13 | A partner-enforced provisional flow is never represented as a guaranteed hold unless the partner adapter supplies certified enforcement semantics. |
| INV-14 | Every decision has a correlation ID, causation ID, policy version, actor/device identity, timestamps, and tamper-evident audit record without secret material. |
| INV-15 | Recovery after crash preserves terminal outcomes and cannot resurrect an authorization or provisioning request. |

## 4. Deterministic protocol matrix

| ID | Scenario | Deterministic setup | Expected result |
|---|---|---|---|
| DET-01 | Canonical serialization | Same binding fields inserted in every possible property order | Byte-identical canonical payload and signature verification |
| DET-02 | Unicode and normalization | Merchant/subject fixture containing composed/decomposed Unicode | One documented normalization rule; ambiguous encodings rejected |
| DET-03 | Numeric amount | Minimum, maximum, zero, negative, fractional, and overflow fixtures | Only integer minor units within policy bounds accepted |
| DET-04 | Currency | Supported, unsupported, lowercase, empty, and confusable codes | Exact supported uppercase enum only |
| DET-05 | Time boundary | `now` at expiry minus 1 ms, exactly expiry, and plus 1 ms | Boundary behavior explicitly specified and repeatable |
| DET-06 | Required-field sets | Provisioning versus transaction challenges | Purpose-specific required fields enforced |
| DET-07 | Protocol version | Current, absent, future, and downgraded versions | Current accepted; all others rejected unless negotiated explicitly |
| DET-08 | Audience | Correct issuer audience, alternate environment, empty audience | Only exact environment-scoped audience accepted |
| DET-09 | State graph | Enumerate every state pair | Documented edges succeed; every other edge fails without mutation |
| DET-10 | Audit determinism | Replay same fixture with injected clock/IDs | Same ordered semantic events, excluding documented entropy fields |

## 5. Cryptographic-negative matrix

| ID | Mutation or attack | Required assertion |
|---|---|---|
| CRY-01 | Flip one bit in signature | Verification fails; challenge remains unconsumed |
| CRY-02 | Sign with attacker, revoked, rotated-out, or wrong-device key | Verification fails and key ID is audit-recorded safely |
| CRY-03 | Replace challenge ID | Unknown or mismatch response; no oracle revealing another account |
| CRY-04 | Replace account, subject, token, device, transaction, or merchant | Binding mismatch before state mutation |
| CRY-05 | Change amount from 1000 to 1001 or currency from USD to EUR | Signature/binding verification fails |
| CRY-06 | Change purpose between provisioning and transaction confirmation | Domain separation prevents acceptance |
| CRY-07 | Change audience or environment | Cross-environment replay rejected |
| CRY-08 | Change issued/expiry times or extend TTL | Verification fails |
| CRY-09 | Duplicate JSON keys, alternate number forms, whitespace, or field order | Parser rejects ambiguity or canonicalizes to one documented byte sequence |
| CRY-10 | Empty, truncated, oversized, non-base64url, or non-canonical signature | Validation fails before crypto call where possible |
| CRY-11 | Key-ID substitution with same signature | Key lookup and signature verification fail closed |
| CRY-12 | Algorithm/key-type confusion | Only allow-listed algorithm and curve/key type accepted |
| CRY-13 | Replay signed challenge after success | Second and all later attempts fail as terminal |
| CRY-14 | Replay from another session, tenant, region, or API version | Context-bound verification rejects it |
| CRY-15 | Key revoked between issue and consume | Documented policy enforced atomically; no stale cache acceptance |
| CRY-16 | Randomness health | Large generated challenge-ID sample | No collision; platform CSPRNG source confirmed separately |

Private keys must never leave the test keystore, appear in snapshots, logs, or
exceptions, or cross adapter boundaries. Verification failures must not expose
whether a guessed account, device, token, or challenge exists.

## 6. Adversarial abuse matrix

| ID | Threat | Attack sequence | Secure outcome |
|---|---|---|---|
| ADV-01 | Stolen credentials plus new wallet | Attacker initiates provisioning and controls notification channel | Token remains inactive/capped without trusted-device signature |
| ADV-02 | SMS/email phishing | Attacker supplies a captured transferable code | No protocol path accepts a transferable approval code |
| ADV-03 | Push fatigue | Flood victim with repeated requests | Rate limit, grouping/suppression, explicit context, no implicit approval |
| ADV-04 | Approval substitution | Present benign details, submit signed approval for altered details | Exact binding mismatch rejected |
| ADV-05 | Transaction splitting | Parallel purchases each below single-purchase cap | Atomic aggregate/velocity policy catches total exposure |
| ADV-06 | Merchant substitution | Reuse approval at another merchant | Merchant-bound approval rejected |
| ADV-07 | Token swap | Reuse approval for another provisioned token | Token-bound approval rejected |
| ADV-08 | Device compromise | Valid key but failed attestation/risk posture | Policy-required step-up or decline; no silent bypass |
| ADV-09 | Notification compromise | Fake “approve” callback without signed device payload | Callback rejected |
| ADV-10 | Insider/API tampering | Operator edits state or resends privileged event | Authorization enforced; immutable audit trail exposes attempt |
| ADV-11 | Enumeration | Probe challenge/account/device IDs and timings | Uniform external failure shape and bounded timing variance |
| ADV-12 | Resource exhaustion | Oversized payloads, high-rate creates/consumes, unique-ID floods | Bounded parsing, quotas, backpressure, no security-state corruption |
| ADV-13 | Clearing after reversal | Clearing simulator races reversal | Explicit exception state; never falsely reported as prevented settlement |
| ADV-14 | Goods-release race | Merchant treats provisional approval as final | Harness demonstrates risk and blocks “airlock guarantee” certification |
| ADV-15 | Downgrade | Partner omits security-capability flag or uses old adapter version | Fail closed for policies requiring airlock semantics |

## 7. Concurrency and atomicity matrix

Concurrency tests use barriers so requests reach the critical section together;
results cannot depend on scheduling luck. Each case runs in-process, across
multiple worker processes, and against the real durable store intended for the
deployment profile.

| ID | Concurrent operation | Required outcome |
|---|---|---|
| CON-01 | 100 valid consumes for one challenge | Exactly one confirmed; 99 terminal/replay failures |
| CON-02 | Valid consume versus expiry worker | Exactly one policy-defined terminal outcome, never both |
| CON-03 | Valid consume versus cancel/decline | One atomic winner following documented precedence |
| CON-04 | Two challenge creates with same idempotency key | One logical challenge and one audit creation event |
| CON-05 | Duplicate provisioning callbacks | One token-state effect |
| CON-06 | Cap-lifting approval versus purchase | Purchase sees either old or new complete policy state, never partial state |
| CON-07 | Many capped-token purchases | Aggregate accepted amount never exceeds cap |
| CON-08 | Reversal versus clearing | Only documented terminal/exception trace; no lost event |
| CON-09 | Key revocation versus approval | Serialized, documented precedence; audit records both causes |
| CON-10 | Two service instances consume same challenge | Distributed atomicity preserves INV-01 |
| CON-11 | Crash immediately before/after durable commit | Recovery produces zero or one effect, never duplicated effect |
| CON-12 | Retry after client timeout with same idempotency key | Original result returned without re-execution |

## 8. Provisioning matrix

| ID | Scenario | Expected outcome |
|---|---|---|
| PRV-01 | Existing trusted device approves exact new-token request | Token activates according to policy with auditable key proof |
| PRV-02 | Trusted device declines | Request terminal-declined; token remains inactive |
| PRV-03 | No response before expiry | Request terminal-expired; token remains inactive |
| PRV-04 | No trusted device available | Documented recovery/identity-proofing path; never silent SMS fallback |
| PRV-05 | Trusted device lost/replaced | Recovery revokes old key and enrolls replacement under stronger identity proof |
| PRV-06 | Device key rotated | Old pending signatures handled by explicit policy; new requests bind new key |
| PRV-07 | Multiple trusted devices | Approval threshold and conflict precedence are deterministic |
| PRV-08 | New device is also requesting wallet | No circular self-approval unless partner policy explicitly permits and certifies it |
| PRV-09 | Risk permits capped activation | Cap and velocity policy active before token can transact |
| PRV-10 | Verification lifts cap | Lift is atomic, immediate, and bound to exact token/account |
| PRV-11 | Fraud detected after activation | Token suspension/revocation transition and downstream adapter event are idempotent |
| PRV-12 | Wallet/TSP callback spoof, replay, or reorder | Authenticated/versioned callback rules reject or safely deduplicate |

Recovery must not rely on a fixed punishment window. Legitimate restrictions
lift when the required verification succeeds, subject to current risk policy.

## 9. Transaction lifecycle matrix

| ID | Strategy and sequence | Expected state/evidence |
|---|---|---|
| LIF-01 | Pre-authorization step-up, confirm before deadline | `received -> confirmation_pending -> confirmed`; issuer simulator may approve |
| LIF-02 | Pre-authorization step-up, decline | `received -> confirmation_pending -> declined`; no approval emitted |
| LIF-03 | Pre-authorization step-up, timeout | `received -> confirmation_pending -> expired`; no approval emitted |
| LIF-04 | Low-risk bypass | Policy decision and version recorded; standard issuer outcome without fabricated confirmation |
| LIF-05 | Provisional approval then confirm | Confirmation recorded, while partner-specific completion semantics remain explicit |
| LIF-06 | Provisional approval then timeout | Reversal requested; result never described as “transaction never existed” |
| LIF-07 | Clearing arrives before reversal completes | `clearing_received`/`exception` path retained; exposure reported truthfully |
| LIF-08 | Clearing after reversed | Explicit late-clearing handling; no impossible-state overwrite |
| LIF-09 | Duplicate clearing | One financial effect, duplicate event audit |
| LIF-10 | Reordered processor events | Causation/version checks preserve a valid state or raise an exception |
| LIF-11 | Partial reversal and multi-clearing presentment | Adapter declares unsupported or models amounts precisely; never silently coalesces |
| LIF-12 | Settlement completes | Terminal state immutable except append-only post-settlement evidence |

## 10. Resilience and availability matrix

| ID | Failure injection | Required behavior |
|---|---|---|
| RES-01 | Protocol service restarts at every state boundary | Durable state and idempotency survive; no resurrection |
| RES-02 | Database unavailable before commit | Fail closed; caller can retry safely |
| RES-03 | Database acknowledgement lost after commit | Retry returns original result without duplicate effect |
| RES-04 | Notification service unavailable | Challenge remains pending; delivery failure is not approval |
| RES-05 | Delayed/duplicate/out-of-order queue delivery | Idempotent, causally valid processing |
| RES-06 | Wallet/TSP or processor timeout | Bounded retry with idempotency; no security downgrade |
| RES-07 | Clock skew within/outside permitted tolerance | Documented acceptance window; large skew rejected and alerted |
| RES-08 | Regional failover | Same one-time state and revocation data visible before accepting approvals |
| RES-09 | Audit sink unavailable | Security decision follows documented fail-open/fail-closed policy; evidence queued durably |
| RES-10 | Key service unavailable | No approval accepted without cryptographic verification |
| RES-11 | Liveness/SETI adapter unavailable | Mandatory native-device control remains; optional signal cannot block indefinitely or become auto-pass |
| RES-12 | Disk full/log rotation | Core state remains correct; secrets never dumped; operator alert emitted |
| RES-13 | Dependency returns malformed success | Schema validation rejects it and preserves prior state |
| RES-14 | Network partition between policy and state store | No split-brain approvals or cap oversubscription |

## 11. Audit, privacy, and observability checks

- Assert one correlated event stream for challenge creation, delivery, decision,
  consume attempt, state transition, adapter request, adapter response, and
  terminal outcome.
- Assert audit records are append-only/tamper-evident and preserve ordering or
  explicit causal links across services.
- Assert logs contain synthetic opaque identifiers, not PAN, CVV, cryptographic
  private material, biometric data, bearer credentials, notification contents,
  or complete signed payloads where minimization is possible.
- Assert external errors are safe and uniform while internal evidence remains
  sufficient for fraud investigation.
- Assert retention, deletion, legal hold, and subject-access workflows against
  the partner-agreed data classification.
- Assert metrics distinguish created, delivered, approved, declined, expired,
  replayed, invalid-signature, policy-blocked, reversed, late-clearing, and
  exception outcomes without high-cardinality secret-bearing labels.
- Assert alerts exist for replay spikes, signature failures, provisioning
  surges, cap pressure, stale dependencies, reconciliation drift, and audit
  pipeline failure.

## 12. Partner acceptance matrices

### Issuer / issuer-processor

| Acceptance ID | Partner must prove | Lab evidence required |
|---|---|---|
| ISS-01 | Authenticated, idempotent authorization ingress | Signed fixture, duplicate/reorder results |
| ISS-02 | Pre-authorization step-up semantics and timeout behavior | Exact response codes, latency budget, and state trace |
| ISS-03 | Risk policy and cap enforcement are atomic | CON-06/07 results against partner sandbox |
| ISS-04 | Reversal, clearing, and settlement reconciliation | LIF-06 through LIF-12 reports |
| ISS-05 | No approval is represented as held unless enforceable | Signed capability declaration and negative test |
| ISS-06 | Fraud-ops override uses least privilege and audit | Role matrix and immutable audit export |

### Wallet / token-service provider

| Acceptance ID | Partner must prove | Lab evidence required |
|---|---|---|
| WLT-01 | Provisioning request and token identity are cryptographically/authentically bound | Signed sandbox event fixtures |
| WLT-02 | App-to-app challenge carries no transferable approval secret | Mobile flow capture and protocol trace |
| WLT-03 | Inactive/capped/full token states map to supported platform controls | Capability mapping and failure behavior |
| WLT-04 | Duplicate, stale, and spoofed callbacks are rejected | PRV-12 conformance result |
| WLT-05 | Device/key revocation propagates within agreed SLA | Timed revocation test |

### Network / acquirer / processor

| Acceptance ID | Partner must prove | Lab evidence required |
|---|---|---|
| NET-01 | Message fields and identifiers survive round-trip without lossy remapping | Golden request/response corpus |
| NET-02 | Duplicate and reordered advice/clearing messages reconcile safely | LIF-09/10 report |
| NET-03 | Provisional or deferred semantics, if claimed, are contractually and technically enforced | Certified capability profile |
| NET-04 | Timeout/retry behavior does not create duplicate financial effects | RES-03/06 report |
| NET-05 | Existing EMV timing and terminal behavior remain unchanged unless separately certified | Integration trace and scope statement |

### Trusted-device application / identity provider

| Acceptance ID | Partner must prove | Lab evidence required |
|---|---|---|
| APP-01 | Hardware-backed, non-exportable device key where platform supports it | Attestation and key-generation evidence |
| APP-02 | User sees exact bound action details before native verification | UX capture matched to signed fields |
| APP-03 | Accessibility and interruption paths never convert into approval | Usability/adversarial test report |
| APP-04 | Lost-device recovery cannot be weaker than initial enrollment | Recovery ceremony and threat review |
| APP-05 | Optional liveness signal is additive and privacy-minimized | Failure/timeout matrix and data-flow review |

## 13. End-to-end acceptance scenarios

Every candidate release must produce a replayable evidence bundle for these
scenarios:

1. legitimate provisioning approved by a pre-existing trusted device;
2. fraudulent provisioning denied, ignored to expiry, and replayed;
3. capped activation followed by atomic verification-triggered cap lift;
4. legitimate transaction-specific pre-authorization confirmation;
5. altered amount, currency, merchant, token, and transaction attacks;
6. 100-way concurrent approval replay with exactly one winner;
7. transaction split attempting to exceed the aggregate cap;
8. crash at every write boundary followed by restart and retry;
9. provisional approval, timeout, reversal, and clearing race showing truthful
   exception handling;
10. loss of notification, key, database, audit, and optional liveness services;
11. revoked/rotated device key during an outstanding challenge;
12. complete partner adapter conformance run with partner-owned credentials
    supplied only through its approved secret store.

Each bundle contains the software commit, dependency lock hash, configuration
profile with secrets redacted, fixture set and generator seeds, test command,
start/end timestamps, ordered audit export, state-transition trace, partner
adapter versions, pass/fail summary, and unresolved deviations.

## 14. Exit criteria

A lab milestone is complete only when G0 through G5 pass and all applicable
end-to-end scenarios have evidence bundles. A partner pilot is complete only
when the relevant G6 matrices are signed by the owners of the real adapters.
Production readiness additionally requires G7, external security review,
payment/compliance review, operational runbooks, incident and key-compromise
exercises, reconciliation sign-off, and rollback rehearsal.

Passing this plan proves the implementation follows its declared protocol and
fails safely under the tested conditions. It does not, by itself, certify EMV
compliance, PCI scope, wallet-provider approval, network acceptance, issuer
authorization, RF relay resistance, or settlement guarantees.
