# Partner Pitch and Demo Acceptance Criteria

## Goal

The demo must give a prospective issuer, processor, wallet provider, TSP, or
network partner a working system they can inspect and replace at defined
boundaries. It must distinguish cryptographic and state-machine proof from
simulated rail behavior. A polished screen without reproducible evidence is not
an accepted demo.

## Required end-to-end demonstrations

### Trusted-device enrollment

- Enroll a device-bound public key without storing biometric material.
- Require device-native user verification before signing.
- Display the registered device and revoke it.
- Prove a revoked, unknown, or substituted key cannot approve a challenge.

### Provisioning defense

- Simulate a criminal attempting to provision a stolen account credential onto
  a new wallet device.
- Send the exact provisioning intent to a previously trusted device.
- Deny or let the challenge expire and prove the simulated token remains
  inactive or partner-policy restricted.
- Approve a fresh request and prove one-time consumption plus the resulting
  simulated lifecycle transition.
- Demonstrate that copied payloads, signatures, or old approvals cannot be
  replayed or applied to a different wallet, device, account, or capability.

### Transaction-specific step-up

- Bind the challenge to amount, currency, merchant, token, transaction
  reference, and expiry.
- Approve the exact intent and reject any field substitution.
- Demonstrate timeout, duplicate delivery, reordered events, and concurrent
  approval attempts.
- Show pre-authorization step-up or decline-and-retry as the strong control.

### Clearing and reversal truth test

- Return a simulated `APPROVED`, then exercise reversal-before-clearing,
  clearing-before-reversal, lost reversal, duplicate clearing, and late
  presentment.
- Show that approved-then-reversal cannot guarantee no merchant release, no
  settlement, or no financial loss.
- Label this path as fraud mitigation and exception handling.
- Demonstrate a strong airlock guarantee only in a simulated partner-enforced
  flow where approval or completion is actually withheld.

## Evidence required for every scenario

- Stable scenario ID and deterministic or recorded inputs.
- Timestamped correlation and causation identifiers.
- Canonical payload digest and key identifier, without secret material.
- State-transition history with the actor and reason for every transition.
- Original and duplicate delivery outcomes.
- Final challenge, token, authorization, reversal, clearing, and settlement
  states as applicable.
- Machine-readable test result plus a human-readable explanation.
- Clean environment reset instructions and a single command to reproduce.

## Security acceptance

The demo fails acceptance if it:

- uses real PAN, CVV, payment tokens, cryptographic secrets, or biometric
  templates;
- logs private keys, complete signed payloads containing sensitive partner data,
  credentials, or bearer tokens;
- accepts unsigned or expired approval;
- permits challenge reuse or transaction-field substitution;
- defaults to approval on adapter error, timeout, or ambiguity;
- represents simulator behavior as a certified production-rail capability;
- claims that reversal makes settlement or merchant loss impossible.

## Reliability acceptance

Automated tests must prove:

- atomic single-use challenge consumption under concurrency;
- idempotent handling of partner retries;
- terminal-state monotonicity;
- safe restart and event reconciliation;
- bounded expiration using server-authoritative time;
- deterministic failure for corrupted or mismatched signatures;
- adapter timeouts and circuit-breaking without default approval;
- no lost audit event between committed decision and emitted response;
- clean handling of delayed and contradictory lifecycle events.

The default test suite must be simulation-only and must not contact production
services. Partner sandbox tests must be separately marked, explicitly enabled,
and leave no active transaction or token requests after completion.

## Partner replacement exercise

The pitch is technically complete when a thin reference adapter can be replaced
without changing the protocol core. The partner should be able to identify:

1. where its authorization request enters;
2. where its issuer decision leaves;
3. where provisioning requests and token lifecycle outcomes enter;
4. how push/app-to-app delivery is invoked;
5. how signatures and attestation are verified;
6. how clearing, reversal, and settlement events reconcile;
7. which system enforces caps or deferred completion;
8. which evidence supports operations, disputes, and security review.

## Claims the demo may make

- It proves device-bound, transaction- or provisioning-specific signed consent.
- It proves replay resistance, exact-field binding, expiry, and atomic
  consumption in the protocol core.
- It demonstrates replaceable processor and wallet/TSP adapters.
- It reproduces race conditions that a partner integration must handle.
- It provides a concrete integration and certification target.

## Claims the demo may not make

- It modifies NFC, EMV kernels, Apple Pay, Google Pay, Secure Elements, or
  production network rails.
- It provides RF distance bounding or prevents every contactless relay.
- It provisions a real payment token without authorized wallet/TSP access.
- It guarantees no settlement after an ordinary approval and later reversal.
- It proves partner infrastructure behavior before sandbox and certification
  evidence exists.

## Pitch completion gate

The partner package is ready to present when all required scenarios pass from a
clean checkout, evidence is exported without secrets, architectural limitations
are displayed in the demo rather than buried in fine print, adapter contracts
are versioned, and an independent reviewer can reproduce both the successful
security paths and the approved-then-reversal failure cases.

