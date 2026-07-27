# Wallet and Token Service Provider Adapter Boundary

## Purpose

This boundary replaces transferable provisioning verification, especially SMS
OTP, with a signed challenge approved on a previously trusted device. The lab
supplies a wallet/TSP simulator so the complete protocol can be demonstrated
without pretending to provision a real Apple Pay, Google Pay, or network token.
A wallet provider, token service provider, issuer, or processor replaces that
simulator with an authorized adapter.

## What the Airlock core owns

- creation of a single-use provisioning challenge;
- binding to issuer, account reference, requested wallet, requesting-device
  reference, token-requestor reference, and requested capability;
- expiry, attempt limits, replay prevention, and atomic consumption;
- verification of the trusted device's registered public key;
- policy outcomes such as reject, cap, suspend, or activate;
- audit evidence linking request, user confirmation, decision, and token state.

## What the partner adapter owns

- authenticated receipt of the real provisioning request;
- mapping wallet/TSP fields into the canonical challenge;
- device and application attestation verification where supported;
- push or app-to-app delivery through approved provider channels;
- calling the TSP or wallet lifecycle API to activate, restrict, suspend, or
  reject the token;
- reflecting the authoritative token state back to the Airlock core;
- reconciling delayed, duplicated, or out-of-order lifecycle events.

The adapter must use documented partner interfaces. The lab does not emulate a
Secure Element, payment cryptogram, wallet private API, or network token vault.

## Signed-challenge flow

1. The partner receives a provisioning request and assigns an idempotency key.
2. The adapter creates a canonical request using opaque account and device
   references; raw payment credentials never enter the Airlock core.
3. The core issues a short-lived nonce bound to the exact provisioning intent.
4. A previously enrolled trusted application displays the wallet, requesting
   device, issuer, and capability being requested.
5. Device-native user verification authorizes a hardware-backed signature.
6. The core verifies the signature, challenge state, bindings, and policy.
7. The adapter applies the resulting token action through the real TSP/wallet
   interface and reports the authoritative outcome.

No manually typed or transferable confirmation code is part of this flow.
Biometric material never leaves the device; the core receives only a signed
assertion and permitted attestation evidence.

## Bootstrap and recovery

A trusted-device approval system needs an honest bootstrap path. Initial
enrollment and recovery must be implemented through issuer-controlled identity
proofing appropriate to the account risk. Recovery cannot silently degrade to
the same SMS-only mechanism the protocol is intended to protect against.

Recommended partner options include in-app re-proofing, branch or contact-center
verification with fraud controls, verified account history, passkey recovery,
or multiple previously trusted devices. Recovery events receive stronger
monitoring and may impose temporary restrictions until additional confidence is
established. Restrictions lift on verified evidence, not merely elapsed time.

## Token-state requirements

- State transitions are monotonic and idempotent.
- `ACTIVE` is never inferred from a successful notification or signature alone;
  it is recorded only after the partner confirms the lifecycle operation.
- A denied or expired challenge cannot activate a token.
- Concurrent approvals consume at most one challenge.
- A replacement challenge invalidates or explicitly supersedes its predecessor.
- Caps and restrictions are enforced by the system that actually authorizes
  spend, not only displayed in the Airlock application.
- Token deletion, suspension, device loss, and account closure propagate in
  both directions and are reconciled after outages.

## Optional SETI or liveness signal

SETI/liveness can contribute an additional confidence score only through a
versioned adapter. Device-native user verification and the signed challenge
remain the baseline. SETI failure, unavailability, or timeout must follow an
explicit partner policy and must not leave provisioning indefinitely pending.
No biometric template is stored in this repository or transmitted through its
canonical protocol.

## Replaceability test

The wallet/TSP simulator is replaceable when a partner adapter can pass the
same contract suite without changes to challenge construction, signature
verification, state transitions, or audit semantics. Provider-specific fields
remain inside the adapter; only explicit, versioned canonical extensions may
cross the boundary.

## Production acceptance

Acceptance requires partner-side proof of lifecycle enforcement, not merely a
successful simulated API response. Tests must cover stolen credentials,
criminal-controlled requesting devices, push fatigue, replay, substituted
wallet/device identifiers, expired challenges, concurrent approvals, lost
callbacks, key rotation, recovery abuse, token suspension, and reconciliation.

