# Processor and Issuer Integration Boundary

## Purpose

This boundary turns the lab's payment-rail simulator into an integration target
for an issuer, issuer processor, network program, or acquiring partner. The
protocol core is production-shaped, but the included processor adapter is a
replaceable simulator. It does not send or receive real authorization,
clearing, settlement, or reversal messages.

## Ownership

The Airlock core owns:

- challenge creation, canonical transaction binding, expiry, and one-time use;
- trusted-device signature verification;
- policy decisions such as `ALLOW`, `STEP_UP`, `DECLINE`, or `LIMIT`;
- monotonic challenge and approval state;
- idempotency records and tamper-evident audit events;
- correlation of authorization, confirmation, reversal, and clearing events.

The processor or issuer adapter owns:

- translating network- or processor-specific messages into the canonical
  Airlock request;
- verifying transport identity, signatures, certificates, and webhook replay
  controls at the partner edge;
- returning the issuer decision within the rail's actual response deadline;
- transmitting declines, approvals, advice, reversals, and exceptions;
- delivering clearing and settlement notifications;
- reconciliation against the processor's system of record.

## Canonical authorization input

An adapter should provide, when available:

- stable partner, issuer, account-token, and device-token references;
- amount and currency in unambiguous minor units;
- merchant identifier, merchant name, category code, terminal identifier, and
  country;
- transaction type, channel, card-present indicator, token assurance data, CVM
  result, terminal unpredictable-number reference, and network trace reference;
- event time, partner idempotency key, correlation ID, and causation ID.

The core must never require raw PAN, CVV, track data, payment cryptograms, or
production token keys. Partner references must be opaque and non-reversible.

## Supported decision patterns

### Pre-authorization step-up

The partner withholds approval while a transaction-specific challenge is
confirmed. This provides the strongest airlock property because the merchant
has not received an approval. It is deployable only where the issuer,
processor, network, and merchant experience can tolerate the bounded
confirmation workflow. Timeout must fail according to an agreed policy,
normally decline or a low-risk fallback explicitly approved by the issuer.

### Decline-and-retry

The issuer declines a policy-selected transaction and requests trusted-device
confirmation. A later merchant retry can be approved if it matches the
confirmed intent within a narrow window. Matching rules and customer messaging
are partner-specific, and the design must prevent a confirmation for one
transaction from authorizing a substituted amount, currency, merchant, token,
or replay.

### Partner-enforced deferred completion

A partner may expose a provisional state that cannot become a merchant-releasable
approval until confirmation. This can support a strong airlock only when the
partner contract and rail mechanics actually enforce deferred completion.
The simulator demonstrates the state machine; it does not prove that an
existing payment rail supports it.

### Approved then reversal

Returning `APPROVED` and later sending a reversal is not a settlement
guarantee. The merchant may release goods immediately, clearing may race the
reversal, a reversal may be lost or rejected, and later presentment may still
require exception handling. The lab models these outcomes as fraud mitigation
and operational recovery, never as proof that settlement or loss is impossible.

## Adapter contract

Every adapter implementation must:

1. Authenticate the caller and validate the partner-specific envelope.
2. Map inputs to the canonical model without silently dropping security-bound
   fields.
3. Submit each external event with a partner-scoped idempotency key.
4. Treat duplicate delivery as a replay-safe read of the original result.
5. Preserve correlation and causation IDs across subsequent events.
6. Enforce real response deadlines outside the protocol core.
7. Map core errors to documented partner outcomes without default approval.
8. Deliver clearing, reversal, and settlement events even when they contradict
   an earlier expected path.
9. Reconcile missed events after outages.
10. Emit metrics without exposing payment credentials or signed payloads.

## Security and operational requirements

- Mutual TLS or an equivalent authenticated private transport.
- Signed webhooks with timestamp, nonce, key identifier, and replay window.
- Partner-specific keys stored in a managed secret system, never source control.
- Key rotation with overlapping verification and an auditable cutover.
- Least-privilege service identities and environment separation.
- Fail-closed behavior for malformed, unverifiable, or ambiguous requests.
- Atomic decision and audit persistence before any response is emitted.
- Redacted structured logs and immutable security-event retention.

## Certification evidence

A production adapter is not accepted until it passes duplicate delivery,
reordering, delayed clearing, reversal/clearing races, timeouts, network
partitions, key rotation, mismatched transaction binding, retry storms, and
reconciliation tests. Simulator success establishes protocol behavior only;
partner certification establishes rail behavior.

