# Threat Model

## Scope and security objective

Contactless Airlock Lab is a reference implementation for two controls:

1. a new payment token cannot become fully usable until a previously trusted
   device authorizes a transaction-bound provisioning challenge; and
2. a policy-selected transaction can require a fresh, transaction-specific
   approval before an issuer or participating processor makes the decision
   that its integration contract permits.

The objective is to prevent possession of transferable account data, an SMS
code, or a compromised wallet account from being sufficient to provision and
use a payment token. The objective is not to replace EMV cryptograms, detect RF
distance, or create settlement guarantees outside a partner's actual authority.

## Protected assets

- trusted-device private keys and their enrollment records;
- challenge uniqueness, expiry, purpose, audience, and one-time status;
- the binding between an approval and the exact account, token, device,
  transaction, merchant, amount, currency, and protocol version;
- token activation state and temporary spending restrictions;
- issuer authorization and risk decisions;
- idempotency, correlation, and causation identifiers;
- append-only security and audit evidence;
- customer notification destinations and privacy-sensitive transaction data;
- adapter credentials used to reach issuer, processor, wallet/TSP, network, or
  notification systems.

No real PAN, CVV, production payment token, biometric template, or production
credential is an acceptable lab asset. Test fixtures must use synthetic values.

## Trust boundaries

### Wallet/TSP to issuer provisioning

The wallet or token service provider initiates provisioning, but it is not
trusted to assert that a previously enrolled issuer device approved it. The
issuer must authenticate the partner message, bind it to a unique request, and
verify the trusted-device signature itself. A wallet-generated success signal
cannot substitute for issuer-side challenge consumption.

### Merchant, acquirer, processor, and network to issuer

Authorization and clearing events cross separately authenticated boundaries.
They may be delayed, duplicated, reordered, or delivered after a timeout or
reversal request. The issuer must not infer that a reversal erased an approval,
prevented release of goods, or guaranteed that clearing cannot arrive.

### Issuer backend to trusted application

Push delivery is an untrusted notification mechanism. A push message may wake
the application, but all authoritative challenge content must be fetched over
an authenticated channel and independently verified. Push text and deep-link
parameters are never signing inputs by themselves.

### Trusted application to device key

Application code and the operating system are less trusted than a
hardware-backed, non-exportable key. The lab's PEM keys demonstrate protocol
semantics only. A production adapter must use platform-backed key storage,
require local user verification under issuer policy, and provide attestation
or equivalent key-origin evidence where the platform supports it.

### Partner adapters to protocol core

Adapters are hostile-input boundaries. Every inbound message must be
authenticated, authorized for the named audience, schema-validated, versioned,
size-bounded, replay-protected, and idempotent. Adapter failures must not mutate
core state through an unverified callback or ambiguous retry.

### Operators to fraud and audit systems

Operators receive least-privilege roles. No single support operator may enroll
a new trusted device and approve that same device's provisioning request.
Administrative overrides require strong authentication, explicit reason codes,
dual control for high-risk actions, and immutable audit events.

## Threat actors and assumptions

Threat actors include a thief with card/account information, a social engineer,
malware on an endpoint, a compromised wallet account, a malicious merchant, a
partner or operator with excessive access, an attacker replaying captured API
traffic, and an attacker able to delay or reorder messages. We assume modern
cryptographic primitives remain secure and that at least one originally
enrolled trust anchor was established through an issuer-approved identity
process. We do not assume push delivery, SMS, email, device display text,
merchant-supplied labels, or wall-clock ordering is trustworthy.

## Primary attack scenarios and controls

### Fraudulent token provisioning

An attacker uses stolen account data and intercepts or social-engineers an SMS
OTP. The defense is a signed challenge delivered to a previously trusted
device, bound to the candidate payment token and account. No typed or
transferable confirmation code is accepted. Absence of approval leaves the
token inactive or subject to a deliberately narrow, issuer-defined cap.

### Approval phishing and push fatigue

An attacker repeatedly triggers prompts or lies about their purpose. The
trusted application displays issuer-sourced purpose and salient request facts,
rate-limits prompts, groups duplicates, and provides a prominent deny/report
path. Provisioning and transaction approvals use different purpose values, so
a signature collected for one cannot authorize the other.

### Replay, substitution, and confused deputy

An attacker replays a valid signature or substitutes a different token,
transaction, merchant, amount, currency, account, device, or audience. The
canonical signed binding includes all of those applicable fields plus a unique
challenge ID, issuance time, expiry, purpose, and protocol version. Verification
must compare the signed binding to the issuer's stored record before atomically
consuming it exactly once.

### Concurrent approval and timeout

Approval, denial, expiry, cancellation, retry, and clearing may race. State
changes require compare-and-set semantics in one durable transaction. A
challenge cannot transition from a terminal status, and only one contender can
consume it. Wall-clock expiry must be evaluated by the authoritative service,
not accepted from the client.

### Compromised or replaced trusted device

A compromised device may approve requests while unlocked or leak application
data. Production keys must be non-exportable and gated by device-local user
verification. Recovery, device replacement, and revocation require a separate
high-assurance process; a newly enrolled device must not instantly become the
sole authority for approving its own enrollment or removing every older device.

### Partner webhook forgery

An attacker forges authorization, clearing, reversal, or provisioning events.
Partner adapters require mutually authenticated transport or signed messages,
short-lived credentials, source authorization, replay windows, idempotency
keys, and key rotation. Network location or a secret URL is not authentication.

### Reversal and late clearing

A merchant releases goods after an approval, clearing arrives after expiry, or
a reversal races clearing. The state machine records these outcomes rather than
pretending they cannot occur. A post-approval reversal is mitigation, not a
cryptographic airlock. A true pre-release guarantee is claimed only when a
partner contract enforces confirmation before approval or deferred completion.

### Denial of service

An attacker floods challenges, withholds confirmations, targets notification
delivery, or exhausts signing-verification capacity. Controls include per-
account/device/IP/partner rate limits, bounded queues and payloads, circuit
breakers, independent authorization-service capacity, and an issuer-defined
fail policy. Availability pressure must never silently convert a protected
request into an unprotected approval.

### Audit tampering and repudiation

An attacker or operator edits evidence after a dispute. Security events are
append-only, time-synchronized, correlation-linked, integrity-protected, and
exported to retention-controlled storage. Logs record decisions and key IDs,
not private keys, full credentials, biometric material, or sensitive payment
data unnecessary to the investigation.

The optional authenticated audit profile adds per-event HMAC tags and an
external chain-tip anchor. Its key and anchor must remain outside the
SQLite/snapshot compromise boundary; the ordinary hash chain alone cannot stop
an attacker with write access from recomputing the entire chain. The current
browser simulator does not yet wire the optional profile into restart storage.
See [docs/AUTHENTICATED_AUDIT.md](docs/AUTHENTICATED_AUDIT.md).

The current lab uses an unkeyed SHA-256 hash chain. It detects accidental
damage and edits whose hashes were not recomputed, but it does not authenticate
the origin of a complete chain. A writer who controls the SQLite snapshot can
replace the events and recompute every hash. Therefore the local database is
inside the simulator trust boundary and the lab must not describe its audit
chain as immutable or independently authentic. A production design needs an
append-only external sink plus an HMAC, signature, or signed chain checkpoint
whose key or trust anchor is not stored beside the database.

## Required cryptographic properties

- Production device keys are hardware-backed, non-exportable, independently
  identified, revocable, and scoped to this protocol.
- The current P-256/SHA-256 implementation is a lab profile; production
  deployments must use partner-approved algorithms and crypto modules.
- Canonicalization is deterministic, versioned, unambiguous, and tested across
  every supported language. Unknown or duplicate fields are rejected.
- Challenge IDs contain at least 128 bits of cryptographically random entropy.
- Signatures are verified against the stored device key and stored challenge,
  never solely against client-returned content.
- Expiry, audience, purpose, account, token, and device authorization are
  checked before atomic one-time consumption.
- Transport security is mandatory but does not replace message authentication,
  authorization, or replay protection.
- Key rotation preserves verifiable historical key identifiers without
  retaining superseded private keys.

## Failure policy

For a request selected for mandatory protection, signature failure, unknown
key, expired challenge, state conflict, missing binding, unavailable trusted
device, unavailable verifier, or ambiguous partner response fails closed:
decline, remain inactive/capped, or return a defined retry/step-up outcome.
There is no silent fallback to SMS or an unprotected approval.

Low-risk traffic may follow an issuer's documented baseline policy only when
the policy engine selected it before a failure. An outage must not downgrade a
request that was already classified as requiring the airlock. Partner retries
are idempotent. Human overrides are exceptional, least-privilege, reason-coded,
and audited.

## Privacy and data minimization

The trusted-device screen receives only the information needed for an informed
decision. Logs and analytics use opaque identifiers or keyed pseudonyms rather
than PANs or stable cross-context identifiers. Notification payloads contain no
sensitive transaction details. Biometric matching remains device-native; the
issuer receives only the platform's authorization result and allowed
attestation evidence, never a biometric template.

Retention is purpose-limited by data class. Test and demonstration environments
use synthetic identities and payments. Production partner adapters require a
data-flow inventory, regional and contractual review, subject-access/deletion
procedures where applicable, and controls preventing production data from
entering development telemetry.

## Explicit non-goals

This project does not:

- modify NFC radio behavior, EMV kernels, Secure Elements, Apple Pay, Google
  Pay, card-network rules, or terminal timeout requirements;
- provide RF distance-bounding or claim to prevent NFC relay attacks;
- claim that an issuer reversal recovers released goods or prevents clearing;
- create a universal hold between authorization and capture without an
  enforcing processor/network/merchant partnership;
- replace EMV cryptograms, issuer authorization, PCI controls, device platform
  security, or partner fraud systems;
- treat SETI/liveness signals as mandatory or blocking; they are optional
  additive evidence and never replace the device-native authorization baseline;
- prove patentability, regulatory compliance, network certification, or
  production readiness by the existence of this lab.

## Validation obligations

Release gates must include deterministic canonicalization vectors, negative
signature tests, replay and cross-purpose substitution, one-time consumption
under concurrency, expiry-boundary races, device revocation, duplicate and
out-of-order partner events, delayed clearing, reversal races, notification
failure, verifier outage, audit-integrity checks, and privacy-log inspection.
Partner demonstrations must label simulated boundaries and must not present a
mock adapter as evidence of production rail control.
