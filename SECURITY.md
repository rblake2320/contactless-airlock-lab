# Security Policy

## Project status

Contactless Airlock Lab is a security reference implementation and partner
demonstration. It is not certified payment software and must not process real
cardholder data, production payment tokens, biometric templates, or production
credentials. The current software demonstrates protocol and state-machine
properties with simulated partner boundaries.

The threat model and security claims are defined in
[THREAT_MODEL.md](THREAT_MODEL.md). Claims made by code, tests, documentation,
or demonstrations must remain within that boundary.

## Reporting a vulnerability

Do not include secrets, personal information, live payment data, or an
unredacted exploit against a production system in a public issue.

Report a suspected vulnerability privately to the repository owner through
GitHub's private vulnerability-reporting feature when enabled. Include:

- affected commit and component;
- reproducible steps using synthetic data;
- expected and observed security behavior;
- impact and plausible attacker prerequisites;
- relevant logs with credentials and sensitive identifiers removed; and
- a suggested remediation, if known.

If private reporting is unavailable, contact the repository owner through a
private channel and request a secure disclosure path before sending details.
The maintainer should acknowledge receipt, preserve evidence, assess severity,
and coordinate a fix and disclosure timeline. No response-time guarantee is
offered until a formal support program exists.

## Supported versions

Only the latest revision of the default branch is evaluated for security fixes
during the laboratory phase. Tags or releases intended for a partner
demonstration must identify the exact commit and dependency lockfile used.
Older snapshots may contain known defects and are not supported unless a
partner agreement states otherwise.

## Data and credential rules

- Use synthetic account, device, token, merchant, and transaction identifiers.
- Never commit PAN, CVV, track data, production tokens, private signing keys,
  API credentials, attestation secrets, or biometric data.
- Store development secrets outside the repository with owner-only access.
- Use distinct credentials and signing roots for development, testing,
  demonstration, staging, and production.
- Redact authorization headers, cookies, signatures, notification tokens,
  partner payload secrets, and sensitive payment fields from logs.
- Treat generated PEM private keys in tests as disposable fixtures. They are
  not a production key-management pattern.

Suspected secret exposure requires immediate containment: revoke or rotate the
credential, preserve a redacted incident timeline, search history and build
artifacts, and remove the secret from every reachable distribution point.
Deleting the current file alone is insufficient.

## Production security requirements

Before any partner pilot with real payment data, the implementation must add
or verify:

- hardware-backed, non-exportable device keys and platform-native user
  verification;
- approved device/app attestation with replay and downgrade protection;
- production key management, rotation, revocation, separation of duties, and
  cryptographic-module requirements agreed with the partner;
- mutually authenticated or message-signed partner integrations;
- durable transactional storage with atomic one-time challenge consumption;
- strong service and operator authentication, least privilege, and dual
  control for sensitive overrides;
- authenticated, idempotent, versioned, schema-validated webhooks;
- rate limiting, abuse controls, circuit breakers, capacity isolation, and
  denial-of-service testing;
- append-only, integrity-protected audit evidence and synchronized clocks;
- dependency pinning, provenance, scanning, signed builds, and controlled
  deployment promotion;
- data classification, encryption, retention, deletion, backup, recovery, and
  regional handling controls;
- independent penetration testing and an architecture review by the issuer,
  processor, wallet/TSP, network, and compliance owners in scope;
- applicable PCI, privacy, consumer-protection, accessibility, operational-
  resilience, and payment-network certification work.

Passing repository tests is evidence about the tested lab behavior only. It is
not evidence of PCI compliance, network certification, regulatory approval, or
production authorization.

The simulator's field-level purposes, locations, retention behavior, deletion
limits, and current downstream status are recorded in
[docs/DATA_INVENTORY.md](docs/DATA_INVENTORY.md). That inventory explicitly
includes the exportable synthetic private key used by persistent demonstrations
and does not approve the same design for production.

The simulator audit log is an unkeyed SHA-256 hash chain. It detects accidental
damage or mutation when the stored chain tip and prior events remain trusted,
but it does not authenticate the history against an attacker who can replace
the entire SQLite snapshot and recompute every hash. The SQLite file is therefore
inside the trusted boundary of this local lab. Production evidence requires an
append-only external sink and an HMAC, digital signature, or independently
anchored chain tip whose key or trust anchor is not stored beside the database.

The repository CI performs strict TypeScript checking, executable lab checks,
a dependency vulnerability audit, an obvious-credential precheck, full-history
Gitleaks scanning, CodeQL JavaScript/TypeScript analysis, and CycloneDX SBOM
generation without repository secrets. GitHub actions are pinned to reviewed
commit SHAs; downloaded scanner archives are version-pinned and checksum
verified before execution. These controls are baseline hygiene, not a
replacement for dependency-review policy, artifact attestation, signed-build
provenance, penetration testing, independent workflow/action review, or partner
security assessment. There is no deployable container in this repository, so
the workflow does not pretend to perform container scanning. See
[docs/PRODUCTION_READINESS.md](docs/PRODUCTION_READINESS.md) for the closure
gate.

## Cryptographic review rules

Protocol changes require review of the complete signed binding, canonical
encoding, algorithm identifiers, key authorization, expiry, replay behavior,
and transaction semantics. Adding a field to an API model without including it
in the authenticated binding can create a substitution vulnerability.

Verification must reconstruct or compare against issuer-owned state. It must
not trust a client-returned binding merely because the signature is valid.
Unknown protocol versions, purposes, audiences, algorithms, fields, keys, and
state transitions fail closed.

Cryptographic code must have cross-language test vectors before a second SDK or
partner adapter is treated as compatible. Randomness must come from the
operating system's cryptographically secure generator. Custom cryptographic
primitives are prohibited.

## Failure and fallback rules

A request already classified as requiring trusted-device confirmation cannot
be silently downgraded because push delivery, the verifier, a partner adapter,
attestation, or the trusted device is unavailable. It must remain inactive or
capped, decline, expire, or return an explicit retry/step-up result according
to the documented issuer policy.

SMS, email, support knowledge questions, and manually transferable codes are
not equivalent fallback authenticators for this protocol. Account recovery is
a separate, high-assurance workflow with delay, notification, revocation, and
operator controls appropriate to its risk.

Optional SETI/liveness inputs are additive signals. Their failure or timeout
must fall back to the mandatory device-native authorization baseline rather
than blocking indefinitely or approving without that baseline.

## Secure development and review

Every security-relevant change should include:

1. the threat or invariant it addresses;
2. tests for the successful path and adversarial failure paths;
3. concurrency tests when state can race;
4. review of log and error-message data exposure;
5. compatibility and downgrade analysis; and
6. updated protocol documentation when externally visible behavior changes.

Tests must cover replay, purpose/audience substitution, field tampering,
unknown and revoked keys, expiry boundaries, concurrent consumption, duplicate
partner delivery, clearing/reversal ordering, verifier outages, and
authorization-policy failures. Network calls in the default test suite must be
mocked or use a deliberately isolated local simulator. Live partner tests must
be separately marked and opt-in.

## Demonstration integrity

A demonstration must identify which systems are real and which are simulated.
It may prove device-key signing, binding validation, single-process one-time
consumption, state transitions, policy behavior, and adapter contracts. It may
not claim to prove durable multi-instance atomicity or
control of a wallet, TSP, issuer processor, network, merchant, or clearing
system that was represented by a simulator.

Performance figures must state hardware, workload, concurrency, warm/cold
state, software revision, and whether any partner boundary was mocked. Security
scores or claims must be tied to reproducible tests or an identified external
assessment rather than generated narrative.

## Security ownership

Until formal owners are named, the repository owner is the final decision-maker
for vulnerability triage and release acceptance. A production pilot must assign
named owners for protocol security, fraud policy, cryptographic key management,
partner integrations, privacy, incident response, and operational reliability.
No single person should be able to change signing policy, deploy that change,
and erase its audit evidence.
