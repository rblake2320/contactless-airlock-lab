# Contactless Airlock Lab

Contactless Airlock Lab is a standalone reference implementation for preventing
fraudulent wallet provisioning and proving transaction-specific trusted-device
approval. It is designed to become a concrete partner pitch: issuer,
issuer-processor, wallet/TSP, and network adapters can replace the included
simulators without changing the protocol core.

This repository is intentionally independent. It contains no Beast Studio or
SelfConnect product code. SelfConnect may be used externally to coordinate
development agents, but it is not part of the system.

## Product boundary

The lab builds and tests:

- device-bound trusted-device enrollment;
- signed, single-use provisioning and transaction challenges;
- exact transaction-field binding and replay prevention;
- monotonic state machines with single-process one-time challenge consumption;
- token activation and temporary spending-control policies;
- simulated authorization, confirmation, reversal, clearing, and settlement;
- adversarial scenarios and partner-facing integration contracts.

The lab does not claim to modify NFC, EMV kernels, Secure Elements, Apple Pay,
Google Pay, or production payment rails. A later partner replaces simulator
adapters with their authorized processor, issuer, TSP, or wallet interfaces.

The programmatic browser lab is ephemeral by default. CLI startup fails closed
unless `AIRLOCK_SIMULATOR_MODE=true` explicitly selects the local simulator or
`AIRLOCK_AUTH_CONFIG_PATH` selects authenticated tenant-isolated mode with one
explicit `identityProvider`: `bootstrap-controlled-demo` for synthetic local
use, or `oidc` with verifier options for signed access-token exchange. When
`AIRLOCK_DB_PATH` is set in simulator mode, it
persists a versioned simulator snapshot in SQLite using compare-and-swap
updates and restores pending protocol work after restart. That mode deliberately
stores an exportable synthetic demonstration key and is not a production key
storage design. The lower-level durable store also demonstrates transactional
idempotency, outbox delivery, and competing-writer behavior; it is not yet a
complete production service composition.

An issuer returning `APPROVED` and later reversing cannot by itself guarantee
that goods were not released or that clearing cannot arrive. The simulator
models that race explicitly. A production "airlock" guarantee requires either
confirmation before approval or partner-enforced deferred completion.

## Run

```powershell
npm test
npm run demo
```

For an interactive local browser demonstration:

```powershell
npm run lab
```

Then open `http://127.0.0.1:8788`. The live lab drives the same
`AirlockEngine`, P-256 signatures, challenge store, state transitions,
revocation checks, and hash-chained audit log as the automated tests. It uses
synthetic identifiers and does not connect to a card, wallet, bank, processor,
terminal, or payment network.

`packages/credentials` contains both a production-shaped WebAuthn assertion
adapter backed by pinned `@simplewebauthn/server` code and a deterministic HMAC
test double. The production adapter is exercised with real ES256/COSE fixtures,
but registration, attestation trust, hardware-backed keys, and live-lab
composition remain open. The HMAC verifier is test-only, is cryptographically
not WebAuthn, and is mechanically barred from runtime imports by the default
test suite.
See [`docs/WEBAUTHN_BOUNDARY.md`](docs/WEBAUTHN_BOUNDARY.md).

The repository also contains deliberately bounded, non-deployed adapter
contracts for PostgreSQL durability, signed partner transport, remote audit-key
custody, customer/fraud operations, privacy-safe service telemetry, and an
opt-in controlled-demo capacity gate. Their exact evidence and remaining
external dependencies are tracked in
[`docs/PRODUCTION_READINESS.md`](docs/PRODUCTION_READINESS.md); none substitutes
for a real issuer, processor, wallet/TSP, identity provider, HSM/KMS, or
certification environment.

To exercise simulator-only restart persistence:

```powershell
$env:AIRLOCK_DB_PATH = "$PWD\airlock-lab.sqlite"
npm run lab
```

Stop and restart the process with the same path to restore the exact simulated
engine, pending challenges, audit chain, and UI state. The database contains a
synthetic exportable private key so that the demonstration can continue after
restart. Protect and delete it like test credential material; never reuse this
pattern for production device keys.

Startup is intentionally fail-closed if persisted state is corrupt or
incompatible. Follow
[`docs/SIMULATOR_RECOVERY.md`](docs/SIMULATOR_RECOVERY.md); do not bypass
validation or silently reset evidence.

No real PAN, CVV, payment token, biometric template, or production credential
belongs in this repository.
