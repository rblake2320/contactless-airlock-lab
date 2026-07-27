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

The browser lab is ephemeral by default. When `AIRLOCK_DB_PATH` is set, it
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

`packages/credentials` defines and tests the boundary a reviewed WebAuthn/FIDO2
adapter must eventually satisfy. It is not wired into the live lab. Its
deterministic HMAC verifier is test-only, is cryptographically not WebAuthn,
and is mechanically barred from runtime imports by the default test suite.
See [`docs/WEBAUTHN_BOUNDARY.md`](docs/WEBAUTHN_BOUNDARY.md).

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
