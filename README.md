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

The current storage adapters are in-memory and intended for protocol
demonstration. Durable multi-instance atomicity requires the planned
transactional database adapter and is not claimed by this milestone.

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

No real PAN, CVV, payment token, biometric template, or production credential
belongs in this repository.
