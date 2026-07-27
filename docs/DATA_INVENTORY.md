# Current-Scope Data Inventory

## Status and scope

This inventory describes the repository's current simulator and development
artifacts. It is not a production data-protection impact assessment, PCI scope
decision, retention approval, or partner privacy authorization. The lab accepts
synthetic data only. A real pilot requires a new inventory tied to actual
controllers, processors, regions, integrations, backups, telemetry, and legal
requirements.

The default lab is ephemeral. When `AIRLOCK_DB_PATH` is configured, the
simulator intentionally persists state—including an exportable synthetic demo
private key—to a local SQLite database. That design exists only so restart and
race behavior can be demonstrated. It is prohibited for production keys.

## Inventory

| Data class | Current examples | Purpose | Current location | Current retention | Deletion | Current downstream status |
|---|---|---|---|---|---|---|
| Synthetic subject/account identifiers | `demo-subject-001`, `demo-account-001` | Correlate simulator state and exercise bindings | Process memory; public `/api/state`; audit events; optional SQLite snapshot | Process lifetime when ephemeral; until SQLite file removal when persistence is enabled | Reset replaces active state but persisted history may remain in idempotency/outbox records; delete the disposable database and evidence artifacts for full lab cleanup | Browser lab and local test clients only; no partner |
| Synthetic trusted-device and credential identifiers | device ID, key ID, credential ID | Bind approval authority and demonstrate revocation | Process memory; public state/audit as opaque identifiers; optional SQLite snapshot | Same as simulator state | Reset/database deletion; credential revocation changes status but is not erasure | Browser/test clients only |
| Synthetic payment-token identifier and token policy | token ID, activation state, cap values | Exercise provisioning and spend-control state | Process memory; public state/audit; optional SQLite snapshot | Same as simulator state | Reset/database deletion | Browser/test clients only; not a network token |
| Synthetic transaction and merchant data | transaction ID, merchant ID, amount minor, currency, lifecycle state | Exercise exact transaction binding, timeout, reversal, and clearing races | Process memory; public state/audit; optional SQLite snapshot/idempotent response | Same as simulator state; idempotent responses remain until disposable database deletion | Reset removes active state only; delete database to remove durable copies | Browser/test clients only; no acquirer, processor, issuer, or network |
| Challenge bindings | random challenge ID, purpose, account/token/device/transaction bindings, issuance and expiry | Prevent replay and substitution in the protocol demonstration | Process memory; public state/audit where needed for the visible demonstration; optional SQLite snapshot | Until terminal state/process exit, or database deletion | Reset/database deletion | Browser/test clients only |
| Synthetic P-256 public key material | PEM public key inside engine/device state | Verify simulator approvals | Process memory and optional SQLite snapshot | Process lifetime or database lifetime | Reset/database deletion | Not returned by the current public snapshot; no downstream partner |
| **Synthetic exportable P-256 private key** | PEM private key generated at simulator startup | Sign deterministic local demonstration approvals | Process memory; optional SQLite snapshot when persistence is enabled | Process lifetime or until database deletion | Stop/reset replaces the in-memory key; securely dispose of the disposable database and copies | Never belongs in HTTP output, audit, logs, source control, or partner messages. This is simulator-only risk and is not hardware-backed WebAuthn |
| Approval signatures | Base64url signature created during local approval | Exercise signature verification | Transient call-local object; not intentionally persisted, logged, audited, or returned | Until garbage-collected after verification | Process termination; no durable copy is intended | Protocol verifier only |
| Audit events and integrity hashes | event type, correlation/causation IDs, selected synthetic decision fields, timestamps, hash chain | Demonstrate decision trace and tamper evidence | Process memory; public `/api/state`; optional SQLite snapshot | Process/database lifetime | Reset/database deletion; no selective mutation is supported | Browser/test clients only; not an authentic production audit sink |
| Public UI state | provisioning, token, transaction, challenge, last-result, and audit views | Drive the transparent partner demonstration | HTTP JSON/SSE response and browser memory | Response/browser lifetime; server sends `no-store` | Close/reset browser and reset/delete lab state | Same-origin browser or explicit local client |
| HTTP request bodies | amount and merchant; hostile tests may include ignored synthetic fields | Invoke simulator mutations and test validation | Bounded request buffer in process memory; canonical request hash for persistent idempotency | Buffer is request-scoped; hash/response follows database lifetime | Garbage collection; database deletion for durable hash/response | No downstream system |
| HTTP authorization/cookie-like headers | Test-only sentinel values; no current authentication implementation | Negative privacy and security testing only | Node request object for request lifetime | Request lifetime | Automatic after request object release | Must not enter error responses, public state, audit, console output, or durable simulator state |
| Idempotency key and request hash | `Idempotency-Key`, SHA-256 request hash | Deduplicate persistent mutations and reject key/body reuse | Request memory and SQLite `idempotency_records` in persistent mode | Until disposable SQLite database deletion; no current TTL compactor | Delete database; production requires bounded retention/compaction | Not exposed in public state/audit; no partner |
| Idempotent HTTP response | status and public response JSON | Replay the original result exactly | SQLite `idempotency_records` | Until database deletion | Delete database | Returned only to a request presenting the same scoped idempotency key/hash |
| Durable simulator snapshot | engine, challenges, audit, UI state, synthetic key pair | Demonstrate restart continuity and competing-writer rejection | SQLite durable record | Until database deletion | Delete disposable database and copies | Local simulator only |
| Transactional outbox test records | topic, aggregate/event IDs, synthetic JSON payload, lease/delivery metadata | Exercise at-least-once delivery mechanics | SQLite outbox table in storage tests/lab components | Until database deletion | Delete database; production needs retention/compaction policy | No real consumer or partner |
| Console startup diagnostics | bind address/port, simulator-only warning, configured database path | Local operator awareness | Standard output of the server process | Terminal/service log policy outside this repository | Delete/rotate external process logs | Local operator; database path may be operationally sensitive and must not contain credentials |
| Source, fixtures, and protocol vectors | synthetic identifiers, invalid cases, canonical bytes/hashes | Reproducible development and cross-language verification | Git repository and CI checkout | Repository history | Normal reviewed history rewrite/removal policy; rotate any accidentally committed real secret regardless of removal | GitHub collaborators/public readers according to repository visibility |
| CI evidence | test output, dependency audit, CodeQL/Gitleaks results, CycloneDX SBOM | Quality and supply-chain evidence | GitHub Actions logs/security UI; SBOM artifact | GitHub policy; SBOM artifact explicitly 14 days | GitHub artifact/log controls | GitHub and authorized repository users; must contain no live payment/customer data |

## Current minimization rules

- Do not enter real PAN, CVV, track data, payment tokens, customer identities,
  notification tokens, credentials, biometric material, or partner payloads.
- HTTP errors describe validation or state failures without reflecting request
  values, headers, private key material, or signatures.
- Public state exposes demonstration bindings and synthetic decisions but not
  the synthetic private key, public-key PEM, raw approval signatures,
  authorization headers, or idempotency keys.
- Audit payloads contain synthetic decision evidence only. They do not receive
  raw requests or headers.
- The server has startup diagnostics, not per-request logging. Adding request
  logs requires a privacy review and field allowlist before deployment.
- Reset is a workflow reset, not guaranteed erasure of SQLite idempotency,
  outbox, filesystem copies, terminal output, CI evidence, or backups.

## Production decisions still required

Before real data is allowed, named privacy, security, fraud, legal, operations,
and partner owners must approve:

1. the controller/processor and downstream-recipient map;
2. PCI and regional privacy scope for each field and system;
3. field-level collection purposes and necessity;
4. retention, compaction, legal-hold, deletion, backup, and restoration rules;
5. access roles, audit access, subject-rights handling, and dispute evidence;
6. encryption and key-management boundaries;
7. telemetry schemas and redaction/tokenization controls;
8. partner contracts and cross-region transfers; and
9. an incident process for payment, identity, credential, or logging exposure.

Until that approval exists, this inventory supports simulator engineering
claims only.
