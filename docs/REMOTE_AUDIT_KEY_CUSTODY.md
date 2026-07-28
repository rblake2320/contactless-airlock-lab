# Remote Audit Key Custody and Trust Anchors

## Current status

`AsyncRemoteAuditLog` is a production-composition boundary, not a deployed
cloud integration. This turn adds no AWS KMS, Azure Key Vault, Google Cloud
KMS, PKCS#11 HSM, workload credential, external database, or object-lock
account. Both provided production adapters are deliberately unconfigured and
throw on every operation. There is no local-key fallback.

The existing synchronous `AuditLog` and `InMemoryAuditKeyring` remain supported
for deterministic tests and simulator use. They still hold key bytes in process
and must not be represented as production key custody.

The machine-readable adapter requirements are in
[`contracts/audit/remote-audit-custody.v1.json`](../contracts/audit/remote-audit-custody.v1.json).

## Custody boundary

Application code receives only key ID, monotonic version, and active/retired
status. It sends the exact canonical MAC input to `RemoteAuditMacProvider` and
receives a base64url tag or a verification decision. The provider interface has
no method or field that returns raw key bytes.

A real adapter must use a non-exportable HMAC-SHA256 key of at least 256 bits,
authenticate with workload identity, restrict sign/verify/key-metadata
permissions to the audit role, emit provider audit logs, rate-limit abuse, and
retain retired keys for verification throughout audit retention. Provider
unavailability fails the append or restore operation.

Cloud-specific note: an adapter must verify that its selected service actually
supports remote HMAC generation and verification with non-exportable symmetric
keys. A generic asymmetric `Sign` API is not interchangeable with this HMAC
contract. If a provider cannot meet the exact primitive, define and version a
new audit authentication algorithm rather than silently changing semantics.

## Independent anchor boundary

`AuditTrustAnchorPublisher` must use credentials and administration independent
from the mutable audit state store. It publishes with compare-and-swap against
a monotonic revision. Suitable designs may include a separately administered
database, append-only transparency service, or object-lock/WORM record plus a
monotonic index. Merely writing another row in the same SQLite/PostgreSQL
database does not satisfy independence.

An anchor contains hashes, authentication tags, counts, and key metadata. It is
not secret, but it is integrity-critical. Access control must prevent the audit
writer from rolling it back or rewriting history outside the CAS operation.

## Crash consistency

Appending uses a small cross-system journal:

1. construct and remotely MAC the candidate event;
2. atomically prepare the candidate snapshot and anchor in the local state
   store;
3. compare-and-swap publish the anchor externally; then
4. atomically commit the prepared local snapshot.

If anchor publication fails, the prepared state is aborted. If the process
crashes after anchor publication but before local commit, reopen compares the
pending anchor with the published anchor and completes that exact commit once.
If a post-commit acknowledgement is lost, reopen observes the committed state
and does not duplicate it. Any anchor that matches neither committed nor
prepared state fails closed.

This protocol assumes the adapter operations themselves meet their documented
atomic/CAS behavior. It is not a distributed transaction and cannot compensate
for a provider that acknowledges writes it later loses.

## Rotation and rollback

Each event binds key ID and monotonically increasing key version. Historical
events are verified using retired-key metadata and remote verification. A new
active key may be observed before the next append; that append advances the
external anchor to the new active metadata. Equal-version key substitution and
lower-version rollback are rejected.

Operational rotation requires:

- provision and test the next non-exportable key;
- grant the audit workload only the new required permissions;
- activate it monotonically;
- append a rotation evidence event and publish the new anchor;
- retain the prior key in verify-only/retired state;
- test full restore from the oldest retained event; and
- revoke signing permission on the old key without deleting verification
  capability.

## Required adapter and recovery tests

Before production approval, run tests against the real services for:

- provider timeout, throttling, access denial, disabled key, and wrong region;
- anchor CAS conflict, stale reads, partial outage, and credential separation;
- crash before/after prepare, anchor publish, and local commit;
- rotation with historical verification and attempted rollback;
- backup restore with an independently fetched anchor;
- loss of local state, loss of anchor availability, and mismatched pending
  recovery; and
- proof that logs, traces, errors, snapshots, and crash dumps contain no raw
  key material or workload credential.

The deterministic in-memory tests demonstrate protocol behavior only. They do
not prove cloud/HSM durability, credential security, service availability, or
regulatory compliance.
