# Authenticated Audit Evidence

## Threat and smallest honest design

The legacy audit log is a SHA-256 hash chain. It detects accidental edits, but
anyone who can modify its SQLite snapshot can change an event and recompute
every later hash. A valid-looking chain therefore does not authenticate who
produced it.

The optional authenticated profile adds:

- an HMAC-SHA-256 tag to every event;
- a versioned key ID on every tag, allowing explicit rotation;
- authentication-tag linkage across rotations; and
- an external chain-tip trust anchor containing event count, tip hash, tip
  authentication tag, and tip key ID.

The HMAC key and latest accepted trust anchor are deliberately absent from
`AuditLogSnapshot`. Restoring schema version 2 requires both through a separate
trust boundary. This is the smallest design that demonstrates resistance to
snapshot rewriting and suffix deletion without pretending the local SQLite
database can authenticate itself.

## Provisioning and custody

`AuditKeyProvider` is the production integration boundary. The included
`InMemoryAuditKeyring` copies keys into process memory for simulator tests; it
is not an HSM, KMS, secret manager, or production custody mechanism.

For a real deployment:

1. Generate at least 256 bits with an approved cryptographic random generator.
2. Provision keys through an HSM/KMS or equivalent controlled key service.
3. Give the audit writer permission to compute tags, not export raw keys.
4. Give the verifier only the minimum verification capability it needs.
5. Keep keys out of SQLite, snapshots, browser state, logs, CI artifacts,
   source control, environment dumps, and error responses.
6. Protect key-provider configuration and the trust anchor independently from
   the database and its administrative identities.
7. Record creation, activation, retirement, compromise, and destruction under
   dual-controlled policy.

This lab uses symmetric HMAC because it is small and testable. In a system
where independent parties must verify evidence without tag-generation power,
use a reviewed asymmetric signature or remote verification service instead.

## Rotation and versioning

Every authenticated event stores `algorithm: hmac-sha256`, a `keyId`, and a
monotonic `keyVersion`. Rotation provisions a new unique key ID, irreversibly
retires the old active key, increments the external activation version, then
activates the new key. Old key bytes remain available for historical
verification for the complete required retention period, but a retired key
cannot become active again. Reusing a key ID for different bytes is prohibited.

Rotation does not rewrite historical events. The first event under the new key
authenticates its own event hash, activation version, and the preceding event's
authentication tag, so the chain remains linked across key versions. Restore
rejects a decreasing activation version or a different key ID reusing the same
version. Removing the historical key causes restore to fail rather than
silently treating old evidence as valid.

Algorithm migration needs a new schema/profile and explicit verification
rules. It must not reinterpret an unknown algorithm as HMAC-SHA-256 or downgrade
an authenticated snapshot to the legacy unauthenticated format.

## Trust-anchor lifecycle

`trustAnchor()` returns no secret. It records both the chain-tip key/version
and the externally active key/version, including a rotation that occurred
before another event was written. It is still security-critical: if an
attacker can replace the database and anchor together, they can restore an
earlier valid prefix. Store accepted anchors in an append-only remote audit
service, signed release/evidence record, independently administered database,
or other system outside the snapshot's compromise boundary.

Anchor updates must be ordered and compare-and-set against the previous
accepted count/tip. A production writer must define the atomicity boundary
between committing an event and publishing its anchor, plus recovery behavior
for either side succeeding alone. This repository has not implemented that
distributed protocol.

During restore:

1. validate every event and recompute the ordinary hash chain;
2. resolve each historical key ID externally;
3. recompute and constant-time compare every authentication tag;
4. compare the resulting event count and chain tip with the externally supplied
   anchor; and
5. fail closed on a missing key, tag mismatch, truncated suffix, malformed
   snapshot, or anchor mismatch.

## Simulator integration status

The authenticated `AuditLog` profile and restore checks are implemented and
tested directly. The existing browser simulator continues to construct the
legacy profile unless a separately provisioned key provider and external
anchor store are wired into its composition and restart path. This deliberate
compatibility means this work does **not** claim that current SQLite-backed
browser demonstrations already have production-authenticated audit evidence.

No key is embedded in this repository, no authenticated snapshot contains key
bytes, and audit authentication material is not added to browser public state.

## Remaining production requirements

- HSM/KMS adapter and independent anchor service
- atomic event/anchor publication and crash recovery
- service identity, authorization, rate limiting, and availability controls
- key compromise and historical re-verification procedures
- remote timestamping or an independently trusted time source where required
- retention, legal hold, export, redaction, and evidence-access policy
- signed/asymmetric evidence if third-party offline verification is required
- independent cryptographic, application-security, and operational review

Passing the included tests proves the implemented HMAC/anchor invariants only.
It is not proof of non-repudiation, regulatory admissibility, production key
custody, immutability, or an authentic external audit sink.
