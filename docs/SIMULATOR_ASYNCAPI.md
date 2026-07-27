# Simulator AsyncAPI and Outbox Semantics

The machine-readable contract is
[`contracts/asyncapi/simulator-outbox.asyncapi.json`](../contracts/asyncapi/simulator-outbox.asyncapi.json).
It describes the exact `OutboxEvent` record and leased-delivery behavior
currently implemented by `DurableStore`.

## Boundary

This is an AsyncAPI-shaped description of an internal SQLite API. There is no
message broker, network publisher, partner consumer, authenticated transport,
or negotiated topic registry. The custom `sqlite-outbox` protocol and single
`outbox_events` channel represent the table as a whole. The record's `topic`
is payload metadata, not proof of topic-based routing.

The contract is **not**:

- an issuer or processor authorization/advice/clearing contract;
- a wallet/TSP provisioning event contract;
- a network or merchant integration;
- proof that any external side effect occurred;
- a delivery service-level agreement; or
- an agreement that the example topic names are production names.

## Exact current semantics

### Schema version

The contract and message schema are version 1, identified by the AsyncAPI
document version, message name, and schema reference. The runtime record does
not carry a schema-version field and does not negotiate versions. A production
wire envelope needs an authenticated, required version field and compatibility
policy before multiple versions exist.

### Producer idempotency

`eventKey` has a SQLite unique constraint. A second enqueue with the same key
fails, and if enqueue occurs inside `runIdempotent`, the surrounding state,
idempotent response, and event mutation roll back together. Uniqueness lasts
for the database record's lifetime because there is no compactor today.
Enqueue rejects blank or oversized keys, topics, and aggregate IDs, rejects
non-JSON payloads, and caps serialized payloads at 1 MiB.

`eventId` is a generated UUID identifying the stored delivery record. Neither
field proves a remote consumer processed the event. An at-least-once consumer
must retain its own deduplication record keyed by an agreed identity.

### Correlation

`aggregateId` is the only current grouping field. It is not a complete
correlation or causation model. The outbox record does not currently carry a
request correlation ID, causation ID, trace context, producer identity,
tenant/issuer identity, or subject type. Those cannot be inferred from topic or
payload without a partner schema.

### Lease, retry, and acknowledgement

Claiming:

- selects undelivered records whose `availableAt` is due;
- excludes records with an unexpired lease;
- orders the scan by `createdAt`, then `eventId`;
- assigns `claimedBy` and `claimedUntil`; and
- increments `attempts` for each successful claim.

Acknowledgement succeeds only for the current owner while its lease is still
active, sets `deliveredAt`, and clears the ownership fields. It means the local
dispatcher acknowledged its work; no current code proves a partner accepted or
durably committed an effect.

Explicit release likewise requires a current, unexpired lease, clears ownership,
and moves `availableAt` to a caller-supplied retry time. A crashed worker does
not release; the event becomes eligible after `claimedUntil`. There is no
built-in exponential backoff, jitter, maximum
attempt count, dead-letter queue, poison-message quarantine, global ordering,
or exactly-once delivery.

## Drift evidence

Executable tests:

1. compare every TypeScript `OutboxEvent` property and optionality with the
   AsyncAPI schema;
2. compare schema types and bounds with exported runtime limits and real SQLite
   table/index/check metadata;
3. create, claim, release, reclaim, and acknowledge a real `DurableStore`
   record and validate each serialized state;
4. prove invalid enqueue boundaries, duplicate `eventKey`, and stale lease
   mutations fail closed; and
5. assert the document keeps its simulator-only and production-gap markers.

These tests catch source/schema drift. They do not validate the document
against an external partner implementation.

## Production contract work

A partner contract must separately agree:

- transport and mutual authentication/message signing;
- required envelope version and compatibility/deprecation rules;
- topic registry and topic-specific payload schemas;
- issuer/tenant, correlation, causation, trace, and business idempotency fields;
- clock, expiry, replay-window, ordering, partitioning, and size rules;
- retry classifications, backoff, maximum attempts, DLQ and recovery;
- acknowledgement meaning and remote idempotency retention;
- privacy classification, redaction, retention, deletion, and regional flow;
- availability, incident, reconciliation, and dispute evidence; and
- certification fixtures and conformance ownership.

No simulator field should be promoted into that contract merely because it
exists in SQLite.
