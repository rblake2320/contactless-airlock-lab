# Durable storage foundation

This package is a dependency-free P1 reference implementation built on
Node's `node:sqlite`. It replaces process memory for the invariants that are
most dangerous to postpone:

- versioned schema migrations;
- restart-persistent challenge records;
- compare-and-swap state transitions using status and version predicates;
- request-scoped idempotency with request-hash conflict detection;
- atomic commit of domain state, idempotent response, and outbox events;
- leased transactional outbox delivery with acknowledgement, retry delay, and
  recovery after a worker crash.

`BEGIN IMMEDIATE` serializes each compound write transaction. SQLite WAL mode,
full synchronous writes, foreign-key checking, and a bounded busy timeout are
enabled on every connection. Node 24 or newer is required because the
`DatabaseSync` constructor timeout installs the busy handler before the first
PRAGMA; a later `PRAGMA busy_timeout` alone cannot protect opening a database
while another process already holds its write lock. A regression test holds
that lock in an independent process and proves a new store waits and opens
within the configured timeout. Two independent connections are used in tests to
prove stale compare-and-swap rejection and outbox lease exclusion. Closing and
reopening the database proves restart persistence and expired leases provide
at-least-once redelivery.

## Intended integration

External mutations should enter through `runIdempotent`. The operation receives
a transaction-scoped interface and should perform its state compare-and-swap
and enqueue its partner event within the same callback. The idempotency result
is stored in the same transaction. Repeating the same scope/key/request hash
returns the original response without rerunning the operation; reusing the key
with a different hash fails closed.

Outbox consumers claim bounded batches with a worker ID and lease. They must
acknowledge only after the external side effect succeeds. A failed delivery can
be explicitly released with a retry time. A crashed worker makes the event
eligible again when its lease expires. Consumers must still be idempotent
because delivery is deliberately at least once.

## Production gap

This is not the roadmap's PostgreSQL completion. SQLite is appropriate for a
single-host lab and provides real durable transactional evidence without an
external service, but it does not prove multi-host failover, PostgreSQL locking
semantics, connection-pool behavior, replica consistency, managed backup and
restore, or production operational controls.

The production adapter should preserve this interface and map:

- compound mutations to PostgreSQL transactions;
- compare-and-swap to conditional `UPDATE ... WHERE version = ...`;
- outbox claiming to `SELECT ... FOR UPDATE SKIP LOCKED`;
- idempotency uniqueness to a composite unique constraint;
- migrations to a production migration runner with advisory locking.

Barrier-driven tests use separate Node processes and independent SQLite
connections on one host; they do not prove multi-host behavior. PostgreSQL
integration, equivalent races against that real database, backup/restore
exercises, and partner service integration remain required before checking the
PostgreSQL P1 roadmap item.

