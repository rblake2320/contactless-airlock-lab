# Realtime Lab HTTP Idempotency

When `AIRLOCK_DB_PATH` (or `createLabServer({ dbPath })`) enables persistence,
every mutating `POST /api/...` request requires an `Idempotency-Key`.

- Keys are 1–128 ASCII characters.
- The first character is alphanumeric.
- Remaining characters may be letters, numbers, `.`, `_`, `:`, or `-`.
- Missing keys in persistent mode return HTTP 428.
- Oversized keys return HTTP 431.
- Invalid keys return HTTP 400.
- Reusing a key for a different path, query, or canonical JSON body returns
  HTTP 409.
- Reusing a key for the same request returns the originally stored HTTP status
  and JSON response without executing the protocol effect again.

The request hash binds the method, complete path/query, and recursively
key-sorted JSON object. Empty mutation bodies canonicalize as `{}`. A non-empty
mutation body must use `application/json`.

The response record and versioned simulator snapshot are committed in the same
SQLite transaction through `DurableStore.runIdempotent`. This supports safe
retry after a lost response or process restart. It is simulator evidence, not
a claim about a partner processor's idempotency behavior.

Ephemeral mode remains compatible with existing CLI use: an idempotency key is
accepted and validated when supplied but is not required or durably replayed.
