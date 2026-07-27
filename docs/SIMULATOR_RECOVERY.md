# Simulator Persistence Recovery

This runbook applies only to the optional SQLite persistence used by the
browser demonstration. It is not a payment-service disaster-recovery plan.

## Normal restart

Set `AIRLOCK_DB_PATH` to the same absolute path and start `npm run lab`. Startup
validates the snapshot schema, audit chain, device key pair, cross-record
bindings, challenge lifecycles, cap reservations, and UI pointers before the
HTTP listener opens. Invalid state fails startup; the server never silently
resets or repairs it.

## Corruption or incompatible state

1. Stop the lab process. Do not edit a live SQLite database.
2. Preserve the database and any `-wal`/`-shm` sidecars as incident evidence.
3. Record the application commit, Node version, absolute database path, startup
   error, and file hashes. Do not publish the files: the simulator snapshot
   contains an exportable synthetic private key.
4. Reproduce against a copy. Never experiment on the only evidence.
5. If the demonstration must resume immediately, start with a new database path
   and treat it as a new simulator identity. Do not copy records selectively or
   bypass restore validation.
6. Repair or migrate the preserved copy only with a reviewed, versioned tool
   and tests for the exact failure. The current repository intentionally has no
   automatic repair command.

Deleting or replacing the simulator database destroys its local protocol and
audit history. That is acceptable only for synthetic demonstrations after the
evidence above is preserved. A production design requires independently tested
backup, point-in-time recovery, retention, key management, and an external
authentic audit sink.
