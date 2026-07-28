# PostgreSQL durability adapter

`packages/storage/postgresStore.ts` is an asynchronous, tenant-scoped
PostgreSQL adapter. It is separate from the synchronous SQLite `DurableStore`,
which remains the local simulator default.

Implemented PostgreSQL guarantees:

- tenant-scoped aggregate state with optimistic status/version compare-and-swap;
- transaction-scoped idempotency serialized by a transaction advisory lock;
- state, idempotent response, and outbox writes committed atomically;
- leased outbox claiming with `FOR UPDATE SKIP LOCKED`;
- active-lease acknowledgement semantics;
- tenant-scoped daily cap aggregates and reservation IDs;
- atomic cap admission under concurrent writers, idempotent reservation replay,
  and release/retry; and
- migration serialization with a PostgreSQL transaction advisory lock.

Operations passed to `runIdempotent` must remain database-local. A database
rollback cannot undo an external network call.

## Real integration test

The default test suite loads the integration test but skips it with an explicit
reason when no database URL is configured. To run the real test:

```powershell
$env:AIRLOCK_POSTGRES_URL = "postgresql://airlock:airlock@127.0.0.1:5432/airlock"
npm run test:postgres
```

One reproducible local database command is:

```powershell
docker run --rm --name airlock-postgres-test `
  -e POSTGRES_USER=airlock -e POSTGRES_PASSWORD=airlock `
  -e POSTGRES_DB=airlock -p 5432:5432 postgres:17-alpine
```

Use an organization-approved digest pin in CI rather than relying on the
floating example tag. A CI PostgreSQL service should set
`AIRLOCK_POSTGRES_URL` and run `npm run test:postgres`; the test creates unique
synthetic tenant IDs and deletes only those tenants afterward. It starts
separate adapter pools plus separate Node processes for the cap race.

This proves real PostgreSQL behavior on one database cluster. It does not yet
prove managed-service failover, replica consistency, cross-region behavior,
backup/restore, schema rollback, pooler compatibility, or production
operations. Tenant IDs participate in every key and predicate, but database
row-level security is not configured; production deployments still need
least-privilege roles/RLS appropriate to their tenancy threat model. TLS,
credentials, connection limits, and timeouts are supplied through `pg`
`PoolConfig` by the deployment. No issuer, processor, wallet, or payment
network is connected.
