import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { POSTGRES_MIGRATIONS } from "../packages/storage/postgresMigrations.ts";

test("PostgreSQL schema keeps every durable aggregate tenant-scoped", () => {
  const sql = POSTGRES_MIGRATIONS.map((migration) => migration.sql).join("\n");
  for (const table of [
    "airlock_tenant_state",
    "airlock_idempotency",
    "airlock_outbox",
    "airlock_daily_caps",
    "airlock_cap_reservations",
  ]) {
    const block = new RegExp(
      `CREATE TABLE IF NOT EXISTS ${table} \\(([\\s\\S]*?)\\n    \\);`,
    ).exec(sql)?.[1];
    assert.ok(block, `missing ${table}`);
    assert.match(block, /\btenant_id TEXT NOT NULL\b/);
    assert.match(block, /(?:PRIMARY KEY|UNIQUE) \(tenant_id,/);
  }
  assert.match(
    sql,
    /CHECK \(reserved_minor >= 0 AND reserved_minor <= cap_minor\)/,
  );
  assert.match(
    sql,
    /FOREIGN KEY \(tenant_id, token_id, spend_date\)/,
  );
});

test("PostgreSQL adapter source locks migrations/idempotency and leases outbox atomically", async () => {
  const source = await readFile(
    new URL("../packages/storage/postgresStore.ts", import.meta.url),
    "utf8",
  );
  assert.match(source, /pg_advisory_xact_lock/);
  assert.match(source, /FOR UPDATE SKIP LOCKED/);
  assert.match(source, /ON CONFLICT \(tenant_id, token_id, spend_date\) DO UPDATE/);
  assert.match(source, /claimed_until > \$1/);
  assert.match(source, /BEGIN/);
  assert.match(source, /ROLLBACK/);
});

test("real PostgreSQL test is opt-in and never substitutes a mock", async () => {
  const source = await readFile(
    new URL("./postgres-integration.test.ts", import.meta.url),
    "utf8",
  );
  assert.match(source, /AIRLOCK_POSTGRES_URL is not configured/);
  assert.match(source, /PostgresDurableStore\.connect/);
  assert.match(source, /postgres-cap-worker/);
  assert.doesNotMatch(source, /mock|fake postgres/i);
});
