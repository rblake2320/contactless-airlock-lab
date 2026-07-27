export interface Migration {
  version: number;
  name: string;
  sql: string;
}

export const MIGRATIONS: readonly Migration[] = [
  {
    version: 1,
    name: "durable_challenges_idempotency_outbox",
    sql: `
      CREATE TABLE durable_challenges (
        challenge_id TEXT PRIMARY KEY,
        status TEXT NOT NULL,
        version INTEGER NOT NULL CHECK (version >= 0),
        record_json TEXT NOT NULL,
        updated_at TEXT NOT NULL
      ) STRICT;

      CREATE TABLE idempotency_records (
        scope TEXT NOT NULL,
        idempotency_key TEXT NOT NULL,
        request_hash TEXT NOT NULL,
        response_json TEXT NOT NULL,
        created_at TEXT NOT NULL,
        PRIMARY KEY (scope, idempotency_key)
      ) STRICT;

      CREATE TABLE outbox_events (
        event_id TEXT PRIMARY KEY,
        event_key TEXT NOT NULL UNIQUE,
        topic TEXT NOT NULL,
        aggregate_id TEXT NOT NULL,
        payload_json TEXT NOT NULL,
        created_at TEXT NOT NULL,
        available_at TEXT NOT NULL,
        attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
        claimed_by TEXT,
        claimed_until TEXT,
        delivered_at TEXT
      ) STRICT;

      CREATE INDEX outbox_delivery_scan
        ON outbox_events(delivered_at, available_at, claimed_until, created_at);
    `,
  },
];

