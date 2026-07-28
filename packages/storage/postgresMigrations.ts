export interface PostgresMigration {
  version: number;
  name: string;
  sql: string;
}

export const POSTGRES_MIGRATIONS: readonly PostgresMigration[] = [{
  version: 1,
  name: "tenant_state_idempotency_outbox_caps",
  sql: `
    CREATE TABLE IF NOT EXISTS airlock_tenant_state (
      tenant_id TEXT NOT NULL,
      aggregate_id TEXT NOT NULL,
      status TEXT NOT NULL,
      version BIGINT NOT NULL DEFAULT 0 CHECK (version >= 0),
      record_json JSONB NOT NULL,
      updated_at TIMESTAMPTZ NOT NULL,
      PRIMARY KEY (tenant_id, aggregate_id)
    );

    CREATE TABLE IF NOT EXISTS airlock_idempotency (
      tenant_id TEXT NOT NULL,
      scope TEXT NOT NULL,
      idempotency_key TEXT NOT NULL,
      request_hash TEXT NOT NULL,
      response_json JSONB NOT NULL,
      created_at TIMESTAMPTZ NOT NULL,
      PRIMARY KEY (tenant_id, scope, idempotency_key)
    );

    CREATE TABLE IF NOT EXISTS airlock_outbox (
      tenant_id TEXT NOT NULL,
      event_id UUID NOT NULL,
      event_key TEXT NOT NULL,
      topic TEXT NOT NULL,
      aggregate_id TEXT NOT NULL,
      payload_json JSONB NOT NULL,
      created_at TIMESTAMPTZ NOT NULL,
      available_at TIMESTAMPTZ NOT NULL,
      attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
      claimed_by TEXT,
      claimed_until TIMESTAMPTZ,
      delivered_at TIMESTAMPTZ,
      PRIMARY KEY (tenant_id, event_id),
      UNIQUE (tenant_id, event_key)
    );
    CREATE INDEX IF NOT EXISTS airlock_outbox_delivery_scan
      ON airlock_outbox (
        tenant_id, delivered_at, available_at, claimed_until, created_at, event_id
      );

    CREATE TABLE IF NOT EXISTS airlock_daily_caps (
      tenant_id TEXT NOT NULL,
      token_id TEXT NOT NULL,
      spend_date DATE NOT NULL,
      cap_minor BIGINT NOT NULL CHECK (cap_minor > 0),
      reserved_minor BIGINT NOT NULL DEFAULT 0
        CHECK (reserved_minor >= 0 AND reserved_minor <= cap_minor),
      PRIMARY KEY (tenant_id, token_id, spend_date)
    );

    CREATE TABLE IF NOT EXISTS airlock_cap_reservations (
      tenant_id TEXT NOT NULL,
      reservation_id TEXT NOT NULL,
      token_id TEXT NOT NULL,
      spend_date DATE NOT NULL,
      amount_minor BIGINT NOT NULL CHECK (amount_minor > 0),
      status TEXT NOT NULL CHECK (status IN ('active', 'released')),
      created_at TIMESTAMPTZ NOT NULL,
      released_at TIMESTAMPTZ,
      PRIMARY KEY (tenant_id, reservation_id),
      FOREIGN KEY (tenant_id, token_id, spend_date)
        REFERENCES airlock_daily_caps (tenant_id, token_id, spend_date)
    );
  `,
}];
