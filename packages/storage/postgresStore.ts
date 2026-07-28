import { randomUUID } from "node:crypto";
import {
  Pool,
  type PoolClient,
  type PoolConfig,
  type QueryResultRow,
} from "pg";
import {
  OUTBOX_LIMITS,
  type OutboxEvent,
  type VersionedRecord,
} from "./durableStore.ts";
import { POSTGRES_MIGRATIONS } from "./postgresMigrations.ts";

const IDENTIFIER_LIMIT = 256;

function assertIdentifier(value: string, field: string, maximum = IDENTIFIER_LIMIT) {
  if (
    typeof value !== "string" ||
    value.trim().length === 0 ||
    value.length > maximum
  ) {
    throw new Error(`invalid PostgreSQL ${field}`);
  }
}

function assertDate(value: Date, field: string) {
  if (!(value instanceof Date) || !Number.isFinite(value.getTime())) {
    throw new Error(`invalid PostgreSQL ${field}`);
  }
}

function safeInteger(value: unknown, field: string): number {
  const number = typeof value === "string" ? Number(value) : value;
  if (!Number.isSafeInteger(number)) {
    throw new Error(`PostgreSQL ${field} exceeds JavaScript safe integer range`);
  }
  return number as number;
}

function iso(value: unknown): string {
  if (value instanceof Date) return value.toISOString();
  const parsed = new Date(String(value));
  if (!Number.isFinite(parsed.getTime())) throw new Error("invalid PostgreSQL timestamp");
  return parsed.toISOString();
}

function record<T>(row: QueryResultRow): VersionedRecord<T> {
  return {
    value: structuredClone(row.record_json as T),
    status: row.status as string,
    version: safeInteger(row.version, "state version"),
    updatedAt: iso(row.updated_at),
  };
}

function outbox<T>(row: QueryResultRow): OutboxEvent<T> {
  return {
    eventId: row.event_id as string,
    eventKey: row.event_key as string,
    topic: row.topic as string,
    aggregateId: row.aggregate_id as string,
    payload: structuredClone(row.payload_json as T),
    createdAt: iso(row.created_at),
    availableAt: iso(row.available_at),
    attempts: safeInteger(row.attempts, "outbox attempts"),
    claimedBy: (row.claimed_by as string | null) ?? undefined,
    claimedUntil: row.claimed_until ? iso(row.claimed_until) : undefined,
    deliveredAt: row.delivered_at ? iso(row.delivered_at) : undefined,
  };
}

export interface PostgresMutation {
  get<T>(tenantId: string, aggregateId: string): Promise<VersionedRecord<T> | undefined>;
  create<T extends object>(
    tenantId: string,
    aggregateId: string,
    status: string,
    value: T,
    now?: Date,
  ): Promise<VersionedRecord<T>>;
  compareAndSwap<T extends object>(
    tenantId: string,
    aggregateId: string,
    expectedVersion: number,
    expectedStatus: string,
    nextStatus: string,
    nextValue: T,
    now?: Date,
  ): Promise<VersionedRecord<T>>;
  enqueue<T>(
    tenantId: string,
    eventKey: string,
    topic: string,
    aggregateId: string,
    payload: T,
    now?: Date,
  ): Promise<OutboxEvent<T>>;
}

export interface CapReservationResult {
  replayed: boolean;
  tenantId: string;
  reservationId: string;
  tokenId: string;
  spendDate: string;
  amountMinor: number;
  reservedMinor: number;
  capMinor: number;
  status: "active" | "released";
}

/**
 * Asynchronous, tenant-scoped PostgreSQL durability adapter.
 *
 * This is separate from the synchronous SQLite simulator adapter. Callers must
 * keep operations passed to runIdempotent database-local: PostgreSQL rollback
 * cannot undo an external network side effect.
 */
export class PostgresDurableStore {
  readonly #pool: Pool;

  constructor(config: PoolConfig | Pool) {
    this.#pool = config instanceof Pool ? config : new Pool(config);
  }

  static async connect(config: PoolConfig): Promise<PostgresDurableStore> {
    const store = new PostgresDurableStore(config);
    try {
      await store.migrate();
      return store;
    } catch (error) {
      await store.close();
      throw error;
    }
  }

  async close(): Promise<void> {
    await this.#pool.end();
  }

  async migrate(): Promise<void> {
    const client = await this.#pool.connect();
    try {
      await client.query("BEGIN");
      await client.query(
        "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))",
        ["contactless-airlock:postgres-migrations"],
      );
      await client.query(`
        CREATE TABLE IF NOT EXISTS airlock_schema_migrations (
          version INTEGER PRIMARY KEY,
          name TEXT NOT NULL,
          applied_at TIMESTAMPTZ NOT NULL
        )
      `);
      for (const migration of POSTGRES_MIGRATIONS) {
        const exists = await client.query(
          "SELECT 1 FROM airlock_schema_migrations WHERE version = $1",
          [migration.version],
        );
        if (exists.rowCount) continue;
        await client.query(migration.sql);
        await client.query(
          `INSERT INTO airlock_schema_migrations(version, name, applied_at)
           VALUES ($1, $2, $3)`,
          [migration.version, migration.name, new Date()],
        );
      }
      await client.query("COMMIT");
    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    } finally {
      client.release();
    }
  }

  async #transaction<T>(work: (client: PoolClient) => Promise<T>): Promise<T> {
    const client = await this.#pool.connect();
    try {
      await client.query("BEGIN");
      const result = await work(client);
      await client.query("COMMIT");
      return result;
    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    } finally {
      client.release();
    }
  }

  #mutation(client: PoolClient): PostgresMutation {
    return {
      get: <T>(tenantId: string, aggregateId: string) =>
        this.#get<T>(client, tenantId, aggregateId),
      create: <T extends object>(
        tenantId: string,
        aggregateId: string,
        status: string,
        value: T,
        now?: Date,
      ) => this.#create(client, tenantId, aggregateId, status, value, now),
      compareAndSwap: <T extends object>(
        tenantId: string,
        aggregateId: string,
        expectedVersion: number,
        expectedStatus: string,
        nextStatus: string,
        nextValue: T,
        now?: Date,
      ) => this.#compareAndSwap(
        client,
        tenantId,
        aggregateId,
        expectedVersion,
        expectedStatus,
        nextStatus,
        nextValue,
        now,
      ),
      enqueue: <T>(
        tenantId: string,
        eventKey: string,
        topic: string,
        aggregateId: string,
        payload: T,
        now?: Date,
      ) => this.#enqueue(
        client,
        tenantId,
        eventKey,
        topic,
        aggregateId,
        payload,
        now,
      ),
    };
  }

  async get<T>(
    tenantId: string,
    aggregateId: string,
  ): Promise<VersionedRecord<T> | undefined> {
    const client = await this.#pool.connect();
    try {
      return await this.#get(client, tenantId, aggregateId);
    } finally {
      client.release();
    }
  }

  async #get<T>(
    client: PoolClient,
    tenantId: string,
    aggregateId: string,
  ): Promise<VersionedRecord<T> | undefined> {
    assertIdentifier(tenantId, "tenant id");
    assertIdentifier(aggregateId, "aggregate id");
    const result = await client.query(
      `SELECT status, version, record_json, updated_at
         FROM airlock_tenant_state
        WHERE tenant_id = $1 AND aggregate_id = $2`,
      [tenantId, aggregateId],
    );
    return result.rows[0] ? record<T>(result.rows[0]) : undefined;
  }

  async create<T extends object>(
    tenantId: string,
    aggregateId: string,
    status: string,
    value: T,
    now = new Date(),
  ): Promise<VersionedRecord<T>> {
    return this.#transaction((client) =>
      this.#create(client, tenantId, aggregateId, status, value, now));
  }

  async #create<T extends object>(
    client: PoolClient,
    tenantId: string,
    aggregateId: string,
    status: string,
    value: T,
    now = new Date(),
  ): Promise<VersionedRecord<T>> {
    assertIdentifier(tenantId, "tenant id");
    assertIdentifier(aggregateId, "aggregate id");
    assertIdentifier(status, "state status", 128);
    assertDate(now, "state timestamp");
    const result = await client.query(
      `INSERT INTO airlock_tenant_state(
         tenant_id, aggregate_id, status, version, record_json, updated_at
       ) VALUES ($1, $2, $3, 0, $4::jsonb, $5)
       RETURNING status, version, record_json, updated_at`,
      [tenantId, aggregateId, status, JSON.stringify(value), now],
    );
    return record<T>(result.rows[0]);
  }

  async compareAndSwap<T extends object>(
    tenantId: string,
    aggregateId: string,
    expectedVersion: number,
    expectedStatus: string,
    nextStatus: string,
    nextValue: T,
    now = new Date(),
  ): Promise<VersionedRecord<T>> {
    return this.#transaction((client) => this.#compareAndSwap(
      client,
      tenantId,
      aggregateId,
      expectedVersion,
      expectedStatus,
      nextStatus,
      nextValue,
      now,
    ));
  }

  async #compareAndSwap<T extends object>(
    client: PoolClient,
    tenantId: string,
    aggregateId: string,
    expectedVersion: number,
    expectedStatus: string,
    nextStatus: string,
    nextValue: T,
    now = new Date(),
  ): Promise<VersionedRecord<T>> {
    assertIdentifier(tenantId, "tenant id");
    assertIdentifier(aggregateId, "aggregate id");
    assertIdentifier(expectedStatus, "expected status", 128);
    assertIdentifier(nextStatus, "next status", 128);
    if (!Number.isSafeInteger(expectedVersion) || expectedVersion < 0) {
      throw new Error("invalid PostgreSQL expected version");
    }
    assertDate(now, "state timestamp");
    const result = await client.query(
      `UPDATE airlock_tenant_state
          SET status = $1, version = version + 1,
              record_json = $2::jsonb, updated_at = $3
        WHERE tenant_id = $4 AND aggregate_id = $5
          AND version = $6 AND status = $7
        RETURNING status, version, record_json, updated_at`,
      [
        nextStatus,
        JSON.stringify(nextValue),
        now,
        tenantId,
        aggregateId,
        expectedVersion,
        expectedStatus,
      ],
    );
    if (result.rowCount !== 1) throw new Error("compare-and-swap conflict");
    return record<T>(result.rows[0]);
  }

  async runIdempotent<T>(
    tenantId: string,
    scope: string,
    key: string,
    requestHash: string,
    operation: (tx: PostgresMutation) => Promise<T>,
    now = new Date(),
  ): Promise<{ replayed: boolean; value: T }> {
    assertIdentifier(tenantId, "tenant id");
    assertIdentifier(scope, "idempotency scope");
    assertIdentifier(key, "idempotency key");
    assertIdentifier(requestHash, "request hash");
    assertDate(now, "idempotency timestamp");
    return this.#transaction(async (client) => {
      await client.query(
        "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))",
        [`${tenantId}\n${scope}\n${key}`],
      );
      const prior = await client.query(
        `SELECT request_hash, response_json
           FROM airlock_idempotency
          WHERE tenant_id = $1 AND scope = $2 AND idempotency_key = $3`,
        [tenantId, scope, key],
      );
      if (prior.rows[0]) {
        if (prior.rows[0].request_hash !== requestHash) {
          throw new Error("idempotency key reused with a different request");
        }
        return {
          replayed: true,
          value: structuredClone(prior.rows[0].response_json as T),
        };
      }
      const value = await operation(this.#mutation(client));
      await client.query(
        `INSERT INTO airlock_idempotency(
           tenant_id, scope, idempotency_key, request_hash, response_json, created_at
         ) VALUES ($1, $2, $3, $4, $5::jsonb, $6)`,
        [tenantId, scope, key, requestHash, JSON.stringify(value), now],
      );
      return { replayed: false, value };
    });
  }

  async enqueue<T>(
    tenantId: string,
    eventKey: string,
    topic: string,
    aggregateId: string,
    payload: T,
    now = new Date(),
  ): Promise<OutboxEvent<T>> {
    return this.#transaction((client) => this.#enqueue(
      client,
      tenantId,
      eventKey,
      topic,
      aggregateId,
      payload,
      now,
    ));
  }

  async #enqueue<T>(
    client: PoolClient,
    tenantId: string,
    eventKey: string,
    topic: string,
    aggregateId: string,
    payload: T,
    now = new Date(),
  ): Promise<OutboxEvent<T>> {
    assertIdentifier(tenantId, "tenant id");
    assertIdentifier(eventKey, "outbox event key", OUTBOX_LIMITS.eventKey);
    assertIdentifier(topic, "outbox topic", OUTBOX_LIMITS.topic);
    assertIdentifier(
      aggregateId,
      "outbox aggregate id",
      OUTBOX_LIMITS.aggregateId,
    );
    assertDate(now, "outbox timestamp");
    const payloadJson = JSON.stringify(payload);
    if (
      payloadJson === undefined ||
      Buffer.byteLength(payloadJson) > OUTBOX_LIMITS.payloadBytes
    ) {
      throw new Error("invalid PostgreSQL outbox payload");
    }
    const eventId = randomUUID();
    const result = await client.query(
      `INSERT INTO airlock_outbox(
         tenant_id, event_id, event_key, topic, aggregate_id,
         payload_json, created_at, available_at
       ) VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7, $7)
       RETURNING *`,
      [
        tenantId,
        eventId,
        eventKey,
        topic,
        aggregateId,
        payloadJson,
        now,
      ],
    );
    return outbox<T>(result.rows[0]);
  }

  async claimOutbox(
    tenantId: string,
    workerId: string,
    limit: number,
    leaseMs: number,
    now = new Date(),
  ): Promise<OutboxEvent[]> {
    assertIdentifier(tenantId, "tenant id");
    assertIdentifier(workerId, "outbox worker id", OUTBOX_LIMITS.workerId);
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > 1_000) {
      throw new Error("invalid PostgreSQL outbox claim");
    }
    if (!Number.isSafeInteger(leaseMs) || leaseMs < 1_000) {
      throw new Error("invalid PostgreSQL outbox lease");
    }
    assertDate(now, "outbox claim timestamp");
    const claimedUntil = new Date(now.getTime() + leaseMs);
    return this.#transaction(async (client) => {
      const result = await client.query(
        `WITH candidates AS (
           SELECT event_id
             FROM airlock_outbox
            WHERE tenant_id = $1
              AND delivered_at IS NULL
              AND available_at <= $2
              AND (claimed_until IS NULL OR claimed_until <= $2)
            ORDER BY created_at, event_id
            FOR UPDATE SKIP LOCKED
            LIMIT $3
         )
         UPDATE airlock_outbox AS event
            SET claimed_by = $4, claimed_until = $5,
                attempts = event.attempts + 1
           FROM candidates
          WHERE event.tenant_id = $1
            AND event.event_id = candidates.event_id
         RETURNING event.*`,
        [tenantId, now, limit, workerId, claimedUntil],
      );
      return result.rows.map((row) => outbox(row));
    });
  }

  async acknowledgeOutbox(
    tenantId: string,
    eventId: string,
    workerId: string,
    now = new Date(),
  ): Promise<void> {
    assertIdentifier(tenantId, "tenant id");
    assertIdentifier(eventId, "outbox event id");
    assertIdentifier(workerId, "outbox worker id", OUTBOX_LIMITS.workerId);
    assertDate(now, "outbox acknowledgement timestamp");
    const result = await this.#pool.query(
      `UPDATE airlock_outbox
          SET delivered_at = $1, claimed_by = NULL, claimed_until = NULL
        WHERE tenant_id = $2 AND event_id = $3
          AND claimed_by = $4 AND claimed_until > $1
          AND delivered_at IS NULL`,
      [now, tenantId, eventId, workerId],
    );
    if (result.rowCount !== 1) throw new Error("outbox acknowledgement conflict");
  }

  async reserveCap(input: {
    tenantId: string;
    reservationId: string;
    tokenId: string;
    spendDate: string;
    amountMinor: number;
    capMinor: number;
    now?: Date;
  }): Promise<CapReservationResult> {
    const now = input.now ?? new Date();
    for (const [value, field] of [
      [input.tenantId, "tenant id"],
      [input.reservationId, "reservation id"],
      [input.tokenId, "token id"],
    ] as const) assertIdentifier(value, field);
    if (!/^\d{4}-\d{2}-\d{2}$/.test(input.spendDate)) {
      throw new Error("invalid PostgreSQL cap spend date");
    }
    if (
      !Number.isSafeInteger(input.amountMinor) || input.amountMinor <= 0 ||
      !Number.isSafeInteger(input.capMinor) ||
      input.capMinor <= 0 ||
      input.amountMinor > input.capMinor
    ) {
      throw new Error("invalid PostgreSQL cap amount");
    }
    assertDate(now, "cap timestamp");
    return this.#transaction(async (client) => {
      await client.query(
        "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))",
        [`${input.tenantId}\ncap\n${input.reservationId}`],
      );
      const prior = await client.query(
        `SELECT reservation_id, token_id,
                to_char(spend_date, 'YYYY-MM-DD') AS spend_date,
                amount_minor, status
           FROM airlock_cap_reservations
          WHERE tenant_id = $1 AND reservation_id = $2`,
        [input.tenantId, input.reservationId],
      );
      if (prior.rows[0]) {
        const row = prior.rows[0];
        if (
          row.token_id !== input.tokenId ||
          row.spend_date !== input.spendDate ||
          safeInteger(row.amount_minor, "cap amount") !== input.amountMinor
        ) {
          throw new Error("cap reservation id reused with different input");
        }
        const usage = await this.#capUsage(
          client,
          input.tenantId,
          input.tokenId,
          input.spendDate,
        );
        return {
          replayed: true,
          tenantId: input.tenantId,
          reservationId: input.reservationId,
          tokenId: input.tokenId,
          spendDate: input.spendDate,
          amountMinor: input.amountMinor,
          ...usage,
          status: row.status as "active" | "released",
        };
      }
      const updated = await client.query(
        `INSERT INTO airlock_daily_caps(
           tenant_id, token_id, spend_date, cap_minor, reserved_minor
         ) VALUES ($1, $2, $3::date, $4, $5)
         ON CONFLICT (tenant_id, token_id, spend_date) DO UPDATE
           SET reserved_minor =
             airlock_daily_caps.reserved_minor + EXCLUDED.reserved_minor
         WHERE airlock_daily_caps.cap_minor = EXCLUDED.cap_minor
           AND airlock_daily_caps.reserved_minor + EXCLUDED.reserved_minor
               <= airlock_daily_caps.cap_minor
         RETURNING reserved_minor, cap_minor`,
        [
          input.tenantId,
          input.tokenId,
          input.spendDate,
          input.capMinor,
          input.amountMinor,
        ],
      );
      if (updated.rowCount !== 1) {
        throw new Error("transaction exceeds token daily cap");
      }
      await client.query(
        `INSERT INTO airlock_cap_reservations(
           tenant_id, reservation_id, token_id, spend_date,
           amount_minor, status, created_at
         ) VALUES ($1, $2, $3, $4::date, $5, 'active', $6)`,
        [
          input.tenantId,
          input.reservationId,
          input.tokenId,
          input.spendDate,
          input.amountMinor,
          now,
        ],
      );
      return {
        replayed: false,
        tenantId: input.tenantId,
        reservationId: input.reservationId,
        tokenId: input.tokenId,
        spendDate: input.spendDate,
        amountMinor: input.amountMinor,
        reservedMinor: safeInteger(updated.rows[0].reserved_minor, "reserved cap"),
        capMinor: safeInteger(updated.rows[0].cap_minor, "daily cap"),
        status: "active",
      };
    });
  }

  async releaseCap(
    tenantId: string,
    reservationId: string,
    now = new Date(),
  ): Promise<CapReservationResult> {
    assertIdentifier(tenantId, "tenant id");
    assertIdentifier(reservationId, "reservation id");
    assertDate(now, "cap release timestamp");
    return this.#transaction(async (client) => {
      const result = await client.query(
        `SELECT reservation_id, token_id,
                to_char(spend_date, 'YYYY-MM-DD') AS spend_date,
                amount_minor, status
           FROM airlock_cap_reservations
          WHERE tenant_id = $1 AND reservation_id = $2
          FOR UPDATE`,
        [tenantId, reservationId],
      );
      if (!result.rows[0]) throw new Error("unknown cap reservation");
      const row = result.rows[0];
      if (row.status === "active") {
        await client.query(
          `UPDATE airlock_daily_caps
              SET reserved_minor = reserved_minor - $1
            WHERE tenant_id = $2 AND token_id = $3 AND spend_date = $4::date`,
          [row.amount_minor, tenantId, row.token_id, row.spend_date],
        );
        await client.query(
          `UPDATE airlock_cap_reservations
              SET status = 'released', released_at = $1
            WHERE tenant_id = $2 AND reservation_id = $3`,
          [now, tenantId, reservationId],
        );
      }
      const usage = await this.#capUsage(
        client,
        tenantId,
        row.token_id,
        row.spend_date,
      );
      return {
        replayed: row.status === "released",
        tenantId,
        reservationId,
        tokenId: row.token_id,
        spendDate: row.spend_date,
        amountMinor: safeInteger(row.amount_minor, "cap amount"),
        ...usage,
        status: "released",
      };
    });
  }

  async capUsage(
    tenantId: string,
    tokenId: string,
    spendDate: string,
  ): Promise<{ reservedMinor: number; capMinor: number }> {
    const client = await this.#pool.connect();
    try {
      return await this.#capUsage(client, tenantId, tokenId, spendDate);
    } finally {
      client.release();
    }
  }

  async #capUsage(
    client: PoolClient,
    tenantId: string,
    tokenId: string,
    spendDate: string,
  ): Promise<{ reservedMinor: number; capMinor: number }> {
    const result = await client.query(
      `SELECT reserved_minor, cap_minor
         FROM airlock_daily_caps
        WHERE tenant_id = $1 AND token_id = $2 AND spend_date = $3::date`,
      [tenantId, tokenId, spendDate],
    );
    if (!result.rows[0]) throw new Error("unknown daily cap");
    return {
      reservedMinor: safeInteger(result.rows[0].reserved_minor, "reserved cap"),
      capMinor: safeInteger(result.rows[0].cap_minor, "daily cap"),
    };
  }

  async deleteTenantForTest(tenantId: string): Promise<void> {
    if (process.env.NODE_ENV !== "test") {
      throw new Error("tenant cleanup is test-only");
    }
    assertIdentifier(tenantId, "tenant id");
    await this.#transaction(async (client) => {
      for (const table of [
        "airlock_cap_reservations",
        "airlock_daily_caps",
        "airlock_outbox",
        "airlock_idempotency",
        "airlock_tenant_state",
      ]) {
        await client.query(`DELETE FROM ${table} WHERE tenant_id = $1`, [tenantId]);
      }
    });
  }
}
