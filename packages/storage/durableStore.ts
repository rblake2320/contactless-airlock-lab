import { randomUUID } from "node:crypto";
import { mkdirSync } from "node:fs";
import { dirname } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { MIGRATIONS } from "./migrations.ts";

export interface VersionedRecord<T> {
  value: T;
  status: string;
  version: number;
  updatedAt: string;
}

export interface OutboxEvent<T = unknown> {
  eventId: string;
  eventKey: string;
  topic: string;
  aggregateId: string;
  payload: T;
  createdAt: string;
  availableAt: string;
  attempts: number;
  claimedBy?: string;
  claimedUntil?: string;
  deliveredAt?: string;
}

export interface MutationTransaction {
  create<T extends object>(
    challengeId: string,
    status: string,
    value: T,
    now?: Date,
  ): VersionedRecord<T>;
  compareAndSwap<T extends object>(
    challengeId: string,
    expectedVersion: number,
    expectedStatus: string,
    nextStatus: string,
    nextValue: T,
    now?: Date,
  ): VersionedRecord<T>;
  enqueue<T>(
    eventKey: string,
    topic: string,
    aggregateId: string,
    payload: T,
    now?: Date,
  ): OutboxEvent<T>;
}

function parse<T>(text: string): T {
  return JSON.parse(text) as T;
}

function rowToRecord<T>(row: Record<string, unknown>): VersionedRecord<T> {
  return {
    value: parse<T>(row.record_json as string),
    status: row.status as string,
    version: row.version as number,
    updatedAt: row.updated_at as string,
  };
}

function rowToEvent<T>(row: Record<string, unknown>): OutboxEvent<T> {
  return {
    eventId: row.event_id as string,
    eventKey: row.event_key as string,
    topic: row.topic as string,
    aggregateId: row.aggregate_id as string,
    payload: parse<T>(row.payload_json as string),
    createdAt: row.created_at as string,
    availableAt: row.available_at as string,
    attempts: row.attempts as number,
    claimedBy: (row.claimed_by as string | null) ?? undefined,
    claimedUntil: (row.claimed_until as string | null) ?? undefined,
    deliveredAt: (row.delivered_at as string | null) ?? undefined,
  };
}

export class DurableStore implements MutationTransaction {
  readonly #db: DatabaseSync;
  #inTransaction = false;

  constructor(path: string) {
    if (path !== ":memory:") mkdirSync(dirname(path), { recursive: true });
    this.#db = new DatabaseSync(path);
    this.#db.exec("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000;");
    this.#migrate();
  }

  close(): void {
    this.#db.close();
  }

  schemaVersion(): number {
    const row = this.#db.prepare("SELECT COALESCE(MAX(version), 0) AS version FROM schema_migrations").get()!;
    return row.version as number;
  }

  #migrate(): void {
    this.#db.exec(`
      CREATE TABLE IF NOT EXISTS schema_migrations (
        version INTEGER PRIMARY KEY,
        name TEXT NOT NULL,
        applied_at TEXT NOT NULL
      ) STRICT;
    `);
    for (const migration of MIGRATIONS) {
      this.#transaction(() => {
        const exists = this.#db.prepare(
          "SELECT 1 FROM schema_migrations WHERE version = ?",
        ).get(migration.version);
        if (exists) return;
        this.#db.exec(migration.sql);
        this.#db.prepare(
          "INSERT INTO schema_migrations(version, name, applied_at) VALUES (?, ?, ?)",
        ).run(migration.version, migration.name, new Date().toISOString());
      });
    }
  }

  #transaction<T>(work: () => T): T {
    if (this.#inTransaction) return work();
    this.#db.exec("BEGIN IMMEDIATE");
    this.#inTransaction = true;
    try {
      const result = work();
      this.#db.exec("COMMIT");
      return result;
    } catch (error) {
      this.#db.exec("ROLLBACK");
      throw error;
    } finally {
      this.#inTransaction = false;
    }
  }

  create<T extends object>(
    challengeId: string,
    status: string,
    value: T,
    now = new Date(),
  ): VersionedRecord<T> {
    const updatedAt = now.toISOString();
    this.#db.prepare(`
      INSERT INTO durable_challenges(challenge_id, status, version, record_json, updated_at)
      VALUES (?, ?, 0, ?, ?)
    `).run(challengeId, status, JSON.stringify(value), updatedAt);
    return { value: structuredClone(value), status, version: 0, updatedAt };
  }

  get<T>(challengeId: string): VersionedRecord<T> | undefined {
    const row = this.#db.prepare("SELECT * FROM durable_challenges WHERE challenge_id = ?").get(challengeId);
    return row ? rowToRecord<T>(row) : undefined;
  }

  compareAndSwap<T extends object>(
    challengeId: string,
    expectedVersion: number,
    expectedStatus: string,
    nextStatus: string,
    nextValue: T,
    now = new Date(),
  ): VersionedRecord<T> {
    const updatedAt = now.toISOString();
    const result = this.#db.prepare(`
      UPDATE durable_challenges
         SET status = ?, version = version + 1, record_json = ?, updated_at = ?
       WHERE challenge_id = ? AND version = ? AND status = ?
    `).run(
      nextStatus,
      JSON.stringify(nextValue),
      updatedAt,
      challengeId,
      expectedVersion,
      expectedStatus,
    );
    if (result.changes !== 1) throw new Error("compare-and-swap conflict");
    return {
      value: structuredClone(nextValue),
      status: nextStatus,
      version: expectedVersion + 1,
      updatedAt,
    };
  }

  runIdempotent<T>(
    scope: string,
    key: string,
    requestHash: string,
    operation: (tx: MutationTransaction) => T,
    now = new Date(),
  ): { replayed: boolean; value: T } {
    return this.#transaction(() => {
      const prior = this.#db.prepare(`
        SELECT request_hash, response_json
          FROM idempotency_records
         WHERE scope = ? AND idempotency_key = ?
      `).get(scope, key);
      if (prior) {
        if (prior.request_hash !== requestHash) {
          throw new Error("idempotency key reused with a different request");
        }
        return { replayed: true, value: parse<T>(prior.response_json as string) };
      }
      const value = operation(this);
      this.#db.prepare(`
        INSERT INTO idempotency_records(
          scope, idempotency_key, request_hash, response_json, created_at
        ) VALUES (?, ?, ?, ?, ?)
      `).run(scope, key, requestHash, JSON.stringify(value), now.toISOString());
      return { replayed: false, value };
    });
  }

  enqueue<T>(
    eventKey: string,
    topic: string,
    aggregateId: string,
    payload: T,
    now = new Date(),
  ): OutboxEvent<T> {
    const eventId = randomUUID();
    const timestamp = now.toISOString();
    this.#db.prepare(`
      INSERT INTO outbox_events(
        event_id, event_key, topic, aggregate_id, payload_json, created_at, available_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?)
    `).run(eventId, eventKey, topic, aggregateId, JSON.stringify(payload), timestamp, timestamp);
    return {
      eventId,
      eventKey,
      topic,
      aggregateId,
      payload: structuredClone(payload),
      createdAt: timestamp,
      availableAt: timestamp,
      attempts: 0,
    };
  }

  claimOutbox(
    workerId: string,
    limit: number,
    leaseMs: number,
    now = new Date(),
  ): OutboxEvent[] {
    if (!workerId || !Number.isSafeInteger(limit) || limit < 1 || limit > 1_000) {
      throw new Error("invalid outbox claim");
    }
    if (!Number.isSafeInteger(leaseMs) || leaseMs < 1_000) throw new Error("invalid lease");
    return this.#transaction(() => {
      const nowIso = now.toISOString();
      const claimedUntil = new Date(now.getTime() + leaseMs).toISOString();
      const rows = this.#db.prepare(`
        SELECT event_id
          FROM outbox_events
         WHERE delivered_at IS NULL
           AND available_at <= ?
           AND (claimed_until IS NULL OR claimed_until <= ?)
         ORDER BY created_at, event_id
         LIMIT ?
      `).all(nowIso, nowIso, limit);
      if (rows.length === 0) return [];
      const update = this.#db.prepare(`
        UPDATE outbox_events
           SET claimed_by = ?, claimed_until = ?, attempts = attempts + 1
         WHERE event_id = ?
           AND delivered_at IS NULL
           AND (claimed_until IS NULL OR claimed_until <= ?)
      `);
      const claimed: OutboxEvent[] = [];
      for (const row of rows) {
        const eventId = row.event_id as string;
        if (update.run(workerId, claimedUntil, eventId, nowIso).changes !== 1) continue;
        claimed.push(rowToEvent(this.#db.prepare(
          "SELECT * FROM outbox_events WHERE event_id = ?",
        ).get(eventId)!));
      }
      return claimed;
    });
  }

  acknowledgeOutbox(eventId: string, workerId: string, now = new Date()): void {
    const result = this.#db.prepare(`
      UPDATE outbox_events
         SET delivered_at = ?, claimed_until = NULL
       WHERE event_id = ? AND claimed_by = ? AND delivered_at IS NULL
    `).run(now.toISOString(), eventId, workerId);
    if (result.changes !== 1) throw new Error("outbox acknowledgement conflict");
  }

  releaseOutbox(
    eventId: string,
    workerId: string,
    retryAt: Date,
  ): void {
    const result = this.#db.prepare(`
      UPDATE outbox_events
         SET available_at = ?, claimed_by = NULL, claimed_until = NULL
       WHERE event_id = ? AND claimed_by = ? AND delivered_at IS NULL
    `).run(retryAt.toISOString(), eventId, workerId);
    if (result.changes !== 1) throw new Error("outbox release conflict");
  }

  outboxEvent<T>(eventId: string): OutboxEvent<T> | undefined {
    const row = this.#db.prepare("SELECT * FROM outbox_events WHERE event_id = ?").get(eventId);
    return row ? rowToEvent<T>(row) : undefined;
  }
}
