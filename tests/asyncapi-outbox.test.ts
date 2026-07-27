import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import test from "node:test";
import {
  DurableStore,
  OUTBOX_LIMITS,
} from "../packages/storage/durableStore.ts";

interface JsonSchema {
  type: "object";
  additionalProperties: false;
  required: string[];
  properties: Record<string, {
    type?: string;
    format?: string;
    minimum?: number;
    minLength?: number;
    maxLength?: number;
    "x-maxSerializedBytes"?: number;
    "x-sqlite-column": string;
  }>;
}

async function contract() {
  return JSON.parse(
    await readFile(
      new URL(
        "../contracts/asyncapi/simulator-outbox.asyncapi.json",
        import.meta.url,
      ),
      "utf8",
    ),
  ) as Record<string, any>;
}

function validateRecord(schema: JsonSchema, input: unknown): void {
  const value = JSON.parse(JSON.stringify(input)) as Record<string, unknown>;
  assert.equal(Array.isArray(value), false);
  assert.deepEqual(
    Object.keys(value).filter((key) => !(key in schema.properties)),
    [],
  );
  for (const required of schema.required) {
    assert.equal(required in value, true, `missing ${required}`);
  }
  for (const [key, field] of Object.entries(schema.properties)) {
    const candidate = value[key];
    if (candidate === undefined) continue;
    if (field.type === "string") {
      assert.equal(typeof candidate, "string", key);
      if (field.minLength) assert.ok((candidate as string).length >= field.minLength, key);
      if (field.maxLength) assert.ok((candidate as string).length <= field.maxLength, key);
      if (field.format === "date-time") {
        assert.ok(Number.isFinite(Date.parse(candidate as string)), key);
      }
      if (field.format === "uuid") {
        assert.match(
          candidate as string,
          /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i,
        );
      }
    } else if (field.type === "integer") {
      assert.equal(Number.isSafeInteger(candidate), true, key);
      assert.ok((candidate as number) >= (field.minimum ?? 0), key);
    }
  }
}

test("AsyncAPI schema is an exact property/optionality projection of OutboxEvent", async () => {
  const document = await contract();
  assert.equal(document.asyncapi, "3.0.0");
  const schema = document.components.schemas.SimulatorOutboxRecordV1 as JsonSchema;
  const source = await readFile(
    new URL("../packages/storage/durableStore.ts", import.meta.url),
    "utf8",
  );
  const block = /export interface OutboxEvent<[^>]+> \{([\s\S]*?)\n\}/.exec(source)?.[1];
  assert.ok(block, "OutboxEvent source interface not found");
  const fields = [...block.matchAll(/^\s+([A-Za-z][A-Za-z0-9]*)(\?)?:/gm)]
    .map((match) => ({ name: match[1], optional: Boolean(match[2]) }));

  assert.deepEqual(
    Object.keys(schema.properties).sort(),
    fields.map((field) => field.name).sort(),
  );
  assert.deepEqual(
    [...schema.required].sort(),
    fields.filter((field) => !field.optional).map((field) => field.name).sort(),
  );
});

test("AsyncAPI SQLite mappings and simulator-only limitations cannot drift silently", async () => {
  const document = await contract();
  const schema = document.components.schemas.SimulatorOutboxRecordV1 as JsonSchema;
  assert.equal(document.channels.simulatorOutbox.address, "outbox_events");
  assert.equal(document.channels.simulatorOutbox.parameters, undefined);
  assert.equal(schema.properties.eventKey.maxLength, OUTBOX_LIMITS.eventKey);
  assert.equal(schema.properties.topic.maxLength, OUTBOX_LIMITS.topic);
  assert.equal(schema.properties.aggregateId.maxLength, OUTBOX_LIMITS.aggregateId);
  assert.equal(schema.properties.claimedBy.maxLength, OUTBOX_LIMITS.workerId);
  assert.equal(
    schema.properties.payload["x-maxSerializedBytes"],
    OUTBOX_LIMITS.payloadBytes,
  );

  const directory = mkdtempSync(join(tmpdir(), "airlock-outbox-metadata-"));
  const path = join(directory, "store.sqlite");
  const store = new DurableStore(path);
  store.close();
  const db = new DatabaseSync(path);
  try {
    const columns = db.prepare("PRAGMA table_info(outbox_events)").all() as Array<
      Record<string, unknown>
    >;
    const byName = new Map(columns.map((column) => [column.name, column]));
    const expectedTypes: Record<string, string> = {
      event_id: "TEXT",
      event_key: "TEXT",
      topic: "TEXT",
      aggregate_id: "TEXT",
      payload_json: "TEXT",
      created_at: "TEXT",
      available_at: "TEXT",
      attempts: "INTEGER",
      claimed_by: "TEXT",
      claimed_until: "TEXT",
      delivered_at: "TEXT",
    };
    for (const field of Object.values(schema.properties)) {
      const column = byName.get(field["x-sqlite-column"]);
      assert.ok(column, `missing SQLite column ${field["x-sqlite-column"]}`);
      assert.equal(column.type, expectedTypes[field["x-sqlite-column"]]);
      const optional = !schema.required.includes(
        Object.entries(schema.properties).find(([, value]) => value === field)![0],
      );
      assert.equal(column.notnull === 0, optional, `${String(column.name)} nullability`);
    }
    const indexes = db.prepare("PRAGMA index_list(outbox_events)").all() as Array<
      Record<string, unknown>
    >;
    const unique = indexes.find((index) => index.unique === 1);
    assert.ok(unique, "event_key UNIQUE index missing");
    const indexed = db.prepare(`PRAGMA index_info("${String(unique.name)}")`).all();
    assert.deepEqual(indexed.map((column: any) => column.name), ["event_key"]);
    const ddl = db.prepare(
      "SELECT sql FROM sqlite_master WHERE type='table' AND name='outbox_events'",
    ).get()!.sql as string;
    assert.match(ddl, /attempts INTEGER NOT NULL DEFAULT 0 CHECK \(attempts >= 0\)/);
    assert.throws(
      () => db.prepare(`
        INSERT INTO outbox_events(
          event_id,event_key,topic,aggregate_id,payload_json,created_at,available_at,attempts
        ) VALUES ('id','key','topic','aggregate','{}','now','now',-1)
      `).run(),
      /CHECK constraint failed/,
    );
  } finally {
    db.close();
    rmSync(directory, { recursive: true, force: true });
  }

  const message = document.components.messages.simulatorOutboxRecord;
  assert.equal(message["x-contract-version"], 1);
  assert.equal(message["x-versioning"].runtimeFieldPresent, false);
  assert.equal(message["x-idempotency"].producerKey, "eventKey");
  assert.equal(message["x-correlation"].currentField, "aggregateId");
  assert.equal(message["x-correlation"].explicitCorrelationIdPresent, false);
  assert.equal(message["x-retry"].delivery, "at-least-once");
  assert.equal(message["x-retry"].automaticBackoffImplemented, false);
  assert.equal(message["x-retry"].maximumAttemptsImplemented, false);
  assert.equal(message["x-retry"].deadLetterQueueImplemented, false);
  assert.deepEqual(document["x-production-contract-status"], {
    agreed: false,
    partnerReviewed: false,
    authenticationDefined: false,
    transportDefined: false,
    topicPayloadSchemasDefined: false,
    compatibilityPolicyDefined: false,
  });
});

test("real outbox create, lease, retry, and acknowledgement states conform", async () => {
  const document = await contract();
  const schema = document.components.schemas.SimulatorOutboxRecordV1 as JsonSchema;
  const store = new DurableStore(":memory:");
  try {
    const start = new Date("2026-07-27T12:00:00.000Z");
    const event = store.enqueue(
      "synthetic-aggregate:decision:v1",
      "simulator.decision.recorded",
      "synthetic-aggregate",
      { schemaVersion: 1, decision: "declined" },
      start,
    );
    validateRecord(schema, event);
    assert.throws(
      () =>
        store.enqueue(
          event.eventKey,
          event.topic,
          event.aggregateId,
          event.payload,
          start,
        ),
      /UNIQUE constraint failed/,
    );

    const [claimed] = store.claimOutbox("worker-a", 1, 5_000, start);
    validateRecord(schema, claimed);
    assert.equal(claimed.attempts, 1);
    assert.equal(claimed.claimedBy, "worker-a");

    const retryAt = new Date(start.getTime() + 10_000);
    store.releaseOutbox(event.eventId, "worker-a", retryAt, start);
    const released = store.outboxEvent(event.eventId)!;
    assert.equal(released.claimedBy, undefined);
    assert.equal(released.claimedUntil, undefined);
    assert.deepEqual(
      store.claimOutbox("worker-b", 1, 5_000, new Date(retryAt.getTime() - 1)),
      [],
    );
    const [retried] = store.claimOutbox("worker-b", 1, 5_000, retryAt);
    validateRecord(schema, retried);
    assert.equal(retried.attempts, 2);

    store.acknowledgeOutbox(event.eventId, "worker-b", retryAt);
    const delivered = store.outboxEvent(event.eventId)!;
    validateRecord(schema, delivered);
    assert.equal(typeof delivered.deliveredAt, "string");
    assert.equal(delivered.claimedBy, undefined);
    assert.equal(delivered.claimedUntil, undefined);
    assert.deepEqual(
      store.claimOutbox(
        "worker-c",
        1,
        5_000,
        new Date(retryAt.getTime() + 10_000),
      ),
      [],
    );
  } finally {
    store.close();
  }
});

test("outbox input and lease boundaries fail closed", () => {
  const store = new DurableStore(":memory:");
  const start = new Date("2026-07-27T12:00:00.000Z");
  const oversizedPayload = { value: "x".repeat(OUTBOX_LIMITS.payloadBytes) };
  try {
    const boundary = store.enqueue(
      "k".repeat(OUTBOX_LIMITS.eventKey),
      "t".repeat(OUTBOX_LIMITS.topic),
      "a".repeat(OUTBOX_LIMITS.aggregateId),
      "p".repeat(OUTBOX_LIMITS.payloadBytes - 2),
      start,
    );
    assert.equal(
      Buffer.byteLength(JSON.stringify(boundary.payload)),
      OUTBOX_LIMITS.payloadBytes,
    );
    store.claimOutbox(
      "w".repeat(OUTBOX_LIMITS.workerId),
      1,
      1_000,
      start,
    );
    store.acknowledgeOutbox(
      boundary.eventId,
      "w".repeat(OUTBOX_LIMITS.workerId),
      new Date(start.getTime() + 1),
    );
    for (const eventKey of ["", "   ", "x".repeat(OUTBOX_LIMITS.eventKey + 1)]) {
      assert.throws(
        () => store.enqueue(eventKey, "topic", "aggregate", {}, start),
        /invalid outbox event key/,
      );
    }
    for (const topic of ["", " ", "x".repeat(OUTBOX_LIMITS.topic + 1)]) {
      assert.throws(
        () => store.enqueue("key", topic, "aggregate", {}, start),
        /invalid outbox topic/,
      );
    }
    for (const aggregate of ["", "\t", "x".repeat(OUTBOX_LIMITS.aggregateId + 1)]) {
      assert.throws(
        () => store.enqueue("key", "topic", aggregate, {}, start),
        /invalid outbox aggregate id/,
      );
    }
    assert.throws(
      () => store.enqueue("key", "topic", "aggregate", undefined, start),
      /invalid outbox payload/,
    );
    assert.throws(
      () => store.enqueue("key", "topic", "aggregate", 1n, start),
      /invalid outbox payload/,
    );
    assert.throws(
      () => store.enqueue("key", "topic", "aggregate", oversizedPayload, start),
      /invalid outbox payload/,
    );
    assert.throws(
      () =>
        store.claimOutbox(
          "w".repeat(OUTBOX_LIMITS.workerId + 1),
          1,
          1_000,
          start,
        ),
      /invalid outbox worker id/,
    );

    const event = store.enqueue("leased", "topic", "aggregate", {}, start);
    store.claimOutbox("worker", 1, 1_000, start);
    const expiry = new Date(start.getTime() + 1_000);
    assert.throws(
      () => store.acknowledgeOutbox(event.eventId, "worker", expiry),
      /conflict/,
    );
    assert.throws(
      () => store.releaseOutbox(event.eventId, "worker", expiry, expiry),
      /conflict/,
    );
    const [reclaimed] = store.claimOutbox("next-worker", 1, 1_000, expiry);
    assert.equal(reclaimed.eventId, event.eventId);
    assert.throws(
      () => store.acknowledgeOutbox(event.eventId, "worker", expiry),
      /conflict/,
    );
  } finally {
    store.close();
  }
});
