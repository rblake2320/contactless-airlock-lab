import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { DurableStore } from "../packages/storage/durableStore.ts";
import {
  PARTNER_EVENT_TYPES,
  PARTNER_WEBHOOK_VERSION,
  assertPartnerEnvelope,
  encodePartnerEnvelope,
  type PartnerWebhookEnvelopeV1,
} from "../packages/partner-transport/contract.ts";
import {
  PartnerOutboxDispatcher,
  UnconfiguredPartnerWebhookAdapter,
  type PartnerWebhookRequest,
} from "../packages/partner-transport/dispatcher.ts";
import {
  emptyPartnerTransportMetrics,
  partnerTransportReadiness,
} from "../packages/partner-transport/operations.ts";
import {
  MemoryPartnerIdempotencyStore,
  receivePartnerWebhook,
} from "../packages/partner-transport/receiver.ts";
import {
  MAX_WEBHOOK_BYTES,
  MemoryReplayStore,
  signPartnerWebhook,
  verifyPartnerWebhook,
} from "../packages/partner-transport/signing.ts";

const now = new Date("2026-07-28T12:00:00.000Z");
const epoch = Math.floor(now.getTime() / 1_000);
const key = {
  keyId: "issuer-key-2026-07",
  secret: Buffer.alloc(32, 0x5a),
};

function envelope(
  overrides: Partial<PartnerWebhookEnvelopeV1> = {},
): PartnerWebhookEnvelopeV1 {
  return {
    schemaVersion: PARTNER_WEBHOOK_VERSION,
    eventId: "d9428888-122b-4aa7-9fcc-1f3f57d1bf0b",
    eventType: "authorization.provisional",
    occurredAt: now.toISOString(),
    issuerId: "issuer-demo",
    processorId: "processor-candidate",
    correlationId: "corr-001",
    aggregateId: "auth-001",
    payload: {
      authorizationId: "auth-001",
      tokenReference: "token-001",
      merchantId: "merchant-001",
      amountMinor: 2500,
      currency: "USD",
      confirmationExpiresAt: "2026-07-28T12:05:00.000Z",
    },
    ...overrides,
  };
}

test("candidate schema vocabulary and runtime envelope cannot drift", async () => {
  const schema = JSON.parse(await readFile(
    new URL(
      "../contracts/partner/issuer-processor-webhook.v1.schema.json",
      import.meta.url,
    ),
    "utf8",
  ));
  assert.equal(schema.properties.schemaVersion.const, PARTNER_WEBHOOK_VERSION);
  assert.deepEqual(schema.properties.eventType.enum, [...PARTNER_EVENT_TYPES]);
  assert.equal(schema["x-contract-status"], "candidate-unagreed");
  assert.equal(schema["x-delivery"].externalEndpointImplemented, false);
  assertPartnerEnvelope(envelope());
  assert.throws(
    () => assertPartnerEnvelope({ ...envelope(), extra: true }),
    /unknown fields/,
  );
  assert.throws(
    () => assertPartnerEnvelope({ ...envelope(), schemaVersion: "v2" }),
    /unsupported/,
  );
  for (const candidate of [
    envelope({
      eventType: "authorization.confirmed",
      payload: { authorizationId: "auth-001", confirmedAt: now.toISOString() },
    }),
    envelope({
      eventType: "authorization.reversal_requested",
      payload: {
        authorizationId: "auth-001",
        reason: "confirmation_timeout",
        requestedAt: now.toISOString(),
      },
    }),
    envelope({
      eventType: "authorization.clearing_exception",
      payload: {
        authorizationId: "auth-001",
        clearingReference: "clear-001",
        detectedAt: now.toISOString(),
      },
    }),
  ]) {
    assertPartnerEnvelope(candidate);
  }
  assert.throws(
    () => assertPartnerEnvelope(envelope({
      eventType: "authorization.confirmed",
    })),
    /confirmation payload fields/,
  );
});

test("signature binds raw body, timestamp, nonce, and idempotency key", () => {
  const body = encodePartnerEnvelope(envelope());
  const headers = signPartnerWebhook({
    body,
    idempotencyKey: "delivery-001",
    nonce: "nonce-001",
    timestampEpochSeconds: epoch,
    key,
  });
  const replayStore = new MemoryReplayStore();
  assert.deepEqual(
    verifyPartnerWebhook({
      body,
      headers,
      resolveKey: (id) => id === key.keyId ? key.secret : undefined,
      replayStore,
      nowEpochSeconds: epoch,
    }),
    { keyId: key.keyId, idempotencyKey: "delivery-001" },
  );
  assert.throws(
    () => verifyPartnerWebhook({
      body,
      headers,
      resolveKey: () => key.secret,
      replayStore,
      nowEpochSeconds: epoch,
    }),
    /replay/,
  );
  for (const changed of [
    { ...headers, "idempotency-key": "delivery-002" },
    { ...headers, "x-airlock-nonce": "nonce-002" },
    { ...headers, "x-airlock-timestamp": String(epoch + 1) },
  ]) {
    assert.throws(
      () => verifyPartnerWebhook({
        body,
        headers: changed,
        resolveKey: () => key.secret,
        replayStore: new MemoryReplayStore(),
        nowEpochSeconds: epoch,
      }),
      /signature/,
    );
  }
  const changedBody = Buffer.from(body);
  changedBody[changedBody.length - 2] ^= 1;
  assert.throws(
    () => verifyPartnerWebhook({
      body: changedBody,
      headers,
      resolveKey: () => key.secret,
      replayStore: new MemoryReplayStore(),
      nowEpochSeconds: epoch,
    }),
    /signature/,
  );
});

test("replay window, key strength, and body limits fail closed", () => {
  const body = encodePartnerEnvelope(envelope());
  const headers = signPartnerWebhook({
    body,
    idempotencyKey: "delivery-001",
    nonce: "nonce-001",
    timestampEpochSeconds: epoch,
    key,
  });
  assert.throws(
    () => verifyPartnerWebhook({
      body,
      headers,
      resolveKey: () => key.secret,
      replayStore: new MemoryReplayStore(),
      nowEpochSeconds: epoch + 301,
    }),
    /replay window/,
  );
  assert.throws(
    () => signPartnerWebhook({
      body,
      idempotencyKey: "delivery-001",
      nonce: "nonce-001",
      timestampEpochSeconds: epoch,
      key: { keyId: "weak", secret: Buffer.alloc(31) },
    }),
    /at least 32/,
  );
  assert.throws(
    () => verifyPartnerWebhook({
      body: Buffer.alloc(MAX_WEBHOOK_BYTES + 1),
      headers,
      resolveKey: () => key.secret,
      replayStore: new MemoryReplayStore(),
      nowEpochSeconds: epoch,
    }),
    /too large/,
  );
  const authoritativeCleanup = new MemoryReplayStore();
  assert.equal(authoritativeCleanup.consumeOnce("key:nonce", 10, 0), true);
  assert.equal(authoritativeCleanup.consumeOnce("key:nonce", 20, 9), false);
  assert.equal(authoritativeCleanup.consumeOnce("key:nonce", 30, 10), true);
});

test("receiver applies once and rejects idempotency substitution", () => {
  const replayStore = new MemoryReplayStore();
  const idempotencyStore = new MemoryPartnerIdempotencyStore();
  let applications = 0;
  const send = (
    body: Uint8Array,
    nonce: string,
    idempotencyKey = "delivery-001",
  ) => receivePartnerWebhook({
    body,
    headers: signPartnerWebhook({
      body,
      idempotencyKey,
      nonce,
      timestampEpochSeconds: epoch,
      key,
    }),
    resolveKey: () => key.secret,
    replayStore,
    idempotencyStore,
    nowEpochSeconds: epoch,
    apply: () => { applications += 1; },
  });
  const firstBody = encodePartnerEnvelope(envelope());
  assert.equal(send(firstBody, "nonce-1").code, "ACCEPTED");
  assert.equal(send(firstBody, "nonce-2").code, "DUPLICATE");
  assert.equal(applications, 1);
  assert.throws(
    () => send(
      encodePartnerEnvelope(envelope({ correlationId: "different" })),
      "nonce-3",
    ),
    /different request/,
  );
  assert.equal(applications, 1);
});

test("real outbox dispatcher acknowledges 2xx and releases retryable failures", async () => {
  const store = new DurableStore(":memory:");
  const first = store.enqueue(
    "delivery-1",
    "partner.webhook",
    "auth-001",
    envelope(),
    now,
  );
  const sent: PartnerWebhookRequest[] = [];
  const clockValues = [
    now,
    new Date(now.getTime() + 1),
    new Date(now.getTime() + 2),
  ];
  const dispatcher = new PartnerOutboxDispatcher(
    store,
    { send: async (request) => { sent.push(request); return { status: 202 }; } },
    key,
    { record: async () => { throw new Error("unexpected dead letter"); } },
    {
      workerId: "dispatcher-1",
      clock: () => clockValues.shift() ?? new Date(now.getTime() + 2),
      nonce: () => "dispatch-nonce-1",
    },
  );
  assert.deepEqual(await dispatcher.dispatchOnce(), [
    { eventId: first.eventId, outcome: "delivered", status: 202 },
  ]);
  assert.ok(store.outboxEvent(first.eventId)?.deliveredAt);
  verifyPartnerWebhook({
    body: sent[0].body,
    headers: sent[0].headers,
    resolveKey: () => key.secret,
    replayStore: new MemoryReplayStore(),
    nowEpochSeconds: epoch,
  });

  const retryStart = new Date(now.getTime() + 10_000);
  const retryEvent = store.enqueue(
    "delivery-2",
    "partner.webhook",
    "auth-002",
    envelope({
      eventId: randomUUID(),
      aggregateId: "auth-002",
      payload: {
        authorizationId: "auth-002",
        tokenReference: "token-001",
        merchantId: "merchant-001",
        amountMinor: 2500,
        currency: "USD",
        confirmationExpiresAt: "2026-07-28T12:05:00.000Z",
      },
    }),
    retryStart,
  );
  const retryTimes = [
    retryStart,
    new Date(retryStart.getTime() + 1),
    new Date(retryStart.getTime() + 2),
  ];
  const retryDispatcher = new PartnerOutboxDispatcher(
    store,
    { send: async () => ({ status: 503 }) },
    key,
    { record: async () => { throw new Error("unexpected dead letter"); } },
    {
      workerId: "dispatcher-2",
      retryDelayMs: 5_000,
      clock: () => retryTimes.shift() ?? new Date(retryStart.getTime() + 2),
      nonce: () => "dispatch-nonce-2",
    },
  );
  assert.equal((await retryDispatcher.dispatchOnce())[0].outcome, "retry_scheduled");
  const retried = store.outboxEvent(retryEvent.eventId)!;
  assert.equal(retried.deliveredAt, undefined);
  assert.equal(retried.availableAt, new Date(retryStart.getTime() + 5_002).toISOString());
  assert.equal(retried.claimedBy, undefined);
  store.close();
});

test("dispatcher bounds hangs, opens its circuit, and dead-letters terminal outcomes", async () => {
  const store = new DurableStore(":memory:");
  let current = new Date(now);
  const deadLetters: Array<{ event: { eventId: string }; reason: string; status?: number }> = [];
  const enqueue = (keyValue: string, aggregateId: string) => store.enqueue(
    keyValue,
    "partner.webhook",
    aggregateId,
    envelope({
      eventId: randomUUID(),
      aggregateId,
      payload: {
        authorizationId: aggregateId,
        tokenReference: "token-001",
        merchantId: "merchant-001",
        amountMinor: 2500,
        currency: "USD",
        confirmationExpiresAt: "2026-07-28T12:05:00.000Z",
      },
    }),
    current,
  );

  const permanent = enqueue("permanent", "auth-permanent");
  const terminal = new PartnerOutboxDispatcher(
    store,
    { send: async () => ({ status: 400 }) },
    key,
    { record: async (record) => { deadLetters.push(record); } },
    {
      workerId: "terminal-worker",
      clock: () => new Date(current),
      nonce: () => "terminal-nonce",
    },
  );
  assert.equal((await terminal.dispatchOnce())[0].outcome, "dead_lettered");
  assert.ok(store.outboxEvent(permanent.eventId)?.deliveredAt);
  assert.equal(deadLetters[0].status, 400);

  current = new Date(current.getTime() + 10);
  const exhausted = enqueue("exhausted", "auth-exhausted");
  const budget = new PartnerOutboxDispatcher(
    store,
    { send: async () => ({ status: 503 }) },
    key,
    { record: async (record) => { deadLetters.push(record); } },
    {
      workerId: "budget-worker",
      maximumAttempts: 1,
      clock: () => new Date(current),
      nonce: () => "budget-nonce",
    },
  );
  assert.equal((await budget.dispatchOnce())[0].outcome, "dead_lettered");
  assert.ok(store.outboxEvent(exhausted.eventId)?.deliveredAt);

  current = new Date(current.getTime() + 10);
  const timedOut = enqueue("timeout", "auth-timeout");
  let aborted = false;
  const timeoutDispatcher = new PartnerOutboxDispatcher(
    store,
    {
      send: async (_request, signal) => new Promise((_resolve, reject) => {
        signal.addEventListener("abort", () => {
          aborted = true;
          reject(new Error("adapter aborted"));
        }, { once: true });
      }),
    },
    key,
    { record: async (record) => { deadLetters.push(record); } },
    {
      workerId: "timeout-worker",
      requestTimeoutMs: 5,
      clock: () => new Date(current),
      nonce: () => "timeout-nonce",
    },
  );
  const timeoutOutcome = (await timeoutDispatcher.dispatchOnce())[0];
  assert.equal(timeoutOutcome.outcome, "retry_scheduled");
  assert.equal(aborted, true);
  assert.equal(store.outboxEvent(timedOut.eventId)?.deliveredAt, undefined);

  current = new Date(current.getTime() + 10);
  let sends = 0;
  const circuitFirst = enqueue("circuit-1", "auth-circuit-1");
  const circuit = new PartnerOutboxDispatcher(
    store,
    { send: async () => { sends += 1; return { status: 503 }; } },
    key,
    { record: async (record) => { deadLetters.push(record); } },
    {
      workerId: "circuit-worker",
      circuitFailureThreshold: 1,
      circuitCooldownMs: 30_000,
      clock: () => new Date(current),
      nonce: () => `circuit-nonce-${sends}`,
    },
  );
  assert.equal((await circuit.dispatchOnce())[0].outcome, "retry_scheduled");
  assert.equal(store.outboxEvent(circuitFirst.eventId)?.deliveredAt, undefined);
  current = new Date(current.getTime() + 10);
  enqueue("circuit-2", "auth-circuit-2");
  const openOutcome = (await circuit.dispatchOnce())[0];
  assert.equal(openOutcome.error, "partner circuit breaker is open");
  assert.equal(sends, 1);

  current = new Date(current.getTime() + 31_000);
  const noSink = enqueue("no-sink", "auth-no-sink");
  const failClosed = new PartnerOutboxDispatcher(
    store,
    { send: async () => ({ status: 400 }) },
    key,
    { record: async () => { throw new Error("dead-letter unavailable"); } },
    {
      workerId: "no-sink-worker",
      clock: () => new Date(current),
      nonce: () => "no-sink-nonce",
    },
  );
  assert.equal((await failClosed.dispatchOnce())[0].outcome, "retry_scheduled");
  assert.equal(store.outboxEvent(noSink.eventId)?.deliveredAt, undefined);
  store.close();
});

test("stub adapter fails closed and readiness never implies an integration", async () => {
  await assert.rejects(
    () => new UnconfiguredPartnerWebhookAdapter().send({
      body: Buffer.from("{}"),
      headers: signPartnerWebhook({
        body: Buffer.from("{}"),
        idempotencyKey: "id",
        nonce: "nonce",
        timestampEpochSeconds: epoch,
        key,
      }),
    }, new AbortController().signal),
    /not configured/,
  );
  const readiness = partnerTransportReadiness({
      signingKeyConfigured: true,
      replayStoreReachable: true,
      outboxReachable: true,
      partnerAdapterConfigured: false,
    });
  assert.deepEqual(
    readiness,
    {
      schemaVersion: "airlock.partner-transport.readiness.v1",
      ready: false,
      checks: {
        signingKeyConfigured: true,
        replayStoreReachable: true,
        outboxReachable: true,
        partnerAdapterConfigured: false,
      },
    },
  );
  const metrics = emptyPartnerTransportMetrics(now);
  assert.equal(
    metrics.schemaVersion,
    "airlock.partner-transport.metrics.v1",
  );
  const schema = JSON.parse(await readFile(
    new URL("../contracts/partner/operations.v1.schema.json", import.meta.url),
    "utf8",
  ));
  assert.deepEqual(
    Object.keys(metrics.counters).sort(),
    [...schema.$defs.metrics.properties.counters.required].sort(),
  );
  assert.deepEqual(
    Object.keys(metrics.gauges).sort(),
    [...schema.$defs.metrics.properties.gauges.required].sort(),
  );
  assert.deepEqual(
    Object.keys(readiness.checks).sort(),
    [...schema.$defs.readiness.properties.checks.required].sort(),
  );
});
