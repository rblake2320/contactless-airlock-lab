import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { DurableStore } from "../packages/storage/durableStore.ts";

function databasePath(): { directory: string; path: string } {
  const directory = mkdtempSync(join(tmpdir(), "airlock-durable-"));
  return { directory, path: join(directory, "airlock.sqlite") };
}

test("migration is idempotent and persisted records survive restart", () => {
  const target = databasePath();
  let store: DurableStore | undefined;
  try {
    store = new DurableStore(target.path);
    assert.equal(store.schemaVersion(), 1);
    store.create("challenge-1", "created", { binding: "exact" });
    store.close();
    store = undefined;

    store = new DurableStore(target.path);
    assert.equal(store.schemaVersion(), 1);
    const recovered = store.get<{ binding: string }>("challenge-1");
    assert.equal(recovered?.value.binding, "exact");
    assert.equal(recovered?.status, "created");
    assert.equal(recovered?.version, 0);
    assert.match(recovered?.updatedAt ?? "", /^\d{4}-\d{2}-\d{2}T/);
    store.close();
    store = undefined;
  } finally {
    store?.close();
    rmSync(target.directory, { recursive: true, force: true });
  }
});

test("compare-and-swap permits exactly one terminal transition across two connections", () => {
  const target = databasePath();
  try {
    const first = new DurableStore(target.path);
    const second = new DurableStore(target.path);
    first.create("challenge-race", "created", { result: "pending" });

    first.compareAndSwap(
      "challenge-race", 0, "created", "confirmed", { result: "approved" },
    );
    assert.throws(
      () => second.compareAndSwap(
        "challenge-race", 0, "created", "cancelled", { result: "denied" },
      ),
      /compare-and-swap conflict/,
    );
    assert.equal(second.get("challenge-race")?.status, "confirmed");
    assert.equal(second.get("challenge-race")?.version, 1);
    first.close();
    second.close();
  } finally {
    rmSync(target.directory, { recursive: true, force: true });
  }
});

test("idempotent mutation replays its first response without repeating writes", () => {
  const store = new DurableStore(":memory:");
  let calls = 0;
  const first = store.runIdempotent("issuer", "request-1", "sha256:a", (tx) => {
    calls += 1;
    tx.create("challenge-idem", "created", { once: true });
    tx.enqueue("challenge-idem:created", "challenge.created", "challenge-idem", { once: true });
    return { challengeId: "challenge-idem" };
  });
  const replay = store.runIdempotent("issuer", "request-1", "sha256:a", () => {
    calls += 1;
    return { challengeId: "wrong" };
  });
  assert.equal(first.replayed, false);
  assert.equal(replay.replayed, true);
  assert.deepEqual(replay.value, first.value);
  assert.equal(calls, 1);
  assert.throws(
    () => store.runIdempotent("issuer", "request-1", "sha256:different", () => ({})),
    /different request/,
  );
  store.close();
});

test("failed idempotent operation rolls back state, response, and outbox atomically", () => {
  const store = new DurableStore(":memory:");
  assert.throws(
    () => store.runIdempotent("issuer", "failed", "sha256:x", (tx) => {
      tx.create("rolled-back", "created", { shouldPersist: false });
      tx.enqueue("rolled-back:event", "challenge.created", "rolled-back", {});
      throw new Error("simulated failure");
    }),
    /simulated failure/,
  );
  assert.equal(store.get("rolled-back"), undefined);
  assert.deepEqual(store.claimOutbox("worker", 10, 5_000), []);
  const retry = store.runIdempotent("issuer", "failed", "sha256:x", () => ({ ok: true }));
  assert.equal(retry.replayed, false);
  store.close();
});

test("outbox uniqueness failure rolls back an earlier compare-and-swap", () => {
  const store = new DurableStore(":memory:");
  store.create("atomic-cas", "created", { outcome: "pending" });
  store.enqueue("already-used", "challenge.created", "atomic-cas", {});
  assert.throws(
    () => store.runIdempotent("issuer", "atomic", "sha256:atomic", (tx) => {
      tx.compareAndSwap(
        "atomic-cas", 0, "created", "confirmed", { outcome: "confirmed" },
      );
      tx.enqueue("already-used", "challenge.confirmed", "atomic-cas", {});
      return { ok: true };
    }),
    /UNIQUE constraint failed/,
  );
  const recovered = store.get("atomic-cas");
  assert.equal(recovered?.status, "created");
  assert.equal(recovered?.version, 0);
  const retry = store.runIdempotent(
    "issuer",
    "atomic",
    "sha256:atomic",
    () => ({ recovered: true }),
  );
  assert.equal(retry.replayed, false);
  store.close();
});

test("outbox leases give at-least-once delivery without concurrent ownership", () => {
  const target = databasePath();
  const start = new Date("2026-07-27T12:00:00Z");
  try {
    const producer = new DurableStore(target.path);
    const event = producer.enqueue(
      "challenge-1:confirmed",
      "challenge.confirmed",
      "challenge-1",
      { status: "confirmed" },
      start,
    );
    producer.close();

    let firstWorker = new DurableStore(target.path);
    const secondWorker = new DurableStore(target.path);
    const firstClaim = firstWorker.claimOutbox("worker-a", 10, 5_000, start);
    assert.equal(firstClaim.length, 1);
    assert.equal(firstClaim[0].attempts, 1);
    assert.deepEqual(secondWorker.claimOutbox("worker-b", 10, 5_000, start), []);

    firstWorker.close(); // Simulated worker crash without acknowledgement.
    firstWorker = new DurableStore(target.path);
    const afterLease = new Date(start.getTime() + 5_001);
    const redelivery = secondWorker.claimOutbox("worker-b", 10, 5_000, afterLease);
    assert.equal(redelivery.length, 1);
    assert.equal(redelivery[0].eventId, event.eventId);
    assert.equal(redelivery[0].attempts, 2);
    secondWorker.acknowledgeOutbox(event.eventId, "worker-b", afterLease);
    assert.deepEqual(firstWorker.claimOutbox(
      "worker-c", 10, 5_000, new Date(afterLease.getTime() + 10_000),
    ), []);
    assert.ok(secondWorker.outboxEvent(event.eventId)?.deliveredAt);
    firstWorker.close();
    secondWorker.close();
  } finally {
    rmSync(target.directory, { recursive: true, force: true });
  }
});

test("released outbox event observes retry delay and rejects the wrong owner", () => {
  const store = new DurableStore(":memory:");
  const start = new Date("2026-07-27T12:00:00Z");
  const event = store.enqueue("retry-key", "partner.notify", "aggregate", {}, start);
  store.claimOutbox("worker-a", 1, 5_000, start);
  assert.throws(
    () => store.releaseOutbox(
      event.eventId,
      "worker-b",
      new Date(start.getTime() + 10_000),
      start,
    ),
    /conflict/,
  );
  const retryAt = new Date(start.getTime() + 10_000);
  store.releaseOutbox(event.eventId, "worker-a", retryAt, start);
  assert.deepEqual(
    store.claimOutbox("worker-b", 1, 5_000, new Date(retryAt.getTime() - 1)),
    [],
  );
  assert.equal(store.claimOutbox("worker-b", 1, 5_000, retryAt).length, 1);
  store.close();
});
