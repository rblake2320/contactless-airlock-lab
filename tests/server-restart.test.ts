import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import test from "node:test";
import type { AddressInfo } from "node:net";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { createLabServer } from "../apps/realtime-lab/server.ts";
import {
  DurableStore,
  type VersionedRecord,
} from "../packages/storage/durableStore.ts";

async function start(dbPath?: string) {
  const server = createLabServer(dbPath ? { dbPath } : {});
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address() as AddressInfo;
  return {
    baseUrl: `http://127.0.0.1:${port}`,
    close: () => new Promise<void>((resolve, reject) =>
      server.close((error) => error ? reject(error) : resolve())),
  };
}

let idempotencySequence = 0;

async function post(
  baseUrl: string,
  path: string,
  body?: unknown,
  idempotencyKey = `test-${++idempotencySequence}`,
) {
  const init: RequestInit = {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "idempotency-key": idempotencyKey,
    },
    body: JSON.stringify(body ?? {}),
  };
  const response = await fetch(`${baseUrl}${path}`, init);
  return { response, payload: await response.json() };
}

async function state(baseUrl: string) {
  return (await fetch(`${baseUrl}/api/state`)).json();
}

async function withDatabase(
  fn: (dbPath: string) => Promise<void>,
): Promise<void> {
  const directory = await mkdtemp(join(tmpdir(), "airlock-server-restart-"));
  try {
    await fn(join(directory, "lab.sqlite"));
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
}

test("persisted realtime lab restores exact protocol progress and can continue", async () => {
  await withDatabase(async (dbPath) => {
    const first = await start(dbPath);
    assert.equal((await post(first.baseUrl, "/api/provision/request")).response.status, 200);
    assert.equal((await post(first.baseUrl, "/api/provision/approve")).response.status, 200);
    const requested = await post(first.baseUrl, "/api/transaction/request", {
      amount: "25.00",
      merchantId: "restart-merchant",
    });
    assert.equal(requested.response.status, 200);
    const challengeId = requested.payload.transaction.challenge.challengeId;
    const auditCount = requested.payload.audit.events.length;
    await first.close();

    const second = await start(dbPath);
    const restored = await state(second.baseUrl);
    assert.equal(restored.token.state, "active_full");
    assert.equal(restored.transaction.state, "confirmation_pending");
    assert.equal(restored.transaction.challenge.challengeId, challengeId);
    assert.equal(restored.audit.events.length, auditCount);
    assert.equal(restored.audit.valid, true);
    assert.equal(
      (await post(second.baseUrl, "/api/transaction/confirm")).response.status,
      200,
    );
    await second.close();

    const third = await start(dbPath);
    const continued = await state(third.baseUrl);
    assert.equal(continued.transaction.state, "confirmed");
    assert.equal(continued.audit.valid, true);
    await third.close();
  });
});

test("every successful mutation advances the durable snapshot version", async () => {
  await withDatabase(async (dbPath) => {
    const lab = await start(dbPath);
    const inspect = () => {
      const store = new DurableStore(dbPath);
      try {
        return store.get<Record<string, unknown>>("realtime-lab:simulator-state");
      } finally {
        store.close();
      }
    };
    assert.equal(inspect()?.version, 0, "initial enrollment snapshot");
    assert.equal((await post(lab.baseUrl, "/api/provision/request")).response.status, 200);
    assert.equal(inspect()?.version, 1);
    assert.equal((await post(lab.baseUrl, "/api/provision/approve")).response.status, 200);
    assert.equal(inspect()?.version, 2);
    assert.equal((await post(lab.baseUrl, "/api/device/revoke")).response.status, 200);
    assert.equal(inspect()?.version, 3);
    await lab.close();
  });
});

test("persisted synthetic private key is explicitly labeled simulator-only", async () => {
  await withDatabase(async (dbPath) => {
    const lab = await start(dbPath);
    await lab.close();
    const store = new DurableStore(dbPath);
    try {
      const record = store.get<{
        simulatorOnly: boolean;
        keyMaterialWarning: string;
        keys: { privateKeyPem: string };
      }>("realtime-lab:simulator-state");
      assert.equal(record?.value.simulatorOnly, true);
      assert.match(record?.value.keyMaterialWarning ?? "", /SIMULATOR ONLY/);
      assert.match(record?.value.keyMaterialWarning ?? "", /never use.*production/i);
      assert.match(
        record?.value.keys.privateKeyPem ?? "",
        new RegExp(`BEGIN ${"PRIVATE KEY"}`),
      );
    } finally {
      store.close();
    }
  });
});

test("without AIRLOCK_DB_PATH-equivalent option each server remains ephemeral", async () => {
  const first = await start();
  assert.equal((await post(first.baseUrl, "/api/provision/request")).response.status, 200);
  await first.close();
  const second = await start();
  const restored = await state(second.baseUrl);
  assert.equal(restored.provisioning, undefined);
  assert.equal(restored.token, undefined);
  await second.close();
});

test("two lab servers cannot overwrite a newer snapshot with stale state", async () => {
  await withDatabase(async (dbPath) => {
    const first = await start(dbPath);
    const stale = await start(dbPath);
    assert.equal((await post(first.baseUrl, "/api/provision/request")).response.status, 200);
    const conflict = await post(stale.baseUrl, "/api/provision/request");
    assert.equal(conflict.response.status, 409);
    assert.match(conflict.payload.error, /stale mutation was rolled back/);
    assert.equal(conflict.payload.state.provisioning.state, "trusted_device_challenge");
    await first.close();
    await stale.close();

    const restored = await start(dbPath);
    const snapshot = await state(restored.baseUrl);
    assert.equal(snapshot.provisioning.state, "trusted_device_challenge");
    assert.equal(snapshot.token.state, "pending");
    assert.equal(snapshot.audit.valid, true);
    await restored.close();
  });
});

test("tampered simulator-key persistence fails closed during restore", async () => {
  await withDatabase(async (dbPath) => {
    const lab = await start(dbPath);
    await lab.close();
    const store = new DurableStore(dbPath);
    const record = store.get<Record<string, unknown>>("realtime-lab:simulator-state")!;
    store.compareAndSwap(
      "realtime-lab:simulator-state",
      record.version,
      record.status,
      record.status,
      { ...record.value, keyMaterialWarning: "production-safe" },
    );
    store.close();
    assert.throws(
      () => createLabServer({ dbPath }),
      /invalid realtime-lab simulator snapshot/,
    );
  });
});

test("persistence failure rolls memory back and cannot leak into a later save", async () => {
  await withDatabase(async (dbPath) => {
    class FailOnceStore extends DurableStore {
      failNextSave = true;

      override compareAndSwap<T extends object>(
        challengeId: string,
        expectedVersion: number,
        expectedStatus: string,
        nextStatus: string,
        nextValue: T,
        now?: Date,
      ): VersionedRecord<T> {
        if (this.failNextSave) {
          this.failNextSave = false;
          throw new Error("synthetic disk failure");
        }
        return super.compareAndSwap(
          challengeId,
          expectedVersion,
          expectedStatus,
          nextStatus,
          nextValue,
          now,
        );
      }
    }
    const lab = createLabServer({
      dbPath,
      storeFactory: (path) => new FailOnceStore(path),
    });
    await new Promise<void>((resolve) => lab.listen(0, "127.0.0.1", resolve));
    const { port } = lab.address() as AddressInfo;
    const baseUrl = `http://127.0.0.1:${port}`;

    const failed = await post(baseUrl, "/api/provision/request");
    assert.equal(failed.response.status, 503);
    assert.match(failed.payload.error, /durably save/);
    assert.equal(failed.payload.state.provisioning, undefined);
    assert.equal(failed.payload.state.token, undefined);

    const succeeded = await post(baseUrl, "/api/provision/request");
    assert.equal(succeeded.response.status, 200);
    await new Promise<void>((resolve, reject) =>
      lab.close((error) => error ? reject(error) : resolve()));

    const restored = await start(dbPath);
    const snapshot = await state(restored.baseUrl);
    assert.equal(snapshot.provisioning.requestId, succeeded.payload.provisioning.requestId);
    assert.equal(snapshot.token.state, "pending");
    assert.equal(snapshot.audit.events.filter(
      (event: { type: string }) => event.type === "provisioning.challenge_created",
    ).length, 1);
    await restored.close();
  });
});

test("handler failure after engine mutation cannot commit partial protocol state", async () => {
  await withDatabase(async (dbPath) => {
    let fail = true;
    const lab = createLabServer({
      dbPath,
      faultInjector: (action) => {
        if (fail && action === "provision.request") {
          fail = false;
          throw new Error("synthetic handler failure after mutation");
        }
      },
    });
    await new Promise<void>((resolve) => lab.listen(0, "127.0.0.1", resolve));
    const { port } = lab.address() as AddressInfo;
    const baseUrl = `http://127.0.0.1:${port}`;
    const failed = await post(baseUrl, "/api/provision/request");
    assert.equal(failed.response.status, 409);
    assert.match(failed.payload.error, /synthetic handler failure/);
    assert.equal(failed.payload.state.provisioning, undefined);
    assert.equal(failed.payload.state.token, undefined);
    await new Promise<void>((resolve, reject) =>
      lab.close((error) => error ? reject(error) : resolve()));

    const restored = await start(dbPath);
    const snapshot = await state(restored.baseUrl);
    assert.equal(snapshot.provisioning, undefined);
    assert.equal(snapshot.token, undefined);
    assert.equal(snapshot.audit.events.some(
      (event: { type: string }) => event.type === "provisioning.challenge_created",
    ), false);
    assert.match(snapshot.lastResult.message, /synthetic handler failure/);
    await restored.close();
  });
});
