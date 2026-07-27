import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import test from "node:test";
import type { AddressInfo } from "node:net";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { createLabServer } from "../apps/realtime-lab/server.ts";
import { DurableStore } from "../packages/storage/durableStore.ts";

async function withDatabase(fn: (dbPath: string) => Promise<void>): Promise<void> {
  const directory = await mkdtemp(join(tmpdir(), "airlock-idempotency-"));
  try {
    await fn(join(directory, "lab.sqlite"));
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
}

async function start(dbPath?: string) {
  const server = createLabServer(dbPath ? { dbPath } : {});
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address() as AddressInfo;
  return {
    server,
    baseUrl: `http://127.0.0.1:${port}`,
    close: () => new Promise<void>((resolve, reject) =>
      server.close((error) => error ? reject(error) : resolve())),
  };
}

async function post(
  baseUrl: string,
  path: string,
  key: string | undefined,
  body: Record<string, unknown> = {},
) {
  const headers: Record<string, string> = { "content-type": "application/json" };
  if (key !== undefined) headers["idempotency-key"] = key;
  const response = await fetch(`${baseUrl}${path}`, {
    method: "POST",
    headers,
    body: JSON.stringify(body),
  });
  const text = await response.text();
  return { response, text, payload: JSON.parse(text) };
}

function snapshotVersion(dbPath: string): number {
  const store = new DurableStore(dbPath);
  try {
    return store.get<Record<string, unknown>>("realtime-lab:simulator-state")!.version;
  } finally {
    store.close();
  }
}

test("same key and canonical request replays exact original response after restart", async () => {
  await withDatabase(async (dbPath) => {
    const first = await start(dbPath);
    let original;
    try {
      original = await post(
        first.baseUrl,
        "/api/provision/request",
        "provision-restart-1",
      );
      assert.equal(original.response.status, 200);
      assert.equal(snapshotVersion(dbPath), 1);
    } finally {
      await first.close();
    }

    const second = await start(dbPath);
    try {
      const replay = await post(
        second.baseUrl,
        "/api/provision/request",
        "provision-restart-1",
      );
      assert.equal(replay.response.status, original.response.status);
      assert.equal(replay.text, original.text);
      assert.equal(snapshotVersion(dbPath), 1, "replay must not save a new snapshot");
      assert.equal(replay.payload.audit.events.filter(
        (event: { type: string }) => event.type === "provisioning.challenge_created",
      ).length, 1);
    } finally {
      await second.close();
    }
  });
});
test("same key with a different body or path is rejected without effects", async () => {
  await withDatabase(async (dbPath) => {
    const lab = await start(dbPath);
    try {
      await post(lab.baseUrl, "/api/provision/request", "setup-request");
      await post(lab.baseUrl, "/api/provision/approve", "setup-approve");
      const original = await post(
        lab.baseUrl,
        "/api/transaction/request",
        "transaction-once",
        { merchantId: "merchant-A", amount: "25.00" },
      );
      assert.equal(original.response.status, 200);
      const version = snapshotVersion(dbPath);

      const changedBody = await post(
        lab.baseUrl,
        "/api/transaction/request",
        "transaction-once",
        { amount: "25.01", merchantId: "merchant-A" },
      );
      assert.equal(changedBody.response.status, 409);
      assert.match(changedBody.payload.error, /different request/);

      const changedPath = await post(
        lab.baseUrl,
        "/api/reset",
        "transaction-once",
      );
      assert.equal(changedPath.response.status, 409);
      assert.match(changedPath.payload.error, /different request/);
      assert.equal(snapshotVersion(dbPath), version);
      const current = await (await fetch(`${lab.baseUrl}/api/state`)).json();
      assert.equal(current.transaction.transactionId, original.payload.transaction.transactionId);
    } finally {
      await lab.close();
    }
  });
});

test("concurrent duplicate requests across two servers produce exactly one effect", async () => {
  await withDatabase(async (dbPath) => {
    const first = await start(dbPath);
    const second = await start(dbPath);
    try {
      const [left, right] = await Promise.all([
        post(first.baseUrl, "/api/provision/request", "concurrent-provision"),
        post(second.baseUrl, "/api/provision/request", "concurrent-provision"),
      ]);
      assert.equal(left.response.status, 200);
      assert.equal(right.response.status, 200);
      assert.equal(left.text, right.text);
      assert.equal(snapshotVersion(dbPath), 1);
      assert.equal(left.payload.audit.events.filter(
        (event: { type: string }) => event.type === "provisioning.challenge_created",
      ).length, 1);
    } finally {
      await first.close();
      await second.close();
    }
  });
});

test("persistent key policy is required, bounded, validated; ephemeral mode stays compatible", async () => {
  await withDatabase(async (dbPath) => {
    const persistent = await start(dbPath);
    try {
      assert.equal(
        (await post(persistent.baseUrl, "/api/provision/request", undefined)).response.status,
        428,
      );
      assert.equal(
        (await post(persistent.baseUrl, "/api/provision/request", "x".repeat(129))).response.status,
        431,
      );
      assert.equal(
        (await post(persistent.baseUrl, "/api/provision/request", "invalid key")).response.status,
        400,
      );
      assert.equal(
        (await post(persistent.baseUrl, "/api/provision/request", "x".repeat(128))).response.status,
        200,
      );
    } finally {
      await persistent.close();
    }
  });

  const ephemeral = await start();
  try {
    assert.equal(
      (await post(ephemeral.baseUrl, "/api/provision/request", undefined)).response.status,
      200,
    );
  } finally {
    await ephemeral.close();
  }
});
