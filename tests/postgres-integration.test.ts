import assert from "node:assert/strict";
import { spawn, type ChildProcess } from "node:child_process";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { randomUUID } from "node:crypto";
import { PostgresDurableStore } from "../packages/storage/postgresStore.ts";

const connectionString = process.env.AIRLOCK_POSTGRES_URL;
const workerPath = fileURLToPath(
  new URL("./fixtures/postgres-cap-worker.ts", import.meta.url),
);

interface WorkerResult {
  type: "result";
  ok: boolean;
  value?: { reservationId: string };
  error?: string;
}

function capWorker(tenantId: string, reservationId: string) {
  const child = spawn(
    process.execPath,
    ["--experimental-strip-types", workerPath, tenantId, reservationId],
    {
      stdio: ["ignore", "ignore", "pipe", "ipc"],
      env: { ...process.env, AIRLOCK_POSTGRES_URL: connectionString! },
      windowsHide: true,
    },
  );
  let stderr = "";
  child.stderr?.on("data", (chunk) => { stderr += chunk.toString(); });
  const ready = new Promise<void>((resolve, reject) => {
    const timeout = setTimeout(
      () => reject(new Error(`PostgreSQL worker startup timed out: ${stderr}`)),
      15_000,
    );
    child.once("error", reject);
    child.on("message", (message: { type?: string }) => {
      if (message.type === "ready") {
        clearTimeout(timeout);
        resolve();
      }
    });
  });
  const result = new Promise<WorkerResult>((resolve, reject) => {
    const timeout = setTimeout(
      () => reject(new Error(`PostgreSQL worker race timed out: ${stderr}`)),
      15_000,
    );
    child.once("error", reject);
    child.on("message", (message: WorkerResult) => {
      if (message.type === "result") {
        clearTimeout(timeout);
        resolve(message);
      }
    });
  });
  return { child, ready, result, stderr: () => stderr };
}

test("PostgreSQL adapter proves tenant CAS, idempotency, outbox, and cap races", {
  skip: connectionString
    ? false
    : "AIRLOCK_POSTGRES_URL is not configured; real PostgreSQL integration skipped",
  timeout: 60_000,
}, async () => {
  const tenant = `integration-${randomUUID()}`;
  const otherTenant = `integration-${randomUUID()}`;
  const [first, second] = await Promise.all([
    PostgresDurableStore.connect({ connectionString, max: 4 }),
    PostgresDurableStore.connect({ connectionString, max: 4 }),
  ]);
  const children = new Set<ChildProcess>();
  try {
    await first.create(tenant, "state", "active", { winner: null });
    await first.create(otherTenant, "state", "active", { isolated: true });
    const cas = await Promise.allSettled([
      first.compareAndSwap(tenant, "state", 0, "active", "active", { winner: "first" }),
      second.compareAndSwap(tenant, "state", 0, "active", "active", { winner: "second" }),
    ]);
    assert.equal(cas.filter((result) => result.status === "fulfilled").length, 1);
    assert.equal((await first.get(tenant, "state"))?.version, 1);
    assert.deepEqual((await first.get(otherTenant, "state"))?.value, { isolated: true });

    await first.create(tenant, "idempotent", "created", { executions: 0 });
    let executions = 0;
    const operation = async (
      store: PostgresDurableStore,
      label: string,
    ) => store.runIdempotent(
      tenant,
      "mutation",
      "same-key",
      "sha256:same-request",
      async (tx) => {
        executions += 1;
        const current = await tx.get<{ executions: number }>(tenant, "idempotent");
        const saved = await tx.compareAndSwap(
          tenant,
          "idempotent",
          current!.version,
          "created",
          "created",
          { executions: current!.value.executions + 1 },
        );
        await tx.enqueue(
          tenant,
          "idempotent-effect",
          "integration.effect",
          "idempotent",
          { version: saved.version, label },
        );
        return { version: saved.version };
      },
    );
    const idem = await Promise.all([
      operation(first, "first"),
      operation(second, "second"),
    ]);
    assert.equal(executions, 1);
    assert.equal(idem.filter((result) => result.replayed).length, 1);
    assert.deepEqual(idem[0].value, idem[1].value);
    assert.equal((await first.get(tenant, "idempotent"))?.version, 1);
    await assert.rejects(
      () => first.runIdempotent(
        tenant,
        "mutation",
        "same-key",
        "sha256:different",
        async () => ({ impossible: true }),
      ),
      /different request/,
    );

    for (let index = 0; index < 3; index += 1) {
      await first.enqueue(
        tenant,
        `event-${index}`,
        "integration.effect",
        "state",
        { index },
        new Date(`2026-07-28T12:00:0${index}Z`),
      );
    }
    const claimed = (await Promise.all([
      first.claimOutbox(tenant, "worker-a", 2, 30_000, new Date("2026-07-28T12:01:00Z")),
      second.claimOutbox(tenant, "worker-b", 2, 30_000, new Date("2026-07-28T12:01:00Z")),
    ])).flat();
    assert.equal(claimed.length, 4);
    assert.equal(new Set(claimed.map((event) => event.eventId)).size, 4);

    const workers = [
      capWorker(tenant, "reservation-a"),
      capWorker(tenant, "reservation-b"),
    ];
    workers.forEach(({ child }) => children.add(child));
    await Promise.all(workers.map(({ ready }) => ready));
    workers.forEach(({ child }) => child.send("go"));
    const cap = await Promise.all(workers.map(({ result }) => result));
    await Promise.all(workers.map(({ child, stderr }) =>
      new Promise<void>((resolve, reject) => {
        if (child.exitCode !== null) return resolve();
        child.once("exit", (code) =>
          code === 0
            ? resolve()
            : reject(new Error(`PostgreSQL worker exited ${code}: ${stderr()}`)));
      })));
    workers.forEach(({ child }) => children.delete(child));
    assert.equal(cap.filter((result) => result.ok).length, 1, JSON.stringify(cap));
    assert.equal(cap.filter((result) =>
      result.error === "transaction exceeds token daily cap").length, 1);
    assert.deepEqual(
      await first.capUsage(tenant, "shared-token", "2026-07-28"),
      { reservedMinor: 750, capMinor: 1_000 },
    );
    const winner = cap.find((result) => result.ok)!.value!.reservationId;
    const loser = winner === "reservation-a" ? "reservation-b" : "reservation-a";
    await first.releaseCap(tenant, winner, new Date("2026-07-28T12:02:00Z"));
    const retried = await second.reserveCap({
      tenantId: tenant,
      reservationId: loser,
      tokenId: "shared-token",
      spendDate: "2026-07-28",
      amountMinor: 750,
      capMinor: 1_000,
      now: new Date("2026-07-28T12:03:00Z"),
    });
    assert.equal(retried.replayed, false);
    assert.equal((await second.reserveCap({
      tenantId: tenant,
      reservationId: loser,
      tokenId: "shared-token",
      spendDate: "2026-07-28",
      amountMinor: 750,
      capMinor: 1_000,
    })).replayed, true);
    assert.deepEqual(
      await first.capUsage(tenant, "shared-token", "2026-07-28"),
      { reservedMinor: 750, capMinor: 1_000 },
    );

    await first.reserveCap({
      tenantId: otherTenant,
      reservationId: "same-reservation-id",
      tokenId: "shared-token",
      spendDate: "2026-07-28",
      amountMinor: 1_000,
      capMinor: 1_000,
    });
    assert.deepEqual(
      await first.capUsage(otherTenant, "shared-token", "2026-07-28"),
      { reservedMinor: 1_000, capMinor: 1_000 },
    );
  } finally {
    for (const child of children) {
      if (child.exitCode === null) child.kill();
    }
    const priorNodeEnv = process.env.NODE_ENV;
    process.env.NODE_ENV = "test";
    try {
      await first.deleteTenantForTest(tenant);
      await first.deleteTenantForTest(otherTenant);
    } finally {
      if (priorNodeEnv === undefined) delete process.env.NODE_ENV;
      else process.env.NODE_ENV = priorNodeEnv;
    }
    await Promise.all([first.close(), second.close()]);
  }
});
