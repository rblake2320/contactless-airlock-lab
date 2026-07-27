import assert from "node:assert/strict";
import { spawn, type ChildProcess } from "node:child_process";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import {
  AirlockEngine,
  type AirlockEngineSnapshot,
} from "../apps/issuer-simulator/airlockEngine.ts";
import {
  generateDeviceKeyPair,
  signApproval,
} from "../packages/crypto/deviceKeys.ts";
import { DurableStore } from "../packages/storage/durableStore.ts";

interface WorkerResult {
  type: "result";
  ok: boolean;
  operationRan: boolean;
  replayed: boolean;
  value?: {
    operation: string;
    transactionId: string;
    committedVersion: number;
  };
  error?: string;
}

const workerPath = fileURLToPath(
  new URL("./fixtures/cap-reservation-worker.ts", import.meta.url),
);
const recordId = "cap-engine";

function cappedEngine(): AirlockEngine {
  const engine = new AirlockEngine();
  const keys = generateDeviceKeyPair("trusted-key-1");
  engine.enrollTrustedDevice("subject-1", keys, "device-1");
  const request = engine.requestProvisioning({
    subjectId: "subject-1",
    accountId: "account-1",
    tokenId: "capped-token",
    trustedDeviceId: "device-1",
    capMinor: 1_000,
    now: new Date("2026-07-27T11:00:00Z"),
  });
  engine.approveProvisioning(
    request.requestId,
    signApproval(request.challenge, keys.keyId, keys.privateKeyPem),
    new Date("2026-07-27T11:00:01Z"),
    "capped",
  );
  engine.authorize({
    transactionId: "seed-reservation",
    tokenId: "capped-token",
    merchantId: "seed-merchant",
    amountMinor: 1_000,
    strategy: "pre_authorization_step_up",
    trustedDeviceId: "device-1",
    now: new Date("2026-07-27T12:00:00Z"),
  });
  return engine;
}

function spawnWorker(
  dbPath: string,
  operation: "reserve" | "expire",
  transactionId: string,
  key: string,
  requestHash: string,
  releasePath?: string,
) {
  const child = spawn(
    process.execPath,
    [
      "--experimental-strip-types",
      workerPath,
      dbPath,
      recordId,
      operation,
      transactionId,
      key,
      requestHash,
      ...(releasePath ? [releasePath] : []),
    ],
    { stdio: ["ignore", "ignore", "pipe", "ipc"] },
  );
  let errors = "";
  child.stderr?.on("data", (chunk) => { errors += chunk.toString(); });
  const ready = new Promise<void>((resolve, reject) => {
    const timeout = setTimeout(
      () => reject(new Error(`worker did not reach barrier: ${errors}`)),
      10_000,
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
      () => reject(new Error(`worker did not return result: ${errors}`)),
      10_000,
    );
    child.once("error", reject);
    child.on("message", (message: WorkerResult) => {
      if (message.type === "result") {
        clearTimeout(timeout);
        resolve(message);
      }
    });
  });
  let finished = false;
  void result.then(
    () => { finished = true; },
    () => { finished = true; },
  );
  const locked = new Promise<void>((resolve, reject) => {
    if (!releasePath) return resolve();
    const timeout = setTimeout(
      () => reject(new Error(`worker did not acquire transaction lock: ${errors}`)),
      10_000,
    );
    child.once("error", reject);
    child.on("message", (message: { type?: string }) => {
      if (message.type === "locked") {
        clearTimeout(timeout);
        resolve();
      }
    });
  });
  return {
    child,
    ready,
    result,
    locked,
    finished: () => finished,
    errors: () => errors,
  };
}

async function runWorkers(
  workers: ReturnType<typeof spawnWorker>[],
  children: Set<ChildProcess>,
) {
  workers.forEach(({ child }) => children.add(child));
  await Promise.all(workers.map(({ ready }) => ready));
  workers.forEach(({ child }) => child.send("go"));
  const results = await Promise.all(workers.map(({ result }) => result));
  await Promise.all(workers.map(({ child, errors }) =>
    new Promise<void>((resolve, reject) => {
      if (child.exitCode !== null) return resolve();
      child.once("exit", (code) =>
        code === 0 ? resolve() : reject(new Error(`worker exited ${code}: ${errors()}`)));
    })));
  workers.forEach(({ child }) => children.delete(child));
  return results;
}

test("process races preserve capped aggregate across failure, expiry, retry, and replay", async () => {
  const directory = await mkdtemp(join(tmpdir(), "airlock-cap-race-"));
  const dbPath = join(directory, "cap.sqlite");
  const children = new Set<ChildProcess>();
  try {
    const setup = new DurableStore(dbPath);
    setup.create(recordId, "active", cappedEngine().snapshot());
    setup.close();

    const contenders = [
      { transactionId: "race-a", key: "reserve-a", hash: "sha256:reserve-a" },
      { transactionId: "race-b", key: "reserve-b", hash: "sha256:reserve-b" },
    ] as const;
    const releasePath = join(directory, "release-winner");
    const controlledWinner = spawnWorker(
      dbPath,
      "reserve",
      contenders[0].transactionId,
      contenders[0].key,
      contenders[0].hash,
      releasePath,
    );
    children.add(controlledWinner.child);
    await controlledWinner.ready;
    controlledWinner.child.send("go");
    await controlledWinner.locked;

    const blockedLoser = spawnWorker(
      dbPath,
      "reserve",
      contenders[1].transactionId,
      contenders[1].key,
      contenders[1].hash,
    );
    children.add(blockedLoser.child);
    await blockedLoser.ready;
    blockedLoser.child.send("go");
    await new Promise((resolve) => setTimeout(resolve, 150));
    assert.equal(
      blockedLoser.finished(),
      false,
      "second process must remain blocked while the first owns BEGIN IMMEDIATE",
    );
    await writeFile(releasePath, "release\n");
    const raced = await Promise.all([
      controlledWinner.result,
      blockedLoser.result,
    ]);
    await Promise.all([controlledWinner, blockedLoser].map(({ child, errors }) =>
      new Promise<void>((resolve, reject) => {
        if (child.exitCode !== null) return resolve();
        child.once("exit", (code) =>
          code === 0 ? resolve() : reject(new Error(`worker exited ${code}: ${errors()}`)));
      })));
    children.delete(controlledWinner.child);
    children.delete(blockedLoser.child);

    const winner = raced.find((result) => result.ok)!;
    const loser = raced.find((result) => !result.ok)!;
    assert.equal(raced.filter((result) => result.ok).length, 1, JSON.stringify(raced));
    assert.equal(winner.operationRan, true);
    assert.equal(winner.replayed, false);
    assert.equal(winner.value?.transactionId, "race-a");
    assert.equal(loser.operationRan, true);
    assert.equal(loser.error, "transaction exceeds new-token daily cap");
    const winnerSpec = contenders.find(
      (item) => item.transactionId === winner.value?.transactionId,
    )!;
    const loserSpec = contenders.find(
      (item) => item.transactionId !== winner.value?.transactionId,
    )!;

    let inspect = new DurableStore(dbPath);
    let durable = inspect.get<AirlockEngineSnapshot>(recordId)!;
    assert.equal(durable.version, 1);
    assert.deepEqual(durable.value.dailySpend, [{
      spendKey: "capped-token:2026-07-27",
      amountMinor: 2_000,
    }]);
    assert.equal(durable.value.transactions.length, 2);
    assert.equal(
      inspect.getIdempotent(
        "cap-reservation",
        loserSpec.key,
        loserSpec.hash,
      ),
      undefined,
      "failed reservation must roll back its idempotency record",
    );
    assert.equal(
      inspect.get(`cap-attempt:${loserSpec.transactionId}`),
      undefined,
      "write performed before the losing cap check must roll back",
    );
    assert.deepEqual(
      inspect.get<{ transactionId: string }>(
        `cap-attempt:${winnerSpec.transactionId}`,
      )?.value,
      { transactionId: winnerSpec.transactionId },
    );
    inspect.close();

    const [expired] = await runWorkers([
      spawnWorker(
        dbPath,
        "expire",
        "seed-reservation",
        "expire-seed",
        "sha256:expire-seed",
      ),
    ], children);
    assert.equal(expired.ok, true);
    assert.equal(expired.operationRan, true);
    assert.equal(expired.replayed, false);

    const [retried] = await runWorkers([
      spawnWorker(
        dbPath,
        "reserve",
        loserSpec.transactionId,
        loserSpec.key,
        loserSpec.hash,
      ),
    ], children);
    assert.equal(retried.ok, true);
    assert.equal(retried.operationRan, true);
    assert.equal(retried.replayed, false);

    const [replayed] = await runWorkers([
      spawnWorker(
        dbPath,
        "reserve",
        winnerSpec.transactionId,
        winnerSpec.key,
        winnerSpec.hash,
      ),
    ], children);
    assert.equal(replayed.ok, true);
    assert.equal(replayed.operationRan, false);
    assert.equal(replayed.replayed, true);
    assert.deepEqual(replayed.value, winner.value);

    inspect = new DurableStore(dbPath);
    durable = inspect.get<AirlockEngineSnapshot>(recordId)!;
    assert.equal(durable.version, 3, "winner + expiry + retry are the only effects");
    assert.deepEqual(durable.value.dailySpend, [{
      spendKey: "capped-token:2026-07-27",
      amountMinor: 2_000,
    }]);
    assert.equal(durable.value.transactions.length, 3);
    assert.equal(
      durable.value.transactions.filter((transaction) =>
        transaction.capReservation).length,
      2,
    );
    assert.deepEqual(
      inspect.get<{ transactionId: string }>(
        `cap-attempt:${loserSpec.transactionId}`,
      )?.value,
      { transactionId: loserSpec.transactionId },
      "successful retry commits the marker that the failed attempt rolled back",
    );
    assert.equal(AirlockEngine.restore(durable.value).audit.verify(), true);
    inspect.close();
  } finally {
    for (const child of children) {
      if (child.exitCode === null) child.kill();
    }
    await rm(directory, { recursive: true, force: true });
  }
});
