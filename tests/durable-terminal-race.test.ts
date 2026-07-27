import assert from "node:assert/strict";
import { spawn, type ChildProcess } from "node:child_process";
import { mkdtemp, rm } from "node:fs/promises";
import test from "node:test";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import { DurableStore } from "../packages/storage/durableStore.ts";

interface WorkerResult {
  type: "result";
  contender: string;
  ok: boolean;
  operationRan: boolean;
  replayed: boolean;
  value?: { terminal: string; winner: string };
  error?: string;
}

const workerPath = fileURLToPath(
  new URL("./fixtures/durable-terminal-worker.ts", import.meta.url),
);
const contenders = ["approval", "retry", "expiry", "cancellation"] as const;

function spawnContender(
  dbPath: string,
  challengeId: string,
  contender: typeof contenders[number],
) {
  const child = spawn(
    process.execPath,
    ["--experimental-strip-types", workerPath, dbPath, challengeId, contender],
    { stdio: ["ignore", "ignore", "pipe", "ipc"] },
  );
  let errors = "";
  child.stderr?.on("data", (chunk) => { errors += chunk.toString(); });
  const ready = new Promise<void>((resolve, reject) => {
    const timeout = setTimeout(
      () => reject(new Error(`${contender} did not reach barrier: ${errors}`)),
      10_000,
    );
    child.on("error", reject);
    child.on("message", (message: { type?: string }) => {
      if (message.type === "ready") {
        clearTimeout(timeout);
        resolve();
      }
    });
  });
  const result = new Promise<WorkerResult>((resolve, reject) => {
    const timeout = setTimeout(
      () => reject(new Error(`${contender} did not finish race: ${errors}`)),
      10_000,
    );
    child.on("error", reject);
    child.on("message", (message: WorkerResult) => {
      if (message.type === "result") {
        clearTimeout(timeout);
        resolve(message);
      }
    });
  });
  return { child, ready, result, stderr: () => errors };
}

test("barrier-driven processes produce one restart-durable terminal outcome", async () => {
  const directory = await mkdtemp(join(tmpdir(), "airlock-terminal-race-"));
  const dbPath = join(directory, "race.sqlite");
  const children = new Set<ChildProcess>();
  try {
    for (let round = 0; round < 5; round += 1) {
      const challengeId = `terminal-race-${round}`;
      const setup = new DurableStore(dbPath);
      setup.create(challengeId, "created", { terminal: "pending", winner: null });
      setup.close();

      const workers = contenders.map((contender) =>
        spawnContender(dbPath, challengeId, contender));
      workers.forEach(({ child }) => children.add(child));
      await Promise.all(workers.map(({ ready }) => ready));
      workers.forEach(({ child }) => child.send("go"));
      const results = await Promise.all(workers.map(({ result }) => result));
      await Promise.all(workers.map(({ child, stderr }) =>
        new Promise<void>((resolve, reject) => {
          if (child.exitCode !== null) return resolve();
          child.once("exit", (code) =>
            code === 0 ? resolve() : reject(new Error(`worker exited ${code}: ${stderr()}`)));
        })));
      workers.forEach(({ child }) => children.delete(child));

      const effectWinners = results.filter((result) =>
        result.ok && result.operationRan);
      assert.equal(effectWinners.length, 1, JSON.stringify(results));
      assert.ok(results.some((result) => result.contender === "retry"));
      assert.ok(results.some((result) => result.contender === "expiry"));
      assert.ok(results.some((result) => result.contender === "cancellation"));
      for (const result of results.filter((item) => !item.ok)) {
        assert.match(result.error ?? "", /compare-and-swap conflict/);
      }

      const restarted = new DurableStore(dbPath);
      const terminal = restarted.get<{ terminal: string; winner: string }>(
        challengeId,
      )!;
      assert.equal(terminal.version, 1);
      assert.ok(["confirmed", "expired", "cancelled"].includes(terminal.status));
      assert.equal(terminal.value.terminal, terminal.status);
      assert.equal(terminal.value.winner, effectWinners[0].contender);
      assert.throws(
        () => restarted.compareAndSwap(
          challengeId,
          0,
          "created",
          "confirmed",
          { terminal: "confirmed", winner: "late-retry" },
        ),
        /compare-and-swap conflict/,
      );
      assert.equal(restarted.get(challengeId)?.version, 1);
      restarted.close();
    }
  } finally {
    for (const child of children) {
      if (child.exitCode === null) child.kill();
    }
    await rm(directory, { recursive: true, force: true });
  }
});
