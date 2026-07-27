import { AirlockEngine, type AirlockEngineSnapshot } from "../../apps/issuer-simulator/airlockEngine.ts";
import { existsSync } from "node:fs";
import { DurableStore } from "../../packages/storage/durableStore.ts";

const [dbPath, recordId, operation, transactionId, key, requestHash, releasePath] =
  process.argv.slice(2);
if (!dbPath || !recordId || !operation || !transactionId || !key || !requestHash) {
  throw new Error("missing cap-reservation worker arguments");
}

process.send?.({ type: "ready" });
process.once("message", () => {
  const store = new DurableStore(dbPath);
  let operationRan = false;
  try {
    const result = store.runIdempotent(
      "cap-reservation",
      key,
      requestHash,
      (tx) => {
        operationRan = true;
        if (releasePath) {
          process.send?.({ type: "locked" });
          const deadline = Date.now() + 5_000;
          while (!existsSync(releasePath)) {
            if (Date.now() >= deadline) throw new Error("timed out waiting for lock release");
            Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 10);
          }
        }
        const current = store.get<AirlockEngineSnapshot>(recordId);
        if (!current) throw new Error("engine snapshot is missing");
        const engine = AirlockEngine.restore(current.value);
        if (operation === "reserve") {
          // This write happens before cap evaluation. If authorize fails, the
          // enclosing idempotency transaction must roll it back.
          tx.create(
            `cap-attempt:${transactionId}`,
            "attempted",
            { transactionId },
          );
          engine.authorize({
            transactionId,
            tokenId: "capped-token",
            merchantId: `merchant-${transactionId}`,
            amountMinor: 1_000,
            strategy: "pre_authorization_step_up",
            trustedDeviceId: "device-1",
            now: new Date("2026-07-27T12:00:00Z"),
          });
        } else if (operation === "expire") {
          engine.expireAndReverse(transactionId, new Date("2026-07-27T12:00:10Z"));
        } else {
          throw new Error(`unknown operation: ${operation}`);
        }
        const saved = tx.compareAndSwap(
          recordId,
          current.version,
          current.status,
          current.status,
          engine.snapshot(),
        );
        return {
          operation,
          transactionId,
          committedVersion: saved.version,
        };
      },
    );
    process.send?.({
      type: "result",
      ok: true,
      operationRan,
      replayed: result.replayed,
      value: result.value,
    });
  } catch (error) {
    process.send?.({
      type: "result",
      ok: false,
      operationRan,
      replayed: false,
      error: error instanceof Error ? error.message : String(error),
    });
  } finally {
    store.close();
    process.disconnect?.();
  }
});
