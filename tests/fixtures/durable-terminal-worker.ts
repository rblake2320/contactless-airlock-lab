import { DurableStore } from "../../packages/storage/durableStore.ts";

const [dbPath, challengeId, contender] = process.argv.slice(2);
if (!dbPath || !challengeId || !contender) {
  throw new Error("worker requires dbPath, challengeId, and contender");
}
const profile = {
  approval: { key: "approval-delivery", hash: "sha256:approval", status: "confirmed" },
  retry: { key: "approval-delivery", hash: "sha256:approval", status: "confirmed" },
  expiry: { key: "expiry-worker", hash: "sha256:expiry", status: "expired" },
  cancellation: { key: "cancellation-worker", hash: "sha256:cancellation", status: "cancelled" },
}[contender];
if (!profile) throw new Error(`unknown contender: ${contender}`);

const store = new DurableStore(dbPath);
process.send?.({ type: "ready", contender });
process.once("message", (message) => {
  if (message !== "go") return;
  let operationRan = false;
  try {
    const result = store.runIdempotent(
      `terminal-race:${challengeId}`,
      profile.key,
      profile.hash,
      (tx) => {
        operationRan = true;
        tx.compareAndSwap(challengeId, 0, "created", profile.status, {
          terminal: profile.status,
          winner: contender,
        });
        return { terminal: profile.status, winner: contender };
      },
    );
    process.send?.({
      type: "result",
      contender,
      ok: true,
      operationRan,
      replayed: result.replayed,
      value: result.value,
    });
  } catch (error) {
    process.send?.({
      type: "result",
      contender,
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
