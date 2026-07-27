/**
 * Concurrent-writer fixture for the backup race regression. Writes a burst
 * of rows to a DurableStore SQLite file in a real, separate OS process, so
 * a backup running in the parent process races against genuine concurrent
 * writes rather than anything happening on the same thread/event loop.
 *
 * Usage: node --experimental-strip-types backup-concurrent-writer.ts <dbPath> <count>
 * Signals "ready" over IPC once open, writes <count> rows on "go", then
 * signals "done" with the actual number of rows it wrote.
 */
import { DurableStore } from "../../packages/storage/durableStore.ts";

const [dbPath, countArg] = process.argv.slice(2);
const count = Number(countArg);
if (!dbPath || !Number.isSafeInteger(count) || count < 1) {
  throw new Error("worker requires dbPath and a positive integer count");
}

const store = new DurableStore(dbPath);
process.send?.({ type: "ready" });
process.once("message", (message) => {
  if (message !== "go") return;
  let written = 0;
  try {
    for (let i = 0; i < count; i += 1) {
      store.create(`concurrent-writer-${process.pid}-${i}`, "created", { i });
      store.enqueue(`concurrent-writer-event-${process.pid}-${i}`, "topic", "aggregate", { i });
      written += 1;
    }
    process.send?.({ type: "done", written });
  } catch (error) {
    process.send?.({ type: "done", written, error: error instanceof Error ? error.message : String(error) });
  } finally {
    store.close();
    process.disconnect?.();
  }
});
