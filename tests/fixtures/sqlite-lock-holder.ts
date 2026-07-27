import { DatabaseSync } from "node:sqlite";

const [dbPath, holdText] = process.argv.slice(2);
const holdMs = Number(holdText);
if (!dbPath || !Number.isSafeInteger(holdMs) || holdMs < 1) {
  throw new Error("lock holder requires dbPath and positive holdMs");
}

const db = new DatabaseSync(dbPath, { timeout: 5_000 });
db.exec("BEGIN IMMEDIATE");
process.send?.({ type: "locked" });
setTimeout(() => {
  db.exec("COMMIT");
  db.close();
  process.send?.({ type: "released" });
  process.disconnect?.();
}, holdMs);
