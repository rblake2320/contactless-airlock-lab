import { PostgresDurableStore } from "../../packages/storage/postgresStore.ts";

const [tenantId, reservationId] = process.argv.slice(2);
const connectionString = process.env.AIRLOCK_POSTGRES_URL;
if (!connectionString || !tenantId || !reservationId) {
  throw new Error("missing PostgreSQL cap worker configuration");
}

process.send?.({ type: "ready" });
process.once("message", async () => {
  const store = await PostgresDurableStore.connect({
    connectionString,
    max: 2,
  });
  try {
    const value = await store.reserveCap({
      tenantId,
      reservationId,
      tokenId: "shared-token",
      spendDate: "2026-07-28",
      amountMinor: 750,
      capMinor: 1_000,
      now: new Date("2026-07-28T12:00:00Z"),
    });
    process.send?.({ type: "result", ok: true, value });
  } catch (error) {
    process.send?.({
      type: "result",
      ok: false,
      error: error instanceof Error ? error.message : String(error),
    });
  } finally {
    await store.close();
    process.disconnect?.();
  }
});
