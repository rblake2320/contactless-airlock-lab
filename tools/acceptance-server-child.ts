import { createLabServer, type RateLimitConfig } from "../apps/realtime-lab/server.ts";

interface ChildOptions {
  dbPath?: string;
  rateLimit?: RateLimitConfig | false;
}

const encoded = process.argv[2];
if (!encoded) throw new Error("acceptance server child requires encoded options");
const options = JSON.parse(Buffer.from(encoded, "base64url").toString("utf8")) as ChildOptions;
const server = createLabServer(options);
let closing = false;

async function close() {
  if (closing) return;
  closing = true;
  await new Promise<void>((resolve, reject) =>
    server.close((error) => error ? reject(error) : resolve()));
}

server.once("error", (error) => {
  process.send?.({ type: "error", error: error.message });
  process.exitCode = 1;
});
server.listen(0, "127.0.0.1", () => {
  const address = server.address();
  if (!address || typeof address === "string") {
    throw new Error("acceptance server did not bind a TCP port");
  }
  process.send?.({ type: "ready", port: address.port });
});
process.on("message", (message: { type?: string }) => {
  if (message.type !== "close") return;
  void close().then(
    () => {
      process.send?.({ type: "closed" });
      process.disconnect?.();
    },
    (error) => {
      process.send?.({
        type: "error",
        error: error instanceof Error ? error.message : String(error),
      });
      process.exitCode = 1;
      process.disconnect?.();
    },
  );
});
process.on("disconnect", () => {
  void close().finally(() => process.exit());
});
