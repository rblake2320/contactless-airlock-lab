import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { readFile } from "node:fs/promises";
import { dirname, extname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { AirlockEngine, type ProvisioningRequest, type TransactionRecord } from "../issuer-simulator/airlockEngine.ts";
import { generateDeviceKeyPair, signApproval, type DeviceKeyPair } from "../../packages/crypto/deviceKeys.ts";

const PUBLIC_DIR = join(dirname(fileURLToPath(import.meta.url)), "public");
const SYNTHETIC = Object.freeze({
  subjectId: "demo-subject-001",
  accountId: "demo-account-001",
  deviceId: "trusted-device-001",
  tokenId: "synthetic-token-001",
});

interface LabState {
  engine: AirlockEngine;
  keys: DeviceKeyPair;
  provisioning?: ProvisioningRequest;
  transaction?: TransactionRecord;
  lastResult: { ok: boolean; action: string; message: string; at: string };
}

function freshState(): LabState {
  const engine = new AirlockEngine();
  const keys = generateDeviceKeyPair("demo-p256-key");
  engine.enrollTrustedDevice(SYNTHETIC.subjectId, keys, SYNTHETIC.deviceId);
  return {
    engine,
    keys,
    lastResult: {
      ok: true,
      action: "reset",
      message: "Synthetic trusted device enrolled. No payment network was contacted.",
      at: new Date().toISOString(),
    },
  };
}

function publicSnapshot(state: LabState) {
  const token = state.engine.getToken(SYNTHETIC.tokenId);
  const transaction = state.transaction
    ? state.engine.getTransaction(state.transaction.transactionId)
    : undefined;
  return {
    simulator: true,
    notice: "Synthetic reference implementation. No PAN, bank, wallet, processor, or payment rail is connected.",
    device: state.engine.getDevice(SYNTHETIC.deviceId),
    token,
    provisioning: state.provisioning,
    transaction,
    audit: { valid: state.engine.audit.verify(), events: state.engine.audit.all() },
    lastResult: state.lastResult,
  };
}

async function readJson(req: IncomingMessage): Promise<Record<string, unknown>> {
  const chunks: Buffer[] = [];
  for await (const chunk of req) chunks.push(Buffer.from(chunk));
  if (!chunks.length) return {};
  const value = JSON.parse(Buffer.concat(chunks).toString("utf8"));
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("JSON body must be an object");
  }
  return value as Record<string, unknown>;
}

function json(res: ServerResponse, status: number, value: unknown) {
  const body = JSON.stringify(value);
  res.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "content-length": Buffer.byteLength(body),
    "cache-control": "no-store",
  });
  res.end(body);
}

export function createLabServer() {
  let state = freshState();
  const listeners = new Set<ServerResponse>();
  const broadcast = () => {
    const payload = `event: state\ndata: ${JSON.stringify(publicSnapshot(state))}\n\n`;
    for (const listener of listeners) listener.write(payload);
  };
  const succeed = (action: string, message: string) => {
    state.lastResult = { ok: true, action, message, at: new Date().toISOString() };
    broadcast();
  };

  return createServer(async (req, res) => {
    try {
      const url = new URL(req.url ?? "/", "http://127.0.0.1");
      if (req.method === "GET" && url.pathname === "/api/health") {
        return json(res, 200, { ok: true, simulator: true });
      }
      if (req.method === "GET" && url.pathname === "/api/state") {
        return json(res, 200, publicSnapshot(state));
      }
      if (req.method === "GET" && url.pathname === "/api/events") {
        res.writeHead(200, {
          "content-type": "text/event-stream",
          "cache-control": "no-store",
          connection: "keep-alive",
        });
        listeners.add(res);
        res.write(`event: state\ndata: ${JSON.stringify(publicSnapshot(state))}\n\n`);
        const heartbeat = setInterval(() => res.write(": heartbeat\n\n"), 15_000);
        req.on("close", () => {
          clearInterval(heartbeat);
          listeners.delete(res);
        });
        return;
      }

      if (req.method === "POST" && url.pathname === "/api/reset") {
        state = freshState();
        broadcast();
        return json(res, 200, publicSnapshot(state));
      }
      if (req.method === "POST" && url.pathname === "/api/provision/request") {
        state.provisioning = state.engine.requestProvisioning({
          subjectId: SYNTHETIC.subjectId,
          accountId: SYNTHETIC.accountId,
          tokenId: SYNTHETIC.tokenId,
          trustedDeviceId: SYNTHETIC.deviceId,
          capMinor: 5_000,
        });
        succeed("provision.request", "Provisioning challenge issued to the trusted device.");
        return json(res, 200, publicSnapshot(state));
      }
      if (req.method === "POST" && url.pathname === "/api/provision/attack") {
        if (!state.provisioning) throw new Error("request provisioning first");
        state.engine.authorize({
          transactionId: `blocked-${crypto.randomUUID()}`,
          tokenId: SYNTHETIC.tokenId,
          merchantId: "synthetic-gift-card-store",
          amountMinor: 4_999,
          strategy: "pre_authorization_step_up",
          trustedDeviceId: SYNTHETIC.deviceId,
        });
        throw new Error("unexpected: pending token became spendable");
      }
      if (req.method === "POST" && url.pathname === "/api/provision/approve") {
        if (!state.provisioning) throw new Error("request provisioning first");
        const approval = signApproval(state.provisioning.challenge, state.keys.keyId, state.keys.privateKeyPem);
        state.provisioning = state.engine.approveProvisioning(state.provisioning.requestId, approval);
        succeed("provision.approve", "Exact challenge binding signed with the enrolled P-256 key.");
        return json(res, 200, publicSnapshot(state));
      }
      if (req.method === "POST" && url.pathname === "/api/device/revoke") {
        state.engine.revokeTrustedDevice(SYNTHETIC.deviceId);
        succeed("device.revoke", "Trusted device revoked; outstanding approvals now fail closed.");
        return json(res, 200, publicSnapshot(state));
      }
      if (req.method === "POST" && url.pathname === "/api/transaction/request") {
        const body = await readJson(req);
        state.transaction = state.engine.authorize({
          transactionId: `synthetic-tx-${Date.now()}`,
          tokenId: SYNTHETIC.tokenId,
          merchantId: String(body.merchantId ?? "synthetic-merchant-001"),
          amountMinor: Number(body.amountMinor ?? 2_500),
          strategy: "pre_authorization_step_up",
          trustedDeviceId: SYNTHETIC.deviceId,
        });
        succeed("transaction.request", "Transaction is pending exact trusted-device confirmation.");
        return json(res, 200, publicSnapshot(state));
      }
      if (req.method === "POST" && url.pathname === "/api/transaction/confirm") {
        if (!state.transaction?.challenge) throw new Error("request a transaction first");
        const approval = signApproval(state.transaction.challenge, state.keys.keyId, state.keys.privateKeyPem);
        state.transaction = state.engine.confirmTransaction(state.transaction.transactionId, approval);
        succeed("transaction.confirm", "Amount, merchant, token, device, nonce, and expiry binding verified.");
        return json(res, 200, publicSnapshot(state));
      }
      if (req.method === "POST" && url.pathname === "/api/transaction/expire") {
        if (!state.transaction) throw new Error("request a transaction first");
        state.transaction = state.engine.expireAndReverse(state.transaction.transactionId);
        succeed("transaction.expire", "Confirmation timed out; reversal requested and recorded.");
        return json(res, 200, publicSnapshot(state));
      }
      if (req.method === "POST" && url.pathname === "/api/transaction/clear") {
        if (!state.transaction) throw new Error("request a transaction first");
        state.transaction = state.engine.receiveClearing(state.transaction.transactionId);
        succeed("transaction.clear", "Synthetic clearing received; final state follows the state machine.");
        return json(res, 200, publicSnapshot(state));
      }

      if (req.method === "GET") {
        const relative = url.pathname === "/" ? "index.html" : url.pathname.slice(1);
        if (!["index.html", "app.js", "styles.css"].includes(relative)) {
          return json(res, 404, { error: "not found" });
        }
        const body = await readFile(join(PUBLIC_DIR, relative));
        const types: Record<string, string> = {
          ".html": "text/html; charset=utf-8",
          ".js": "text/javascript; charset=utf-8",
          ".css": "text/css; charset=utf-8",
        };
        res.writeHead(200, {
          "content-type": types[extname(relative)] ?? "application/octet-stream",
          "content-length": body.length,
          "cache-control": "no-store",
        });
        return res.end(body);
      }
      return json(res, 404, { error: "not found" });
    } catch (error) {
      const message = error instanceof Error ? error.message : "unknown error";
      state.lastResult = { ok: false, action: "blocked", message, at: new Date().toISOString() };
      broadcast();
      return json(res, 409, { error: message, state: publicSnapshot(state) });
    }
  });
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const host = process.env.AIRLOCK_HOST ?? "127.0.0.1";
  const port = Number(process.env.AIRLOCK_PORT ?? 8788);
  createLabServer().listen(port, host, () => {
    console.log(`Contactless Airlock Lab: http://${host}:${port}`);
    console.log("SIMULATOR ONLY — no real payment network or customer data is connected.");
  });
}
