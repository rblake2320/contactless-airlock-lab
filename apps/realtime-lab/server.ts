import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { dirname, extname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { AirlockEngine, type ProvisioningRequest, type TransactionRecord } from "../issuer-simulator/airlockEngine.ts";
import { generateDeviceKeyPair, signApproval, type DeviceKeyPair } from "../../packages/crypto/deviceKeys.ts";

const PUBLIC_DIR = join(dirname(fileURLToPath(import.meta.url)), "public");
const MAX_REQUEST_BODY_BYTES = 16 * 1024;
const SECURITY_HEADERS = Object.freeze({
  "content-security-policy": "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'",
  "cross-origin-opener-policy": "same-origin",
  "cross-origin-resource-policy": "same-origin",
  "permissions-policy": "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
  "referrer-policy": "no-referrer",
  "x-content-type-options": "nosniff",
  "x-frame-options": "DENY",
});
const SYNTHETIC = Object.freeze({
  subjectId: "demo-subject-001",
  accountId: "demo-account-001",
  deviceId: "00000000-0000-4000-8000-000000000001",
  tokenId: "synthetic-token-001",
});

interface LabState {
  engine: AirlockEngine;
  keys: DeviceKeyPair;
  provisioning?: ProvisioningRequest;
  transaction?: TransactionRecord;
  demonstration?: {
    name: string;
    blocked: boolean;
    message: string;
    auditCopyValid?: boolean;
  };
  lastResult: {
    ok: boolean;
    outcome: "accepted" | "blocked" | "warning";
    action: string;
    message: string;
    at: string;
  };
}

class HttpError extends Error {
  readonly status: number;

  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

function applySecurityHeaders(res: ServerResponse): void {
  for (const [name, value] of Object.entries(SECURITY_HEADERS)) {
    res.setHeader(name, value);
  }
}

function enforceMutationSource(req: IncomingMessage): void {
  const fetchSite = req.headers["sec-fetch-site"];
  if (
    typeof fetchSite === "string" &&
    fetchSite !== "same-origin" &&
    fetchSite !== "none"
  ) {
    throw new HttpError(403, "Cross-origin mutation request rejected.");
  }

  const origin = req.headers.origin;
  if (origin === undefined) return; // Preserve non-browser CLI/partner harness operation.
  if (typeof origin !== "string" || origin === "null") {
    throw new HttpError(403, "Untrusted mutation origin rejected.");
  }
  const host = req.headers.host;
  if (!host) throw new HttpError(400, "Host header is required.");
  let normalizedOrigin: string;
  try {
    const parsed = new URL(origin);
    if (origin !== parsed.origin || parsed.protocol !== "http:") {
      throw new Error("not a serialized HTTP origin");
    }
    normalizedOrigin = parsed.origin;
  } catch {
    throw new HttpError(403, "Invalid mutation origin rejected.");
  }
  if (normalizedOrigin !== `http://${host}`) {
    throw new HttpError(403, "Cross-origin mutation request rejected.");
  }
}

async function readBoundedBody(req: IncomingMessage): Promise<Buffer> {
  const declaredLength = req.headers["content-length"];
  if (declaredLength !== undefined) {
    const length = Number(declaredLength);
    if (!Number.isSafeInteger(length) || length < 0) {
      throw new HttpError(400, "Invalid Content-Length.");
    }
    if (length > MAX_REQUEST_BODY_BYTES) {
      throw new HttpError(413, `Request body exceeds ${MAX_REQUEST_BODY_BYTES} bytes.`);
    }
  }
  const chunks: Buffer[] = [];
  let total = 0;
  for await (const chunk of req) {
    const buffer = Buffer.from(chunk);
    total += buffer.length;
    if (total > MAX_REQUEST_BODY_BYTES) {
      throw new HttpError(413, `Request body exceeds ${MAX_REQUEST_BODY_BYTES} bytes.`);
    }
    chunks.push(buffer);
  }
  return Buffer.concat(chunks, total);
}

function parseJsonBody(req: IncomingMessage, body: Buffer): Record<string, unknown> {
  const contentType = req.headers["content-type"]?.split(";", 1)[0]?.trim().toLowerCase();
  if (contentType !== "application/json") {
    throw new HttpError(415, "Content-Type must be application/json.");
  }
  if (!body.length) throw new HttpError(400, "JSON request body is required.");
  let value: unknown;
  try {
    value = JSON.parse(body.toString("utf8"));
  } catch {
    throw new HttpError(400, "Malformed JSON request body.");
  }
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new HttpError(400, "JSON body must be an object.");
  }
  return value as Record<string, unknown>;
}

function parseAmountMinor(value: unknown): number {
  if (typeof value !== "string") throw new Error("Amount is required in decimal form, for example 25.00.");
  const input = value.trim();
  if (/^-\d+(?:\.\d+)?$/.test(input)) throw new Error("Amount must be greater than zero.");
  const match = /^(0|[1-9]\d*)(?:\.(\d{1,2}))?$/.exec(input);
  if (!match) throw new Error("Amount must be a finite decimal with no more than two fractional digits.");
  const fraction = (match[2] ?? "").padEnd(2, "0");
  const minor = BigInt(match[1]) * 100n + BigInt(fraction || "0");
  if (minor <= 0n) throw new Error("Amount must be greater than zero.");
  if (minor > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error("Amount exceeds the safe supported limit.");
  return Number(minor);
}

function parseMerchantId(value: unknown): string {
  if (typeof value !== "string") throw new Error("Merchant identifier is required.");
  const merchantId = value.trim();
  if (!merchantId) throw new Error("Merchant identifier is required.");
  if (!/^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$/.test(merchantId)) {
    throw new Error("Merchant identifier must be 1–64 letters, numbers, dots, colons, underscores, or hyphens.");
  }
  return merchantId;
}

function verifyAuditCopy(events: ReturnType<AirlockEngine["audit"]["all"]>): boolean {
  let previousHash = "GENESIS";
  for (const event of events) {
    const { hash, ...body } = event;
    const digest = createHash("sha256").update(JSON.stringify(body)).digest("hex");
    if (body.previousHash !== previousHash || digest !== hash) return false;
    previousHash = hash;
  }
  return true;
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
      outcome: "accepted",
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
    confirmation: transaction?.challenge ? {
      amountMinor: transaction.challenge.amountMinor,
      currency: transaction.challenge.currency,
      merchantId: transaction.challenge.merchantId,
      paymentTokenId: transaction.challenge.paymentTokenId,
      trustedDeviceId: transaction.challenge.trustedDeviceId,
      challengeId: transaction.challenge.challengeId,
      expiresAt: transaction.challenge.expiresAt,
    } : undefined,
    actions: {
      requestProvisioning: !state.provisioning && state.engine.getDevice(SYNTHETIC.deviceId)?.status === "active",
      attackProvisioning: state.provisioning?.state === "trusted_device_challenge",
      approveProvisioning: state.provisioning?.state === "trusted_device_challenge" &&
        state.engine.getDevice(SYNTHETIC.deviceId)?.status === "active",
      revokeDevice: state.engine.getDevice(SYNTHETIC.deviceId)?.status === "active",
      requestTransaction: Boolean(token && ["active_capped", "active_full"].includes(token.state) &&
        state.engine.getDevice(SYNTHETIC.deviceId)?.status === "active" && !transaction),
      confirmTransaction: transaction?.state === "confirmation_pending" &&
        state.engine.getDevice(SYNTHETIC.deviceId)?.status === "active",
      expireTransaction: transaction?.state === "confirmation_pending",
      receiveClearing: Boolean(transaction && ["confirmed", "reversed"].includes(transaction.state)),
      negativeBinding: transaction?.state === "confirmation_pending" &&
        state.engine.getDevice(SYNTHETIC.deviceId)?.status === "active",
    },
    audit: { valid: state.engine.audit.verify(), events: state.engine.audit.all() },
    demonstration: state.demonstration,
    lastResult: state.lastResult,
  };
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
    state.lastResult = {
      ok: true,
      outcome: "accepted",
      action,
      message,
      at: new Date().toISOString(),
    };
    broadcast();
  };
  const warn = (action: string, message: string) => {
    state.lastResult = {
      ok: false,
      outcome: "warning",
      action,
      message,
      at: new Date().toISOString(),
    };
    broadcast();
  };

  return createServer(async (req, res) => {
    applySecurityHeaders(res);
    try {
      const url = new URL(req.url ?? "/", "http://127.0.0.1");
      let requestBody: Buffer<ArrayBufferLike> = Buffer.alloc(0);
      if (req.method === "POST" && url.pathname.startsWith("/api/")) {
        enforceMutationSource(req);
        requestBody = await readBoundedBody(req);
      }
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
        if (state.provisioning) throw new Error("Provisioning was already requested. Reset the lab to start a new request.");
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
        if (state.provisioning.state !== "trusted_device_challenge") {
          throw new Error("Provisioning is no longer waiting for approval.");
        }
        const approval = signApproval(state.provisioning.challenge, state.keys.keyId, state.keys.privateKeyPem);
        state.provisioning = state.engine.approveProvisioning(state.provisioning.requestId, approval);
        succeed("provision.approve", "Exact challenge binding signed with the enrolled P-256 key.");
        return json(res, 200, publicSnapshot(state));
      }
      if (req.method === "POST" && url.pathname === "/api/device/revoke") {
        if (state.engine.getDevice(SYNTHETIC.deviceId)?.status !== "active") {
          throw new Error("Trusted device is already revoked.");
        }
        state.engine.revokeTrustedDevice(SYNTHETIC.deviceId);
        succeed("device.revoke", "Trusted device revoked; outstanding approvals now fail closed.");
        return json(res, 200, publicSnapshot(state));
      }
      if (req.method === "POST" && url.pathname === "/api/transaction/request") {
        const body = parseJsonBody(req, requestBody);
        if (state.transaction) throw new Error("A transaction already exists. Reset the lab to start another.");
        state.transaction = state.engine.authorize({
          transactionId: `synthetic-tx-${Date.now()}`,
          tokenId: SYNTHETIC.tokenId,
          merchantId: parseMerchantId(body.merchantId),
          amountMinor: parseAmountMinor(body.amount),
          strategy: "pre_authorization_step_up",
          trustedDeviceId: SYNTHETIC.deviceId,
        });
        succeed("transaction.request", "Transaction is pending exact trusted-device confirmation.");
        return json(res, 200, publicSnapshot(state));
      }
      if (req.method === "POST" && url.pathname === "/api/transaction/confirm") {
        if (!state.transaction?.challenge) throw new Error("request a transaction first");
        if (state.transaction.state !== "confirmation_pending") {
          throw new Error("Only a transaction awaiting confirmation can be confirmed.");
        }
        const approval = signApproval(state.transaction.challenge, state.keys.keyId, state.keys.privateKeyPem);
        state.transaction = state.engine.confirmTransaction(state.transaction.transactionId, approval);
        succeed("transaction.confirm", "Amount, merchant, token, device, nonce, and expiry binding verified.");
        return json(res, 200, publicSnapshot(state));
      }
      if (req.method === "POST" && url.pathname === "/api/transaction/expire") {
        if (!state.transaction) throw new Error("request a transaction first");
        if (state.transaction.state !== "confirmation_pending") {
          throw new Error("Only a transaction awaiting confirmation can time out.");
        }
        state.transaction = state.engine.expireAndReverse(state.transaction.transactionId);
        succeed("transaction.expire", "Confirmation timed out; reversal requested and recorded.");
        return json(res, 200, publicSnapshot(state));
      }
      if (req.method === "POST" && url.pathname === "/api/transaction/clear") {
        if (!state.transaction) throw new Error("request a transaction first");
        if (!["confirmed", "reversed"].includes(state.transaction.state)) {
          throw new Error("Clearing can only follow confirmation or reversal in this demonstration.");
        }
        state.transaction = state.engine.receiveClearing(state.transaction.transactionId);
        if (state.transaction.state === "exception") {
          warn(
            "transaction.clear.exception",
            "Exception detected: clearing arrived after reversal. Partner reconciliation is required; settlement prevention is not claimed.",
          );
        } else {
          succeed("transaction.clear", "Synthetic clearing received; transaction settled.");
        }
        return json(res, 200, publicSnapshot(state));
      }
      if (req.method === "POST" && url.pathname === "/api/demonstrate/audit-tamper") {
        const tampered = state.engine.audit.all();
        if (!tampered.length) throw new Error("No audit event exists to tamper with.");
        tampered[0].payload = { ...tampered[0].payload, tampered: true };
        const detected = !verifyAuditCopy(tampered);
        state.demonstration = {
          name: "audit-tamper",
          blocked: detected,
          message: detected ? "Modified audit payload invalidated the hash chain." : "Tampering was not detected.",
          auditCopyValid: !detected,
        };
        state.engine.audit.append("security.attack_blocked", "audit-copy", {
          attack: "audit-tamper",
          reason: state.demonstration.message,
          authoritativeAuditModified: false,
        });
        state.lastResult = {
          ok: false,
          outcome: "blocked",
          action: "demonstrate.audit-tamper",
          message: `Attack blocked: ${state.demonstration.message} The authoritative audit remains valid.`,
          at: new Date().toISOString(),
        };
        broadcast();
        return json(res, detected ? 200 : 500, publicSnapshot(state));
      }
      if (req.method === "POST" && url.pathname.startsWith("/api/demonstrate/")) {
        if (!state.transaction?.challenge || state.transaction.state !== "confirmation_pending") {
          throw new Error("Request a pending transaction before running a binding attack.");
        }
        const name = url.pathname.slice("/api/demonstrate/".length);
        const original = state.transaction.challenge;
        try {
          if (
            name === "altered-amount" ||
            name === "altered-merchant" ||
            name === "modified-nonce" ||
            name === "wrong-device"
          ) {
            const binding = structuredClone(original);
            if (name === "altered-amount") binding.amountMinor = (binding.amountMinor ?? 0) + 1;
            if (name === "altered-merchant") binding.merchantId = `${binding.merchantId}-altered`;
            if (name === "modified-nonce") binding.challengeId = crypto.randomUUID();
            if (name === "wrong-device") binding.trustedDeviceId = "substituted-device";
            const approval = signApproval(binding, state.keys.keyId, state.keys.privateKeyPem);
            state.engine.confirmTransaction(state.transaction.transactionId, approval);
          } else if (name === "wrong-key") {
            const wrongKeys = generateDeviceKeyPair("wrong-demo-key");
            const approval = signApproval(original, wrongKeys.keyId, wrongKeys.privateKeyPem);
            state.engine.confirmTransaction(state.transaction.transactionId, approval);
          } else if (name === "expired-challenge") {
            const approval = signApproval(original, state.keys.keyId, state.keys.privateKeyPem);
            state.engine.confirmTransaction(state.transaction.transactionId, approval, new Date(original.expiresAt));
          } else if (name === "reused-signature") {
            const approval = signApproval(original, state.keys.keyId, state.keys.privateKeyPem);
            state.transaction = state.engine.confirmTransaction(state.transaction.transactionId, approval);
            state.engine.confirmTransaction(state.transaction.transactionId, approval);
          } else {
            throw new Error("Unknown security demonstration.");
          }
          throw new Error("Unexpected: the attack was accepted.");
        } catch (error) {
          const message = error instanceof Error ? error.message : "attack rejected";
          if (message.startsWith("Unexpected:")) throw error;
          if (name === "expired-challenge" && state.transaction.state === "confirmation_pending") {
            state.transaction = state.engine.expireAndReverse(state.transaction.transactionId);
          }
          state.engine.audit.append("security.attack_blocked", state.transaction.transactionId, {
            attack: name,
            reason: message,
          });
          state.demonstration = { name, blocked: true, message };
          state.lastResult = {
            ok: false,
            outcome: "blocked",
            action: `demonstrate.${name}`,
            message: `Attack blocked: ${message}`,
            at: new Date().toISOString(),
          };
          broadcast();
          return json(res, 200, publicSnapshot(state));
        }
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
      if (error instanceof HttpError) {
        return json(res, error.status, { error: message });
      }
      state.lastResult = {
        ok: false,
        outcome: "blocked",
        action: "blocked",
        message,
        at: new Date().toISOString(),
      };
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
