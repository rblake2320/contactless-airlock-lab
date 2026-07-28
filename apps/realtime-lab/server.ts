import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { createHash, createPrivateKey, createPublicKey } from "node:crypto";
import { readFile } from "node:fs/promises";
import { dirname, extname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import {
  AirlockEngine,
  type AirlockEngineSnapshot,
  type ProvisioningRequest,
  type TransactionRecord,
} from "../issuer-simulator/airlockEngine.ts";
import { generateDeviceKeyPair, signApproval, type DeviceKeyPair } from "../../packages/crypto/deviceKeys.ts";
import { DurableStore } from "../../packages/storage/durableStore.ts";

const PUBLIC_DIR = join(dirname(fileURLToPath(import.meta.url)), "public");
const MAX_REQUEST_BODY_BYTES = 16 * 1024;
const LAB_SNAPSHOT_ID = "realtime-lab:simulator-state";
const LAB_SNAPSHOT_STATUS = "active";
const IDEMPOTENCY_SCOPE = "realtime-lab:http:v1";
const MAX_IDEMPOTENCY_KEY_LENGTH = 128;
const SIMULATOR_KEY_WARNING =
  "SIMULATOR ONLY: contains a synthetic exportable private key; never use this storage pattern for production device keys.";
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

export const REASON_CODES = [
  "RESET", "PROVISIONING_REQUESTED", "PROVISIONING_APPROVED",
  "DEVICE_REVOKED", "TRANSACTION_PENDING", "TRANSACTION_CONFIRMED",
  "TRANSACTION_EXPIRED_REVERSED", "TRANSACTION_SETTLED",
  "CLEARING_AFTER_REVERSAL", "ATTACK_BLOCKED", "SECURITY_INVARIANT_FAILED",
  "NOT_FOUND", "INVALID_CONTENT_LENGTH", "PAYLOAD_TOO_LARGE",
  "UNSUPPORTED_MEDIA_TYPE", "BODY_REQUIRED", "MALFORMED_JSON",
  "BODY_NOT_OBJECT", "CROSS_ORIGIN_REJECTED", "UNTRUSTED_ORIGIN",
  "HOST_REQUIRED", "INVALID_ORIGIN", "IDEMPOTENCY_KEY_REQUIRED",
  "IDEMPOTENCY_KEY_INVALID", "IDEMPOTENCY_KEY_TOO_LONG",
  "IDEMPOTENCY_CONFLICT", "PERSISTENCE_CONFLICT",
  "PERSISTENCE_UNAVAILABLE", "PROVISIONING_ALREADY_REQUESTED",
  "PROVISIONING_REQUIRED", "PROVISIONING_NOT_PENDING",
  "DEVICE_ALREADY_REVOKED", "TOKEN_NOT_SPENDABLE",
  "TRANSACTION_ALREADY_EXISTS", "TRANSACTION_REQUIRED",
  "TRANSACTION_NOT_PENDING", "CLEARING_NOT_ALLOWED", "AMOUNT_REQUIRED",
  "AMOUNT_NON_POSITIVE", "AMOUNT_FORMAT_INVALID", "AMOUNT_TOO_LARGE",
  "MERCHANT_REQUIRED", "MERCHANT_INVALID", "AUDIT_EMPTY",
  "UNKNOWN_DEMONSTRATION", "CHALLENGE_BINDING_MISMATCH",
  "CHALLENGE_EXPIRED", "CHALLENGE_TERMINAL", "DEVICE_KEY_MISMATCH",
  "DEVICE_NOT_ACTIVE", "INVALID_STATE_TRANSITION", "CAP_EXCEEDED",
  "DOMAIN_REJECTED", "INTERNAL_ERROR", "RATE_LIMITED",
] as const;
export type ReasonCode = typeof REASON_CODES[number];

// ---- Per-client mutation rate limiting (in-process, single-instance only) ----
// SCOPE: a local abuse control for ONE simulator process. NOT distributed or
// production enforcement — horizontal scaling, edge/CDN throttling, and
// shared-state limiting (Redis, API gateway) are explicitly left EXTERNAL.
// See docs/REALTIME_LAB_RATE_LIMIT.md.
export interface RateLimitConfig {
  /** Bucket capacity = maximum burst of mutations a client may make at once. */
  capacity: number;
  /** Sustained refill rate in tokens per second. */
  refillPerSecond: number;
  /** Hard cap on tracked client buckets (memory bound); LRU-evicted past it. */
  maxClients: number;
}

const DEFAULT_RATE_LIMIT: RateLimitConfig = Object.freeze({
  // Generous defaults: invisible to functional use, still a real abuse ceiling.
  capacity: 300,
  refillPerSecond: 150,
  maxClients: 10_000,
});

// ---- SSE connection bounding (in-process, single-instance only) ----
// Long-lived `GET /api/events` streams each pin a socket and a heartbeat timer.
// Without a bound, one client can open unbounded streams and exhaust sockets/
// memory. These caps are per-process; distributed/edge connection limits remain
// external. See docs/REALTIME_LAB_RATE_LIMIT.md.
export interface SseLimitConfig {
  /** Max concurrent event streams from a single client identity. */
  maxPerClient: number;
  /** Max concurrent event streams across all clients. */
  maxTotal: number;
}

const DEFAULT_SSE_LIMIT: SseLimitConfig = Object.freeze({
  maxPerClient: 4,
  maxTotal: 64,
});

// Heartbeat comment interval for SSE keep-alive (ms). Overridable for tests.
const DEFAULT_SSE_HEARTBEAT_MS = 15_000;

interface Bucket {
  tokens: number;
  updatedMs: number;
}

export interface RateLimitDecision {
  allowed: boolean;
  /** Seconds until a token frees (>=1); only meaningful when blocked. */
  retryAfterSeconds: number;
}

/**
 * Token-bucket limiter keyed by client identity. Deterministic under an injected
 * clock. Backed by a Map used as an LRU (re-insertion moves a key to the tail;
 * eviction drops the head) so memory is bounded by `maxClients`.
 */
export class MutationRateLimiter {
  readonly #buckets = new Map<string, Bucket>();
  readonly #config: RateLimitConfig;
  readonly #clock: () => number;

  constructor(config: RateLimitConfig, clock: () => number) {
    if (
      !Number.isFinite(config.capacity) || config.capacity < 1 ||
      !Number.isFinite(config.refillPerSecond) || config.refillPerSecond <= 0 ||
      !Number.isInteger(config.maxClients) || config.maxClients < 1
    ) {
      throw new Error("invalid rate-limit configuration");
    }
    this.#config = config;
    this.#clock = clock;
  }

  #admissionRejections = 0;

  /** Synchronously (atomically) attempt to consume one token for `clientKey`. */
  take(clientKey: string): RateLimitDecision {
    const now = this.#clock();
    const { capacity, refillPerSecond, maxClients } = this.#config;
    const existing = this.#buckets.get(clientKey);

    // New client at capacity: apply bounded, fail-closed admission control that
    // NEVER refunds tokens to a penalized bucket. Evicting a bucket that has
    // spent tokens and re-creating it fresh (full capacity) would let attacker-
    // controlled identity churn wipe a victim's active penalty. So we only evict
    // a fully-refilled bucket; if none exists, we reject the NEW identity without
    // allocating (the table never grows past maxClients and no penalty is lost).
    if (!existing && this.#buckets.size >= maxClients) {
      const evictable = this.#findEvictableFullBucket(now);
      if (evictable === undefined) {
        this.#admissionRejections += 1;
        return {
          allowed: false,
          retryAfterSeconds: Math.max(1, Math.ceil(1 / refillPerSecond)),
        };
      }
      this.#buckets.delete(evictable);
    }

    // Refresh LRU position: delete now, re-insert at tail below.
    if (existing) this.#buckets.delete(clientKey);
    const bucket: Bucket = existing ?? { tokens: capacity, updatedMs: now };
    const elapsedSec = Math.max(0, (now - bucket.updatedMs) / 1000);
    bucket.tokens = Math.min(capacity, bucket.tokens + elapsedSec * refillPerSecond);
    bucket.updatedMs = now;

    let decision: RateLimitDecision;
    if (bucket.tokens >= 1) {
      bucket.tokens -= 1;
      decision = { allowed: true, retryAfterSeconds: 0 };
    } else {
      const deficit = 1 - bucket.tokens;
      decision = {
        allowed: false,
        retryAfterSeconds: Math.max(1, Math.ceil(deficit / refillPerSecond)),
      };
    }
    this.#buckets.set(clientKey, bucket);
    return decision;
  }

  /**
   * Oldest-first scan (Map iteration order = insertion/LRU order) for a bucket
   * that has fully refilled at `now`. Such a bucket carries no penalty, so
   * evicting it and letting the owner re-create it later is a no-op — safe.
   * A partially-drained ("penalized") bucket is never returned, so churn cannot
   * refund it. Returns the client key to evict, or undefined if none is safe.
   */
  #findEvictableFullBucket(now: number): string | undefined {
    const { capacity, refillPerSecond } = this.#config;
    for (const [key, bucket] of this.#buckets) {
      const elapsedSec = Math.max(0, (now - bucket.updatedMs) / 1000);
      const refilled = Math.min(capacity, bucket.tokens + elapsedSec * refillPerSecond);
      if (refilled >= capacity) return key;
    }
    return undefined;
  }

  /** Introspection helper: number of tracked client buckets. */
  get trackedClients(): number {
    return this.#buckets.size;
  }

  /** Introspection helper: count of new identities refused by admission control. */
  get admissionRejections(): number {
    return this.#admissionRejections;
  }
}

/** Normalize an IP: strip IPv6 zone id, unwrap v4-mapped IPv6, lowercase. */
function normalizeIp(raw: string): string {
  let ip = raw.trim().toLowerCase();
  if (!ip) return "";
  const zone = ip.indexOf("%");
  if (zone >= 0) ip = ip.slice(0, zone);
  if (ip.startsWith("::ffff:") && ip.includes(".")) ip = ip.slice("::ffff:".length);
  return ip;
}

/** Bucket key for an address: IPv4 -> exact; IPv6 -> /64 prefix (first 4 groups). */
function addressBucketKey(ip: string): string {
  if (!ip) return "unknown";
  if (ip.includes(":")) {
    const [head, tail = ""] = ip.split("::", 2);
    const headGroups = head ? head.split(":") : [];
    const tailGroups = tail ? tail.split(":") : [];
    const missing = 8 - headGroups.length - tailGroups.length;
    const groups = ip.includes("::")
      ? [...headGroups, ...Array(Math.max(0, missing)).fill("0"), ...tailGroups]
      : ip.split(":");
    return "v6:" + groups.slice(0, 4).map((g) => g || "0").join(":") + "::/64";
  }
  return "v4:" + ip;
}

/**
 * Resolve the client identity used for rate limiting. Forwarding headers are
 * trusted ONLY when the direct socket peer is in `trustedProxies`; otherwise a
 * spoofed X-Forwarded-For is ignored and the real peer address is used. With a
 * trusted proxy present we take the right-most chain address that is not itself
 * a trusted proxy (the client as seen by the outermost trusted hop).
 */
function resolveClientKey(
  req: IncomingMessage,
  trustedProxies: ReadonlySet<string>,
): string {
  const peer = normalizeIp(req.socket?.remoteAddress ?? "");
  if (trustedProxies.size === 0 || !trustedProxies.has(peer)) {
    return addressBucketKey(peer);
  }
  const forwarded = req.headers["x-forwarded-for"];
  const header = Array.isArray(forwarded) ? forwarded.join(",") : forwarded;
  if (typeof header === "string" && header.length > 0) {
    const chain = header.split(",").map((part) => normalizeIp(part)).filter(Boolean);
    for (let i = chain.length - 1; i >= 0; i -= 1) {
      if (!trustedProxies.has(chain[i])) return addressBucketKey(chain[i]);
    }
  }
  return addressBucketKey(peer);
}

export const REALTIME_LAB_API_ROUTES = Object.freeze({
  health: "/api/health",
  state: "/api/state",
  events: "/api/events",
  reset: "/api/reset",
  provisionRequest: "/api/provision/request",
  provisionAttack: "/api/provision/attack",
  provisionApprove: "/api/provision/approve",
  deviceRevoke: "/api/device/revoke",
  transactionRequest: "/api/transaction/request",
  transactionConfirm: "/api/transaction/confirm",
  transactionExpire: "/api/transaction/expire",
  transactionClear: "/api/transaction/clear",
  auditTamper: "/api/demonstrate/audit-tamper",
  demonstrationPrefix: "/api/demonstrate/",
});

export interface RouteManifestEntry {
  readonly label: string;
  /** The exact path, or the prefix, this entry was declared with — kept for
   *  introspection (parity tests) separately from `matches`, which is what
   *  the dispatcher itself actually calls. */
  readonly path: string;
  readonly isPrefix: boolean;
  readonly methods: readonly string[];
  readonly matches: (pathname: string) => boolean;
}

function exactRoute(label: string, path: string, methods: readonly string[]): RouteManifestEntry {
  return { label, path, isPrefix: false, methods, matches: (pathname) => pathname === path };
}

function prefixRoute(label: string, prefix: string, methods: readonly string[]): RouteManifestEntry {
  return { label, path: prefix, isPrefix: true, methods, matches: (pathname) => pathname.startsWith(prefix) };
}

/**
 * Every route this server recognizes, with the exact method set each one
 * accepts. This is the single source of truth for both HEAD support and
 * 405 dispatch below — a route's allowed methods are declared here once,
 * not duplicated across handler `if` conditions, so `Allow` headers and
 * actual handler behavior cannot independently drift from each other.
 *
 * `/api/events` intentionally omits HEAD (see docs/HEAD_REQUESTS.md: an
 * open-ended SSE stream has no fixed body for HEAD to describe). Exact
 * entries are listed before the `/api/demonstrate/` prefix entry so a
 * lookup by array order finds the more specific match first, though today
 * both resolve to the same POST-only method set either way.
 */
export const ROUTE_MANIFEST: readonly RouteManifestEntry[] = Object.freeze([
  exactRoute("root", "/", ["GET", "HEAD"]),
  exactRoute("app.js", "/app.js", ["GET", "HEAD"]),
  exactRoute("styles.css", "/styles.css", ["GET", "HEAD"]),
  exactRoute("health", REALTIME_LAB_API_ROUTES.health, ["GET", "HEAD"]),
  exactRoute("state", REALTIME_LAB_API_ROUTES.state, ["GET", "HEAD"]),
  exactRoute("events", REALTIME_LAB_API_ROUTES.events, ["GET"]),
  exactRoute("reset", REALTIME_LAB_API_ROUTES.reset, ["POST"]),
  exactRoute("provisionRequest", REALTIME_LAB_API_ROUTES.provisionRequest, ["POST"]),
  exactRoute("provisionAttack", REALTIME_LAB_API_ROUTES.provisionAttack, ["POST"]),
  exactRoute("provisionApprove", REALTIME_LAB_API_ROUTES.provisionApprove, ["POST"]),
  exactRoute("deviceRevoke", REALTIME_LAB_API_ROUTES.deviceRevoke, ["POST"]),
  exactRoute("transactionRequest", REALTIME_LAB_API_ROUTES.transactionRequest, ["POST"]),
  exactRoute("transactionConfirm", REALTIME_LAB_API_ROUTES.transactionConfirm, ["POST"]),
  exactRoute("transactionExpire", REALTIME_LAB_API_ROUTES.transactionExpire, ["POST"]),
  exactRoute("transactionClear", REALTIME_LAB_API_ROUTES.transactionClear, ["POST"]),
  exactRoute("auditTamper", REALTIME_LAB_API_ROUTES.auditTamper, ["POST"]),
  prefixRoute("demonstration", REALTIME_LAB_API_ROUTES.demonstrationPrefix, ["POST"]),
]);

export function findRouteManifestEntry(pathname: string): RouteManifestEntry | undefined {
  return ROUTE_MANIFEST.find((entry) => entry.matches(pathname));
}

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
    code: ReasonCode;
    action: string;
    message: string;
    at: string;
  };
}

interface PersistedLabSnapshot {
  schemaVersion: 1 | 2;
  simulatorOnly: true;
  keyMaterialWarning: typeof SIMULATOR_KEY_WARNING;
  engine: AirlockEngineSnapshot;
  keys: DeviceKeyPair;
  provisioningRequestId?: string;
  transactionId?: string;
  demonstration?: LabState["demonstration"];
  lastResult: LabState["lastResult"] | Omit<LabState["lastResult"], "code">;
}

interface PersistedHttpResponse {
  status: number;
  body: unknown;
}

interface RequestIdempotency {
  key: string;
  requestHash: string;
}

export interface CreateLabServerOptions {
  dbPath?: string;
  /** Test-only dependency injection for deterministic storage failures. */
  storeFactory?: (path: string) => Pick<
    DurableStore,
    "get" | "create" | "compareAndSwap" | "runIdempotent" | "getIdempotent" | "close"
  >;
  /** Test-only fault point; production callers must leave this unset. */
  faultInjector?: (action: string) => void;
  /** Test-only verifier substitution for exercising the fail-closed invariant. */
  auditCopyVerifier?: typeof verifyAuditCopy;
  /**
   * Per-client mutation rate limit. Omit for the generous default; pass `false`
   * to disable enforcement entirely; pass a config to override.
   */
  rateLimit?: RateLimitConfig | false;
  /**
   * Deterministic monotonic-ish clock (ms epoch) for the rate limiter. Tests
   * inject a controllable clock; production leaves it as `Date.now`.
   */
  clock?: () => number;
  /**
   * Socket peer addresses whose `X-Forwarded-For` is trusted. Empty by default,
   * so forwarding headers are ignored and the real peer address is used.
   */
  trustedProxies?: readonly string[];
  /**
   * Concurrent `GET /api/events` stream caps. Omit for the default; pass `false`
   * to disable SSE connection bounding entirely; pass a config to override.
   */
  sseLimit?: SseLimitConfig | false;
  /** Test-only override for the SSE heartbeat interval (ms). */
  sseHeartbeatMs?: number;
}

class HttpError extends Error {
  readonly status: number;
  readonly code: ReasonCode;

  constructor(status: number, message: string, code?: ReasonCode) {
    super(message);
    this.status = status;
    this.code = code ?? reasonCodeFor(message, status);
  }
}

class DomainError extends Error {
  readonly code: ReasonCode;

  constructor(code: ReasonCode, message: string) {
    super(message);
    this.code = code;
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
    throw new HttpError(403, "Cross-origin mutation request rejected.", "CROSS_ORIGIN_REJECTED");
  }

  const origin = req.headers.origin;
  if (origin === undefined) return; // Preserve non-browser CLI/partner harness operation.
  if (typeof origin !== "string" || origin === "null") {
    throw new HttpError(403, "Untrusted mutation origin rejected.", "UNTRUSTED_ORIGIN");
  }
  const host = req.headers.host;
  if (!host) throw new HttpError(400, "Host header is required.", "HOST_REQUIRED");
  let normalizedOrigin: string;
  try {
    const parsed = new URL(origin);
    if (origin !== parsed.origin || parsed.protocol !== "http:") {
      throw new Error("not a serialized HTTP origin");
    }
    normalizedOrigin = parsed.origin;
  } catch {
    throw new HttpError(403, "Invalid mutation origin rejected.", "INVALID_ORIGIN");
  }
  if (normalizedOrigin !== `http://${host}`) {
    throw new HttpError(403, "Cross-origin mutation request rejected.", "CROSS_ORIGIN_REJECTED");
  }
}

async function readBoundedBody(req: IncomingMessage): Promise<Buffer> {
  const declaredLength = req.headers["content-length"];
  if (declaredLength !== undefined) {
    const length = Number(declaredLength);
    if (!Number.isSafeInteger(length) || length < 0) {
      throw new HttpError(400, "Invalid Content-Length.", "INVALID_CONTENT_LENGTH");
    }
    if (length > MAX_REQUEST_BODY_BYTES) {
      throw new HttpError(413, `Request body exceeds ${MAX_REQUEST_BODY_BYTES} bytes.`, "PAYLOAD_TOO_LARGE");
    }
  }
  const chunks: Buffer[] = [];
  let total = 0;
  for await (const chunk of req) {
    const buffer = Buffer.from(chunk);
    total += buffer.length;
    if (total > MAX_REQUEST_BODY_BYTES) {
      throw new HttpError(413, `Request body exceeds ${MAX_REQUEST_BODY_BYTES} bytes.`, "PAYLOAD_TOO_LARGE");
    }
    chunks.push(buffer);
  }
  return Buffer.concat(chunks, total);
}

function parseJsonBody(req: IncomingMessage, body: Buffer): Record<string, unknown> {
  const contentType = req.headers["content-type"]?.split(";", 1)[0]?.trim().toLowerCase();
  if (contentType !== "application/json") {
    throw new HttpError(415, "Content-Type must be application/json.", "UNSUPPORTED_MEDIA_TYPE");
  }
  if (!body.length) throw new HttpError(400, "JSON request body is required.", "BODY_REQUIRED");
  let value: unknown;
  try {
    value = JSON.parse(body.toString("utf8"));
  } catch {
    throw new HttpError(400, "Malformed JSON request body.", "MALFORMED_JSON");
  }
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new HttpError(400, "JSON body must be an object.", "BODY_NOT_OBJECT");
  }
  return value as Record<string, unknown>;
}

function parseAmountMinor(value: unknown): number {
  if (typeof value !== "string") throw new DomainError("AMOUNT_REQUIRED", "Amount is required in decimal form, for example 25.00.");
  const input = value.trim();
  if (/^-\d+(?:\.\d+)?$/.test(input)) throw new DomainError("AMOUNT_NON_POSITIVE", "Amount must be greater than zero.");
  const match = /^(0|[1-9]\d*)(?:\.(\d{1,2}))?$/.exec(input);
  if (!match) throw new DomainError("AMOUNT_FORMAT_INVALID", "Amount must be a finite decimal with no more than two fractional digits.");
  const fraction = (match[2] ?? "").padEnd(2, "0");
  const minor = BigInt(match[1]) * 100n + BigInt(fraction || "0");
  if (minor <= 0n) throw new DomainError("AMOUNT_NON_POSITIVE", "Amount must be greater than zero.");
  if (minor > BigInt(Number.MAX_SAFE_INTEGER)) throw new DomainError("AMOUNT_TOO_LARGE", "Amount exceeds the safe supported limit.");
  return Number(minor);
}

function parseMerchantId(value: unknown): string {
  if (typeof value !== "string") throw new DomainError("MERCHANT_REQUIRED", "Merchant identifier is required.");
  const merchantId = value.trim();
  if (!merchantId) throw new DomainError("MERCHANT_REQUIRED", "Merchant identifier is required.");
  if (!/^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$/.test(merchantId)) {
    throw new DomainError("MERCHANT_INVALID", "Merchant identifier must be 1–64 letters, numbers, dots, colons, underscores, or hyphens.");
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
      code: "RESET",
      action: "reset",
      message: "Synthetic trusted device enrolled. No payment network was contacted.",
      at: new Date().toISOString(),
    },
  };
}

function reasonCodeFor(message: string, status: number): ReasonCode {
  if (message === "not found") return "NOT_FOUND";
  if (message === "Invalid Content-Length.") return "INVALID_CONTENT_LENGTH";
  if (message.startsWith("Request body exceeds")) return "PAYLOAD_TOO_LARGE";
  if (message.includes("Content-Type") || message.includes("content-type")) return "UNSUPPORTED_MEDIA_TYPE";
  if (message === "JSON request body is required.") return "BODY_REQUIRED";
  if (message === "Malformed JSON request body.") return "MALFORMED_JSON";
  if (message === "JSON body must be an object.") return "BODY_NOT_OBJECT";
  if (message === "Cross-origin mutation request rejected.") return "CROSS_ORIGIN_REJECTED";
  if (message === "Untrusted mutation origin rejected.") return "UNTRUSTED_ORIGIN";
  if (message === "Host header is required.") return "HOST_REQUIRED";
  if (message === "Invalid mutation origin rejected.") return "INVALID_ORIGIN";
  if (message.includes("Idempotency-Key is required")) return "IDEMPOTENCY_KEY_REQUIRED";
  if (message.includes("Idempotency-Key must not exceed")) return "IDEMPOTENCY_KEY_TOO_LONG";
  if (message.includes("Idempotency-Key was already used")) return "IDEMPOTENCY_CONFLICT";
  if (message.startsWith("Idempotency-Key must")) return "IDEMPOTENCY_KEY_INVALID";
  if (message.includes("Persistent simulator state changed")) return "PERSISTENCE_CONFLICT";
  if (message.includes("durably save") || message.includes("persistence version")) return "PERSISTENCE_UNAVAILABLE";
  if (message.includes("Provisioning was already requested")) return "PROVISIONING_ALREADY_REQUESTED";
  if (message === "request provisioning first") return "PROVISIONING_REQUIRED";
  if (message.includes("Provisioning is no longer waiting")) return "PROVISIONING_NOT_PENDING";
  if (message.includes("already revoked")) return "DEVICE_ALREADY_REVOKED";
  if (message.includes("payment token is not spendable")) return "TOKEN_NOT_SPENDABLE";
  if (message.includes("transaction already exists") || message.includes("transaction id already exists")) return "TRANSACTION_ALREADY_EXISTS";
  if (message === "request a transaction first") return "TRANSACTION_REQUIRED";
  if (message.includes("awaiting confirmation") || message.includes("can be confirmed")) return "TRANSACTION_NOT_PENDING";
  if (message.includes("Clearing can only follow")) return "CLEARING_NOT_ALLOWED";
  if (message.startsWith("Amount is required")) return "AMOUNT_REQUIRED";
  if (message === "Amount must be greater than zero.") return "AMOUNT_NON_POSITIVE";
  if (message.includes("finite decimal")) return "AMOUNT_FORMAT_INVALID";
  if (message.includes("safe supported limit")) return "AMOUNT_TOO_LARGE";
  if (message === "Merchant identifier is required.") return "MERCHANT_REQUIRED";
  if (message.startsWith("Merchant identifier must")) return "MERCHANT_INVALID";
  if (message.includes("No audit event exists")) return "AUDIT_EMPTY";
  if (message === "Unknown security demonstration.") return "UNKNOWN_DEMONSTRATION";
  if (message.includes("binding mismatch")) return "CHALLENGE_BINDING_MISMATCH";
  if (message.includes("challenge expired")) return "CHALLENGE_EXPIRED";
  if (message.includes("challenge already terminal")) return "CHALLENGE_TERMINAL";
  if (message.includes("key id mismatch")) return "DEVICE_KEY_MISMATCH";
  if (message.includes("trusted device is revoked")) return "DEVICE_NOT_ACTIVE";
  if (message.includes("invalid transaction transition") || message.includes("invalid provisioning transition")) return "INVALID_STATE_TRANSITION";
  if (message.includes("cap")) return "CAP_EXCEEDED";
  return status >= 500 ? "INTERNAL_ERROR" : "DOMAIN_REJECTED";
}

function legacyResultCode(result: Omit<LabState["lastResult"], "code">): ReasonCode {
  const byAction: Readonly<Record<string, ReasonCode>> = {
    reset: "RESET",
    "provision.request": "PROVISIONING_REQUESTED",
    "provision.approve": "PROVISIONING_APPROVED",
    "device.revoke": "DEVICE_REVOKED",
    "transaction.request": "TRANSACTION_PENDING",
    "transaction.confirm": "TRANSACTION_CONFIRMED",
    "transaction.expire": "TRANSACTION_EXPIRED_REVERSED",
    "transaction.clear": "TRANSACTION_SETTLED",
    "transaction.clear.exception": "CLEARING_AFTER_REVERSAL",
    "demonstrate.audit-tamper": "ATTACK_BLOCKED",
  };
  if (result.action.startsWith("demonstrate.")) return "ATTACK_BLOCKED";
  return byAction[result.action] ??
    reasonCodeFor(result.message, result.ok ? 200 : 409);
}

function stableJson(value: unknown): string {
  if (value === null || typeof value !== "object") {
    const encoded = JSON.stringify(value);
    if (encoded === undefined) throw new HttpError(400, "JSON value is not canonicalizable.", "BODY_NOT_OBJECT");
    return encoded;
  }
  if (Array.isArray(value)) return `[${value.map(stableJson).join(",")}]`;
  const object = value as Record<string, unknown>;
  return `{${Object.keys(object).sort().map(
    (key) => `${JSON.stringify(key)}:${stableJson(object[key])}`,
  ).join(",")}}`;
}

function canonicalMutationBody(req: IncomingMessage, body: Buffer): string {
  if (!body.length) return "{}";
  const contentType = req.headers["content-type"]?.split(";", 1)[0]?.trim().toLowerCase();
  if (contentType !== "application/json") {
    throw new HttpError(415, "Mutation bodies must use Content-Type application/json.", "UNSUPPORTED_MEDIA_TYPE");
  }
  let value: unknown;
  try {
    value = JSON.parse(body.toString("utf8"));
  } catch {
    throw new HttpError(400, "Malformed JSON request body.", "MALFORMED_JSON");
  }
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new HttpError(400, "JSON body must be an object.", "BODY_NOT_OBJECT");
  }
  return stableJson(value);
}

function requestIdempotency(
  req: IncomingMessage,
  path: string,
  canonicalBody: string,
  required: boolean,
): RequestIdempotency | undefined {
  const header = req.headers["idempotency-key"];
  if (header === undefined) {
    if (required) {
      throw new HttpError(
        428,
        "Idempotency-Key is required for persistent mutating requests.",
        "IDEMPOTENCY_KEY_REQUIRED",
      );
    }
    return undefined;
  }
  if (typeof header !== "string") {
    throw new HttpError(400, "Idempotency-Key must be a single header value.", "IDEMPOTENCY_KEY_INVALID");
  }
  if (header.length > MAX_IDEMPOTENCY_KEY_LENGTH) {
    throw new HttpError(
      431,
      `Idempotency-Key must not exceed ${MAX_IDEMPOTENCY_KEY_LENGTH} characters.`,
      "IDEMPOTENCY_KEY_TOO_LONG",
    );
  }
  if (!/^[A-Za-z0-9][A-Za-z0-9._:-]*$/.test(header)) {
    throw new HttpError(
      400,
      "Idempotency-Key must use only letters, numbers, dots, underscores, colons, or hyphens.",
      "IDEMPOTENCY_KEY_INVALID",
    );
  }
  const requestHash = createHash("sha256")
    .update(`POST\n${path}\n${canonicalBody}`)
    .digest("hex");
  return { key: header, requestHash };
}

class PersistenceError extends Error {
  readonly status: number;
  readonly code: ReasonCode;
  readonly authoritativeState?: LabState;

  constructor(
    status: number,
    message: string,
    authoritativeState?: LabState,
    code: ReasonCode = status === 503
      ? "PERSISTENCE_UNAVAILABLE"
      : message.startsWith("Idempotency-Key")
      ? "IDEMPOTENCY_CONFLICT"
      : "PERSISTENCE_CONFLICT",
  ) {
    super(message);
    this.status = status;
    this.code = code;
    if (authoritativeState) this.authoritativeState = authoritativeState;
  }
}

function snapshotLabState(state: LabState): PersistedLabSnapshot {
  return {
    schemaVersion: 2,
    simulatorOnly: true,
    keyMaterialWarning: SIMULATOR_KEY_WARNING,
    engine: state.engine.snapshot(),
    keys: structuredClone(state.keys),
    ...(state.provisioning
      ? { provisioningRequestId: state.provisioning.requestId }
      : {}),
    ...(state.transaction ? { transactionId: state.transaction.transactionId } : {}),
    ...(state.demonstration
      ? { demonstration: structuredClone(state.demonstration) }
      : {}),
    lastResult: structuredClone(state.lastResult),
  };
}

function restoreLabState(snapshot: PersistedLabSnapshot): LabState {
  if (
    !snapshot ||
    ![1, 2].includes(snapshot.schemaVersion) ||
    snapshot.simulatorOnly !== true ||
    snapshot.keyMaterialWarning !== SIMULATOR_KEY_WARNING ||
    !snapshot.keys ||
    typeof snapshot.keys.keyId !== "string" ||
    typeof snapshot.keys.privateKeyPem !== "string" ||
    typeof snapshot.keys.publicKeyPem !== "string" ||
    !snapshot.lastResult ||
    typeof snapshot.lastResult.message !== "string"
  ) {
    throw new Error("invalid realtime-lab simulator snapshot");
  }
  const restoredCode = "code" in snapshot.lastResult
    ? snapshot.lastResult.code
    : legacyResultCode(snapshot.lastResult);
  if (!REASON_CODES.includes(restoredCode)) {
    throw new Error("invalid realtime-lab simulator snapshot");
  }
  let derivedPublic: string;
  try {
    derivedPublic = createPublicKey(createPrivateKey(snapshot.keys.privateKeyPem))
      .export({ type: "spki", format: "pem" })
      .toString();
  } catch {
    throw new Error("invalid realtime-lab simulator key material");
  }
  if (derivedPublic !== snapshot.keys.publicKeyPem) {
    throw new Error("realtime-lab simulator key pair mismatch");
  }
  const engine = AirlockEngine.restore(snapshot.engine);
  const device = engine.getDevice(SYNTHETIC.deviceId);
  if (
    !device ||
    device.keyId !== snapshot.keys.keyId ||
    device.publicKeyPem !== snapshot.keys.publicKeyPem
  ) {
    throw new Error("realtime-lab simulator key does not match restored device");
  }
  const provisioning = snapshot.provisioningRequestId
    ? snapshot.engine.provisioning.find(
      (request) => request.requestId === snapshot.provisioningRequestId,
    )
    : undefined;
  if (snapshot.provisioningRequestId && !provisioning) {
    throw new Error("realtime-lab provisioning pointer is invalid");
  }
  const transaction = snapshot.transactionId
    ? engine.getTransaction(snapshot.transactionId)
    : undefined;
  if (snapshot.transactionId && !transaction) {
    throw new Error("realtime-lab transaction pointer is invalid");
  }
  return {
    engine,
    keys: structuredClone(snapshot.keys),
    ...(provisioning ? { provisioning: structuredClone(provisioning) } : {}),
    ...(transaction ? { transaction } : {}),
    ...(snapshot.demonstration
      ? { demonstration: structuredClone(snapshot.demonstration) }
      : {}),
    lastResult: {
      ...structuredClone(snapshot.lastResult),
      code: restoredCode,
    },
  };
}

function publicSnapshot(state: LabState) {
  const token = state.engine.getToken(SYNTHETIC.tokenId);
  const device = state.engine.getDevice(SYNTHETIC.deviceId);
  const transaction = state.transaction
    ? state.engine.getTransaction(state.transaction.transactionId)
    : undefined;
  return {
    simulator: true,
    notice: "Synthetic reference implementation. No PAN, bank, wallet, processor, or payment rail is connected.",
    device: device ? {
      deviceId: device.deviceId,
      subjectId: device.subjectId,
      keyId: device.keyId,
      status: device.status,
    } : undefined,
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
      confirmTransaction: Boolean(transaction?.state === "confirmation_pending" &&
        state.engine.getDevice(SYNTHETIC.deviceId)?.status === "active"),
      expireTransaction: Boolean(transaction?.state === "confirmation_pending"),
      receiveClearing: Boolean(transaction && ["confirmed", "reversed"].includes(transaction.state)),
      negativeBinding: Boolean(transaction?.state === "confirmation_pending" &&
        state.engine.getDevice(SYNTHETIC.deviceId)?.status === "active"),
    },
    audit: { valid: state.engine.audit.verify(), events: state.engine.audit.all() },
    demonstration: state.demonstration,
    lastResult: state.lastResult,
  };
}

/**
 * `method` defaults to "GET" so every existing call site is unaffected.
 * Passing "HEAD" keeps status/headers — including a Content-Length that
 * matches what the equivalent GET would have sent — but writes no body, per
 * RFC 7231 §4.3.2. Only the routes that actually accept HEAD (see the
 * root/static handler below) ever pass "HEAD" through.
 */
function json(
  res: ServerResponse,
  status: number,
  value: unknown,
  method: string = "GET",
  extraHeaders?: Record<string, string>,
) {
  const body = JSON.stringify(value);
  res.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "content-length": Buffer.byteLength(body),
    "cache-control": "no-store",
    ...extraHeaders,
  });
  res.end(method === "HEAD" ? undefined : body);
}

/**
 * 405 for a route the manifest recognizes but not with this method. `Allow`
 * lists exactly the manifest's methods for that route — never a generic or
 * hand-maintained list — so it cannot drift from what the dispatcher itself
 * enforces. Emitted before any body read/idempotency/rate-limit handling so
 * a 405 is always side-effect-free, matching HEAD's zero-body rule too.
 */
function methodNotAllowed(res: ServerResponse, method: string, allowedMethods: readonly string[]): void {
  json(
    res,
    405,
    { code: "METHOD_NOT_ALLOWED", error: `${method} is not allowed on this route.` },
    method,
    { allow: allowedMethods.join(", ") },
  );
}

/**
 * 429 rejection with a SimpleError body and a Retry-After header. Emitted before
 * any state snapshot so the rejected mutation leaves state untouched and is
 * never persisted as an idempotent response.
 */
function rateLimited(res: ServerResponse, retryAfterSeconds: number): void {
  const body = JSON.stringify({
    code: "RATE_LIMITED" satisfies ReasonCode,
    error: "Too many mutation requests from this client. Retry after the " +
      "indicated delay. (SIMULATOR: in-process single-instance limiter only.)",
  });
  res.writeHead(429, {
    "content-type": "application/json; charset=utf-8",
    "content-length": Buffer.byteLength(body),
    "cache-control": "no-store",
    "retry-after": String(Math.max(1, Math.trunc(retryAfterSeconds))),
  });
  res.end(body);
}

export function createLabServer(options: CreateLabServerOptions = {}) {
  const clock = options.clock ?? Date.now;
  const trustedProxies = new Set(
    (options.trustedProxies ?? []).map((proxy) => normalizeIp(proxy)).filter(Boolean),
  );
  const rateLimiter = options.rateLimit === false
    ? undefined
    : new MutationRateLimiter(options.rateLimit ?? DEFAULT_RATE_LIMIT, clock);
  const persistentStore = options.dbPath
    ? options.storeFactory?.(options.dbPath) ?? new DurableStore(options.dbPath)
    : undefined;
  let state: LabState;
  let persistedVersion: number | undefined;
  try {
    const stored = persistentStore?.get<PersistedLabSnapshot>(LAB_SNAPSHOT_ID);
    if (stored && stored.status !== LAB_SNAPSHOT_STATUS) {
      throw new Error("invalid realtime-lab snapshot status");
    }
    state = stored ? restoreLabState(stored.value) : freshState();
    persistedVersion = stored?.version;
    if (persistentStore && stored?.value.schemaVersion === 1) {
      const migrated = persistentStore.compareAndSwap(
        LAB_SNAPSHOT_ID,
        stored.version,
        LAB_SNAPSHOT_STATUS,
        LAB_SNAPSHOT_STATUS,
        snapshotLabState(state),
      );
      persistedVersion = migrated.version;
    }
    if (persistentStore && !stored) {
      const created = persistentStore.create(
        LAB_SNAPSHOT_ID,
        LAB_SNAPSHOT_STATUS,
        snapshotLabState(state),
      );
      persistedVersion = created.version;
    }
  } catch (error) {
    persistentStore?.close();
    throw error;
  }
  const persist = () => {
    if (!persistentStore) return;
    if (persistedVersion === undefined) {
      throw new Error("realtime-lab persistence version is unavailable");
    }
    try {
      const saved = persistentStore.compareAndSwap(
        LAB_SNAPSHOT_ID,
        persistedVersion,
        LAB_SNAPSHOT_STATUS,
        LAB_SNAPSHOT_STATUS,
        snapshotLabState(state),
      );
      persistedVersion = saved.version;
    } catch (error) {
      if (error instanceof Error && error.message === "compare-and-swap conflict") {
        const current = persistentStore.get<PersistedLabSnapshot>(LAB_SNAPSHOT_ID);
        if (current) {
          persistedVersion = current.version;
          throw new PersistenceError(
            409,
            "Persistent simulator state changed in another process; stale mutation was rolled back.",
            restoreLabState(current.value),
          );
        }
      }
      throw new PersistenceError(
        503,
        "Failed to durably save simulator state; mutation was rolled back.",
      );
    }
  };
  const persistResponse = (
    idempotency: RequestIdempotency | undefined,
    response: PersistedHttpResponse,
  ): { replayed: boolean; response: PersistedHttpResponse } => {
    if (!persistentStore || !idempotency) {
      persist();
      return { replayed: false, response };
    }
    if (persistedVersion === undefined) {
      throw new PersistenceError(
        503,
        "Persistent simulator version is unavailable; mutation was rolled back.",
      );
    }
    let committedVersion: number | undefined;
    try {
      const result = persistentStore.runIdempotent(
        IDEMPOTENCY_SCOPE,
        idempotency.key,
        idempotency.requestHash,
        (tx) => {
          const saved = tx.compareAndSwap(
            LAB_SNAPSHOT_ID,
            persistedVersion!,
            LAB_SNAPSHOT_STATUS,
            LAB_SNAPSHOT_STATUS,
            snapshotLabState(state),
          );
          committedVersion = saved.version;
          return response;
        },
      );
      if (result.replayed) {
        const current = persistentStore.get<PersistedLabSnapshot>(LAB_SNAPSHOT_ID);
        if (!current) throw new Error("persistent simulator snapshot is missing");
        state = restoreLabState(current.value);
        persistedVersion = current.version;
      } else {
        persistedVersion = committedVersion;
      }
      return { replayed: result.replayed, response: result.value };
    } catch (error) {
      const current = persistentStore.get<PersistedLabSnapshot>(LAB_SNAPSHOT_ID);
      const authoritativeState = current ? restoreLabState(current.value) : undefined;
      if (current) persistedVersion = current.version;
      if (
        error instanceof Error &&
        error.message === "idempotency key reused with a different request"
      ) {
        throw new PersistenceError(
          409,
          "Idempotency-Key was already used for a different request.",
          authoritativeState,
        );
      }
      if (error instanceof Error && error.message === "compare-and-swap conflict") {
        throw new PersistenceError(
          409,
          "Persistent simulator state changed in another process; stale mutation was rolled back.",
          authoritativeState,
        );
      }
      throw new PersistenceError(
        503,
        "Failed to durably save simulator state; mutation was rolled back.",
        authoritativeState,
      );
    }
  };
  const sseLimit = options.sseLimit === false ? undefined : options.sseLimit ?? DEFAULT_SSE_LIMIT;
  const sseHeartbeatMs = options.sseHeartbeatMs ?? DEFAULT_SSE_HEARTBEAT_MS;
  interface SseListener {
    res: ServerResponse;
    clientKey: string;
    heartbeat: ReturnType<typeof setInterval>;
    cleanup: () => void;
  }
  const listeners = new Set<SseListener>();
  const ssePerClient = new Map<string, number>();
  const broadcast = () => {
    const payload = `event: state\ndata: ${JSON.stringify(publicSnapshot(state))}\n\n`;
    for (const listener of listeners) listener.res.write(payload);
  };
  const succeed = (action: string, message: string, code: ReasonCode) => {
    state.lastResult = {
      ok: true,
      outcome: "accepted",
      code,
      action,
      message,
      at: new Date().toISOString(),
    };
    options.faultInjector?.(action);
  };
  const warn = (action: string, message: string, code: ReasonCode) => {
    state.lastResult = {
      ok: false,
      outcome: "warning",
      code,
      action,
      message,
      at: new Date().toISOString(),
    };
    options.faultInjector?.(action);
  };

  const server = createServer(async (req, res) => {
    applySecurityHeaders(res);
    let rollbackSnapshot: PersistedLabSnapshot | undefined;
    let idempotency: RequestIdempotency | undefined;
    const finalize = (status: number, body: unknown) => {
      const saved = persistResponse(idempotency, { status, body });
      if (!saved.replayed) broadcast();
      return json(res, saved.response.status, saved.response.body);
    };
    try {
      const url = new URL(req.url ?? "/", "http://127.0.0.1");
      const method = req.method ?? "GET";
      // Manifest-driven 405 dispatch runs before ANY body read, idempotency
      // lookup, or rate-limit check: a wrong-method request to a known route
      // must be fully side-effect-free, exactly like the HEAD zero-body rule
      // below. An unrecognized path has no manifest entry and falls through
      // unchanged to the existing GET/HEAD-or-404 handling further down.
      const manifestEntry = findRouteManifestEntry(url.pathname);
      if (manifestEntry && !manifestEntry.methods.includes(method)) {
        return methodNotAllowed(res, method, manifestEntry.methods);
      }
      let requestBody: Buffer<ArrayBufferLike> = Buffer.alloc(0);
      if (req.method === "POST" && url.pathname.startsWith("/api/")) {
        enforceMutationSource(req);
        requestBody = await readBoundedBody(req);
        const canonicalBody = canonicalMutationBody(req, requestBody);
        idempotency = requestIdempotency(
          req,
          `${url.pathname}${url.search}`,
          canonicalBody,
          Boolean(persistentStore),
        );
        if (persistentStore && idempotency) {
          let replay: PersistedHttpResponse | undefined;
          try {
            replay = persistentStore.getIdempotent<PersistedHttpResponse>(
              IDEMPOTENCY_SCOPE,
              idempotency.key,
              idempotency.requestHash,
            );
          } catch (error) {
            if (
              error instanceof Error &&
              error.message === "idempotency key reused with a different request"
            ) {
              throw new HttpError(
                409,
                "Idempotency-Key was already used for a different request.",
              );
            }
            throw error;
          }
          if (replay) return json(res, replay.status, replay.body);
        }
        // Rate limit AFTER the idempotent-replay short-circuit (a replay is a
        // no-op that must always return its stored response) and BEFORE any
        // state snapshot/mutation (a rejected request must not mutate).
        if (rateLimiter) {
          const decision = rateLimiter.take(resolveClientKey(req, trustedProxies));
          if (!decision.allowed) {
            return rateLimited(res, decision.retryAfterSeconds);
          }
        }
        rollbackSnapshot = snapshotLabState(state);
      }
      if (
        (req.method === "GET" || req.method === "HEAD") &&
        url.pathname === REALTIME_LAB_API_ROUTES.health
      ) {
        return json(res, 200, { ok: true, simulator: true }, req.method);
      }
      if (
        (req.method === "GET" || req.method === "HEAD") &&
        url.pathname === REALTIME_LAB_API_ROUTES.state
      ) {
        return json(res, 200, publicSnapshot(state), req.method);
      }
      if (req.method === "GET" && url.pathname === REALTIME_LAB_API_ROUTES.events) {
        // Bound concurrent streams BEFORE sending the SSE head, so a rejection
        // is a normal 429 (EventSource surfaces it via onerror) rather than a
        // half-open stream. Global cap first, then per-client cap.
        if (sseLimit) {
          const clientKey = resolveClientKey(req, trustedProxies);
          const perClient = ssePerClient.get(clientKey) ?? 0;
          if (listeners.size >= sseLimit.maxTotal || perClient >= sseLimit.maxPerClient) {
            // Retry-After is advisory: streams free as clients disconnect.
            return rateLimited(res, 1);
          }
          res.writeHead(200, {
            "content-type": "text/event-stream",
            "cache-control": "no-store",
            connection: "keep-alive",
          });
          res.write(`event: state\ndata: ${JSON.stringify(publicSnapshot(state))}\n\n`);
          const heartbeat = setInterval(() => res.write(": heartbeat\n\n"), sseHeartbeatMs);
          // Do not let the heartbeat timer keep the process alive on its own.
          heartbeat.unref?.();
          let released = false;
          const listener: SseListener = {
            res,
            clientKey,
            heartbeat,
            cleanup: () => {
              if (released) return; // idempotent: close AND error may both fire
              released = true;
              clearInterval(heartbeat);
              listeners.delete(listener);
              const next = (ssePerClient.get(clientKey) ?? 1) - 1;
              if (next <= 0) ssePerClient.delete(clientKey);
              else ssePerClient.set(clientKey, next);
            },
          };
          listeners.add(listener);
          ssePerClient.set(clientKey, perClient + 1);
          req.on("close", listener.cleanup);
          res.on("close", listener.cleanup);
          res.on("error", listener.cleanup);
          return;
        }
        // Unbounded mode (sseLimit disabled): original behavior with cleanup.
        res.writeHead(200, {
          "content-type": "text/event-stream",
          "cache-control": "no-store",
          connection: "keep-alive",
        });
        res.write(`event: state\ndata: ${JSON.stringify(publicSnapshot(state))}\n\n`);
        const heartbeat = setInterval(() => res.write(": heartbeat\n\n"), sseHeartbeatMs);
        heartbeat.unref?.();
        const listener: SseListener = {
          res,
          clientKey: "",
          heartbeat,
          cleanup: () => {
            clearInterval(heartbeat);
            listeners.delete(listener);
          },
        };
        listeners.add(listener);
        req.on("close", listener.cleanup);
        res.on("close", listener.cleanup);
        res.on("error", listener.cleanup);
        return;
      }

      if (req.method === "POST" && url.pathname === REALTIME_LAB_API_ROUTES.reset) {
        state = freshState();
        return finalize(200, publicSnapshot(state));
      }
      if (req.method === "POST" && url.pathname === REALTIME_LAB_API_ROUTES.provisionRequest) {
        if (state.provisioning) throw new Error("Provisioning was already requested. Reset the lab to start a new request.");
        state.provisioning = state.engine.requestProvisioning({
          subjectId: SYNTHETIC.subjectId,
          accountId: SYNTHETIC.accountId,
          tokenId: SYNTHETIC.tokenId,
          trustedDeviceId: SYNTHETIC.deviceId,
          capMinor: 5_000,
        });
        succeed("provision.request", "Provisioning challenge issued to the trusted device.", "PROVISIONING_REQUESTED");
        return finalize(200, publicSnapshot(state));
      }
      if (req.method === "POST" && url.pathname === REALTIME_LAB_API_ROUTES.provisionAttack) {
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
      if (req.method === "POST" && url.pathname === REALTIME_LAB_API_ROUTES.provisionApprove) {
        if (!state.provisioning) throw new Error("request provisioning first");
        if (state.provisioning.state !== "trusted_device_challenge") {
          throw new Error("Provisioning is no longer waiting for approval.");
        }
        const approval = signApproval(state.provisioning.challenge, state.keys.keyId, state.keys.privateKeyPem);
        state.provisioning = state.engine.approveProvisioning(state.provisioning.requestId, approval);
        succeed("provision.approve", "Exact challenge binding signed with the enrolled P-256 key.", "PROVISIONING_APPROVED");
        return finalize(200, publicSnapshot(state));
      }
      if (req.method === "POST" && url.pathname === REALTIME_LAB_API_ROUTES.deviceRevoke) {
        if (state.engine.getDevice(SYNTHETIC.deviceId)?.status !== "active") {
          throw new Error("Trusted device is already revoked.");
        }
        state.engine.revokeTrustedDevice(SYNTHETIC.deviceId);
        succeed("device.revoke", "Trusted device revoked; outstanding approvals now fail closed.", "DEVICE_REVOKED");
        return finalize(200, publicSnapshot(state));
      }
      if (req.method === "POST" && url.pathname === REALTIME_LAB_API_ROUTES.transactionRequest) {
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
        succeed("transaction.request", "Transaction is pending exact trusted-device confirmation.", "TRANSACTION_PENDING");
        return finalize(200, publicSnapshot(state));
      }
      if (req.method === "POST" && url.pathname === REALTIME_LAB_API_ROUTES.transactionConfirm) {
        if (!state.transaction?.challenge) throw new Error("request a transaction first");
        if (state.transaction.state !== "confirmation_pending") {
          throw new Error("Only a transaction awaiting confirmation can be confirmed.");
        }
        const approval = signApproval(state.transaction.challenge, state.keys.keyId, state.keys.privateKeyPem);
        state.transaction = state.engine.confirmTransaction(state.transaction.transactionId, approval);
        succeed("transaction.confirm", "Amount, merchant, token, device, nonce, and expiry binding verified.", "TRANSACTION_CONFIRMED");
        return finalize(200, publicSnapshot(state));
      }
      if (req.method === "POST" && url.pathname === REALTIME_LAB_API_ROUTES.transactionExpire) {
        if (!state.transaction) throw new Error("request a transaction first");
        if (state.transaction.state !== "confirmation_pending") {
          throw new Error("Only a transaction awaiting confirmation can time out.");
        }
        state.transaction = state.engine.expireAndReverse(state.transaction.transactionId);
        succeed("transaction.expire", "Confirmation timed out; reversal requested and recorded.", "TRANSACTION_EXPIRED_REVERSED");
        return finalize(200, publicSnapshot(state));
      }
      if (req.method === "POST" && url.pathname === REALTIME_LAB_API_ROUTES.transactionClear) {
        if (!state.transaction) throw new Error("request a transaction first");
        if (!["confirmed", "reversed"].includes(state.transaction.state)) {
          throw new Error("Clearing can only follow confirmation or reversal in this demonstration.");
        }
        state.transaction = state.engine.receiveClearing(state.transaction.transactionId);
        if (state.transaction.state === "exception") {
          warn(
            "transaction.clear.exception",
            "Exception detected: clearing arrived after reversal. Partner reconciliation is required; settlement prevention is not claimed.",
            "CLEARING_AFTER_REVERSAL",
          );
        } else {
          succeed("transaction.clear", "Synthetic clearing received; transaction settled.", "TRANSACTION_SETTLED");
        }
        return finalize(200, publicSnapshot(state));
      }
      if (req.method === "POST" && url.pathname === REALTIME_LAB_API_ROUTES.auditTamper) {
        const tampered = state.engine.audit.all();
        if (!tampered.length) throw new Error("No audit event exists to tamper with.");
        tampered[0].payload = { ...tampered[0].payload, tampered: true };
        const detected = !(options.auditCopyVerifier ?? verifyAuditCopy)(tampered);
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
          code: detected ? "ATTACK_BLOCKED" : "SECURITY_INVARIANT_FAILED",
          action: "demonstrate.audit-tamper",
          message: `Attack blocked: ${state.demonstration.message} The authoritative audit remains valid.`,
          at: new Date().toISOString(),
        };
        return finalize(detected ? 200 : 500, publicSnapshot(state));
      }
      if (req.method === "POST" && url.pathname.startsWith(REALTIME_LAB_API_ROUTES.demonstrationPrefix)) {
        if (!state.transaction?.challenge || state.transaction.state !== "confirmation_pending") {
          throw new Error("Request a pending transaction before running a binding attack.");
        }
        const name = url.pathname.slice(REALTIME_LAB_API_ROUTES.demonstrationPrefix.length);
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
            state.transaction = state.engine.expireAndReverse(
              state.transaction.transactionId,
              new Date(original.expiresAt),
            );
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
          state.engine.audit.append("security.attack_blocked", state.transaction.transactionId, {
            attack: name,
            reason: message,
          });
          state.demonstration = { name, blocked: true, message };
          state.lastResult = {
            ok: false,
            outcome: "blocked",
            code: "ATTACK_BLOCKED",
            action: `demonstrate.${name}`,
            message: `Attack blocked: ${message}`,
            at: new Date().toISOString(),
          };
          return finalize(200, publicSnapshot(state));
        }
      }

      // Scope decision (documented in docs/HEAD_REQUESTS.md): HEAD is
      // supported for these root/static routes, matching GET's status and
      // headers exactly with no body — RFC 7231 §4.3.2. /api/health and
      // /api/state also accept HEAD (handled above); the Content-Length in
      // that case describes the snapshot as of this instant only, same as
      // any HEAD against dynamic content. /api/events remains GET-only: an
      // open-ended SSE stream has no fixed body to describe the length of,
      // so HEAD's contract does not apply there.
      if (req.method === "GET" || req.method === "HEAD") {
        const relative = url.pathname === "/" ? "index.html" : url.pathname.slice(1);
        if (!["index.html", "app.js", "styles.css"].includes(relative)) {
          return json(res, 404, { code: "NOT_FOUND", error: "not found" }, req.method);
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
        return res.end(req.method === "HEAD" ? undefined : body);
      }
      return json(res, 404, { code: "NOT_FOUND", error: "not found" }, req.method);
    } catch (error) {
      const message = error instanceof Error ? error.message : "unknown error";
      if (error instanceof HttpError) {
        return json(res, error.status, {
          code: error.code,
          error: message,
        });
      }
      if (error instanceof PersistenceError) {
        state = error.authoritativeState ??
          (rollbackSnapshot ? restoreLabState(rollbackSnapshot) : state);
        return json(res, error.status, {
          code: error.code,
          error: error.message,
          state: publicSnapshot(state),
        });
      }
      if (rollbackSnapshot) state = restoreLabState(rollbackSnapshot);
      const knownCode = error instanceof DomainError
        ? error.code
        : reasonCodeFor(message, 409);
      const isKnownDomainFailure = knownCode !== "DOMAIN_REJECTED";
      const publicCode: ReasonCode = isKnownDomainFailure ? knownCode : "INTERNAL_ERROR";
      const publicMessage = isKnownDomainFailure
        ? message
        : "Internal simulator error.";
      const publicStatus = isKnownDomainFailure ? 409 : 500;
      state.lastResult = {
        ok: false,
        outcome: "blocked",
        code: publicCode,
        action: "blocked",
        message: publicMessage,
        at: new Date().toISOString(),
      };
      try {
        return finalize(publicStatus, {
          code: publicCode,
          error: publicMessage,
          state: publicSnapshot(state),
        });
      } catch (persistError) {
        if (persistError instanceof PersistenceError) {
          state = persistError.authoritativeState ??
            (rollbackSnapshot ? restoreLabState(rollbackSnapshot) : state);
          return json(res, persistError.status, {
            code: persistError.code,
            error: persistError.message,
            state: publicSnapshot(state),
          });
        }
        throw persistError;
      }
    }
  });
  server.on("close", () => {
    // Deterministically tear down every live SSE stream: clear its heartbeat,
    // end the response, and drop registry entries so no timer or listener leaks
    // past server shutdown.
    for (const listener of [...listeners]) {
      clearInterval(listener.heartbeat);
      listener.cleanup();
      try {
        listener.res.end();
      } catch {
        // response may already be closing; teardown must not throw
      }
    }
    listeners.clear();
    ssePerClient.clear();
    persistentStore?.close();
  });
  return server;
}

/**
 * Parse `AIRLOCK_RATE_LIMIT` of the form "capacity:refillPerSecond[:maxClients]"
 * (e.g. "300:150" or "300:150:10000"). "off"/"disabled"/"0" disables the
 * limiter. Returns undefined for an unset/blank var (uses the default).
 */
export function parseRateLimitEnv(
  raw: string | undefined,
): RateLimitConfig | false | undefined {
  if (raw === undefined) return undefined;
  const value = raw.trim().toLowerCase();
  if (value === "") return undefined;
  if (value === "off" || value === "disabled" || value === "0") return false;
  const parts = value.split(":");
  const capacity = Number(parts[0]);
  const refillPerSecond = Number(parts[1]);
  const maxClients = parts[2] === undefined ? DEFAULT_RATE_LIMIT.maxClients : Number(parts[2]);
  if (
    !Number.isFinite(capacity) || capacity < 1 ||
    !Number.isFinite(refillPerSecond) || refillPerSecond <= 0 ||
    !Number.isInteger(maxClients) || maxClients < 1
  ) {
    throw new Error(
      'AIRLOCK_RATE_LIMIT must be "capacity:refillPerSecond[:maxClients]" or "off"',
    );
  }
  return { capacity, refillPerSecond, maxClients };
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const host = process.env.AIRLOCK_HOST ?? "127.0.0.1";
  const port = Number(process.env.AIRLOCK_PORT ?? 8788);
  const dbPath = process.env.AIRLOCK_DB_PATH;
  const rateLimit = parseRateLimitEnv(process.env.AIRLOCK_RATE_LIMIT);
  const trustedProxies = (process.env.AIRLOCK_TRUSTED_PROXIES ?? "")
    .split(",")
    .map((proxy) => proxy.trim())
    .filter(Boolean);
  createLabServer({
    ...(dbPath ? { dbPath } : {}),
    ...(rateLimit !== undefined ? { rateLimit } : {}),
    ...(trustedProxies.length ? { trustedProxies } : {}),
  }).listen(port, host, () => {
    console.log(`Contactless Airlock Lab: http://${host}:${port}`);
    console.log("SIMULATOR ONLY — no real payment network or customer data is connected.");
    console.log(
      rateLimit === false
        ? "Per-client mutation rate limiting: DISABLED (AIRLOCK_RATE_LIMIT=off)."
        : "Per-client mutation rate limiting: ENABLED (in-process, single-instance only; " +
            "distributed/edge enforcement is external).",
    );
    if (dbPath) {
      console.log(`SIMULATOR-ONLY persistence enabled at ${dbPath}; synthetic exportable demo keys are stored there.`);
    }
  });
}
