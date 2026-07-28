import {
  createHash,
  createHmac,
  timingSafeEqual,
} from "node:crypto";

export const SIGNATURE_VERSION = "v1" as const;
export const DEFAULT_REPLAY_WINDOW_SECONDS = 300;
export const MAX_WEBHOOK_BYTES = 1_048_576;

export interface PartnerSigningKey {
  keyId: string;
  secret: Uint8Array;
}

export interface PartnerSignatureHeaders {
  "content-type": "application/json";
  "idempotency-key": string;
  "x-airlock-key-id": string;
  "x-airlock-nonce": string;
  "x-airlock-signature": string;
  "x-airlock-timestamp": string;
  "x-airlock-version": typeof SIGNATURE_VERSION;
}

export interface ReplayStore {
  consumeOnce(
    key: string,
    expiresAtEpochSeconds: number,
    nowEpochSeconds: number,
  ): boolean;
}

export class MemoryReplayStore implements ReplayStore {
  readonly #entries = new Map<string, number>();

  consumeOnce(
    key: string,
    expiresAtEpochSeconds: number,
    nowEpochSeconds: number,
  ): boolean {
    for (const [candidate, expiry] of this.#entries) {
      if (expiry <= nowEpochSeconds) this.#entries.delete(candidate);
    }
    if (this.#entries.has(key)) return false;
    this.#entries.set(key, expiresAtEpochSeconds);
    return true;
  }
}

const TOKEN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;

function assertToken(value: string, label: string): void {
  if (typeof value !== "string" || !TOKEN.test(value)) {
    throw new Error(`invalid partner ${label}`);
  }
}

function assertKey(key: PartnerSigningKey): void {
  assertToken(key.keyId, "key id");
  if (!(key.secret instanceof Uint8Array) || key.secret.byteLength < 32) {
    throw new Error("partner HMAC key must contain at least 32 bytes");
  }
}

function bodyDigest(body: Uint8Array): string {
  return createHash("sha256").update(body).digest("hex");
}

function canonicalRequest(
  timestamp: string,
  nonce: string,
  idempotencyKey: string,
  body: Uint8Array,
): string {
  return [
    SIGNATURE_VERSION,
    timestamp,
    nonce,
    idempotencyKey,
    bodyDigest(body),
  ].join("\n");
}

export function signPartnerWebhook(input: {
  body: Uint8Array;
  idempotencyKey: string;
  nonce: string;
  timestampEpochSeconds: number;
  key: PartnerSigningKey;
}): PartnerSignatureHeaders {
  assertKey(input.key);
  assertToken(input.idempotencyKey, "idempotency key");
  assertToken(input.nonce, "nonce");
  if (
    !Number.isSafeInteger(input.timestampEpochSeconds) ||
    input.timestampEpochSeconds < 0 ||
    input.body.byteLength > MAX_WEBHOOK_BYTES
  ) {
    throw new Error("invalid partner signed request");
  }
  const timestamp = String(input.timestampEpochSeconds);
  const signature = createHmac("sha256", input.key.secret)
    .update(canonicalRequest(timestamp, input.nonce, input.idempotencyKey, input.body))
    .digest("hex");
  return {
    "content-type": "application/json",
    "idempotency-key": input.idempotencyKey,
    "x-airlock-key-id": input.key.keyId,
    "x-airlock-nonce": input.nonce,
    "x-airlock-signature": `${SIGNATURE_VERSION}=${signature}`,
    "x-airlock-timestamp": timestamp,
    "x-airlock-version": SIGNATURE_VERSION,
  };
}

export function verifyPartnerWebhook(input: {
  body: Uint8Array;
  headers: Readonly<Partial<PartnerSignatureHeaders>>;
  resolveKey: (keyId: string) => Uint8Array | undefined;
  replayStore: ReplayStore;
  nowEpochSeconds: number;
  replayWindowSeconds?: number;
}): { keyId: string; idempotencyKey: string } {
  if (input.body.byteLength > MAX_WEBHOOK_BYTES) {
    throw new Error("partner webhook payload too large");
  }
  const headers = Object.fromEntries(
    Object.entries(input.headers).map(([key, value]) => [key.toLowerCase(), value]),
  );
  const version = headers["x-airlock-version"];
  const keyId = headers["x-airlock-key-id"] ?? "";
  const nonce = headers["x-airlock-nonce"] ?? "";
  const timestamp = headers["x-airlock-timestamp"] ?? "";
  const idempotencyKey = headers["idempotency-key"] ?? "";
  const supplied = headers["x-airlock-signature"] ?? "";
  if (version !== SIGNATURE_VERSION) throw new Error("unsupported partner signature version");
  assertToken(keyId, "key id");
  assertToken(nonce, "nonce");
  assertToken(idempotencyKey, "idempotency key");
  if (!/^(0|[1-9][0-9]{0,15})$/.test(timestamp)) {
    throw new Error("invalid partner timestamp");
  }
  const sentAt = Number(timestamp);
  const window = input.replayWindowSeconds ?? DEFAULT_REPLAY_WINDOW_SECONDS;
  if (!Number.isSafeInteger(window) || window < 1 || window > 3_600) {
    throw new Error("invalid partner replay window");
  }
  if (
    !Number.isSafeInteger(input.nowEpochSeconds) ||
    Math.abs(input.nowEpochSeconds - sentAt) > window
  ) {
    throw new Error("partner webhook outside replay window");
  }
  const key = input.resolveKey(keyId);
  if (!key) throw new Error("unknown partner signing key");
  assertKey({ keyId, secret: key });
  const expected = `${SIGNATURE_VERSION}=${
    createHmac("sha256", key)
      .update(canonicalRequest(timestamp, nonce, idempotencyKey, input.body))
      .digest("hex")
  }`;
  const actualBytes = Buffer.from(supplied, "utf8");
  const expectedBytes = Buffer.from(expected, "utf8");
  if (
    actualBytes.length !== expectedBytes.length ||
    !timingSafeEqual(actualBytes, expectedBytes)
  ) {
    throw new Error("invalid partner signature");
  }
  if (!input.replayStore.consumeOnce(
    `${keyId}:${nonce}`,
    sentAt + window,
    input.nowEpochSeconds,
  )) {
    throw new Error("partner webhook replay detected");
  }
  return { keyId, idempotencyKey };
}
