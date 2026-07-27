import type { ChallengeBinding } from "./types.ts";

const ORDER: ReadonlyArray<keyof ChallengeBinding> = [
  "protocolVersion",
  "purpose",
  "challengeId",
  "subjectId",
  "accountId",
  "paymentTokenId",
  "trustedDeviceId",
  "transactionId",
  "merchantId",
  "amountMinor",
  "currency",
  "issuedAt",
  "expiresAt",
  "audience",
];

const COMMON_REQUIRED = [
  "protocolVersion",
  "purpose",
  "challengeId",
  "subjectId",
  "accountId",
  "paymentTokenId",
  "trustedDeviceId",
  "issuedAt",
  "expiresAt",
  "audience",
] as const;

export function validateBinding(binding: ChallengeBinding): void {
  if (!binding || typeof binding !== "object" || Array.isArray(binding)) {
    throw new Error("challenge binding must be an object");
  }
  const allowed = new Set<string>(ORDER);
  const unknown = Object.keys(binding).filter((key) => !allowed.has(key));
  if (unknown.length) throw new Error(`unknown challenge field: ${unknown.sort().join(",")}`);
  for (const key of COMMON_REQUIRED) {
    if (typeof binding[key] !== "string" || binding[key].length === 0) {
      throw new Error(`invalid challenge field: ${key}`);
    }
  }
  if (binding.protocolVersion !== "airlock.v1") throw new Error("unsupported protocol version");
  if (binding.audience !== "airlock-issuer") throw new Error("invalid challenge audience");
  if (!Number.isFinite(Date.parse(binding.issuedAt))) throw new Error("invalid issuedAt");
  if (!Number.isFinite(Date.parse(binding.expiresAt))) throw new Error("invalid expiresAt");
  if (Date.parse(binding.expiresAt) <= Date.parse(binding.issuedAt)) {
    throw new Error("challenge expiry must follow issuance");
  }
  if (binding.purpose === "confirm-transaction") {
    for (const key of ["transactionId", "merchantId", "currency"] as const) {
      if (typeof binding[key] !== "string" || binding[key]!.length === 0) {
        throw new Error(`transaction challenge requires ${key}`);
      }
    }
    if (!Number.isSafeInteger(binding.amountMinor) || binding.amountMinor! <= 0) {
      throw new Error("transaction challenge requires a positive safe-integer amount");
    }
  } else if (binding.purpose === "provision-payment-token") {
    const forbidden = ["transactionId", "merchantId", "amountMinor", "currency"] as const;
    if (forbidden.some((key) => binding[key] !== undefined)) {
      throw new Error("provisioning challenge contains transaction-only fields");
    }
  } else {
    throw new Error("unsupported challenge purpose");
  }
}

export function canonicalizeBinding(binding: ChallengeBinding): Uint8Array {
  validateBinding(binding);
  const ordered: Record<string, unknown> = {};
  for (const key of ORDER) {
    const value = binding[key];
    if (value !== undefined) ordered[key] = value;
  }
  return new TextEncoder().encode(JSON.stringify(ordered));
}
