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

const CANONICAL_TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;

function containsUnpairedSurrogate(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code >= 0xd800 && code <= 0xdbff) {
      if (index + 1 >= value.length) return true;
      const next = value.charCodeAt(index + 1);
      if (next < 0xdc00 || next > 0xdfff) return true;
      index += 1;
    } else if (code >= 0xdc00 && code <= 0xdfff) {
      return true;
    }
  }
  return false;
}

export function validateBinding(binding: ChallengeBinding): void {
  if (!binding || typeof binding !== "object" || Array.isArray(binding)) {
    throw new Error("challenge binding must be an object");
  }
  const allowed = new Set<string>(ORDER);
  const unknown = Object.keys(binding).filter((key) => !allowed.has(key));
  if (unknown.length) throw new Error(`unknown challenge field: ${unknown.sort().join(",")}`);
  for (const key of COMMON_REQUIRED) {
    if (
      typeof binding[key] !== "string" ||
      binding[key].length === 0 ||
      containsUnpairedSurrogate(binding[key])
    ) {
      throw new Error(`invalid challenge field: ${key}`);
    }
  }
  if (binding.protocolVersion !== "airlock.v1") throw new Error("unsupported protocol version");
  if (binding.audience !== "airlock-issuer") throw new Error("invalid challenge audience");
  if (
    !CANONICAL_TIMESTAMP.test(binding.issuedAt) ||
    binding.issuedAt.startsWith("0000-") ||
    !Number.isFinite(Date.parse(binding.issuedAt)) ||
    new Date(binding.issuedAt).toISOString() !== binding.issuedAt
  ) {
    throw new Error("invalid issuedAt");
  }
  if (
    !CANONICAL_TIMESTAMP.test(binding.expiresAt) ||
    binding.expiresAt.startsWith("0000-") ||
    !Number.isFinite(Date.parse(binding.expiresAt)) ||
    new Date(binding.expiresAt).toISOString() !== binding.expiresAt
  ) {
    throw new Error("invalid expiresAt");
  }
  if (Date.parse(binding.expiresAt) <= Date.parse(binding.issuedAt)) {
    throw new Error("challenge expiry must follow issuance");
  }
  if (binding.purpose === "confirm-transaction") {
    for (const key of ["transactionId", "merchantId", "currency"] as const) {
      if (
        typeof binding[key] !== "string" ||
        binding[key]!.length === 0 ||
        containsUnpairedSurrogate(binding[key]!)
      ) {
        throw new Error(`transaction challenge requires ${key}`);
      }
    }
    if (!Number.isSafeInteger(binding.amountMinor) || binding.amountMinor! <= 0) {
      throw new Error("transaction challenge requires a positive safe-integer amount");
    }
    if (!["USD", "EUR", "GBP", "CAD", "AUD"].includes(binding.currency!)) {
      throw new Error("unsupported transaction currency");
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
