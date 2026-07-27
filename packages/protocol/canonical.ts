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

export function canonicalizeBinding(binding: ChallengeBinding): Uint8Array {
  const ordered: Record<string, unknown> = {};
  for (const key of ORDER) {
    const value = binding[key];
    if (value !== undefined) ordered[key] = value;
  }
  return new TextEncoder().encode(JSON.stringify(ordered));
}

