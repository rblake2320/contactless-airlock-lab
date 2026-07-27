import assert from "node:assert/strict";
import test from "node:test";
import {
  generateDeviceKeyPair,
  signApproval,
  verifyApproval,
} from "../packages/crypto/deviceKeys.ts";
import { canonicalizeBinding } from "../packages/protocol/canonical.ts";
import type {
  ChallengeBinding,
  Currency,
} from "../packages/protocol/types.ts";

function seeded(seed: number): () => number {
  let state = seed >>> 0;
  return () => {
    state ^= state << 13;
    state ^= state >>> 17;
    state ^= state << 5;
    return (state >>> 0) / 0x1_0000_0000;
  };
}

function integer(random: () => number, max: number): number {
  return Math.floor(random() * max);
}

function shuffle<T>(values: readonly T[], random: () => number): T[] {
  const result = [...values];
  for (let index = result.length - 1; index > 0; index -= 1) {
    const other = integer(random, index + 1);
    [result[index], result[other]] = [result[other], result[index]];
  }
  return result;
}

const TEXT = ["alpha", "é", "東京", "☕", "\\", "\"", "/", "line\nbreak"];
const CURRENCIES: readonly Currency[] = ["USD", "EUR", "GBP", "CAD", "AUD"];

function text(random: () => number, prefix: string): string {
  return `${prefix}-${TEXT[integer(random, TEXT.length)]}-${integer(random, 1_000_000)}`;
}

function binding(random: () => number, index: number): ChallengeBinding {
  const issued = new Date(Date.UTC(2026, 0, 1, 0, 0, index % 60));
  const expires = new Date(issued.getTime() + 30_000 + integer(random, 90_000));
  const common = {
    protocolVersion: "airlock.v1" as const,
    challengeId: text(random, "challenge"),
    subjectId: text(random, "subject"),
    accountId: text(random, "account"),
    paymentTokenId: text(random, "token"),
    trustedDeviceId: text(random, "device"),
    issuedAt: issued.toISOString(),
    expiresAt: expires.toISOString(),
    audience: "airlock-issuer" as const,
  };
  if (index % 2 === 0) {
    return { ...common, purpose: "provision-payment-token" };
  }
  return {
    ...common,
    purpose: "confirm-transaction",
    transactionId: text(random, "transaction"),
    merchantId: text(random, "merchant"),
    amountMinor: 1 + integer(random, 10_000_000),
    currency: CURRENCIES[integer(random, CURRENCIES.length)],
  };
}

test("seeded valid bindings canonicalize identically across property order", () => {
  const random = seeded(0x41_49_52_4c);
  for (let index = 0; index < 300; index += 1) {
    const original = binding(random, index);
    const reordered = Object.fromEntries(
      shuffle(Object.entries(original), random),
    ) as unknown as ChallengeBinding;
    assert.deepEqual(
      canonicalizeBinding(reordered),
      canonicalizeBinding(original),
      `seed=0x4149524c case=${index}`,
    );
  }
});
test("seeded signed bindings remain exact and field mutation never verifies", () => {
  const random = seeded(0x50_32_35_36);
  const keys = generateDeviceKeyPair("property-key");
  for (let index = 1; index <= 40; index += 2) {
    const original = binding(random, index);
    const approval = signApproval(original, keys.keyId, keys.privateKeyPem);
    assert.equal(verifyApproval(approval, keys.publicKeyPem), true);
    const mutated = {
      ...approval,
      binding: {
        ...approval.binding,
        merchantId: `${approval.binding.merchantId}-substituted`,
      },
    };
    assert.equal(verifyApproval(mutated, keys.publicKeyPem), false);
  }
});

test("seeded malformed binding mutations fail closed reproducibly", () => {
  const random = seeded(0x46_55_5a_5a);
  const mutations = [
    (value: Record<string, unknown>) => { value.unknown = true; },
    (value: Record<string, unknown>) => { value.protocolVersion = "airlock.v0"; },
    (value: Record<string, unknown>) => { value.audience = "other"; },
    (value: Record<string, unknown>) => { value.issuedAt = "2026-01-01"; },
    (value: Record<string, unknown>) => { value.expiresAt = value.issuedAt; },
    (value: Record<string, unknown>) => { value.subjectId = 42; },
    (value: Record<string, unknown>) => { value.challengeId = ""; },
    (value: Record<string, unknown>) => { value.purpose = "unknown-purpose"; },
  ] as const;
  for (let index = 0; index < 400; index += 1) {
    const candidate = structuredClone(binding(random, index)) as unknown as Record<string, unknown>;
    const mutation = mutations[integer(random, mutations.length)];
    mutation(candidate);
    assert.throws(
      () => canonicalizeBinding(candidate as unknown as ChallengeBinding),
      Error,
      `seed=0x46555a5a case=${index}`,
    );
  }
});
