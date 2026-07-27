import { randomBytes, timingSafeEqual } from "node:crypto";
import { canonicalizeBinding } from "../protocol/canonical.ts";
import type {
  ChallengeBinding,
  ChallengePurpose,
  ChallengeRecord,
  Currency,
  SignedApproval,
} from "../protocol/types.ts";
import { verifyApproval } from "../crypto/deviceKeys.ts";

export interface CreateChallengeInput {
  purpose: ChallengePurpose;
  subjectId: string;
  accountId: string;
  paymentTokenId: string;
  trustedDeviceId: string;
  transactionId?: string;
  merchantId?: string;
  amountMinor?: number;
  currency?: Currency;
  ttlMs: number;
}

export class ChallengeStore {
  readonly #records = new Map<string, ChallengeRecord>();

  create(input: CreateChallengeInput, now = new Date()): ChallengeBinding {
    if (!Number.isSafeInteger(input.ttlMs) || input.ttlMs < 1_000 || input.ttlMs > 300_000) {
      throw new Error("challenge ttl must be a safe integer between 1000 and 300000 ms");
    }
    const challengeId = randomBytes(32).toString("base64url");
    const binding: ChallengeBinding = {
      protocolVersion: "airlock.v1",
      purpose: input.purpose,
      challengeId,
      subjectId: input.subjectId,
      accountId: input.accountId,
      paymentTokenId: input.paymentTokenId,
      trustedDeviceId: input.trustedDeviceId,
      transactionId: input.transactionId,
      merchantId: input.merchantId,
      amountMinor: input.amountMinor,
      currency: input.currency,
      issuedAt: now.toISOString(),
      expiresAt: new Date(now.getTime() + input.ttlMs).toISOString(),
      audience: "airlock-issuer",
    };
    this.#records.set(challengeId, { binding, status: "created" });
    return binding;
  }

  consume(
    approval: SignedApproval,
    expectedPublicKey: string,
    now = new Date(),
  ): ChallengeRecord {
    const record = this.#records.get(approval.binding.challengeId);
    if (!record) throw new Error("unknown challenge");
    if (record.status !== "created") throw new Error("challenge already terminal");
    const expectedBinding = canonicalizeBinding(record.binding);
    const submittedBinding = canonicalizeBinding(approval.binding);
    if (
      expectedBinding.length !== submittedBinding.length ||
      !timingSafeEqual(expectedBinding, submittedBinding)
    ) {
      throw new Error("challenge binding mismatch");
    }
    if (now.getTime() >= Date.parse(record.binding.expiresAt)) {
      record.status = "expired";
      throw new Error("challenge expired");
    }
    if (!verifyApproval(approval, expectedPublicKey)) {
      throw new Error("invalid device signature");
    }
    record.status = "confirmed";
    record.consumedAt = now.toISOString();
    return structuredClone(record);
  }

  cancel(challengeId: string, now = new Date()): ChallengeRecord {
    const record = this.#records.get(challengeId);
    if (!record) throw new Error("unknown challenge");
    if (record.status !== "created") throw new Error("challenge already terminal");
    record.status = "cancelled";
    record.consumedAt = now.toISOString();
    return structuredClone(record);
  }

  get(challengeId: string): ChallengeRecord | undefined {
    const record = this.#records.get(challengeId);
    return record ? structuredClone(record) : undefined;
  }
}
