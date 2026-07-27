import { randomBytes, timingSafeEqual } from "node:crypto";
import { canonicalizeBinding } from "../protocol/canonical.ts";
import type {
  ChallengeBinding,
  ChallengePurpose,
  ChallengeRecord,
  Currency,
  SignedApproval,
} from "../protocol/types.ts";
import {
  APPROVAL_ALGORITHM,
  verifyApproval,
} from "../crypto/deviceKeys.ts";
import type { ApprovalAlgorithm } from "../protocol/types.ts";

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

export interface ChallengeStoreSnapshot {
  schemaVersion: 1;
  records: ChallengeRecord[];
}

export class ChallengeStore {
  readonly #records = new Map<string, ChallengeRecord>();

  static restore(snapshot: ChallengeStoreSnapshot): ChallengeStore {
    if (
      !snapshot ||
      snapshot.schemaVersion !== 1 ||
      !Array.isArray(snapshot.records)
    ) {
      throw new Error("invalid challenge snapshot");
    }
    const store = new ChallengeStore();
    for (const candidate of snapshot.records) {
      if (
        !candidate ||
        !["created", "confirmed", "expired", "cancelled"].includes(candidate.status) ||
        !candidate.binding ||
        typeof candidate.binding.challengeId !== "string" ||
        !Number.isFinite(Date.parse(candidate.binding.issuedAt)) ||
        !Number.isFinite(Date.parse(candidate.binding.expiresAt)) ||
        Date.parse(candidate.binding.expiresAt) <= Date.parse(candidate.binding.issuedAt)
      ) {
        throw new Error("invalid challenge snapshot record");
      }
      // Canonicalization performs the protocol's exact-field and enum validation.
      canonicalizeBinding(candidate.binding);
      if (store.#records.has(candidate.binding.challengeId)) {
        throw new Error("duplicate challenge in snapshot");
      }
      if (
        (candidate.status === "confirmed" || candidate.status === "cancelled") &&
        (!candidate.consumedAt || !Number.isFinite(Date.parse(candidate.consumedAt)))
      ) {
        throw new Error("terminal challenge missing consumption time");
      }
      if (
        candidate.consumedAt &&
        Date.parse(candidate.consumedAt) < Date.parse(candidate.binding.issuedAt)
      ) {
        throw new Error("challenge consumed before issuance");
      }
      if (candidate.status === "created" && candidate.consumedAt !== undefined) {
        throw new Error("created challenge has consumption time");
      }
      store.#records.set(
        candidate.binding.challengeId,
        structuredClone(candidate),
      );
    }
    return store;
  }

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
    expectedAlgorithm: ApprovalAlgorithm = APPROVAL_ALGORITHM,
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
    if (!verifyApproval(approval, expectedPublicKey, expectedAlgorithm)) {
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
    if (now.getTime() < Date.parse(record.binding.issuedAt)) {
      throw new Error("challenge cannot be cancelled before issuance");
    }
    record.status = "cancelled";
    record.consumedAt = now.toISOString();
    return structuredClone(record);
  }

  get(challengeId: string): ChallengeRecord | undefined {
    const record = this.#records.get(challengeId);
    return record ? structuredClone(record) : undefined;
  }

  snapshot(): ChallengeStoreSnapshot {
    return {
      schemaVersion: 1,
      records: structuredClone([...this.#records.values()]),
    };
  }
}
