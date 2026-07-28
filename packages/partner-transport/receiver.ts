import { createHash } from "node:crypto";
import {
  assertPartnerEnvelope,
  type PartnerWebhookEnvelopeV1,
} from "./contract.ts";
import {
  verifyPartnerWebhook,
  type PartnerSignatureHeaders,
  type ReplayStore,
} from "./signing.ts";

export interface PartnerReceipt {
  status: number;
  code: "ACCEPTED" | "DUPLICATE";
  eventId: string;
}

export interface PartnerIdempotencyStore {
  runOnce<T>(
    key: string,
    requestHash: string,
    work: () => T,
  ): { replayed: boolean; value: T };
}

export class MemoryPartnerIdempotencyStore implements PartnerIdempotencyStore {
  readonly #entries = new Map<string, { requestHash: string; value: unknown }>();

  runOnce<T>(
    key: string,
    requestHash: string,
    work: () => T,
  ): { replayed: boolean; value: T } {
    const prior = this.#entries.get(key);
    if (prior) {
      if (prior.requestHash !== requestHash) {
        throw new Error("partner idempotency key reused with different request");
      }
      return { replayed: true, value: structuredClone(prior.value) as T };
    }
    const value = work();
    this.#entries.set(key, {
      requestHash,
      value: structuredClone(value),
    });
    return { replayed: false, value };
  }
}

export function receivePartnerWebhook(input: {
  body: Uint8Array;
  headers: Readonly<Partial<PartnerSignatureHeaders>>;
  resolveKey: (keyId: string) => Uint8Array | undefined;
  replayStore: ReplayStore;
  idempotencyStore: PartnerIdempotencyStore;
  nowEpochSeconds: number;
  apply: (envelope: PartnerWebhookEnvelopeV1) => void;
}): PartnerReceipt {
  const verified = verifyPartnerWebhook(input);
  let parsed: unknown;
  try {
    parsed = JSON.parse(Buffer.from(input.body).toString("utf8"));
  } catch {
    throw new Error("invalid partner JSON body");
  }
  assertPartnerEnvelope(parsed);
  const requestHash = createHash("sha256").update(input.body).digest("hex");
  const result = input.idempotencyStore.runOnce(
    `${verified.keyId}:${verified.idempotencyKey}`,
    requestHash,
    () => {
      input.apply(parsed);
      return {
        status: 202,
        code: "ACCEPTED" as const,
        eventId: parsed.eventId,
      };
    },
  );
  return result.replayed
    ? { ...result.value, code: "DUPLICATE" }
    : result.value;
}
