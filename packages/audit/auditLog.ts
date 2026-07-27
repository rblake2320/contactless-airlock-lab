import { createHash } from "node:crypto";

export interface AuditEvent {
  sequence: number;
  eventId: string;
  type: string;
  correlationId: string;
  causationId?: string;
  occurredAt: string;
  payload: Record<string, unknown>;
  previousHash: string;
  hash: string;
}

function digest(value: unknown): string {
  return createHash("sha256").update(JSON.stringify(value)).digest("hex");
}

export class AuditLog {
  readonly #events: AuditEvent[] = [];

  append(
    type: string,
    correlationId: string,
    payload: Record<string, unknown>,
    occurredAt = new Date(),
    causationId?: string,
  ): AuditEvent {
    const body = {
      sequence: this.#events.length + 1,
      eventId: crypto.randomUUID(),
      type,
      correlationId,
      causationId,
      occurredAt: occurredAt.toISOString(),
      payload,
      previousHash: this.#events.at(-1)?.hash ?? "GENESIS",
    };
    const event: AuditEvent = { ...body, hash: digest(body) };
    this.#events.push(event);
    return structuredClone(event);
  }

  all(): AuditEvent[] {
    return structuredClone(this.#events);
  }

  verify(): boolean {
    let previousHash = "GENESIS";
    for (const event of this.#events) {
      const { hash, ...body } = event;
      if (body.previousHash !== previousHash || digest(body) !== hash) return false;
      previousHash = hash;
    }
    return true;
  }
}

