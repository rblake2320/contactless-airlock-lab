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

export interface AuditLogSnapshot {
  schemaVersion: 1;
  events: AuditEvent[];
}

function digest(value: unknown): string {
  return createHash("sha256").update(JSON.stringify(value)).digest("hex");
}

export class AuditLog {
  readonly #events: AuditEvent[] = [];

  static restore(snapshot: AuditLogSnapshot): AuditLog {
    if (
      !snapshot ||
      snapshot.schemaVersion !== 1 ||
      !Array.isArray(snapshot.events)
    ) {
      throw new Error("invalid audit snapshot");
    }
    const log = new AuditLog();
    for (const [index, candidate] of snapshot.events.entries()) {
      if (
        !candidate ||
        candidate.sequence !== index + 1 ||
        typeof candidate.eventId !== "string" ||
        typeof candidate.type !== "string" ||
        typeof candidate.correlationId !== "string" ||
        (candidate.causationId !== undefined && typeof candidate.causationId !== "string") ||
        typeof candidate.occurredAt !== "string" ||
        !Number.isFinite(Date.parse(candidate.occurredAt)) ||
        !candidate.payload ||
        typeof candidate.payload !== "object" ||
        Array.isArray(candidate.payload) ||
        typeof candidate.previousHash !== "string" ||
        typeof candidate.hash !== "string"
      ) {
        throw new Error("invalid audit snapshot event");
      }
      log.#events.push(structuredClone(candidate));
    }
    if (!log.verify()) throw new Error("audit snapshot chain verification failed");
    return log;
  }

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

  snapshot(): AuditLogSnapshot {
    return { schemaVersion: 1, events: this.all() };
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
