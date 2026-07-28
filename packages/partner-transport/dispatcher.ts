import { randomUUID } from "node:crypto";
import type { OutboxEvent } from "../storage/durableStore.ts";
import {
  assertPartnerEnvelope,
  encodePartnerEnvelope,
  type PartnerWebhookEnvelopeV1,
} from "./contract.ts";
import {
  signPartnerWebhook,
  type PartnerSignatureHeaders,
  type PartnerSigningKey,
} from "./signing.ts";

export interface PartnerWebhookRequest {
  body: Uint8Array;
  headers: PartnerSignatureHeaders;
}

export interface PartnerWebhookResponse {
  status: number;
}

export interface PartnerWebhookAdapter {
  send(
    request: PartnerWebhookRequest,
    signal: AbortSignal,
  ): Promise<PartnerWebhookResponse>;
}

export class UnconfiguredPartnerWebhookAdapter implements PartnerWebhookAdapter {
  async send(
    _request: PartnerWebhookRequest,
    _signal: AbortSignal,
  ): Promise<PartnerWebhookResponse> {
    throw new Error("partner webhook adapter is not configured");
  }
}

export interface PartnerDeadLetterSink {
  record(input: {
    event: OutboxEvent;
    reason: string;
    status?: number;
    failedAt: string;
  }): Promise<void>;
}

export class UnconfiguredPartnerDeadLetterSink implements PartnerDeadLetterSink {
  async record(): Promise<void> {
    throw new Error("partner dead-letter sink is not configured");
  }
}

export interface OutboxLeaseSource {
  claimOutbox(
    workerId: string,
    limit: number,
    leaseMs: number,
    now?: Date,
  ): OutboxEvent[];
  acknowledgeOutbox(eventId: string, workerId: string, now?: Date): void;
  releaseOutbox(
    eventId: string,
    workerId: string,
    retryAt: Date,
    now?: Date,
  ): void;
}

export interface DispatchOutcome {
  eventId: string;
  outcome: "delivered" | "retry_scheduled" | "dead_lettered";
  status?: number;
  error?: string;
}

export class PartnerOutboxDispatcher {
  readonly source: OutboxLeaseSource;
  readonly adapter: PartnerWebhookAdapter;
  readonly key: PartnerSigningKey;
  readonly deadLetterSink: PartnerDeadLetterSink;
  readonly options: {
    workerId: string;
    leaseMs?: number;
    batchSize?: number;
    retryDelayMs?: number;
    clock?: () => Date;
    nonce?: () => string;
    requestTimeoutMs?: number;
    maximumAttempts?: number;
    circuitFailureThreshold?: number;
    circuitCooldownMs?: number;
  };
  #consecutiveFailures = 0;
  #circuitOpenUntil = 0;

  constructor(
    source: OutboxLeaseSource,
    adapter: PartnerWebhookAdapter,
    key: PartnerSigningKey,
    deadLetterSink: PartnerDeadLetterSink,
    options: {
      workerId: string;
      leaseMs?: number;
      batchSize?: number;
      retryDelayMs?: number;
      clock?: () => Date;
      nonce?: () => string;
      requestTimeoutMs?: number;
      maximumAttempts?: number;
      circuitFailureThreshold?: number;
      circuitCooldownMs?: number;
    },
  ) {
    this.source = source;
    this.adapter = adapter;
    this.key = key;
    this.deadLetterSink = deadLetterSink;
    this.options = options;
  }

  async #sendBounded(
    request: PartnerWebhookRequest,
  ): Promise<PartnerWebhookResponse> {
    const timeoutMs = this.options.requestTimeoutMs ?? 10_000;
    if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 60_000) {
      throw new Error("invalid partner request timeout");
    }
    const controller = new AbortController();
    let timer: NodeJS.Timeout | undefined;
    const timeout = new Promise<never>((_resolve, reject) => {
      timer = setTimeout(() => {
        controller.abort();
        reject(new Error("partner request timed out"));
      }, timeoutMs);
      timer.unref();
    });
    try {
      return await Promise.race([
        this.adapter.send(request, controller.signal),
        timeout,
      ]);
    } finally {
      if (timer) clearTimeout(timer);
    }
  }

  #recordFailure(at: Date): void {
    this.#consecutiveFailures += 1;
    const threshold = this.options.circuitFailureThreshold ?? 5;
    if (!Number.isSafeInteger(threshold) || threshold < 1 || threshold > 100) {
      throw new Error("invalid partner circuit threshold");
    }
    if (this.#consecutiveFailures >= threshold) {
      this.#circuitOpenUntil =
        at.getTime() + (this.options.circuitCooldownMs ?? 30_000);
    }
  }

  async #deadLetter(
    event: OutboxEvent,
    reason: string,
    failedAt: Date,
    status?: number,
  ): Promise<DispatchOutcome> {
    await this.deadLetterSink.record({
      event,
      reason,
      status,
      failedAt: failedAt.toISOString(),
    });
    this.source.acknowledgeOutbox(event.eventId, this.options.workerId, failedAt);
    return {
      eventId: event.eventId,
      outcome: "dead_lettered",
      status,
      error: reason,
    };
  }

  async dispatchOnce(): Promise<DispatchOutcome[]> {
    const clock = this.options.clock ?? (() => new Date());
    const started = clock();
    const leaseMs = this.options.leaseMs ?? 30_000;
    const requestTimeoutMs = this.options.requestTimeoutMs ?? 10_000;
    const maximumAttempts = this.options.maximumAttempts ?? 8;
    const cooldownMs = this.options.circuitCooldownMs ?? 30_000;
    const failureThreshold = this.options.circuitFailureThreshold ?? 5;
    const retryDelayMs = this.options.retryDelayMs ?? 5_000;
    if (
      !Number.isSafeInteger(leaseMs) ||
      !Number.isSafeInteger(requestTimeoutMs) ||
      requestTimeoutMs < 1 ||
      requestTimeoutMs >= leaseMs ||
      !Number.isSafeInteger(maximumAttempts) ||
      maximumAttempts < 1 ||
      maximumAttempts > 1_000 ||
      !Number.isSafeInteger(failureThreshold) ||
      failureThreshold < 1 ||
      failureThreshold > 100 ||
      !Number.isSafeInteger(retryDelayMs) ||
      retryDelayMs < 1 ||
      retryDelayMs > 3_600_000 ||
      !Number.isSafeInteger(cooldownMs) ||
      cooldownMs < 1 ||
      cooldownMs > 3_600_000
    ) {
      throw new Error("invalid partner dispatcher policy");
    }
    const events = this.source.claimOutbox(
      this.options.workerId,
      this.options.batchSize ?? 10,
      leaseMs,
      started,
    );
    const outcomes: DispatchOutcome[] = [];
    for (const event of events) {
      try {
        const beforeSend = clock();
        if (beforeSend.getTime() < this.#circuitOpenUntil) {
          this.source.releaseOutbox(
            event.eventId,
            this.options.workerId,
            new Date(this.#circuitOpenUntil),
            beforeSend,
          );
          outcomes.push({
            eventId: event.eventId,
            outcome: "retry_scheduled",
            error: "partner circuit breaker is open",
          });
          continue;
        }
        assertPartnerEnvelope(event.payload);
        const envelope = event.payload as PartnerWebhookEnvelopeV1;
        if (envelope.aggregateId !== event.aggregateId) {
          throw new Error("outbox metadata does not match partner envelope");
        }
        const body = encodePartnerEnvelope(envelope);
        const now = beforeSend;
        const headers = signPartnerWebhook({
          body,
          idempotencyKey: event.eventKey,
          nonce: (this.options.nonce ?? randomUUID)(),
          timestampEpochSeconds: Math.floor(now.getTime() / 1_000),
          key: this.key,
        });
        const response = await this.#sendBounded({ body, headers });
        const completed = clock();
        if (response.status >= 200 && response.status < 300) {
          this.#consecutiveFailures = 0;
          this.#circuitOpenUntil = 0;
          this.source.acknowledgeOutbox(event.eventId, this.options.workerId, completed);
          outcomes.push({ eventId: event.eventId, outcome: "delivered", status: response.status });
        } else if (response.status === 429 || response.status >= 500) {
          this.#recordFailure(completed);
          if (event.attempts >= maximumAttempts) {
            outcomes.push(await this.#deadLetter(
              event,
              "partner retry budget exhausted",
              completed,
              response.status,
            ));
            continue;
          }
          this.source.releaseOutbox(
            event.eventId,
            this.options.workerId,
            new Date(completed.getTime() + (this.options.retryDelayMs ?? 5_000)),
            completed,
          );
          outcomes.push({
            eventId: event.eventId,
            outcome: "retry_scheduled",
            status: response.status,
          });
        } else {
          outcomes.push(await this.#deadLetter(
            event,
            "partner returned a permanent response",
            completed,
            response.status,
          ));
        }
      } catch (error) {
        const completed = clock();
        this.#recordFailure(completed);
        const message = error instanceof Error ? error.message : "partner dispatch failed";
        if (event.attempts >= maximumAttempts) {
          try {
            outcomes.push(await this.#deadLetter(event, message, completed));
            continue;
          } catch {
            // A failed dead-letter write must leave the outbox event unacknowledged.
          }
        }
        try {
          this.source.releaseOutbox(
            event.eventId,
            this.options.workerId,
            new Date(completed.getTime() + (this.options.retryDelayMs ?? 5_000)),
            completed,
          );
        } catch {
          // The lease may already have expired. Never acknowledge after failure.
        }
        outcomes.push({
          eventId: event.eventId,
          outcome: "retry_scheduled",
          error: message,
        });
      }
    }
    return outcomes;
  }
}
