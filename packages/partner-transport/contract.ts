export const PARTNER_WEBHOOK_VERSION = "airlock.partner-webhook.v1" as const;

export const PARTNER_EVENT_TYPES = [
  "authorization.provisional",
  "authorization.confirmed",
  "authorization.reversal_requested",
  "authorization.clearing_exception",
] as const;

export type PartnerEventType = typeof PARTNER_EVENT_TYPES[number];

export interface PartnerWebhookEnvelopeV1 {
  schemaVersion: typeof PARTNER_WEBHOOK_VERSION;
  eventId: string;
  eventType: PartnerEventType;
  occurredAt: string;
  issuerId: string;
  processorId: string;
  correlationId: string;
  aggregateId: string;
  payload: Record<string, unknown>;
}

const ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const CANONICAL_TIME = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;

function assertExactObject(
  value: unknown,
  required: readonly string[],
  label: string,
): asserts value is Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`invalid ${label}`);
  }
  const keys = Object.keys(value);
  if (
    keys.length !== required.length ||
    required.some((key) => !Object.hasOwn(value, key))
  ) {
    throw new Error(`invalid ${label} fields`);
  }
}

function assertIdentifier(value: unknown, label: string): void {
  if (typeof value !== "string" || !ID.test(value)) {
    throw new Error(`invalid ${label}`);
  }
}

function assertCanonicalTime(value: unknown, label: string): void {
  if (
    typeof value !== "string" ||
    !CANONICAL_TIME.test(value) ||
    !Number.isFinite(Date.parse(value)) ||
    new Date(value).toISOString() !== value
  ) {
    throw new Error(`invalid ${label}`);
  }
}

function assertPayload(
  eventType: PartnerEventType,
  payload: unknown,
): asserts payload is Record<string, unknown> {
  if (eventType === "authorization.provisional") {
    assertExactObject(payload, [
      "authorizationId", "tokenReference", "merchantId", "amountMinor",
      "currency", "confirmationExpiresAt",
    ], "provisional payload");
    for (const key of [
      "authorizationId", "tokenReference", "merchantId",
    ] as const) {
      assertIdentifier(payload[key], `provisional ${key}`);
    }
    if (!Number.isSafeInteger(payload.amountMinor) || (payload.amountMinor as number) < 1) {
      throw new Error("invalid provisional amountMinor");
    }
    if (
      typeof payload.currency !== "string" ||
      !["USD", "EUR", "GBP", "CAD", "AUD"].includes(payload.currency)
    ) {
      throw new Error("invalid provisional currency");
    }
    assertCanonicalTime(
      payload.confirmationExpiresAt,
      "provisional confirmationExpiresAt",
    );
    return;
  }
  if (eventType === "authorization.confirmed") {
    assertExactObject(
      payload,
      ["authorizationId", "confirmedAt"],
      "confirmation payload",
    );
    assertIdentifier(payload.authorizationId, "confirmation authorizationId");
    assertCanonicalTime(payload.confirmedAt, "confirmation confirmedAt");
    return;
  }
  if (eventType === "authorization.reversal_requested") {
    assertExactObject(
      payload,
      ["authorizationId", "reason", "requestedAt"],
      "reversal payload",
    );
    assertIdentifier(payload.authorizationId, "reversal authorizationId");
    if (
      typeof payload.reason !== "string" ||
      !["confirmation_timeout", "holder_declined", "risk_declined"].includes(
        payload.reason,
      )
    ) {
      throw new Error("invalid reversal reason");
    }
    assertCanonicalTime(payload.requestedAt, "reversal requestedAt");
    return;
  }
  assertExactObject(
    payload,
    ["authorizationId", "clearingReference", "detectedAt"],
    "clearing exception payload",
  );
  assertIdentifier(payload.authorizationId, "exception authorizationId");
  assertIdentifier(payload.clearingReference, "exception clearingReference");
  assertCanonicalTime(payload.detectedAt, "exception detectedAt");
}

export function assertPartnerEnvelope(
  value: unknown,
): asserts value is PartnerWebhookEnvelopeV1 {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("partner envelope must be an object");
  }
  const envelope = value as Record<string, unknown>;
  const allowed = new Set([
    "schemaVersion", "eventId", "eventType", "occurredAt", "issuerId",
    "processorId", "correlationId", "aggregateId", "payload",
  ]);
  if (Object.keys(envelope).some((key) => !allowed.has(key))) {
    throw new Error("partner envelope contains unknown fields");
  }
  if (envelope.schemaVersion !== PARTNER_WEBHOOK_VERSION) {
    throw new Error("unsupported partner envelope version");
  }
  if (typeof envelope.eventId !== "string" || !UUID.test(envelope.eventId)) {
    throw new Error("invalid partner event id");
  }
  if (
    typeof envelope.eventType !== "string" ||
    !PARTNER_EVENT_TYPES.includes(envelope.eventType as PartnerEventType)
  ) {
    throw new Error("invalid partner event type");
  }
  assertCanonicalTime(envelope.occurredAt, "partner event time");
  for (const key of [
    "issuerId", "processorId", "correlationId", "aggregateId",
  ] as const) {
    if (typeof envelope[key] !== "string" || !ID.test(envelope[key])) {
      throw new Error(`invalid partner ${key}`);
    }
  }
  assertPayload(envelope.eventType as PartnerEventType, envelope.payload);
  if (
    (envelope.payload as Record<string, unknown>).authorizationId !==
      envelope.aggregateId
  ) {
    throw new Error("partner aggregate does not match authorization id");
  }
}

export function encodePartnerEnvelope(
  envelope: PartnerWebhookEnvelopeV1,
): Uint8Array {
  assertPartnerEnvelope(envelope);
  return Buffer.from(JSON.stringify(envelope), "utf8");
}
