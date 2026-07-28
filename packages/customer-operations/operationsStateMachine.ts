import { createHash, randomUUID } from "node:crypto";

export const OPERATIONS_CASE_TYPES = [
  "device_loss",
  "account_recovery",
  "false_decline_review",
  "fraudulent_approval_dispute",
  "compromise_response",
] as const;
export type OperationsCaseType = typeof OPERATIONS_CASE_TYPES[number];

export type OperationsCaseState =
  | "opened"
  | "contained"
  | "proof_verified"
  | "trust_reset_pending"
  | "under_review"
  | "payment_frozen"
  | "eradicated"
  | "upheld"
  | "overturned"
  | "remediated"
  | "resolved"
  | "expired"
  | "cancelled";

export type OperationsRole =
  | "customer"
  | "fraud_analyst"
  | "security_operator"
  | "supervisor"
  | "recovery_officer"
  | "system";

export interface OperationsActor {
  tenantId: string;
  actorId: string;
  role: OperationsRole;
  deviceId?: string;
}

export interface OperationsCase {
  tenantId: string;
  caseId: string;
  caseType: OperationsCaseType;
  state: OperationsCaseState;
  subjectRef: string;
  subjectDeviceId?: string;
  reason: string;
  correlationId: string;
  openedAt: string;
  expiresAt: string;
  updatedAt: string;
}

export interface SensitiveOverride {
  tenantId: string;
  overrideId: string;
  caseId: string;
  action: "destructive_trust_reset";
  state: "pending" | "executed" | "expired" | "cancelled";
  reason: string;
  requestedBy: string;
  requestedAt: string;
  expiresAt: string;
  approvals: Array<{
    actorId: string;
    role: OperationsRole;
    approvedAt: string;
  }>;
  executedAt?: string;
}

export interface OperationsAuditEvent {
  sequence: number;
  eventId: string;
  tenantId: string;
  caseId: string;
  type: string;
  actorId: string;
  actorRole: OperationsRole;
  reason: string;
  correlationId: string;
  occurredAt: string;
  previousHash: string;
  hash: string;
}

export interface NotificationOutboxIntent {
  intentId: string;
  eventKey: string;
  topic: "operations.notification.requested";
  tenantId: string;
  caseId: string;
  template:
    | "case_opened"
    | "case_state_changed"
    | "approval_requested"
    | "trust_reset_completed";
  syntheticRecipientRef: string;
  createdAt: string;
}

export interface CustomerOperationsSnapshot {
  schemaVersion: 1;
  cases: OperationsCase[];
  overrides: SensitiveOverride[];
  auditEvents: OperationsAuditEvent[];
  notificationIntents: NotificationOutboxIntent[];
  idempotency: Array<{
    scope: string;
    key: string;
    requestHash: string;
    response?: unknown;
    error?: string;
  }>;
}

const ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const SYNTHETIC_REF = /^synthetic-[A-Za-z0-9][A-Za-z0-9._:-]{0,118}$/;
const APPROVER_ROLES = new Set<OperationsRole>([
  "security_operator",
  "supervisor",
  "recovery_officer",
]);
const TRANSITION_ROLES: Partial<Record<
  OperationsCaseState,
  ReadonlySet<OperationsRole>
>> = {
  contained: new Set(["fraud_analyst", "security_operator", "supervisor"]),
  proof_verified: new Set(["recovery_officer", "security_operator"]),
  under_review: new Set(["fraud_analyst", "supervisor"]),
  payment_frozen: new Set(["fraud_analyst", "security_operator", "supervisor"]),
  eradicated: new Set(["security_operator", "supervisor"]),
  upheld: new Set(["fraud_analyst", "supervisor"]),
  overturned: new Set(["fraud_analyst", "supervisor"]),
  remediated: new Set(["fraud_analyst", "security_operator", "supervisor"]),
  resolved: new Set(["security_operator", "supervisor"]),
  cancelled: new Set(["customer", "fraud_analyst", "security_operator", "supervisor"]),
};
const MAX_TTL_MS = 30 * 24 * 60 * 60 * 1_000;
const MAX_OVERRIDE_TTL_MS = 24 * 60 * 60 * 1_000;

const TRANSITIONS: Record<OperationsCaseType, Partial<Record<
  OperationsCaseState,
  readonly OperationsCaseState[]
>>> = {
  device_loss: {
    opened: ["contained", "cancelled"],
    contained: ["trust_reset_pending", "resolved"],
    trust_reset_pending: ["resolved"],
  },
  account_recovery: {
    opened: ["proof_verified", "cancelled"],
    proof_verified: ["trust_reset_pending"],
    trust_reset_pending: ["resolved"],
  },
  false_decline_review: {
    opened: ["under_review", "cancelled"],
    under_review: ["upheld", "overturned"],
  },
  fraudulent_approval_dispute: {
    opened: ["payment_frozen", "cancelled"],
    payment_frozen: ["under_review"],
    under_review: ["upheld", "remediated"],
  },
  compromise_response: {
    opened: ["contained"],
    contained: ["eradicated", "trust_reset_pending"],
    eradicated: ["resolved"],
    trust_reset_pending: ["resolved"],
  },
};

function stable(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(stable).join(",")}]`;
  const object = value as Record<string, unknown>;
  return `{${Object.keys(object).sort().map(
    (key) => `${JSON.stringify(key)}:${stable(object[key])}`,
  ).join(",")}}`;
}

function hash(value: unknown): string {
  return createHash("sha256").update(stable(value)).digest("hex");
}

function assertId(value: string, label: string): void {
  if (!ID.test(value)) throw new Error(`invalid operations ${label}`);
}

function assertReason(value: string): void {
  if (
    typeof value !== "string" ||
    value.trim() !== value ||
    value.length < 3 ||
    value.length > 512
  ) throw new Error("invalid operations reason");
}

function assertNow(now: Date): void {
  if (!(now instanceof Date) || !Number.isFinite(now.getTime())) {
    throw new Error("invalid operations time");
  }
}

export class CustomerOperationsStateMachine {
  readonly #cases = new Map<string, OperationsCase>();
  readonly #overrides = new Map<string, SensitiveOverride>();
  readonly #audit: OperationsAuditEvent[] = [];
  readonly #intents: NotificationOutboxIntent[] = [];
  readonly #idempotency = new Map<string, {
    requestHash: string;
    response?: unknown;
    error?: string;
  }>();

  static restore(snapshot: CustomerOperationsSnapshot): CustomerOperationsStateMachine {
    if (!snapshot || snapshot.schemaVersion !== 1) {
      throw new Error("invalid customer operations snapshot");
    }
    const machine = new CustomerOperationsStateMachine();
    for (const value of snapshot.cases) {
      const key = `${value.tenantId}:${value.caseId}`;
      if (machine.#cases.has(key)) throw new Error("duplicate operations case");
      machine.#cases.set(key, structuredClone(value));
    }
    for (const value of snapshot.overrides) {
      const key = `${value.tenantId}:${value.overrideId}`;
      if (machine.#overrides.has(key)) throw new Error("duplicate operations override");
      machine.#overrides.set(key, structuredClone(value));
    }
    machine.#audit.push(...structuredClone(snapshot.auditEvents));
    machine.#intents.push(...structuredClone(snapshot.notificationIntents));
    for (const value of snapshot.idempotency) {
      const key = `${value.scope}\u0000${value.key}`;
      if (
        machine.#idempotency.has(key) ||
        !ID.test(value.scope) ||
        !ID.test(value.key) ||
        !/^[a-f0-9]{64}$/.test(value.requestHash) ||
        (value.error !== undefined) === Object.hasOwn(value, "response") ||
        (value.error !== undefined && (
          typeof value.error !== "string" ||
          value.error.length === 0 ||
          value.error.length > 512
        ))
      ) throw new Error("invalid operations idempotency snapshot");
      machine.#idempotency.set(key, {
        requestHash: value.requestHash,
        ...(value.error !== undefined ? { error: value.error } : {}),
        ...(Object.hasOwn(value, "response")
          ? { response: structuredClone(value.response) }
          : {}),
      });
    }
    if (!machine.verifyAudit() || !machine.#validateRestoredState()) {
      throw new Error("customer operations snapshot verification failed");
    }
    return machine;
  }

  openCase(input: {
    tenantId: string;
    caseType: OperationsCaseType;
    subjectRef: string;
    subjectDeviceId?: string;
    reason: string;
    correlationId: string;
    actor: OperationsActor;
    idempotencyKey: string;
    ttlMs: number;
    now?: Date;
    caseId?: string;
  }): OperationsCase {
    const now = input.now ?? new Date();
    return this.#once(input.tenantId, input.idempotencyKey, {
      operation: "open",
      ...input,
      actor: input.actor,
      now: now.toISOString(),
    }, () => {
      this.#assertActor(input.tenantId, input.actor);
      assertNow(now);
      if (!OPERATIONS_CASE_TYPES.includes(input.caseType)) {
        throw new Error("invalid operations case type");
      }
      if (!SYNTHETIC_REF.test(input.subjectRef)) {
        throw new Error("operations lab accepts synthetic subject references only");
      }
      if (input.subjectDeviceId) assertId(input.subjectDeviceId, "device id");
      assertReason(input.reason);
      assertId(input.correlationId, "correlation id");
      if (
        !Number.isSafeInteger(input.ttlMs) ||
        input.ttlMs < 60_000 ||
        input.ttlMs > MAX_TTL_MS
      ) throw new Error("invalid operations case TTL");
      const caseId = input.caseId ?? randomUUID();
      assertId(caseId, "case id");
      const key = `${input.tenantId}:${caseId}`;
      if (this.#cases.has(key)) throw new Error("operations case already exists");
      const value: OperationsCase = {
        tenantId: input.tenantId,
        caseId,
        caseType: input.caseType,
        state: "opened",
        subjectRef: input.subjectRef,
        subjectDeviceId: input.subjectDeviceId,
        reason: input.reason,
        correlationId: input.correlationId,
        openedAt: now.toISOString(),
        expiresAt: new Date(now.getTime() + input.ttlMs).toISOString(),
        updatedAt: now.toISOString(),
      };
      this.#cases.set(key, value);
      this.#appendAudit(value, "case.opened", input.actor, input.reason, now);
      this.#notify(value, "case_opened", now);
      return structuredClone(value);
    });
  }

  transition(input: {
    tenantId: string;
    caseId: string;
    nextState: OperationsCaseState;
    reason: string;
    actor: OperationsActor;
    idempotencyKey: string;
    now?: Date;
  }): OperationsCase {
    const now = input.now ?? new Date();
    return this.#once(input.tenantId, input.idempotencyKey, {
      operation: "transition",
      ...input,
      actor: input.actor,
      now: now.toISOString(),
    }, () => {
      this.#assertActor(input.tenantId, input.actor);
      assertReason(input.reason);
      const value = this.#activeCase(input.tenantId, input.caseId, now);
      if (
        input.nextState === "trust_reset_pending" ||
        input.nextState === "resolved" &&
          value.state === "trust_reset_pending"
      ) {
        throw new Error("destructive trust reset requires the dual-control API");
      }
      const allowed = TRANSITIONS[value.caseType][value.state] ?? [];
      if (!allowed.includes(input.nextState)) {
        throw new Error("invalid or non-monotonic operations transition");
      }
      if (!TRANSITION_ROLES[input.nextState]?.has(input.actor.role)) {
        throw new Error("operations actor is not authorized for transition");
      }
      value.state = input.nextState;
      value.updatedAt = now.toISOString();
      this.#appendAudit(
        value,
        `case.${input.nextState}`,
        input.actor,
        input.reason,
        now,
      );
      this.#notify(value, "case_state_changed", now);
      return structuredClone(value);
    });
  }

  verifyRecoveryProof(input: {
    tenantId: string;
    caseId: string;
    proofMethod:
      | "existing_passkey"
      | "in_person_strong_identity"
      | "bank_verified_strong_identity";
    reason: string;
    actor: OperationsActor;
    idempotencyKey: string;
    now?: Date;
  }): OperationsCase {
    if (![
      "existing_passkey",
      "in_person_strong_identity",
      "bank_verified_strong_identity",
    ].includes(input.proofMethod)) {
      throw new Error("recovery proof cannot downgrade to SMS or typed codes");
    }
    const value = this.getCase(input.tenantId, input.caseId);
    if (value.caseType !== "account_recovery") {
      throw new Error("recovery proof applies only to account recovery");
    }
    return this.transition({
      ...input,
      nextState: "proof_verified",
      reason: `${input.reason} [proof:${input.proofMethod}]`,
    });
  }

  requestTrustReset(input: {
    tenantId: string;
    caseId: string;
    reason: string;
    actor: OperationsActor;
    idempotencyKey: string;
    ttlMs: number;
    now?: Date;
    overrideId?: string;
  }): SensitiveOverride {
    const now = input.now ?? new Date();
    return this.#once(input.tenantId, input.idempotencyKey, {
      operation: "requestTrustReset",
      ...input,
      actor: input.actor,
      now: now.toISOString(),
    }, () => {
      this.#assertActor(input.tenantId, input.actor);
      assertReason(input.reason);
      if (!APPROVER_ROLES.has(input.actor.role)) {
        throw new Error("trust reset requester is not authorized");
      }
      if (
        !Number.isSafeInteger(input.ttlMs) ||
        input.ttlMs < 60_000 ||
        input.ttlMs > MAX_OVERRIDE_TTL_MS
      ) throw new Error("invalid trust reset approval TTL");
      const value = this.#activeCase(input.tenantId, input.caseId, now);
      const eligible =
        (value.caseType === "account_recovery" && value.state === "proof_verified") ||
        (["device_loss", "compromise_response"].includes(value.caseType) &&
          value.state === "contained");
      if (!eligible) throw new Error("case is not eligible for destructive trust reset");
      const overrideId = input.overrideId ?? randomUUID();
      assertId(overrideId, "override id");
      const key = `${input.tenantId}:${overrideId}`;
      if (this.#overrides.has(key)) throw new Error("trust reset override already exists");
      value.state = "trust_reset_pending";
      value.updatedAt = now.toISOString();
      const override: SensitiveOverride = {
        tenantId: input.tenantId,
        overrideId,
        caseId: value.caseId,
        action: "destructive_trust_reset",
        state: "pending",
        reason: input.reason,
        requestedBy: input.actor.actorId,
        requestedAt: now.toISOString(),
        expiresAt: new Date(now.getTime() + input.ttlMs).toISOString(),
        approvals: [],
      };
      this.#overrides.set(key, override);
      this.#appendAudit(value, "trust_reset.requested", input.actor, input.reason, now);
      this.#notify(value, "approval_requested", now);
      return structuredClone(override);
    });
  }

  approveTrustReset(input: {
    tenantId: string;
    overrideId: string;
    reason: string;
    actor: OperationsActor;
    idempotencyKey: string;
    now?: Date;
  }): SensitiveOverride {
    const now = input.now ?? new Date();
    return this.#once(input.tenantId, input.idempotencyKey, {
      operation: "approveTrustReset",
      ...input,
      actor: input.actor,
      now: now.toISOString(),
    }, () => {
      this.#assertActor(input.tenantId, input.actor);
      assertReason(input.reason);
      if (!APPROVER_ROLES.has(input.actor.role)) {
        throw new Error("trust reset approver is not authorized");
      }
      const override = this.#mustOverride(input.tenantId, input.overrideId);
      const value = this.#activeCase(input.tenantId, override.caseId, now);
      if (override.state !== "pending") {
        throw new Error("trust reset override is terminal");
      }
      if (now.getTime() >= Date.parse(override.expiresAt)) {
        override.state = "expired";
        this.#appendAudit(
          value,
          "trust_reset.expired",
          { ...input.actor, actorId: "system", role: "system" },
          "approval window expired",
          now,
        );
        throw new Error("trust reset override expired");
      }
      if (override.approvals.some((approval) => approval.actorId === input.actor.actorId)) {
        throw new Error("duplicate trust reset approver");
      }
      if (
        value.subjectDeviceId &&
        input.actor.deviceId === value.subjectDeviceId
      ) {
        throw new Error("new or affected device cannot self-approve recovery");
      }
      override.approvals.push({
        actorId: input.actor.actorId,
        role: input.actor.role,
        approvedAt: now.toISOString(),
      });
      this.#appendAudit(value, "trust_reset.approved", input.actor, input.reason, now);
      if (override.approvals.length === 2) {
        override.state = "executed";
        override.executedAt = now.toISOString();
        value.state = "resolved";
        value.updatedAt = now.toISOString();
        this.#appendAudit(
          value,
          "trust_reset.executed",
          { ...input.actor, actorId: "system", role: "system" },
          override.reason,
          now,
        );
        this.#notify(value, "trust_reset_completed", now);
      }
      return structuredClone(override);
    });
  }

  getCase(tenantId: string, caseId: string): OperationsCase {
    assertId(tenantId, "tenant id");
    assertId(caseId, "case id");
    const value = this.#cases.get(`${tenantId}:${caseId}`);
    if (!value) throw new Error("operations case not found");
    return structuredClone(value);
  }

  getOverride(tenantId: string, overrideId: string): SensitiveOverride {
    return structuredClone(this.#mustOverride(tenantId, overrideId));
  }

  auditEvents(tenantId: string): OperationsAuditEvent[] {
    assertId(tenantId, "tenant id");
    return structuredClone(this.#audit.filter((event) => event.tenantId === tenantId));
  }

  notificationIntents(tenantId: string): NotificationOutboxIntent[] {
    assertId(tenantId, "tenant id");
    return structuredClone(this.#intents.filter((intent) => intent.tenantId === tenantId));
  }

  verifyAudit(): boolean {
    let previousHash = "GENESIS";
    for (const [index, event] of this.#audit.entries()) {
      const { hash: eventHash, ...body } = event;
      if (
        event.sequence !== index + 1 ||
        event.previousHash !== previousHash ||
        hash(body) !== eventHash
      ) return false;
      previousHash = eventHash;
    }
    return true;
  }

  snapshot(): CustomerOperationsSnapshot {
    return {
      schemaVersion: 1,
      cases: structuredClone([...this.#cases.values()]),
      overrides: structuredClone([...this.#overrides.values()]),
      auditEvents: structuredClone(this.#audit),
      notificationIntents: structuredClone(this.#intents),
      idempotency: [...this.#idempotency.entries()].map(([composite, value]) => {
        const separator = composite.indexOf("\u0000");
        return {
          scope: composite.slice(0, separator),
          key: composite.slice(separator + 1),
          requestHash: value.requestHash,
          ...(value.error !== undefined ? { error: value.error } : {}),
          ...(Object.hasOwn(value, "response")
            ? { response: structuredClone(value.response) }
            : {}),
        };
      }),
    };
  }

  #once<T>(
    tenantId: string,
    idempotencyKey: string,
    request: unknown,
    work: () => T,
  ): T {
    assertId(tenantId, "tenant id");
    assertId(idempotencyKey, "idempotency key");
    const key = `${tenantId}\u0000${idempotencyKey}`;
    const requestHash = hash(request);
    const prior = this.#idempotency.get(key);
    if (prior) {
      if (prior.requestHash !== requestHash) {
        throw new Error("operations idempotency key reused with different request");
      }
      if (prior.error !== undefined) throw new Error(prior.error);
      return structuredClone(prior.response) as T;
    }
    try {
      const response = work();
      this.#idempotency.set(key, {
        requestHash,
        response: structuredClone(response),
      });
      return response;
    } catch (error) {
      const message = error instanceof Error ? error.message : "operations mutation failed";
      this.#idempotency.set(key, { requestHash, error: message });
      throw error;
    }
  }

  #activeCase(tenantId: string, caseId: string, now: Date): OperationsCase {
    assertNow(now);
    const value = this.#cases.get(`${tenantId}:${caseId}`);
    if (!value) throw new Error("operations case not found");
    if (["resolved", "upheld", "overturned", "remediated", "expired", "cancelled"]
      .includes(value.state)) {
      throw new Error("operations case is terminal");
    }
    if (now.getTime() >= Date.parse(value.expiresAt)) {
      value.state = "expired";
      value.updatedAt = now.toISOString();
      this.#appendAudit(
        value,
        "case.expired",
        { tenantId, actorId: "system", role: "system" },
        "case lifetime expired",
        now,
      );
      throw new Error("operations case expired");
    }
    return value;
  }

  #mustOverride(tenantId: string, overrideId: string): SensitiveOverride {
    assertId(tenantId, "tenant id");
    assertId(overrideId, "override id");
    const value = this.#overrides.get(`${tenantId}:${overrideId}`);
    if (!value) throw new Error("trust reset override not found");
    return value;
  }

  #assertActor(tenantId: string, actor: OperationsActor): void {
    if (!actor || actor.tenantId !== tenantId) {
      throw new Error("cross-tenant operations actor rejected");
    }
    assertId(actor.actorId, "actor id");
    if (actor.deviceId) assertId(actor.deviceId, "actor device id");
    if (![
      "customer", "fraud_analyst", "security_operator", "supervisor",
      "recovery_officer", "system",
    ].includes(actor.role)) throw new Error("invalid operations actor role");
  }

  #appendAudit(
    value: OperationsCase,
    type: string,
    actor: OperationsActor,
    reason: string,
    now: Date,
  ): void {
    assertReason(reason);
    const body = {
      sequence: this.#audit.length + 1,
      eventId: randomUUID(),
      tenantId: value.tenantId,
      caseId: value.caseId,
      type,
      actorId: actor.actorId,
      actorRole: actor.role,
      reason,
      correlationId: value.correlationId,
      occurredAt: now.toISOString(),
      previousHash: this.#audit.at(-1)?.hash ?? "GENESIS",
    };
    this.#audit.push({ ...body, hash: hash(body) });
  }

  #notify(
    value: OperationsCase,
    template: NotificationOutboxIntent["template"],
    now: Date,
  ): void {
    const intentId = randomUUID();
    this.#intents.push({
      intentId,
      eventKey: `${value.tenantId}:${value.caseId}:${template}:${intentId}`,
      topic: "operations.notification.requested",
      tenantId: value.tenantId,
      caseId: value.caseId,
      template,
      syntheticRecipientRef: value.subjectRef,
      createdAt: now.toISOString(),
    });
  }

  #validateRestoredState(): boolean {
    const caseKeys = new Set<string>();
    for (const value of this.#cases.values()) {
      const key = `${value.tenantId}:${value.caseId}`;
      if (
        caseKeys.has(key) ||
        !ID.test(value.tenantId) ||
        !ID.test(value.caseId) ||
        !SYNTHETIC_REF.test(value.subjectRef) ||
        !OPERATIONS_CASE_TYPES.includes(value.caseType)
      ) return false;
      const events = this.#audit.filter((event) =>
        event.tenantId === value.tenantId && event.caseId === value.caseId
      );
      const opened = events.find((event) => event.type === "case.opened");
      if (
        !opened ||
        opened.reason !== value.reason ||
        events.some((event) => event.correlationId !== value.correlationId)
      ) return false;
      const stateByEvent: Partial<Record<string, OperationsCaseState>> = {
        "case.opened": "opened",
        "case.contained": "contained",
        "case.proof_verified": "proof_verified",
        "case.under_review": "under_review",
        "case.payment_frozen": "payment_frozen",
        "case.eradicated": "eradicated",
        "case.upheld": "upheld",
        "case.overturned": "overturned",
        "case.remediated": "remediated",
        "case.resolved": "resolved",
        "case.expired": "expired",
        "case.cancelled": "cancelled",
        "trust_reset.requested": "trust_reset_pending",
        "trust_reset.executed": "resolved",
      };
      const derived = events.reduce<OperationsCaseState>(
        (state, event) => stateByEvent[event.type] ?? state,
        "opened",
      );
      if (derived !== value.state) return false;
      caseKeys.add(key);
    }
    const overrideCases = new Set<string>();
    for (const override of this.#overrides.values()) {
      const events = this.#audit.filter((event) =>
        event.tenantId === override.tenantId &&
        event.caseId === override.caseId
      );
      const requestEvents = events.filter((event) =>
        event.type === "trust_reset.requested"
      );
      const approvalEvents = events.filter((event) =>
        event.type === "trust_reset.approved"
      );
      const executed = events.find((event) =>
        event.type === "trust_reset.executed"
      );
      const expired = events.find((event) =>
        event.type === "trust_reset.expired"
      );
      const caseKey = `${override.tenantId}:${override.caseId}`;
      if (
        overrideCases.has(caseKey) ||
        !this.#cases.has(caseKey) ||
        override.approvals.length > 2 ||
        new Set(override.approvals.map((value) => value.actorId)).size !==
          override.approvals.length ||
        !override.approvals.every((approval) =>
          APPROVER_ROLES.has(approval.role)
        ) ||
        approvalEvents.length !== override.approvals.length ||
        override.approvals.some((approval) => !approvalEvents.some((event) =>
          event.actorId === approval.actorId &&
          event.actorRole === approval.role &&
          event.occurredAt === approval.approvedAt
        )) ||
        requestEvents.length !== 1 ||
        requestEvents[0].actorId !== override.requestedBy ||
        requestEvents[0].reason !== override.reason ||
        requestEvents[0].occurredAt !== override.requestedAt ||
        (override.state === "executed") !== Boolean(executed) ||
        (override.state === "expired") !== Boolean(expired) ||
        (override.executedAt !== undefined) !== Boolean(executed) ||
        (executed && override.executedAt !== executed.occurredAt)
      ) return false;
      overrideCases.add(caseKey);
    }
    return this.#intents.every((intent) =>
      intent.topic === "operations.notification.requested" &&
      SYNTHETIC_REF.test(intent.syntheticRecipientRef) &&
      this.#cases.has(`${intent.tenantId}:${intent.caseId}`)
    );
  }
}
