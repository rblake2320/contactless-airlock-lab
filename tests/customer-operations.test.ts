import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import {
  CustomerOperationsStateMachine,
  type OperationsActor,
} from "../packages/customer-operations/operationsStateMachine.ts";

const start = new Date("2026-07-28T12:00:00.000Z");
const tenant = "tenant-a";
const actor = (
  actorId: string,
  role: OperationsActor["role"],
  deviceId?: string,
  tenantId = tenant,
): OperationsActor => ({ tenantId, actorId, role, deviceId });

function open(
  machine: CustomerOperationsStateMachine,
  caseType:
    | "device_loss"
    | "account_recovery"
    | "false_decline_review"
    | "fraudulent_approval_dispute"
    | "compromise_response",
  caseId: string,
  subjectDeviceId?: string,
) {
  return machine.openCase({
    tenantId: tenant,
    caseType,
    caseId,
    subjectRef: `synthetic-${caseId}`,
    subjectDeviceId,
    reason: `Open synthetic ${caseType} case`,
    correlationId: `corr-${caseId}`,
    actor: actor("customer-1", "customer", "known-device"),
    idempotencyKey: `open-${caseId}`,
    ttlMs: 60 * 60 * 1_000,
    now: start,
  });
}

test("device loss destructive reset needs two distinct authorized approvers", () => {
  const machine = new CustomerOperationsStateMachine();
  const opened = open(machine, "device_loss", "device-loss-1", "lost-device");
  machine.transition({
    tenantId: tenant,
    caseId: opened.caseId,
    nextState: "contained",
    reason: "Lost credential disabled at the trust boundary",
    actor: actor("security-1", "security_operator"),
    idempotencyKey: "contain-device-loss",
    now: new Date(start.getTime() + 1_000),
  });
  const override = machine.requestTrustReset({
    tenantId: tenant,
    caseId: opened.caseId,
    overrideId: "override-1",
    reason: "Reset old device trust after verified loss report",
    actor: actor("supervisor-1", "supervisor"),
    idempotencyKey: "request-reset",
    ttlMs: 10 * 60 * 1_000,
    now: new Date(start.getTime() + 2_000),
  });
  assert.equal(machine.getCase(tenant, opened.caseId).state, "trust_reset_pending");
  assert.throws(
    () => machine.approveTrustReset({
      tenantId: tenant,
      overrideId: override.overrideId,
      reason: "Affected device attempted approval",
      actor: actor("recovery-affected", "recovery_officer", "lost-device"),
      idempotencyKey: "affected-approval",
      now: new Date(start.getTime() + 3_000),
    }),
    /cannot self-approve/,
  );
  assert.throws(
    () => machine.approveTrustReset({
      tenantId: tenant,
      overrideId: override.overrideId,
      reason: "Customer attempted privileged approval",
      actor: actor("customer-1", "customer"),
      idempotencyKey: "customer-approval",
      now: new Date(start.getTime() + 3_000),
    }),
    /not authorized/,
  );
  const first = machine.approveTrustReset({
    tenantId: tenant,
    overrideId: override.overrideId,
    reason: "Independent recovery evidence reviewed",
    actor: actor("recovery-1", "recovery_officer"),
    idempotencyKey: "approval-1",
    now: new Date(start.getTime() + 3_000),
  });
  assert.equal(first.state, "pending");
  assert.equal(first.approvals.length, 1);
  assert.throws(
    () => machine.approveTrustReset({
      tenantId: tenant,
      overrideId: override.overrideId,
      reason: "Duplicate approval attempt",
      actor: actor("recovery-1", "recovery_officer"),
      idempotencyKey: "approval-1-duplicate",
      now: new Date(start.getTime() + 4_000),
    }),
    /duplicate/,
  );
  const executed = machine.approveTrustReset({
    tenantId: tenant,
    overrideId: override.overrideId,
    reason: "Second independent security approval",
    actor: actor("security-2", "security_operator"),
    idempotencyKey: "approval-2",
    now: new Date(start.getTime() + 5_000),
  });
  assert.equal(executed.state, "executed");
  assert.equal(executed.approvals.length, 2);
  assert.equal(machine.getCase(tenant, opened.caseId).state, "resolved");
  assert.equal(machine.verifyAudit(), true);
  assert.deepEqual(
    machine.notificationIntents(tenant).map((intent) => intent.topic),
    Array(4).fill("operations.notification.requested"),
  );
  assert.equal(
    JSON.stringify(machine.notificationIntents(tenant)).includes("@"),
    false,
  );
});

test("account recovery allows strong proof only and a new device cannot approve itself", () => {
  const machine = new CustomerOperationsStateMachine();
  const opened = open(machine, "account_recovery", "recovery-1", "new-device");
  assert.throws(
    () => machine.verifyRecoveryProof({
      tenantId: tenant,
      caseId: opened.caseId,
      proofMethod: "sms_otp" as never,
      reason: "Attempted downgrade",
      actor: actor("recovery-1", "recovery_officer"),
      idempotencyKey: "sms-proof",
      now: new Date(start.getTime() + 1_000),
    }),
    /cannot downgrade/,
  );
  machine.verifyRecoveryProof({
    tenantId: tenant,
    caseId: opened.caseId,
    proofMethod: "existing_passkey",
    reason: "Existing registered passkey verified",
    actor: actor("recovery-1", "recovery_officer"),
    idempotencyKey: "strong-proof",
    now: new Date(start.getTime() + 1_000),
  });
  const override = machine.requestTrustReset({
    tenantId: tenant,
    caseId: opened.caseId,
    overrideId: "recovery-reset",
    reason: "Strong proof complete; request controlled reset",
    actor: actor("recovery-1", "recovery_officer"),
    idempotencyKey: "recovery-reset-request",
    ttlMs: 10 * 60 * 1_000,
    now: new Date(start.getTime() + 2_000),
  });
  assert.throws(
    () => machine.approveTrustReset({
      tenantId: tenant,
      overrideId: override.overrideId,
      reason: "New device attempted to approve itself",
      actor: actor("security-new", "security_operator", "new-device"),
      idempotencyKey: "new-device-approval",
      now: new Date(start.getTime() + 3_000),
    }),
    /cannot self-approve/,
  );
});

test("false decline, fraudulent approval, and compromise workflows are monotonic", () => {
  const machine = new CustomerOperationsStateMachine();
  const falseDecline = open(machine, "false_decline_review", "false-decline");
  machine.transition({
    tenantId: tenant,
    caseId: falseDecline.caseId,
    nextState: "under_review",
    reason: "Analyst accepted review assignment",
    actor: actor("fraud-1", "fraud_analyst"),
    idempotencyKey: "false-review",
    now: new Date(start.getTime() + 1_000),
  });
  machine.transition({
    tenantId: tenant,
    caseId: falseDecline.caseId,
    nextState: "overturned",
    reason: "Synthetic evidence supports customer transaction",
    actor: actor("fraud-1", "fraud_analyst"),
    idempotencyKey: "false-overturn",
    now: new Date(start.getTime() + 2_000),
  });
  assert.throws(
    () => machine.transition({
      tenantId: tenant,
      caseId: falseDecline.caseId,
      nextState: "under_review",
      reason: "Attempted state rollback",
      actor: actor("fraud-1", "fraud_analyst"),
      idempotencyKey: "false-rollback",
      now: new Date(start.getTime() + 3_000),
    }),
    /terminal/,
  );

  const dispute = open(machine, "fraudulent_approval_dispute", "fraud-dispute");
  for (const [nextState, key, offset] of [
    ["payment_frozen", "freeze", 1],
    ["under_review", "investigate", 2],
    ["remediated", "remediate", 3],
  ] as const) {
    machine.transition({
      tenantId: tenant,
      caseId: dispute.caseId,
      nextState,
      reason: `Synthetic dispute action ${nextState}`,
      actor: actor("fraud-2", "fraud_analyst"),
      idempotencyKey: key,
      now: new Date(start.getTime() + offset * 1_000),
    });
  }

  const compromise = open(machine, "compromise_response", "compromise");
  for (const [nextState, key, offset] of [
    ["contained", "compromise-contain", 1],
    ["eradicated", "compromise-eradicate", 2],
    ["resolved", "compromise-resolve", 3],
  ] as const) {
    machine.transition({
      tenantId: tenant,
      caseId: compromise.caseId,
      nextState,
      reason: `Synthetic compromise action ${nextState}`,
      actor: actor("security-1", "security_operator"),
      idempotencyKey: key,
      now: new Date(start.getTime() + offset * 1_000),
    });
  }
  assert.equal(machine.getCase(tenant, dispute.caseId).state, "remediated");
  assert.equal(machine.getCase(tenant, compromise.caseId).state, "resolved");
});

test("tenant isolation, authorization, idempotency, and immutable evidence fail closed", () => {
  const machine = new CustomerOperationsStateMachine();
  const input = {
    tenantId: tenant,
    caseType: "false_decline_review" as const,
    caseId: "idem-case",
    subjectRef: "synthetic-idem-case",
    reason: "Open synthetic idempotent case",
    correlationId: "corr-idem",
    actor: actor("customer-1", "customer"),
    idempotencyKey: "same-key",
    ttlMs: 60 * 60 * 1_000,
    now: start,
  };
  const first = machine.openCase(input);
  assert.deepEqual(machine.openCase(input), first);
  assert.equal(machine.auditEvents(tenant).length, 1);
  assert.throws(
    () => machine.openCase({ ...input, reason: "Different request body" }),
    /different request/,
  );
  assert.throws(
    () => machine.getCase("tenant-b", first.caseId),
    /not found/,
  );
  assert.throws(
    () => machine.transition({
      tenantId: tenant,
      caseId: first.caseId,
      nextState: "under_review",
      reason: "Cross tenant analyst attempt",
      actor: actor("fraud-b", "fraud_analyst", undefined, "tenant-b"),
      idempotencyKey: "cross-tenant",
      now: new Date(start.getTime() + 1_000),
    }),
    /cross-tenant/,
  );
  assert.throws(
    () => machine.transition({
      tenantId: tenant,
      caseId: first.caseId,
      nextState: "under_review",
      reason: "Customer cannot act as fraud analyst",
      actor: actor("customer-1", "customer"),
      idempotencyKey: "unauthorized",
      now: new Date(start.getTime() + 1_000),
    }),
    /not authorized/,
  );
  const copied = machine.auditEvents(tenant);
  copied[0].reason = "tampered";
  assert.notEqual(machine.auditEvents(tenant)[0].reason, "tampered");
  assert.equal(machine.verifyAudit(), true);
});

test("case and approval expiry are terminal and survive snapshot restoration", () => {
  const machine = new CustomerOperationsStateMachine();
  const expiring = machine.openCase({
    tenantId: tenant,
    caseType: "false_decline_review",
    caseId: "expiring-case",
    subjectRef: "synthetic-expiring-case",
    reason: "Open short synthetic case",
    correlationId: "corr-expiring",
    actor: actor("customer-1", "customer"),
    idempotencyKey: "open-expiring",
    ttlMs: 60_000,
    now: start,
  });
  const expiredTransition = {
      tenantId: tenant,
      caseId: expiring.caseId,
      nextState: "under_review" as const,
      reason: "Attempt exactly at expiry",
      actor: actor("fraud-1", "fraud_analyst"),
      idempotencyKey: "expired-transition",
      now: new Date(start.getTime() + 60_000),
  };
  assert.throws(
    () => machine.transition(expiredTransition),
    /expired/,
  );
  const auditAfterExpiry = machine.auditEvents(tenant).length;
  assert.throws(
    () => machine.transition(expiredTransition),
    /expired/,
  );
  assert.equal(machine.auditEvents(tenant).length, auditAfterExpiry);
  assert.equal(machine.getCase(tenant, expiring.caseId).state, "expired");

  const recovery = open(machine, "account_recovery", "approval-expiry");
  machine.verifyRecoveryProof({
    tenantId: tenant,
    caseId: recovery.caseId,
    proofMethod: "in_person_strong_identity",
    reason: "In-person strong identity verified",
    actor: actor("recovery-1", "recovery_officer"),
    idempotencyKey: "expiry-proof",
    now: new Date(start.getTime() + 1_000),
  });
  const override = machine.requestTrustReset({
    tenantId: tenant,
    caseId: recovery.caseId,
    overrideId: "expiring-override",
    reason: "Request bounded dual approval",
    actor: actor("recovery-1", "recovery_officer"),
    idempotencyKey: "expiry-reset",
    ttlMs: 60_000,
    now: new Date(start.getTime() + 2_000),
  });
  assert.throws(
    () => machine.approveTrustReset({
      tenantId: tenant,
      overrideId: override.overrideId,
      reason: "Attempt exactly at approval expiry",
      actor: actor("security-1", "security_operator"),
      idempotencyKey: "late-approval",
      now: new Date(start.getTime() + 62_000),
    }),
    /expired/,
  );
  assert.equal(machine.getOverride(tenant, override.overrideId).state, "expired");
  const restored = CustomerOperationsStateMachine.restore(machine.snapshot());
  assert.equal(restored.getCase(tenant, expiring.caseId).state, "expired");
  assert.equal(restored.getOverride(tenant, override.overrideId).state, "expired");
  assert.equal(restored.verifyAudit(), true);

  const tampered = machine.snapshot();
  tampered.auditEvents[0].reason = "changed";
  assert.throws(
    () => CustomerOperationsStateMachine.restore(tampered),
    /verification failed/,
  );
  const stateTampered = machine.snapshot();
  stateTampered.cases.find((value) => value.caseId === recovery.caseId)!.state =
    "resolved";
  assert.throws(
    () => CustomerOperationsStateMachine.restore(stateTampered),
    /verification failed/,
  );
});

test("real-looking customer identifiers are rejected and no notification is sent directly", () => {
  const machine = new CustomerOperationsStateMachine();
  assert.throws(
    () => machine.openCase({
      tenantId: tenant,
      caseType: "device_loss",
      caseId: "real-data",
      subjectRef: "4111111111111111",
      reason: "Attempted real card data",
      correlationId: "corr-real",
      actor: actor("customer-1", "customer"),
      idempotencyKey: "real-data",
      ttlMs: 60_000,
      now: start,
    }),
    /synthetic/,
  );
  assert.deepEqual(machine.notificationIntents(tenant), []);
});

test("machine-readable operations contract keeps safety and external gaps explicit", async () => {
  const contract = JSON.parse(await readFile(
    new URL(
      "../contracts/operations/customer-fraud-workflows.v1.json",
      import.meta.url,
    ),
    "utf8",
  ));
  assert.equal(contract.status, "synthetic-reference-only");
  assert.equal(contract.destructiveTrustReset.approvalCount, 2);
  assert.equal(contract.destructiveTrustReset.approversMustBeDistinct, true);
  assert.equal(contract.destructiveTrustReset.affectedOrNewDeviceMayApprove, false);
  assert.equal(contract.notifications.behavior, "outbox intents only");
  assert.equal(contract.notifications.realDeliveryImplemented, false);
  assert.equal(contract.dataPolicy.PANAllowed, false);
  assert.ok(contract.caseTypes.account_recovery.prohibitedProofMethods.includes("SMS OTP"));
  assert.ok(contract.productionExternalGaps.length >= 8);
});
