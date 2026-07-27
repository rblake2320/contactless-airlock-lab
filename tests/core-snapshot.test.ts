import assert from "node:assert/strict";
import test from "node:test";
import { AirlockEngine } from "../apps/issuer-simulator/airlockEngine.ts";
import { AuditLog } from "../packages/audit/auditLog.ts";
import { generateDeviceKeyPair, signApproval } from "../packages/crypto/deviceKeys.ts";
import { ChallengeStore } from "../packages/state-machine/challengeStore.ts";

function provisionedEngine() {
  const engine = new AirlockEngine();
  const keys = generateDeviceKeyPair("snapshot-key");
  engine.enrollTrustedDevice("subject-1", keys, "device-1");
  const provisioning = engine.requestProvisioning({
    subjectId: "subject-1",
    accountId: "account-1",
    tokenId: "token-1",
    trustedDeviceId: "device-1",
    capMinor: 1_000,
    now: new Date("2026-07-27T12:00:00Z"),
  });
  engine.approveProvisioning(
    provisioning.requestId,
    signApproval(provisioning.challenge, keys.keyId, keys.privateKeyPem),
    new Date("2026-07-27T12:00:01Z"),
    "capped",
  );
  return { engine, keys };
}

test("engine snapshot has an exact JSON roundtrip and restores its audit chain", () => {
  const { engine } = provisionedEngine();
  engine.authorize({
    transactionId: "snapshot-transaction",
    tokenId: "token-1",
    merchantId: "merchant-1",
    amountMinor: 800,
    strategy: "provisional_monitoring",
    trustedDeviceId: "device-1",
    now: new Date("2026-07-27T12:01:00Z"),
  });
  engine.expireAndReverse(
    "snapshot-transaction",
    new Date("2026-07-27T12:01:31Z"),
  );

  const encoded = JSON.stringify(engine.snapshot());
  const restored = AirlockEngine.restore(JSON.parse(encoded));
  assert.equal(JSON.stringify(restored.snapshot()), encoded);
  assert.equal(restored.audit.verify(), true);
  assert.equal(restored.getTransaction("snapshot-transaction")?.state, "reversed");
  assert.equal(restored.getToken("token-1")?.state, "active_capped");
});

test("confirmed challenge remains terminal and cannot be replayed after restore", () => {
  const keys = generateDeviceKeyPair("challenge-key");
  const store = new ChallengeStore();
  const binding = store.create({
    purpose: "confirm-transaction",
    subjectId: "subject",
    accountId: "account",
    paymentTokenId: "token",
    trustedDeviceId: "device",
    transactionId: "transaction",
    merchantId: "merchant",
    amountMinor: 100,
    currency: "USD",
    ttlMs: 30_000,
  }, new Date("2026-07-27T12:00:00Z"));
  const approval = signApproval(binding, keys.keyId, keys.privateKeyPem);
  store.consume(approval, keys.publicKeyPem, new Date("2026-07-27T12:00:01Z"));

  const restored = ChallengeStore.restore(JSON.parse(JSON.stringify(store.snapshot())));
  assert.equal(restored.get(binding.challengeId)?.status, "confirmed");
  assert.throws(
    () => restored.consume(
      approval,
      keys.publicKeyPem,
      new Date("2026-07-27T12:00:02Z"),
    ),
    /already terminal/,
  );
});

test("created challenge retains its deadline and expires after restore", () => {
  const keys = generateDeviceKeyPair("expiry-key");
  const store = new ChallengeStore();
  const binding = store.create({
    purpose: "provision-payment-token",
    subjectId: "subject",
    accountId: "account",
    paymentTokenId: "token",
    trustedDeviceId: "device",
    ttlMs: 1_000,
  }, new Date("2026-07-27T12:00:00Z"));
  const restored = ChallengeStore.restore(store.snapshot());
  assert.throws(
    () => restored.consume(
      signApproval(binding, keys.keyId, keys.privateKeyPem),
      keys.publicKeyPem,
      new Date("2026-07-27T12:00:01Z"),
    ),
    /expired/,
  );
  assert.equal(restored.get(binding.challengeId)?.status, "expired");
});

test("daily capped-spend reservation survives restore", () => {
  const { engine } = provisionedEngine();
  engine.authorize({
    transactionId: "first-spend",
    tokenId: "token-1",
    merchantId: "merchant",
    amountMinor: 1_000,
    strategy: "pre_authorization_step_up",
    trustedDeviceId: "device-1",
    now: new Date("2026-07-27T13:00:00Z"),
  });
  const restored = AirlockEngine.restore(engine.snapshot());
  restored.authorize({
    transactionId: "second-spend",
    tokenId: "token-1",
    merchantId: "merchant",
    amountMinor: 1_000,
    strategy: "pre_authorization_step_up",
    trustedDeviceId: "device-1",
    now: new Date("2026-07-27T13:01:00Z"),
  });
  assert.throws(
    () => restored.authorize({
      transactionId: "third-spend",
      tokenId: "token-1",
      merchantId: "merchant",
      amountMinor: 1,
      strategy: "pre_authorization_step_up",
      trustedDeviceId: "device-1",
      now: new Date("2026-07-27T13:02:00Z"),
    }),
    /daily cap/,
  );
});

test("audit restore rejects payload tampering and duplicate engine identities", () => {
  const log = new AuditLog();
  log.append("test.event", "correlation", { decision: "decline" });
  const corrupted = log.snapshot();
  corrupted.events[0].payload.decision = "approve";
  assert.throws(() => AuditLog.restore(corrupted), /chain verification failed/);

  const { engine } = provisionedEngine();
  const snapshot = engine.snapshot();
  snapshot.devices.push(structuredClone(snapshot.devices[0]));
  assert.throws(() => AirlockEngine.restore(snapshot), /duplicate trusted device/);
});

test("snapshot getters remain defensive copies after restoration", () => {
  const { engine } = provisionedEngine();
  const restored = AirlockEngine.restore(engine.snapshot());
  const snapshot = restored.snapshot();
  snapshot.devices[0].status = "revoked";
  snapshot.audit.events[0].payload.subjectId = "tampered";
  assert.equal(restored.getDevice("device-1")?.status, "active");
  assert.equal(restored.audit.verify(), true);
});

test("engine restore rejects tampered cross-record challenge references", () => {
  const { engine } = provisionedEngine();
  engine.authorize({
    transactionId: "cross-reference",
    tokenId: "token-1",
    merchantId: "merchant",
    amountMinor: 100,
    strategy: "pre_authorization_step_up",
    trustedDeviceId: "device-1",
    now: new Date("2026-07-27T14:00:00Z"),
  });

  const provisioningTamper = engine.snapshot();
  provisioningTamper.provisioning[0].challenge.paymentTokenId = "other-token";
  assert.throws(
    () => AirlockEngine.restore(provisioningTamper),
    /invalid provisioning snapshot|challenge reference mismatch/,
  );

  const transactionTamper = engine.snapshot();
  transactionTamper.transactions[0].challenge!.merchantId = "substituted-merchant";
  assert.throws(
    () => AirlockEngine.restore(transactionTamper),
    /invalid transaction snapshot|challenge reference mismatch/,
  );
});

test("engine restore rejects fabricated cap reservations and daily totals", () => {
  const { engine } = provisionedEngine();
  engine.authorize({
    transactionId: "reservation",
    tokenId: "token-1",
    merchantId: "merchant",
    amountMinor: 100,
    strategy: "pre_authorization_step_up",
    trustedDeviceId: "device-1",
    now: new Date("2026-07-27T15:00:00Z"),
  });

  const badReservation = engine.snapshot();
  badReservation.transactions[0].capReservation!.spendKey = "token-1:2026-07-26";
  assert.throws(
    () => AirlockEngine.restore(badReservation),
    /invalid cap reservation/,
  );

  const badAggregate = engine.snapshot();
  badAggregate.dailySpend[0].amountMinor += 1;
  assert.throws(
    () => AirlockEngine.restore(badAggregate),
    /does not match reservations/,
  );
});

test("engine restore rejects lifecycle states paired with consumable challenges", () => {
  const { engine } = provisionedEngine();
  engine.authorize({
    transactionId: "pending-transaction",
    tokenId: "token-1",
    merchantId: "merchant",
    amountMinor: 100,
    strategy: "pre_authorization_step_up",
    trustedDeviceId: "device-1",
    now: new Date("2026-07-27T16:00:00Z"),
  });

  const forgedConfirmed = engine.snapshot();
  forgedConfirmed.transactions[0].state = "confirmed";
  assert.throws(
    () => AirlockEngine.restore(forgedConfirmed),
    /transaction lifecycle\/challenge status mismatch/,
  );

  const forgedSettled = engine.snapshot();
  forgedSettled.transactions[0].state = "settled";
  assert.throws(
    () => AirlockEngine.restore(forgedSettled),
    /transaction lifecycle\/challenge status mismatch/,
  );

  const forgedProvisioning = engine.snapshot();
  forgedProvisioning.provisioning[0].state = "trusted_device_challenge";
  assert.throws(
    () => AirlockEngine.restore(forgedProvisioning),
    /provisioning lifecycle\/challenge status mismatch/,
  );
});

test("legitimate confirmed, settled, and reversed challenge statuses restore", () => {
  const { engine, keys } = provisionedEngine();
  const settled = engine.authorize({
    transactionId: "settled-transaction",
    tokenId: "token-1",
    merchantId: "merchant",
    amountMinor: 100,
    strategy: "pre_authorization_step_up",
    trustedDeviceId: "device-1",
    now: new Date("2026-07-27T17:00:00Z"),
  });
  engine.confirmTransaction(
    settled.transactionId,
    signApproval(settled.challenge!, keys.keyId, keys.privateKeyPem),
    new Date("2026-07-27T17:00:01Z"),
  );
  engine.receiveClearing(
    settled.transactionId,
    new Date("2026-07-27T17:00:02Z"),
  );

  const reversed = engine.authorize({
    transactionId: "reversed-transaction",
    tokenId: "token-1",
    merchantId: "merchant",
    amountMinor: 100,
    strategy: "provisional_monitoring",
    trustedDeviceId: "device-1",
    now: new Date("2026-07-27T17:01:00Z"),
  });
  engine.expireAndReverse(
    reversed.transactionId,
    new Date("2026-07-27T17:01:31Z"),
  );

  const restored = AirlockEngine.restore(engine.snapshot());
  assert.equal(restored.getTransaction(settled.transactionId)?.state, "settled");
  assert.equal(restored.challenges.get(settled.challenge!.challengeId)?.status, "confirmed");
  assert.equal(restored.getTransaction(reversed.transactionId)?.state, "reversed");
  assert.equal(restored.challenges.get(reversed.challenge!.challengeId)?.status, "cancelled");
});
