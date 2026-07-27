import assert from "node:assert/strict";
import test from "node:test";
import { AirlockEngine } from "../apps/issuer-simulator/airlockEngine.ts";
import { generateDeviceKeyPair, signApproval } from "../packages/crypto/deviceKeys.ts";

function setup() {
  const engine = new AirlockEngine();
  const keys = generateDeviceKeyPair("trusted-key-1");
  const device = engine.enrollTrustedDevice("subject-1", keys, "device-1");
  return { engine, keys, device };
}

function activateToken(engine: AirlockEngine, keys: ReturnType<typeof generateDeviceKeyPair>) {
  const request = engine.requestProvisioning({
    subjectId: "subject-1",
    accountId: "account-1",
    tokenId: "token-1",
    trustedDeviceId: "device-1",
    capMinor: 5_000,
    now: new Date("2026-07-27T11:00:00Z"),
  });
  engine.approveProvisioning(
    request.requestId,
    signApproval(request.challenge, keys.keyId, keys.privateKeyPem),
    new Date("2026-07-27T11:00:01Z"),
  );
}

test("fraudulent wallet token remains unspendable before trusted-device approval", () => {
  const { engine } = setup();
  engine.requestProvisioning({
    subjectId: "subject-1",
    accountId: "account-1",
    tokenId: "attacker-token",
    trustedDeviceId: "device-1",
    capMinor: 1_000,
  });
  assert.throws(
    () =>
      engine.authorize({
        transactionId: "tx-fraud",
        tokenId: "attacker-token",
        merchantId: "gift-card-store",
        amountMinor: 999,
        strategy: "pre_authorization_step_up",
        trustedDeviceId: "device-1",
      }),
    /not spendable/,
  );
});

test("exact transaction confirmation succeeds and audit chain verifies", () => {
  const { engine, keys } = setup();
  activateToken(engine, keys);
  const tx = engine.authorize({
    transactionId: "tx-1",
    tokenId: "token-1",
    merchantId: "merchant-1",
    amountMinor: 2_500,
    strategy: "pre_authorization_step_up",
    trustedDeviceId: "device-1",
  });
  engine.confirmTransaction(
    tx.transactionId,
    signApproval(tx.challenge!, keys.keyId, keys.privateKeyPem),
  );
  assert.equal(engine.getTransaction("tx-1")?.state, "confirmed");
  assert.equal(engine.audit.verify(), true);
});

test("amount substitution is rejected", () => {
  const { engine, keys } = setup();
  activateToken(engine, keys);
  const tx = engine.authorize({
    transactionId: "tx-2",
    tokenId: "token-1",
    merchantId: "merchant-1",
    amountMinor: 2_500,
    strategy: "pre_authorization_step_up",
    trustedDeviceId: "device-1",
  });
  const approval = signApproval(tx.challenge!, keys.keyId, keys.privateKeyPem);
  approval.binding = { ...approval.binding, amountMinor: 25_000 };
  assert.throws(() => engine.confirmTransaction("tx-2", approval), /binding mismatch/);
});

test("clearing after reversal is an explicit exception, not claimed prevention", () => {
  const { engine, keys } = setup();
  activateToken(engine, keys);
  engine.authorize({
    transactionId: "tx-race",
    tokenId: "token-1",
    merchantId: "merchant-risk",
    amountMinor: 4_000,
    strategy: "provisional_monitoring",
    trustedDeviceId: "device-1",
  });
  engine.expireAndReverse("tx-race");
  const result = engine.receiveClearing("tx-race");
  assert.equal(result.state, "exception");
  assert.equal(engine.audit.verify(), true);
});
