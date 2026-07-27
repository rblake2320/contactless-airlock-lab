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

test("confirmed provisional transaction settles based on lifecycle, not strategy label", () => {
  const { engine, keys } = setup();
  activateToken(engine, keys);
  const tx = engine.authorize({
    transactionId: "tx-confirmed-provisional",
    tokenId: "token-1",
    merchantId: "merchant",
    amountMinor: 1_000,
    strategy: "provisional_monitoring",
    trustedDeviceId: "device-1",
  });
  engine.confirmTransaction(
    tx.transactionId,
    signApproval(tx.challenge!, keys.keyId, keys.privateKeyPem),
  );
  assert.equal(engine.receiveClearing(tx.transactionId).state, "settled");
});

test("reversed pre-authorization transaction becomes exception on late clearing", () => {
  const { engine, keys } = setup();
  activateToken(engine, keys);
  engine.authorize({
    transactionId: "tx-reversed-preauth",
    tokenId: "token-1",
    merchantId: "merchant",
    amountMinor: 1_000,
    strategy: "pre_authorization_step_up",
    trustedDeviceId: "device-1",
  });
  engine.expireAndReverse("tx-reversed-preauth");
  assert.equal(engine.receiveClearing("tx-reversed-preauth").state, "exception");
});

test("duplicate token and transaction identifiers cannot overwrite live state", () => {
  const { engine, keys } = setup();
  activateToken(engine, keys);
  assert.throws(
    () =>
      engine.requestProvisioning({
        subjectId: "subject-1",
        accountId: "account-1",
        tokenId: "token-1",
        trustedDeviceId: "device-1",
        capMinor: 1_000,
      }),
    /token id already exists/,
  );
  const transaction = {
    transactionId: "duplicate-tx",
    tokenId: "token-1",
    merchantId: "merchant",
    amountMinor: 100,
    strategy: "pre_authorization_step_up" as const,
    trustedDeviceId: "device-1",
  };
  engine.authorize(transaction);
  assert.throws(() => engine.authorize(transaction), /transaction id already exists/);
});

test("capped token enforces per-transaction and daily aggregate limits", () => {
  const { engine, keys } = setup();
  const request = engine.requestProvisioning({
    subjectId: "subject-1",
    accountId: "account-1",
    tokenId: "capped-token",
    trustedDeviceId: "device-1",
    capMinor: 1_000,
    now: new Date("2026-07-27T12:00:00Z"),
  });
  engine.approveProvisioning(
    request.requestId,
    signApproval(request.challenge, keys.keyId, keys.privateKeyPem),
    new Date("2026-07-27T12:00:01Z"),
    "capped",
  );
  assert.equal(engine.getToken("capped-token")?.state, "active_capped");
  assert.throws(
    () =>
      engine.authorize({
        transactionId: "over-per-tx",
        tokenId: "capped-token",
        merchantId: "merchant",
        amountMinor: 1_001,
        strategy: "pre_authorization_step_up",
        trustedDeviceId: "device-1",
      }),
    /new-token cap/,
  );
  for (const [transactionId, amountMinor] of [["cap-a", 1_000], ["cap-b", 1_000]] as const) {
    engine.authorize({
      transactionId,
      tokenId: "capped-token",
      merchantId: "merchant",
      amountMinor,
      strategy: "pre_authorization_step_up",
      trustedDeviceId: "device-1",
      now: new Date("2026-07-27T13:00:00Z"),
    });
  }
  assert.throws(
    () =>
      engine.authorize({
        transactionId: "over-daily",
        tokenId: "capped-token",
        merchantId: "merchant",
        amountMinor: 1,
        strategy: "pre_authorization_step_up",
        trustedDeviceId: "device-1",
        now: new Date("2026-07-27T13:00:00Z"),
      }),
    /daily cap/,
  );
});

test("invalid monetary inputs are rejected", () => {
  const { engine, keys } = setup();
  activateToken(engine, keys);
  assert.throws(
    () =>
      engine.authorize({
        transactionId: "negative",
        tokenId: "token-1",
        merchantId: "merchant",
        amountMinor: -1,
        strategy: "pre_authorization_step_up",
        trustedDeviceId: "device-1",
      }),
    /positive safe integer/,
  );
});

test("cap multiplication cannot exceed safe-integer range", () => {
  const { engine } = setup();
  assert.throws(
    () =>
      engine.requestProvisioning({
        subjectId: "subject-1",
        accountId: "account-1",
        tokenId: "unsafe-cap",
        trustedDeviceId: "device-1",
        capMinor: Number.MAX_SAFE_INTEGER,
      }),
    /cap must be a positive safe integer/,
  );
});

test("expired capped authorization releases its daily reservation", () => {
  const { engine, keys } = setup();
  const request = engine.requestProvisioning({
    subjectId: "subject-1",
    accountId: "account-1",
    tokenId: "reservation-token",
    trustedDeviceId: "device-1",
    capMinor: 1_000,
  });
  engine.approveProvisioning(
    request.requestId,
    signApproval(request.challenge, keys.keyId, keys.privateKeyPem),
    new Date(),
    "capped",
  );
  engine.authorize({
    transactionId: "reservation-a",
    tokenId: "reservation-token",
    merchantId: "merchant",
    amountMinor: 1_000,
    strategy: "provisional_monitoring",
    trustedDeviceId: "device-1",
  });
  engine.expireAndReverse("reservation-a");
  assert.doesNotThrow(() =>
    engine.authorize({
      transactionId: "reservation-b",
      tokenId: "reservation-token",
      merchantId: "merchant",
      amountMinor: 1_000,
      strategy: "pre_authorization_step_up",
      trustedDeviceId: "device-1",
    }),
  );
});

test("revoked trusted device cannot approve a new provisioning challenge", () => {
  const { engine, keys } = setup();
  const request = engine.requestProvisioning({
    subjectId: "subject-1",
    accountId: "account-1",
    tokenId: "revoke-token",
    trustedDeviceId: "device-1",
    capMinor: 1_000,
  });
  engine.revokeTrustedDevice("device-1");
  assert.equal(engine.getDevice("device-1")?.status, "revoked");
  assert.throws(
    () =>
      engine.approveProvisioning(
        request.requestId,
        signApproval(request.challenge, keys.keyId, keys.privateKeyPem),
      ),
    /revoked/,
  );
  assert.throws(
    () => engine.revokeTrustedDevice("device-1"),
    /already revoked/,
  );
});

test("device enrollment collision and unknown runtime enums fail closed", () => {
  const { engine, keys } = setup();
  assert.throws(
    () => engine.enrollTrustedDevice("subject-1", keys, "device-1"),
    /device id already exists/,
  );
  const request = engine.requestProvisioning({
    subjectId: "subject-1",
    accountId: "account-1",
    tokenId: "enum-token",
    trustedDeviceId: "device-1",
    capMinor: 1_000,
  });
  assert.throws(
    () =>
      engine.approveProvisioning(
        request.requestId,
        signApproval(request.challenge, keys.keyId, keys.privateKeyPem),
        new Date(),
        "unexpected" as "full",
      ),
    /invalid activation mode/,
  );
});
