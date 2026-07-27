import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import test from "node:test";
import { AirlockEngine } from "../apps/issuer-simulator/airlockEngine.ts";
import {
  APPROVAL_ALGORITHM,
  generateDeviceKeyPair,
  signApproval,
  verifyApproval,
} from "../packages/crypto/deviceKeys.ts";
import type { ApprovalAlgorithm } from "../packages/protocol/types.ts";

function pendingProvisioning() {
  const engine = new AirlockEngine();
  const keys = generateDeviceKeyPair("algorithm-key");
  engine.enrollTrustedDevice("subject", keys, "device");
  const request = engine.requestProvisioning({
    subjectId: "subject",
    accountId: "account",
    tokenId: "token",
    trustedDeviceId: "device",
    capMinor: 1_000,
  });
  return { engine, keys, request };
}

test("the supported profile is explicit in keys, enrollment, and approvals", () => {
  const { engine, keys, request } = pendingProvisioning();
  const approval = signApproval(
    request.challenge,
    keys.keyId,
    keys.privateKeyPem,
  );
  assert.equal(keys.algorithm, APPROVAL_ALGORITHM);
  assert.equal(engine.getDevice("device")?.algorithm, APPROVAL_ALGORITHM);
  assert.equal(approval.algorithm, APPROVAL_ALGORITHM);
  assert.equal(verifyApproval(approval, keys.publicKeyPem), true);
});

test("unknown, missing, and mismatched approval algorithms fail closed", () => {
  const { engine, keys, request } = pendingProvisioning();
  const approval = signApproval(
    request.challenge,
    keys.keyId,
    keys.privateKeyPem,
  );
  const unknown = {
    ...approval,
    algorithm: "airlock.ecdsa-p256-sha1-der.v0" as ApprovalAlgorithm,
  };
  assert.throws(
    () => engine.approveProvisioning(request.requestId, unknown),
    /algorithm mismatch/,
  );
  const missing = { ...approval } as Record<string, unknown>;
  delete missing.algorithm;
  assert.throws(
    () => engine.approveProvisioning(
      request.requestId,
      missing as unknown as typeof approval,
    ),
    /algorithm mismatch/,
  );
});

test("key curve substitution is rejected at enrollment and restore", () => {
  const { publicKey } = generateKeyPairSync("ec", { namedCurve: "P-384" });
  const p384 = publicKey.export({ type: "spki", format: "pem" }).toString();
  const engine = new AirlockEngine();
  assert.throws(
    () => engine.enrollTrustedDevice("subject", {
      keyId: "wrong-curve",
      algorithm: APPROVAL_ALGORITHM,
      publicKeyPem: p384,
    }),
    /does not match algorithm profile/,
  );

  const valid = pendingProvisioning().engine.snapshot();
  valid.devices[0].publicKeyPem = p384;
  assert.throws(
    () => AirlockEngine.restore(valid),
    /does not match algorithm profile/,
  );
});

test("unknown or absent enrollment profile is rejected during restore", () => {
  const { engine } = pendingProvisioning();
  const unknown = engine.snapshot();
  unknown.devices[0].algorithm =
    "airlock.ecdsa-p256-sha1-der.v0" as ApprovalAlgorithm;
  assert.throws(() => AirlockEngine.restore(unknown), /invalid trusted device/);

  const absent = engine.snapshot() as unknown as {
    devices: Array<Record<string, unknown>>;
  };
  delete absent.devices[0].algorithm;
  assert.throws(
    () => AirlockEngine.restore(
      absent as unknown as ReturnType<AirlockEngine["snapshot"]>,
    ),
    /invalid trusted device/,
  );

  const legacy = engine.snapshot() as unknown as { schemaVersion: number };
  legacy.schemaVersion = 1;
  assert.throws(
    () => AirlockEngine.restore(
      legacy as unknown as ReturnType<AirlockEngine["snapshot"]>,
    ),
    /invalid engine snapshot/,
  );
});
