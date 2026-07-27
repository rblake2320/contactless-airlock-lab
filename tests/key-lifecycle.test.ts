import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import test from "node:test";
import {
  AirlockEngine,
  type AirlockEngineSnapshot,
} from "../apps/issuer-simulator/airlockEngine.ts";
import {
  generateDeviceKeyPair,
  signApproval,
} from "../packages/crypto/deviceKeys.ts";
import { DurableStore } from "../packages/storage/durableStore.ts";

function setup() {
  const engine = new AirlockEngine();
  const oldKeys = generateDeviceKeyPair("old-key");
  engine.enrollTrustedDevice("subject-1", oldKeys, "device-1");
  return { engine, oldKeys };
}

test("key rotation invalidates old provisioning challenges and survives restart", () => {
  const { engine, oldKeys } = setup();
  const replacement = generateDeviceKeyPair("replacement-key");
  const request = engine.requestProvisioning({
    subjectId: "subject-1",
    accountId: "account-1",
    tokenId: "pending-token",
    trustedDeviceId: "device-1",
    capMinor: 1_000,
  });

  const rotated = engine.rotateTrustedDeviceKey(
    "device-1",
    replacement,
    new Date(Date.parse(request.challenge.issuedAt) + 1_000),
  );
  assert.equal(rotated.keyId, replacement.keyId);
  assert.equal(engine.challenges.get(request.challenge.challengeId)?.status, "cancelled");
  assert.equal(
    engine.snapshot().provisioning[0].state,
    "declined",
  );
  assert.equal(engine.getToken("pending-token")?.state, "declined");
  assert.throws(
    () => engine.approveProvisioning(
      request.requestId,
      signApproval(request.challenge, oldKeys.keyId, oldKeys.privateKeyPem),
    ),
    /device key id mismatch/,
  );
  assert.throws(
    () => engine.approveProvisioning(
      request.requestId,
      signApproval(
        request.challenge,
        replacement.keyId,
        replacement.privateKeyPem,
      ),
    ),
    /challenge already terminal/,
  );

  const restored = AirlockEngine.restore(engine.snapshot());
  assert.equal(restored.getDevice("device-1")?.keyId, replacement.keyId);
  assert.equal(restored.getToken("pending-token")?.state, "declined");
  assert.equal(
    restored.challenges.get(request.challenge.challengeId)?.status,
    "cancelled",
  );
  assert.equal(restored.audit.verify(), true);
});

test("rotation cancels pending transaction and releases its cap reservation", () => {
  const { engine, oldKeys } = setup();
  const provisioning = engine.requestProvisioning({
    subjectId: "subject-1",
    accountId: "account-1",
    tokenId: "capped-token",
    trustedDeviceId: "device-1",
    capMinor: 1_000,
    now: new Date("2026-07-27T11:00:00Z"),
  });
  engine.approveProvisioning(
    provisioning.requestId,
    signApproval(
      provisioning.challenge,
      oldKeys.keyId,
      oldKeys.privateKeyPem,
    ),
    new Date("2026-07-27T11:00:01Z"),
    "capped",
  );
  const transaction = engine.authorize({
    transactionId: "pending-transaction",
    tokenId: "capped-token",
    merchantId: "merchant",
    amountMinor: 1_000,
    strategy: "pre_authorization_step_up",
    trustedDeviceId: "device-1",
    now: new Date("2026-07-27T12:00:00Z"),
  });

  engine.rotateTrustedDeviceKey(
    "device-1",
    generateDeviceKeyPair("replacement-key"),
    new Date("2026-07-27T12:00:01Z"),
  );
  const snapshot = engine.snapshot();
  assert.equal(engine.getTransaction(transaction.transactionId)?.state, "declined");
  assert.equal(
    engine.getTransaction(transaction.transactionId)?.capReservation,
    undefined,
  );
  assert.deepEqual(snapshot.dailySpend, []);
  assert.equal(
    engine.challenges.get(transaction.challenge!.challengeId)?.status,
    "cancelled",
  );
  assert.doesNotThrow(() => AirlockEngine.restore(snapshot));
});

test("compromise is terminal, invalidates approvals, and offers no recovery downgrade", () => {
  const { engine, oldKeys } = setup();
  const request = engine.requestProvisioning({
    subjectId: "subject-1",
    accountId: "account-1",
    tokenId: "compromised-token",
    trustedDeviceId: "device-1",
    capMinor: 1_000,
  });
  engine.markTrustedDeviceCompromised(
    "device-1",
    new Date(Date.parse(request.challenge.issuedAt) + 1_000),
  );

  assert.equal(engine.getDevice("device-1")?.status, "revoked");
  assert.equal(engine.challenges.get(request.challenge.challengeId)?.status, "cancelled");
  assert.throws(
    () => engine.approveProvisioning(
      request.requestId,
      signApproval(request.challenge, oldKeys.keyId, oldKeys.privateKeyPem),
    ),
    /revoked/,
  );
  assert.throws(
    () => engine.rotateTrustedDeviceKey(
      "device-1",
      generateDeviceKeyPair("replacement-key"),
    ),
    /only an active/,
  );
  assert.throws(
    () => engine.markTrustedDeviceCompromised("device-1"),
    /not active/,
  );
  const event = engine.audit.all().find(
    (candidate) => candidate.type === "trusted_device.compromised",
  )!;
  assert.equal(event.payload.recoveryDowngradeAvailable, false);
  assert.deepEqual(event.payload.invalidatedChallengeIds, [
    request.challenge.challengeId,
  ]);
});

test("key identifiers are unique, bounded, and restore rejects duplicated identity", () => {
  const { engine } = setup();
  const secondKeys = generateDeviceKeyPair("old-key");
  assert.throws(
    () => engine.enrollTrustedDevice("subject-1", secondKeys, "device-2"),
    /key id already exists/,
  );
  assert.throws(
    () => engine.rotateTrustedDeviceKey(
      "device-1",
      { ...generateDeviceKeyPair("valid"), keyId: "../invalid" },
    ),
    /invalid trusted device key id/,
  );

  const snapshot = engine.snapshot();
  snapshot.devices.push({
    ...structuredClone(snapshot.devices[0]),
    deviceId: "device-2",
  });
  assert.throws(
    () => AirlockEngine.restore(snapshot),
    /key id already exists/,
  );
});

test("rotation rejects relabeled or fleet-duplicate public-key material before invalidation", () => {
  const { engine, oldKeys } = setup();
  const request = engine.requestProvisioning({
    subjectId: "subject-1",
    accountId: "account-1",
    tokenId: "pending-token",
    trustedDeviceId: "device-1",
    capMinor: 1_000,
  });
  assert.throws(
    () => engine.rotateTrustedDeviceKey(
      "device-1",
      { ...oldKeys, keyId: "relabeled-old-key" },
    ),
    /public key must differ/,
  );
  assert.equal(engine.getDevice("device-1")?.keyId, oldKeys.keyId);
  assert.equal(
    engine.challenges.get(request.challenge.challengeId)?.status,
    "created",
  );
  assert.doesNotThrow(() => engine.approveProvisioning(
    request.requestId,
    signApproval(request.challenge, oldKeys.keyId, oldKeys.privateKeyPem),
  ));

  const sharedMaterial = generateDeviceKeyPair("fleet-key-a");
  engine.enrollTrustedDevice("subject-1", sharedMaterial, "device-2");
  assert.throws(
    () => engine.enrollTrustedDevice(
      "subject-1",
      { ...sharedMaterial, keyId: "fleet-key-b" },
      "device-3",
    ),
    /public key already exists/,
  );
  const snapshot = engine.snapshot();
  snapshot.devices.push({
    ...structuredClone(snapshot.devices.find((device) =>
      device.deviceId === "device-2")!),
    deviceId: "device-3",
    keyId: "fleet-key-b",
  });
  assert.throws(
    () => AirlockEngine.restore(snapshot),
    /public key already exists/,
  );
});

test("rotation cannot create a pre-issuance cancellation timestamp", () => {
  const { engine } = setup();
  const request = engine.requestProvisioning({
    subjectId: "subject-1",
    accountId: "account-1",
    tokenId: "future-token",
    trustedDeviceId: "device-1",
    capMinor: 1_000,
    now: new Date("2026-07-27T12:00:00Z"),
  });
  assert.throws(
    () => engine.rotateTrustedDeviceKey(
      "device-1",
      generateDeviceKeyPair("replacement-key"),
      new Date("2026-07-27T11:59:59Z"),
    ),
    /before issuance/,
  );
  assert.equal(engine.getDevice("device-1")?.keyId, "old-key");
  assert.equal(
    engine.challenges.get(request.challenge.challengeId)?.status,
    "created",
  );
});

test("mixed issuance failure leaves the complete engine snapshot unchanged", () => {
  const { engine } = setup();
  engine.requestProvisioning({
    subjectId: "subject-1",
    accountId: "account-1",
    tokenId: "older-token",
    trustedDeviceId: "device-1",
    capMinor: 1_000,
    now: new Date("2026-07-27T10:00:00Z"),
  });
  engine.requestProvisioning({
    subjectId: "subject-1",
    accountId: "account-1",
    tokenId: "future-token",
    trustedDeviceId: "device-1",
    capMinor: 1_000,
    now: new Date("2026-07-27T12:00:00Z"),
  });
  const before = engine.snapshot();
  assert.throws(
    () => engine.rotateTrustedDeviceKey(
      "device-1",
      generateDeviceKeyPair("replacement-key"),
      new Date("2026-07-27T11:00:00Z"),
    ),
    /before issuance/,
  );
  assert.deepEqual(engine.snapshot(), before);
});

function engineWithExpiredOutstandingWork() {
  const { engine, oldKeys } = setup();
  const strandedProvisioning = engine.requestProvisioning({
    subjectId: "subject-1",
    accountId: "account-1",
    tokenId: "stranded-token",
    trustedDeviceId: "device-1",
    capMinor: 1_000,
    now: new Date("2026-07-27T10:00:00Z"),
  });
  assert.throws(
    () => engine.approveProvisioning(
      strandedProvisioning.requestId,
      signApproval(
        strandedProvisioning.challenge,
        oldKeys.keyId,
        oldKeys.privateKeyPem,
      ),
      new Date(strandedProvisioning.challenge.expiresAt),
    ),
    /expired/,
  );

  const activeProvisioning = engine.requestProvisioning({
    subjectId: "subject-1",
    accountId: "account-1",
    tokenId: "capped-token",
    trustedDeviceId: "device-1",
    capMinor: 1_000,
    now: new Date("2026-07-27T11:00:00Z"),
  });
  engine.approveProvisioning(
    activeProvisioning.requestId,
    signApproval(
      activeProvisioning.challenge,
      oldKeys.keyId,
      oldKeys.privateKeyPem,
    ),
    new Date("2026-07-27T11:00:01Z"),
    "capped",
  );
  const transaction = engine.authorize({
    transactionId: "stranded-transaction",
    tokenId: "capped-token",
    merchantId: "merchant",
    amountMinor: 1_000,
    strategy: "pre_authorization_step_up",
    trustedDeviceId: "device-1",
    now: new Date("2026-07-27T12:00:00Z"),
  });
  assert.throws(
    () => engine.confirmTransaction(
      transaction.transactionId,
      signApproval(
        transaction.challenge!,
        oldKeys.keyId,
        oldKeys.privateKeyPem,
      ),
      new Date(transaction.challenge!.expiresAt),
    ),
    /expired/,
  );
  return { engine, strandedProvisioning, transaction };
}

test("rotation, revocation, and compromise reconcile already-expired pending work", () => {
  for (const action of ["rotate", "revoke", "compromise"] as const) {
    const { engine, strandedProvisioning, transaction } =
      engineWithExpiredOutstandingWork();
    const now = new Date("2026-07-27T12:01:00Z");
    if (action === "rotate") {
      engine.rotateTrustedDeviceKey(
        "device-1",
        generateDeviceKeyPair("replacement-key"),
        now,
      );
    } else if (action === "revoke") {
      engine.revokeTrustedDevice("device-1", now);
    } else {
      engine.markTrustedDeviceCompromised("device-1", now);
    }

    const snapshot = engine.snapshot();
    assert.equal(
      snapshot.provisioning.find((request) =>
        request.requestId === strandedProvisioning.requestId)?.state,
      "declined",
      action,
    );
    assert.equal(engine.getToken("stranded-token")?.state, "declined", action);
    assert.equal(engine.getTransaction(transaction.transactionId)?.state, "declined", action);
    assert.equal(
      engine.getTransaction(transaction.transactionId)?.capReservation,
      undefined,
      action,
    );
    assert.deepEqual(snapshot.dailySpend, [], action);
    assert.equal(
      engine.challenges.get(strandedProvisioning.challenge.challengeId)?.status,
      "expired",
      action,
    );
    assert.equal(
      engine.challenges.get(transaction.challenge!.challengeId)?.status,
      "expired",
      action,
    );
    assert.doesNotThrow(() => AirlockEngine.restore(snapshot), action);
  }
});

test("failed durable rotation rolls back snapshot and idempotency, then retries exactly once", async () => {
  const directory = await mkdtemp(join(tmpdir(), "airlock-key-rotation-"));
  const dbPath = join(directory, "rotation.sqlite");
  const replacement = generateDeviceKeyPair("replacement-key");
  try {
    const store = new DurableStore(dbPath);
    store.create("engine", "active", setup().engine.snapshot());
    assert.throws(
      () => store.runIdempotent(
        "key-lifecycle",
        "rotate-device-1",
        "sha256:rotation",
        (tx) => {
          const current = store.get<AirlockEngineSnapshot>("engine")!;
          const engine = AirlockEngine.restore(current.value);
          engine.rotateTrustedDeviceKey("device-1", replacement);
          tx.compareAndSwap(
            "engine",
            current.version,
            current.status,
            current.status,
            engine.snapshot(),
          );
          throw new Error("synthetic post-write failure");
        },
      ),
      /synthetic post-write failure/,
    );
    assert.equal(store.get<AirlockEngineSnapshot>("engine")?.version, 0);
    assert.equal(
      store.get<AirlockEngineSnapshot>("engine")?.value.devices[0].keyId,
      "old-key",
    );
    assert.equal(
      store.getIdempotent(
        "key-lifecycle",
        "rotate-device-1",
        "sha256:rotation",
      ),
      undefined,
    );

    let runs = 0;
    const rotate = () => store.runIdempotent(
      "key-lifecycle",
      "rotate-device-1",
      "sha256:rotation",
      (tx) => {
        runs += 1;
        const current = store.get<AirlockEngineSnapshot>("engine")!;
        const engine = AirlockEngine.restore(current.value);
        engine.rotateTrustedDeviceKey("device-1", replacement);
        const saved = tx.compareAndSwap(
          "engine",
          current.version,
          current.status,
          current.status,
          engine.snapshot(),
        );
        return { keyId: replacement.keyId, version: saved.version };
      },
    );
    const committed = rotate();
    const replayed = rotate();
    assert.equal(committed.replayed, false);
    assert.equal(replayed.replayed, true);
    assert.deepEqual(replayed.value, committed.value);
    assert.equal(runs, 1);
    assert.equal(store.get<AirlockEngineSnapshot>("engine")?.version, 1);
    assert.equal(
      store.get<AirlockEngineSnapshot>("engine")?.value.devices[0].keyId,
      replacement.keyId,
    );
    store.close();

    const restarted = new DurableStore(dbPath);
    assert.equal(
      restarted.get<AirlockEngineSnapshot>("engine")?.value.devices[0].keyId,
      replacement.keyId,
    );
    assert.equal(
      restarted.getIdempotent<{ keyId: string; version: number }>(
        "key-lifecycle",
        "rotate-device-1",
        "sha256:rotation",
      )?.version,
      1,
    );
    restarted.close();
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
