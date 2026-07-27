import assert from "node:assert/strict";
import { createHash, createHmac } from "node:crypto";
import test from "node:test";
import {
  AuditLog,
  InMemoryAuditKeyring,
  type AuditEvent,
  type AuditLogSnapshot,
} from "../packages/audit/auditLog.ts";

function key(fill: number): Uint8Array {
  return new Uint8Array(32).fill(fill);
}

function keyring(): InMemoryAuditKeyring {
  return new InMemoryAuditKeyring(
    [
      { keyId: "audit-2026-q3", key: key(0x31) },
      { keyId: "audit-2026-q4", key: key(0x42) },
    ],
    "audit-2026-q3",
  );
}

function recomputeUnauthenticatedHashes(events: AuditEvent[]): void {
  let previousHash = "GENESIS";
  for (const event of events) {
    event.previousHash = previousHash;
    const { hash: _hash, authentication: _authentication, ...body } = event;
    event.hash = createHash("sha256")
      .update(JSON.stringify(body))
      .digest("hex");
    previousHash = event.hash;
  }
}

test("authenticated snapshot restores only with external keys and exact anchor", () => {
  const keys = keyring();
  const log = new AuditLog(keys);
  log.append("provisioning.requested", "request-1", { decision: "pending" });
  log.append("provisioning.approved", "request-1", { decision: "approved" });
  const snapshot = log.snapshot();
  const anchor = log.trustAnchor();

  assert.equal(snapshot.schemaVersion, 2);
  assert.equal("key" in snapshot, false);
  assert.equal(JSON.stringify(snapshot).includes(Buffer.from(key(0x31)).toString("hex")), false);
  assert.throws(
    () => AuditLog.restore(snapshot),
    /external key provider and trust anchor/,
  );
  const restored = AuditLog.restore(snapshot, {
    keyProvider: keys,
    expectedTrustAnchor: anchor,
  });
  assert.equal(restored.verify(), true);
  assert.equal(restored.verifyTrustAnchor(anchor), true);
});

test("whole-chain hash recomputation cannot forge authenticated evidence", () => {
  const keys = keyring();
  const log = new AuditLog(keys);
  log.append("authorization.received", "tx-1", { amountMinor: 100 });
  log.append("authorization.declined", "tx-1", { reason: "airlock_required" });
  const anchor = log.trustAnchor();
  const forged = structuredClone(log.snapshot());
  forged.events[0].payload.amountMinor = 1;
  recomputeUnauthenticatedHashes(forged.events);

  assert.throws(
    () =>
      AuditLog.restore(forged, {
        keyProvider: keys,
        expectedTrustAnchor: anchor,
      }),
    /chain verification failed/,
  );
});

test("external anchor detects deletion of a valid authenticated suffix", () => {
  const keys = keyring();
  const log = new AuditLog(keys);
  log.append("one", "correlation", {});
  log.append("two", "correlation", {});
  log.append("three", "correlation", {});
  const fullAnchor = log.trustAnchor();
  const truncated = structuredClone(log.snapshot()) as AuditLogSnapshot;
  truncated.events.pop();

  assert.throws(
    () =>
      AuditLog.restore(truncated, {
        keyProvider: keys,
        expectedTrustAnchor: fullAnchor,
      }),
    /does not match external trust anchor/,
  );
});

test("key rotation is explicit, versioned per event, and needs historical keys", () => {
  const keys = keyring();
  const log = new AuditLog(keys);
  log.append("before.rotation", "correlation", {});
  keys.activate("audit-2026-q4");
  log.append("after.rotation", "correlation", {});
  const snapshot = log.snapshot();
  const anchor = log.trustAnchor();

  assert.deepEqual(
    snapshot.events.map((event) => ({
      keyId: event.authentication?.keyId,
      keyVersion: event.authentication?.keyVersion,
    })),
    [
      { keyId: "audit-2026-q3", keyVersion: 1 },
      { keyId: "audit-2026-q4", keyVersion: 2 },
    ],
  );
  assert.equal(
    AuditLog.restore(snapshot, {
      keyProvider: keys,
      expectedTrustAnchor: anchor,
    }).verify(),
    true,
  );

  const currentOnly = new InMemoryAuditKeyring(
    [{ keyId: "audit-2026-q4", key: key(0x42) }],
    "audit-2026-q4",
  );
  assert.throws(
    () =>
      AuditLog.restore(snapshot, {
        keyProvider: currentOnly,
        expectedTrustAnchor: anchor,
      }),
    /chain verification failed/,
  );
});

test("retired key rollback cannot append or restore but remains historically verifiable", () => {
  const keys = keyring();
  const log = new AuditLog(keys);
  log.append("before.rotation", "correlation", {});
  keys.activate("audit-2026-q4");
  log.append("after.rotation", "correlation", {});
  const snapshot = log.snapshot();
  const anchor = log.trustAnchor();

  assert.throws(
    () => keys.activate("audit-2026-q3"),
    /retired audit key cannot be reactivated/,
  );
  const appended = log.append("still.current", "correlation", {});
  assert.equal(appended.authentication?.keyId, "audit-2026-q4");
  assert.equal(appended.authentication?.keyVersion, 2);

  const restoredHistorical = AuditLog.restore(snapshot, {
    keyProvider: keys,
    expectedTrustAnchor: anchor,
  });
  assert.equal(restoredHistorical.verify(), true);

  const rollback = structuredClone(snapshot);
  const body = {
    sequence: 3,
    eventId: crypto.randomUUID(),
    type: "retired.rollback",
    correlationId: "correlation",
    causationId: undefined,
    occurredAt: "2026-07-27T12:00:00.000Z",
    payload: {},
    previousHash: rollback.events[1].hash,
  };
  const hash = createHash("sha256").update(JSON.stringify(body)).digest("hex");
  const previousAuthenticationTag =
    rollback.events[1].authentication!.tag;
  const tag = createHmac("sha256", key(0x31))
    .update("airlock-audit-hmac-v1\n")
    .update("3\n")
    .update(hash)
    .update("\naudit-2026-q3\n1\n")
    .update(previousAuthenticationTag)
    .digest("base64url");
  rollback.events.push({
    ...body,
    hash,
    authentication: {
      algorithm: "hmac-sha256",
      keyId: "audit-2026-q3",
      keyVersion: 1,
      previousAuthenticationTag,
      tag,
    },
  });
  const forgedAnchor = {
    schemaVersion: 1 as const,
    eventCount: 3,
    tipHash: hash,
    tipAuthenticationTag: tag,
    tipKeyId: "audit-2026-q3",
    tipKeyVersion: 1,
    activeKeyId: "audit-2026-q4",
    activeKeyVersion: 2,
  };
  assert.throws(
    () =>
      AuditLog.restore(rollback, {
        keyProvider: keys,
        expectedTrustAnchor: forgedAnchor,
      }),
    /chain verification failed/,
  );
});

test("invalid HMAC key material and duplicate key ids fail closed", () => {
  assert.throws(
    () =>
      new InMemoryAuditKeyring(
        [{ keyId: "audit-short", key: new Uint8Array(16) }],
        "audit-short",
      ),
    /at least 32 bytes/,
  );
  assert.throws(
    () =>
      new InMemoryAuditKeyring(
        [
          { keyId: "duplicate", key: key(1) },
          { keyId: "duplicate", key: key(2) },
        ],
        "duplicate",
      ),
    /already exists/,
  );
});
