import assert from "node:assert/strict";
import { createHmac, timingSafeEqual } from "node:crypto";
import { readFile } from "node:fs/promises";
import test from "node:test";
import type { AuditLogSnapshot, AuditTrustAnchor } from "../packages/audit/auditLog.ts";
import {
  AsyncRemoteAuditLog,
  UnconfiguredAuditTrustAnchorPublisher,
  UnconfiguredRemoteAuditMacProvider,
  type AuditTrustAnchorPublisher,
  type PendingRemoteAuditCommit,
  type PublishedAuditAnchor,
  type RemoteAuditKeyMetadata,
  type RemoteAuditMacProvider,
  type RemoteAuditState,
  type RemoteAuditStateStore,
} from "../packages/audit/remoteAudit.ts";

class TestRemoteMacProvider implements RemoteAuditMacProvider {
  readonly #keys = new Map<string, {
    secret: Uint8Array;
    metadata: RemoteAuditKeyMetadata;
  }>();
  #active: string;

  constructor() {
    this.#keys.set("kms-audit-v1", {
      secret: Buffer.alloc(32, 0x31),
      metadata: { keyId: "kms-audit-v1", keyVersion: 1, status: "active" },
    });
    this.#keys.set("kms-audit-v2", {
      secret: Buffer.alloc(32, 0x42),
      metadata: { keyId: "kms-audit-v2", keyVersion: 2, status: "retired" },
    });
    this.#active = "kms-audit-v1";
  }

  rotate(): void {
    this.#keys.get(this.#active)!.metadata.status = "retired";
    this.#active = "kms-audit-v2";
    this.#keys.get(this.#active)!.metadata.status = "active";
  }

  forceRollbackForTest(): void {
    this.#keys.get(this.#active)!.metadata.status = "retired";
    this.#active = "kms-audit-v1";
    this.#keys.get(this.#active)!.metadata.status = "active";
  }

  forceEqualVersionSubstitutionForTest(): void {
    this.#keys.get(this.#active)!.metadata.status = "retired";
    this.#active = "kms-audit-v2";
    const replacement = this.#keys.get(this.#active)!.metadata;
    replacement.status = "active";
    replacement.keyVersion = 1;
  }

  async activeKey(): Promise<RemoteAuditKeyMetadata> {
    return structuredClone(this.#keys.get(this.#active)!.metadata);
  }

  async keyMetadata(keyId: string): Promise<RemoteAuditKeyMetadata | undefined> {
    const value = this.#keys.get(keyId);
    return value ? structuredClone(value.metadata) : undefined;
  }

  async createMac(
    input: Uint8Array,
    key: RemoteAuditKeyMetadata,
  ): Promise<string> {
    const record = this.#keys.get(key.keyId);
    if (!record || record.metadata.status !== "active") {
      throw new Error("KMS key is not active");
    }
    return createHmac("sha256", record.secret).update(input).digest("base64url");
  }

  async verifyMac(
    input: Uint8Array,
    tag: string,
    key: RemoteAuditKeyMetadata,
  ): Promise<boolean> {
    const record = this.#keys.get(key.keyId);
    if (!record) return false;
    const expected = createHmac("sha256", record.secret)
      .update(input)
      .digest("base64url");
    const left = Buffer.from(expected);
    const right = Buffer.from(tag);
    return left.length === right.length && timingSafeEqual(left, right);
  }
}

class MemoryAnchorPublisher implements AuditTrustAnchorPublisher {
  current?: PublishedAuditAnchor;
  failNext = false;

  async load(): Promise<PublishedAuditAnchor | undefined> {
    return this.current ? structuredClone(this.current) : undefined;
  }

  async publish(
    _logId: string,
    expectedRevision: string | undefined,
    anchor: AuditTrustAnchor,
  ): Promise<PublishedAuditAnchor> {
    if (this.failNext) {
      this.failNext = false;
      throw new Error("synthetic anchor outage");
    }
    if (this.current?.revision !== expectedRevision) {
      throw new Error("anchor compare-and-swap conflict");
    }
    const next = String(Number(this.current?.revision ?? "0") + 1);
    this.current = { anchor: structuredClone(anchor), revision: next };
    return structuredClone(this.current);
  }
}

class MemoryRemoteStateStore implements RemoteAuditStateStore {
  state: RemoteAuditState = {
    revision: 0,
    snapshot: { schemaVersion: 2, events: [] },
  };
  failCommit: "none" | "before" | "after" = "none";

  async load(): Promise<RemoteAuditState> {
    return structuredClone(this.state);
  }

  async prepare(
    _logId: string,
    expectedRevision: number,
    pending: PendingRemoteAuditCommit,
  ): Promise<void> {
    if (this.state.revision !== expectedRevision || this.state.pending) {
      throw new Error("state compare-and-swap conflict");
    }
    this.state.pending = structuredClone(pending);
  }

  async commit(_logId: string, commitId: string): Promise<void> {
    if (!this.state.pending || this.state.pending.commitId !== commitId) {
      throw new Error("pending audit commit mismatch");
    }
    if (this.failCommit === "before") {
      this.failCommit = "none";
      throw new Error("synthetic pre-commit crash");
    }
    this.state.snapshot = structuredClone(this.state.pending.snapshot);
    this.state.revision += 1;
    delete this.state.pending;
    if (this.failCommit === "after") {
      this.failCommit = "none";
      throw new Error("synthetic post-commit crash");
    }
  }

  async abort(_logId: string, commitId: string): Promise<void> {
    if (this.state.pending?.commitId === commitId) delete this.state.pending;
  }
}

function dependencies() {
  return {
    logId: "issuer-audit",
    provider: new TestRemoteMacProvider(),
    publisher: new MemoryAnchorPublisher(),
    store: new MemoryRemoteStateStore(),
  };
}

test("remote audit appends without exposing raw key bytes to the application boundary", async () => {
  const deps = dependencies();
  const log = await AsyncRemoteAuditLog.open(deps);
  const metadata = await deps.provider.activeKey();
  assert.deepEqual(Object.keys(metadata).sort(), ["keyId", "keyVersion", "status"]);
  const event = await log.append(
    "authorization.received",
    "auth-1",
    { amountMinor: 2500 },
    new Date("2026-07-28T12:00:00.000Z"),
  );
  assert.equal(event.authentication?.keyId, "kms-audit-v1");
  assert.equal(log.snapshot().events.length, 1);
  assert.equal(log.trustAnchor().eventCount, 1);
  assert.equal(JSON.stringify(log.snapshot()).includes("3131313131"), false);
  assert.equal((await AsyncRemoteAuditLog.open(deps)).snapshot().events.length, 1);
});

test("machine-readable custody contract prohibits raw-key and fallback claims", async () => {
  const contract = JSON.parse(await readFile(
    new URL(
      "../contracts/audit/remote-audit-custody.v1.json",
      import.meta.url,
    ),
    "utf8",
  ));
  assert.equal(contract.status, "adapter-contract-unconfigured");
  assert.deepEqual(contract.implementedExternalAdapters, []);
  assert.equal(
    contract.macProvider.methods.activeKey.rawKeyMaterialReturned,
    false,
  );
  assert.ok(contract.prohibitedFallbacks.includes(
    "local HMAC when the remote provider is unavailable",
  ));
});

test("anchor publish failure aborts the prepared event without changing committed state", async () => {
  const deps = dependencies();
  const log = await AsyncRemoteAuditLog.open(deps);
  deps.publisher.failNext = true;
  await assert.rejects(
    () => log.append("event", "corr", {}, new Date("2026-07-28T12:00:00.000Z")),
    /anchor outage/,
  );
  assert.equal(deps.store.state.snapshot.events.length, 0);
  assert.equal(deps.store.state.pending, undefined);
  assert.equal(deps.publisher.current?.anchor.eventCount, 0);
  assert.equal((await AsyncRemoteAuditLog.open(deps)).snapshot().events.length, 0);
});

test("crash after anchor publication is completed exactly once during reopen", async () => {
  const deps = dependencies();
  const log = await AsyncRemoteAuditLog.open(deps);
  deps.store.failCommit = "before";
  await assert.rejects(
    () => log.append("event", "corr", {}, new Date("2026-07-28T12:00:00.000Z")),
    /pre-commit crash/,
  );
  assert.equal(deps.store.state.snapshot.events.length, 0);
  assert.ok(deps.store.state.pending);
  assert.equal(deps.publisher.current?.anchor.eventCount, 1);
  const recovered = await AsyncRemoteAuditLog.open(deps);
  assert.equal(recovered.snapshot().events.length, 1);
  assert.equal(deps.store.state.pending, undefined);
  assert.equal(recovered.trustAnchor().eventCount, 1);
});

test("post-commit crash remains committed and reopen does not duplicate it", async () => {
  const deps = dependencies();
  const log = await AsyncRemoteAuditLog.open(deps);
  deps.store.failCommit = "after";
  await assert.rejects(
    () => log.append("event", "corr", {}, new Date("2026-07-28T12:00:00.000Z")),
    /post-commit crash/,
  );
  assert.equal(deps.store.state.snapshot.events.length, 1);
  assert.equal(deps.store.state.pending, undefined);
  const recovered = await AsyncRemoteAuditLog.open(deps);
  assert.equal(recovered.snapshot().events.length, 1);
});

test("concurrent appends permit one prepared revision and reject the stale writer", async () => {
  const deps = dependencies();
  const log = await AsyncRemoteAuditLog.open(deps);
  const results = await Promise.allSettled([
    log.append("one", "corr", {}, new Date("2026-07-28T12:00:00.000Z")),
    log.append("two", "corr", {}, new Date("2026-07-28T12:00:01.000Z")),
  ]);
  assert.equal(results.filter((result) => result.status === "fulfilled").length, 1);
  assert.equal(results.filter((result) => result.status === "rejected").length, 1);
  assert.equal((await AsyncRemoteAuditLog.open(deps)).snapshot().events.length, 1);
});

test("rotation keeps historical verification and active-key rollback fails closed", async () => {
  const deps = dependencies();
  let log = await AsyncRemoteAuditLog.open(deps);
  await log.append("before", "corr", {}, new Date("2026-07-28T12:00:00.000Z"));
  deps.provider.rotate();
  log = await AsyncRemoteAuditLog.open(deps);
  await log.append("after", "corr", {}, new Date("2026-07-28T12:01:00.000Z"));
  assert.deepEqual(
    log.snapshot().events.map((event) => event.authentication?.keyVersion),
    [1, 2],
  );
  assert.equal((await AsyncRemoteAuditLog.open(deps)).snapshot().events.length, 2);
  deps.provider.forceRollbackForTest();
  await assert.rejects(
    () => AsyncRemoteAuditLog.open(deps),
    /verification failed/,
  );
});

test("equal-version key substitution is rejected before an anchor can advance", async () => {
  const deps = dependencies();
  const log = await AsyncRemoteAuditLog.open(deps);
  await log.append("before", "corr", {}, new Date("2026-07-28T12:00:00.000Z"));
  const anchor = log.trustAnchor();
  deps.provider.forceEqualVersionSubstitutionForTest();
  await assert.rejects(
    () => log.append("substitution", "corr", {}, new Date("2026-07-28T12:01:00.000Z")),
    /rollback detected/,
  );
  assert.deepEqual(log.trustAnchor(), anchor);
  assert.equal(deps.store.state.snapshot.events.length, 1);
});

test("external anchor rollback and unconfigured production adapters fail closed", async () => {
  const deps = dependencies();
  const log = await AsyncRemoteAuditLog.open(deps);
  const emptyAnchor = structuredClone(deps.publisher.current!);
  await log.append("event", "corr", {}, new Date("2026-07-28T12:00:00.000Z"));
  deps.publisher.current = emptyAnchor;
  await assert.rejects(
    () => AsyncRemoteAuditLog.open(deps),
    /verification failed/,
  );

  await assert.rejects(
    () => AsyncRemoteAuditLog.open({
      logId: "unconfigured",
      provider: new UnconfiguredRemoteAuditMacProvider(),
      publisher: new UnconfiguredAuditTrustAnchorPublisher(),
      store: new MemoryRemoteStateStore(),
    }),
    /not configured/,
  );
});
