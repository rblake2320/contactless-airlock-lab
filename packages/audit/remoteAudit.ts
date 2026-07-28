import { createHash } from "node:crypto";
import type {
  AuditAuthentication,
  AuditEvent,
  AuditLogSnapshot,
  AuditTrustAnchor,
} from "./auditLog.ts";

const HASH_GENESIS = "GENESIS";
const AUTHENTICATION_GENESIS = "AUTH-GENESIS";
const KEY_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;

export interface RemoteAuditKeyMetadata {
  keyId: string;
  keyVersion: number;
  status: "active" | "retired";
}

/**
 * KMS/HSM boundary. Implementations receive canonical MAC input and return or
 * verify a tag. Raw key bytes are never part of this interface.
 */
export interface RemoteAuditMacProvider {
  activeKey(): Promise<RemoteAuditKeyMetadata>;
  keyMetadata(keyId: string): Promise<RemoteAuditKeyMetadata | undefined>;
  createMac(input: Uint8Array, key: RemoteAuditKeyMetadata): Promise<string>;
  verifyMac(
    input: Uint8Array,
    tag: string,
    key: RemoteAuditKeyMetadata,
  ): Promise<boolean>;
}

export interface PublishedAuditAnchor {
  anchor: AuditTrustAnchor;
  revision: string;
}

/**
 * Must be a physically/administratively independent persistence boundary.
 * publish is compare-and-swap: expectedRevision undefined means create-only.
 */
export interface AuditTrustAnchorPublisher {
  load(logId: string): Promise<PublishedAuditAnchor | undefined>;
  publish(
    logId: string,
    expectedRevision: string | undefined,
    anchor: AuditTrustAnchor,
  ): Promise<PublishedAuditAnchor>;
}

export interface PendingRemoteAuditCommit {
  commitId: string;
  snapshot: AuditLogSnapshot;
  anchor: AuditTrustAnchor;
}

export interface RemoteAuditState {
  revision: number;
  snapshot: AuditLogSnapshot;
  pending?: PendingRemoteAuditCommit;
}

/**
 * Local durable journal. prepare/commit/abort must each be atomic and use the
 * supplied revision/commit identity as a compare-and-swap guard.
 */
export interface RemoteAuditStateStore {
  load(logId: string): Promise<RemoteAuditState>;
  prepare(
    logId: string,
    expectedRevision: number,
    pending: PendingRemoteAuditCommit,
  ): Promise<void>;
  commit(logId: string, commitId: string): Promise<void>;
  abort(logId: string, commitId: string): Promise<void>;
}

export class UnconfiguredRemoteAuditMacProvider implements RemoteAuditMacProvider {
  async activeKey(): Promise<RemoteAuditKeyMetadata> {
    throw new Error("remote audit MAC provider is not configured");
  }
  async keyMetadata(_keyId: string): Promise<RemoteAuditKeyMetadata | undefined> {
    throw new Error("remote audit MAC provider is not configured");
  }
  async createMac(
    _input: Uint8Array,
    _key: RemoteAuditKeyMetadata,
  ): Promise<string> {
    throw new Error("remote audit MAC provider is not configured");
  }
  async verifyMac(
    _input: Uint8Array,
    _tag: string,
    _key: RemoteAuditKeyMetadata,
  ): Promise<boolean> {
    throw new Error("remote audit MAC provider is not configured");
  }
}

export class UnconfiguredAuditTrustAnchorPublisher
  implements AuditTrustAnchorPublisher {
  async load(_logId: string): Promise<PublishedAuditAnchor | undefined> {
    throw new Error("audit trust-anchor publisher is not configured");
  }
  async publish(
    _logId: string,
    _expectedRevision: string | undefined,
    _anchor: AuditTrustAnchor,
  ): Promise<PublishedAuditAnchor> {
    throw new Error("audit trust-anchor publisher is not configured");
  }
}

function digest(value: unknown): string {
  return createHash("sha256").update(JSON.stringify(value)).digest("hex");
}

function macInput(
  event: Pick<AuditEvent, "sequence" | "hash">,
  key: Pick<RemoteAuditKeyMetadata, "keyId" | "keyVersion">,
  previousAuthenticationTag: string,
): Uint8Array {
  return Buffer.from([
    "airlock-audit-hmac-v1",
    String(event.sequence),
    event.hash,
    key.keyId,
    String(key.keyVersion),
    previousAuthenticationTag,
  ].join("\n"), "utf8");
}

function anchorsEqual(
  left: AuditTrustAnchor,
  right: AuditTrustAnchor,
): boolean {
  return (
    left?.schemaVersion === right.schemaVersion &&
    left.eventCount === right.eventCount &&
    left.tipHash === right.tipHash &&
    left.tipAuthenticationTag === right.tipAuthenticationTag &&
    left.tipKeyId === right.tipKeyId &&
    left.tipKeyVersion === right.tipKeyVersion &&
    left.activeKeyId === right.activeKeyId &&
    left.activeKeyVersion === right.activeKeyVersion
  );
}

function validateMetadata(key: RemoteAuditKeyMetadata): void {
  if (
    !key ||
    !KEY_ID.test(key.keyId) ||
    !Number.isSafeInteger(key.keyVersion) ||
    key.keyVersion < 1 ||
    !["active", "retired"].includes(key.status)
  ) {
    throw new Error("invalid remote audit key metadata");
  }
}

function anchorFor(
  events: AuditEvent[],
  active: RemoteAuditKeyMetadata,
): AuditTrustAnchor {
  const tip = events.at(-1);
  return {
    schemaVersion: 1,
    eventCount: events.length,
    tipHash: tip?.hash ?? HASH_GENESIS,
    tipAuthenticationTag:
      tip?.authentication?.tag ?? AUTHENTICATION_GENESIS,
    ...(tip?.authentication?.keyId
      ? { tipKeyId: tip.authentication.keyId }
      : {}),
    ...(tip?.authentication?.keyVersion
      ? { tipKeyVersion: tip.authentication.keyVersion }
      : {}),
    activeKeyId: active.keyId,
    activeKeyVersion: active.keyVersion,
  };
}

async function verifySnapshot(
  snapshot: AuditLogSnapshot,
  provider: RemoteAuditMacProvider,
): Promise<boolean> {
  if (snapshot.schemaVersion !== 2 || !Array.isArray(snapshot.events)) return false;
  let previousHash = HASH_GENESIS;
  let previousTag = AUTHENTICATION_GENESIS;
  let previousVersion = 0;
  let previousKeyId: string | undefined;
  for (const [index, event] of snapshot.events.entries()) {
    if (
      !event ||
      event.sequence !== index + 1 ||
      typeof event.eventId !== "string" ||
      event.eventId.length === 0 ||
      typeof event.type !== "string" ||
      event.type.length === 0 ||
      typeof event.correlationId !== "string" ||
      event.correlationId.length === 0 ||
      (event.causationId !== undefined && typeof event.causationId !== "string") ||
      typeof event.occurredAt !== "string" ||
      !Number.isFinite(Date.parse(event.occurredAt)) ||
      !event.payload ||
      typeof event.payload !== "object" ||
      Array.isArray(event.payload) ||
      typeof event.previousHash !== "string" ||
      typeof event.hash !== "string" ||
      !/^[a-f0-9]{64}$/.test(event.hash) ||
      !event.authentication ||
      event.authentication.algorithm !== "hmac-sha256" ||
      !KEY_ID.test(event.authentication.keyId) ||
      !Number.isSafeInteger(event.authentication.keyVersion) ||
      event.authentication.keyVersion < 1 ||
      typeof event.authentication.previousAuthenticationTag !== "string" ||
      !(
        event.authentication.previousAuthenticationTag ===
          AUTHENTICATION_GENESIS ||
        /^[A-Za-z0-9_-]{43}$/.test(
          event.authentication.previousAuthenticationTag,
        )
      ) ||
      typeof event.authentication.tag !== "string" ||
      !/^[A-Za-z0-9_-]{43}$/.test(event.authentication.tag)
    ) return false;
    const { hash, authentication: _authentication, ...body } = event;
    if (event.previousHash !== previousHash || digest(body) !== hash) return false;
    const authentication = event.authentication;
    if (authentication.previousAuthenticationTag !== previousTag) return false;
    const key = await provider.keyMetadata(authentication.keyId);
    if (!key) return false;
    validateMetadata(key);
    if (
      key.keyVersion !== authentication.keyVersion ||
      key.keyVersion < previousVersion ||
      (key.keyVersion === previousVersion && previousKeyId !== undefined &&
        key.keyId !== previousKeyId)
    ) return false;
    if (!await provider.verifyMac(
      macInput(event, key, previousTag),
      authentication.tag,
      key,
    )) return false;
    previousHash = hash;
    previousTag = authentication.tag;
    previousVersion = key.keyVersion;
    previousKeyId = key.keyId;
  }
  return true;
}

export class AsyncRemoteAuditLog {
  readonly #logId: string;
  readonly #provider: RemoteAuditMacProvider;
  readonly #publisher: AuditTrustAnchorPublisher;
  readonly #store: RemoteAuditStateStore;
  #state: RemoteAuditState;
  #published: PublishedAuditAnchor;

  private constructor(
    logId: string,
    provider: RemoteAuditMacProvider,
    publisher: AuditTrustAnchorPublisher,
    store: RemoteAuditStateStore,
    state: RemoteAuditState,
    published: PublishedAuditAnchor,
  ) {
    this.#logId = logId;
    this.#provider = provider;
    this.#publisher = publisher;
    this.#store = store;
    this.#state = state;
    this.#published = published;
  }

  static async open(input: {
    logId: string;
    provider: RemoteAuditMacProvider;
    publisher: AuditTrustAnchorPublisher;
    store: RemoteAuditStateStore;
  }): Promise<AsyncRemoteAuditLog> {
    if (!KEY_ID.test(input.logId)) throw new Error("invalid remote audit log id");
    let state = await input.store.load(input.logId);
    let published = await input.publisher.load(input.logId);
    if (state.pending) {
      if (published && anchorsEqual(published.anchor, state.pending.anchor)) {
        await input.store.commit(input.logId, state.pending.commitId);
      } else {
        await input.store.abort(input.logId, state.pending.commitId);
      }
      state = await input.store.load(input.logId);
      published = await input.publisher.load(input.logId);
    }
    const active = await input.provider.activeKey();
    validateMetadata(active);
    if (active.status !== "active") throw new Error("remote active audit key is not active");
    if (!published) {
      if (state.snapshot.events.length !== 0) {
        throw new Error("non-empty remote audit log has no external trust anchor");
      }
      published = await input.publisher.publish(
        input.logId,
        undefined,
        anchorFor(state.snapshot.events, active),
      );
    }
    const anchoredActive: RemoteAuditKeyMetadata = {
      keyId: published.anchor.activeKeyId,
      keyVersion: published.anchor.activeKeyVersion,
      status: published.anchor.activeKeyId === active.keyId ? "active" : "retired",
    };
    validateMetadata(anchoredActive);
    const expected = anchorFor(state.snapshot.events, anchoredActive);
    if (
      !anchorsEqual(published.anchor, expected) ||
      active.keyVersion < published.anchor.activeKeyVersion ||
      (active.keyVersion === published.anchor.activeKeyVersion &&
        active.keyId !== published.anchor.activeKeyId) ||
      !await verifySnapshot(state.snapshot, input.provider)
    ) {
      throw new Error("remote audit state or external trust anchor verification failed");
    }
    return new AsyncRemoteAuditLog(
      input.logId,
      input.provider,
      input.publisher,
      input.store,
      state,
      published,
    );
  }

  async append(
    type: string,
    correlationId: string,
    payload: Record<string, unknown>,
    occurredAt = new Date(),
    causationId?: string,
  ): Promise<AuditEvent> {
    if (!type || !correlationId || !Number.isFinite(occurredAt.getTime())) {
      throw new Error("invalid remote audit event");
    }
    const active = await this.#provider.activeKey();
    validateMetadata(active);
    if (active.status !== "active") throw new Error("remote active audit key is not active");
    const previous = this.#state.snapshot.events.at(-1);
    if (
      previous?.authentication &&
      (
        active.keyVersion < previous.authentication.keyVersion ||
        (active.keyVersion === previous.authentication.keyVersion &&
          active.keyId !== previous.authentication.keyId)
      )
    ) {
      throw new Error("remote audit key version rollback detected");
    }
    const body = {
      sequence: this.#state.snapshot.events.length + 1,
      eventId: crypto.randomUUID(),
      type,
      correlationId,
      causationId,
      occurredAt: occurredAt.toISOString(),
      payload: structuredClone(payload),
      previousHash: previous?.hash ?? HASH_GENESIS,
    };
    const base: AuditEvent = { ...body, hash: digest(body) };
    const previousTag =
      previous?.authentication?.tag ?? AUTHENTICATION_GENESIS;
    const tag = await this.#provider.createMac(
      macInput(base, active, previousTag),
      active,
    );
    if (!/^[A-Za-z0-9_-]{43}$/.test(tag)) {
      throw new Error("remote audit MAC provider returned an invalid tag");
    }
    const authentication: AuditAuthentication = {
      algorithm: "hmac-sha256",
      keyId: active.keyId,
      keyVersion: active.keyVersion,
      previousAuthenticationTag: previousTag,
      tag,
    };
    const event = { ...base, authentication };
    const snapshot: AuditLogSnapshot = {
      schemaVersion: 2,
      events: [...this.#state.snapshot.events, event],
    };
    const anchor = anchorFor(snapshot.events, active);
    const pending: PendingRemoteAuditCommit = {
      commitId: crypto.randomUUID(),
      snapshot,
      anchor,
    };
    await this.#store.prepare(this.#logId, this.#state.revision, pending);
    let published: PublishedAuditAnchor;
    try {
      published = await this.#publisher.publish(
        this.#logId,
        this.#published.revision,
        anchor,
      );
    } catch (error) {
      await this.#store.abort(this.#logId, pending.commitId);
      throw error;
    }
    await this.#store.commit(this.#logId, pending.commitId);
    this.#state = await this.#store.load(this.#logId);
    this.#published = published;
    return structuredClone(event);
  }

  snapshot(): AuditLogSnapshot {
    return structuredClone(this.#state.snapshot);
  }

  trustAnchor(): AuditTrustAnchor {
    return structuredClone(this.#published.anchor);
  }
}
