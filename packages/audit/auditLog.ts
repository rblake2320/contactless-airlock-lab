import {
  createHash,
  createHmac,
  timingSafeEqual,
} from "node:crypto";

const HASH_GENESIS = "GENESIS";
const AUTHENTICATION_GENESIS = "AUTH-GENESIS";
const KEY_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;

export interface AuditAuthentication {
  algorithm: "hmac-sha256";
  keyId: string;
  keyVersion: number;
  previousAuthenticationTag: string;
  tag: string;
}

export interface AuditEvent {
  sequence: number;
  eventId: string;
  type: string;
  correlationId: string;
  causationId?: string;
  occurredAt: string;
  payload: Record<string, unknown>;
  previousHash: string;
  hash: string;
  authentication?: AuditAuthentication;
}

export interface AuditLogSnapshot {
  schemaVersion: 1 | 2;
  events: AuditEvent[];
}

/**
 * Store this checkpoint outside the snapshot/SQLite trust boundary.
 *
 * It is not secret, but co-locating it with the mutable snapshot lets an
 * attacker truncate both to the same earlier valid prefix.
 */
export interface AuditTrustAnchor {
  schemaVersion: 1;
  eventCount: number;
  tipHash: string;
  tipAuthenticationTag: string;
  tipKeyId?: string;
  tipKeyVersion?: number;
  activeKeyId: string;
  activeKeyVersion: number;
}

export interface ActiveAuditKey {
  keyId: string;
  keyVersion: number;
  key: Uint8Array;
}

export interface VerificationAuditKey extends ActiveAuditKey {
  status: "active" | "retired";
}

/**
 * Production adapters should resolve key bytes from an HSM/KMS-backed service.
 * Keys and provider configuration must never be serialized into AuditLogSnapshot.
 */
export interface AuditKeyProvider {
  activeKey(): ActiveAuditKey;
  keyFor(keyId: string): VerificationAuditKey | undefined;
}

/**
 * Process-memory keyring for deterministic tests and simulator integration.
 * This is not an HSM/KMS and does not establish production key custody.
 */
export class InMemoryAuditKeyring implements AuditKeyProvider {
  readonly #keys = new Map<string, {
    key: Uint8Array;
    status: "provisioned" | "active" | "retired";
    keyVersion?: number;
  }>();
  #activeKeyId: string;
  #latestKeyVersion = 0;

  constructor(
    keys: ReadonlyArray<{ keyId: string; key: Uint8Array }>,
    activeKeyId: string,
  ) {
    if (keys.length === 0) throw new Error("audit keyring requires a key");
    for (const value of keys) this.add(value.keyId, value.key);
    if (!this.#keys.has(activeKeyId)) {
      throw new Error("active audit key is not provisioned");
    }
    this.#activeKeyId = activeKeyId;
    const active = this.#keys.get(activeKeyId)!;
    active.status = "active";
    active.keyVersion = ++this.#latestKeyVersion;
  }

  add(keyId: string, key: Uint8Array): void {
    validateKey(keyId, key);
    if (this.#keys.has(keyId)) throw new Error("audit key id already exists");
    this.#keys.set(keyId, {
      key: Uint8Array.from(key),
      status: "provisioned",
    });
  }

  activate(keyId: string): void {
    const next = this.#keys.get(keyId);
    if (!next) throw new Error("audit key is not provisioned");
    if (next.status === "retired") {
      throw new Error("retired audit key cannot be reactivated");
    }
    if (next.status === "active") throw new Error("audit key is already active");
    const current = this.#keys.get(this.#activeKeyId)!;
    current.status = "retired";
    next.status = "active";
    next.keyVersion = ++this.#latestKeyVersion;
    this.#activeKeyId = keyId;
  }

  activeKey(): ActiveAuditKey {
    const active = this.#keys.get(this.#activeKeyId)!;
    return {
      keyId: this.#activeKeyId,
      keyVersion: active.keyVersion!,
      key: Uint8Array.from(active.key),
    };
  }

  keyFor(keyId: string): VerificationAuditKey | undefined {
    const record = this.#keys.get(keyId);
    if (
      !record ||
      record.status === "provisioned" ||
      record.keyVersion === undefined
    ) {
      return undefined;
    }
    return {
      keyId,
      keyVersion: record.keyVersion,
      key: Uint8Array.from(record.key),
      status: record.status,
    };
  }
}

export interface RestoreAuthenticatedAudit {
  keyProvider: AuditKeyProvider;
  expectedTrustAnchor: AuditTrustAnchor;
}

function validateKey(keyId: string, key: Uint8Array): void {
  if (!KEY_ID_PATTERN.test(keyId)) throw new Error("invalid audit key id");
  if (!(key instanceof Uint8Array) || key.byteLength < 32) {
    throw new Error("audit HMAC key must contain at least 32 bytes");
  }
}

function digest(value: unknown): string {
  return createHash("sha256").update(JSON.stringify(value)).digest("hex");
}

function authenticationTag(
  key: Uint8Array,
  event: Pick<AuditEvent, "sequence" | "hash">,
  keyId: string,
  keyVersion: number,
  previousAuthenticationTag: string,
): string {
  return createHmac("sha256", key)
    .update("airlock-audit-hmac-v1\n")
    .update(String(event.sequence))
    .update("\n")
    .update(event.hash)
    .update("\n")
    .update(keyId)
    .update("\n")
    .update(String(keyVersion))
    .update("\n")
    .update(previousAuthenticationTag)
    .digest("base64url");
}

function tagsEqual(left: string, right: string): boolean {
  const a = Buffer.from(left, "base64url");
  const b = Buffer.from(right, "base64url");
  return a.length === b.length && timingSafeEqual(a, b);
}

function validateAuthentication(value: AuditAuthentication): boolean {
  const fields = Object.keys(value ?? {}).sort();
  return (
    fields.length === 5 &&
    fields.join(",") ===
      "algorithm,keyId,keyVersion,previousAuthenticationTag,tag" &&
    value?.algorithm === "hmac-sha256" &&
    KEY_ID_PATTERN.test(value.keyId) &&
    Number.isSafeInteger(value.keyVersion) &&
    value.keyVersion > 0 &&
    typeof value.previousAuthenticationTag === "string" &&
    (value.previousAuthenticationTag === AUTHENTICATION_GENESIS ||
      /^[A-Za-z0-9_-]{43}$/.test(value.previousAuthenticationTag)) &&
    typeof value.tag === "string" &&
    /^[A-Za-z0-9_-]{43}$/.test(value.tag)
  );
}

export class AuditLog {
  readonly #events: AuditEvent[] = [];
  readonly #keyProvider?: AuditKeyProvider;

  constructor(keyProvider?: AuditKeyProvider) {
    this.#keyProvider = keyProvider;
  }

  static restore(
    snapshot: AuditLogSnapshot,
    authenticated?: RestoreAuthenticatedAudit,
  ): AuditLog {
    if (
      !snapshot ||
      ![1, 2].includes(snapshot.schemaVersion) ||
      !Array.isArray(snapshot.events)
    ) {
      throw new Error("invalid audit snapshot");
    }
    if (snapshot.schemaVersion === 2 && !authenticated) {
      throw new Error(
        "authenticated audit restore requires an external key provider and trust anchor",
      );
    }
    if (snapshot.schemaVersion === 1 && authenticated) {
      throw new Error("legacy audit snapshot has no authenticated evidence");
    }
    const log = new AuditLog(authenticated?.keyProvider);
    for (const [index, candidate] of snapshot.events.entries()) {
      if (
        !candidate ||
        candidate.sequence !== index + 1 ||
        typeof candidate.eventId !== "string" ||
        typeof candidate.type !== "string" ||
        typeof candidate.correlationId !== "string" ||
        (candidate.causationId !== undefined && typeof candidate.causationId !== "string") ||
        typeof candidate.occurredAt !== "string" ||
        !Number.isFinite(Date.parse(candidate.occurredAt)) ||
        !candidate.payload ||
        typeof candidate.payload !== "object" ||
        Array.isArray(candidate.payload) ||
        typeof candidate.previousHash !== "string" ||
        typeof candidate.hash !== "string" ||
        (snapshot.schemaVersion === 1 && candidate.authentication !== undefined) ||
        (snapshot.schemaVersion === 2 &&
          (!candidate.authentication ||
            !validateAuthentication(candidate.authentication)))
      ) {
        throw new Error("invalid audit snapshot event");
      }
      log.#events.push(structuredClone(candidate));
    }
    if (!log.verify()) {
      throw new Error(
        "audit snapshot chain verification failed (hash or authentication)",
      );
    }
    if (
      authenticated &&
      !log.verifyTrustAnchor(authenticated.expectedTrustAnchor)
    ) {
      throw new Error("audit snapshot does not match external trust anchor");
    }
    return log;
  }

  append(
    type: string,
    correlationId: string,
    payload: Record<string, unknown>,
    occurredAt = new Date(),
    causationId?: string,
  ): AuditEvent {
    const body = {
      sequence: this.#events.length + 1,
      eventId: crypto.randomUUID(),
      type,
      correlationId,
      causationId,
      occurredAt: occurredAt.toISOString(),
      payload,
      previousHash: this.#events.at(-1)?.hash ?? HASH_GENESIS,
    };
    const baseEvent: AuditEvent = { ...body, hash: digest(body) };
    const event = this.#keyProvider
      ? this.#authenticate(baseEvent)
      : baseEvent;
    this.#events.push(event);
    return structuredClone(event);
  }

  #authenticate(event: AuditEvent): AuditEvent {
    const active = this.#keyProvider!.activeKey();
    validateKey(active.keyId, active.key);
    const previousAuthenticationTag =
      this.#events.at(-1)?.authentication?.tag ?? AUTHENTICATION_GENESIS;
    return {
      ...event,
      authentication: {
        algorithm: "hmac-sha256",
        keyId: active.keyId,
        keyVersion: active.keyVersion,
        previousAuthenticationTag,
        tag: authenticationTag(
          active.key,
          event,
          active.keyId,
          active.keyVersion,
          previousAuthenticationTag,
        ),
      },
    };
  }

  all(): AuditEvent[] {
    return structuredClone(this.#events);
  }

  snapshot(): AuditLogSnapshot {
    return {
      schemaVersion: this.#keyProvider ? 2 : 1,
      events: this.all(),
    };
  }

  trustAnchor(): AuditTrustAnchor {
    if (!this.#keyProvider) {
      throw new Error("legacy audit log has no authenticated trust anchor");
    }
    const tip = this.#events.at(-1);
    const active = this.#keyProvider.activeKey();
    return {
      schemaVersion: 1,
      eventCount: this.#events.length,
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

  verifyTrustAnchor(anchor: AuditTrustAnchor): boolean {
    if (
      !anchor ||
      anchor.schemaVersion !== 1 ||
      !Number.isSafeInteger(anchor.eventCount) ||
      anchor.eventCount < 0
    ) {
      return false;
    }
    const current = this.trustAnchor();
    return (
      current.eventCount === anchor.eventCount &&
      current.tipHash === anchor.tipHash &&
      current.tipAuthenticationTag === anchor.tipAuthenticationTag &&
      current.tipKeyId === anchor.tipKeyId &&
      current.tipKeyVersion === anchor.tipKeyVersion &&
      current.activeKeyId === anchor.activeKeyId &&
      current.activeKeyVersion === anchor.activeKeyVersion
    );
  }

  verify(): boolean {
    let previousHash = HASH_GENESIS;
    let previousAuthenticationTag = AUTHENTICATION_GENESIS;
    let previousKeyVersion = 0;
    let previousKeyId: string | undefined;
    for (const event of this.#events) {
      const { hash, authentication, ...body } = event;
      if (body.previousHash !== previousHash || digest(body) !== hash) return false;
      previousHash = hash;

      if (this.#keyProvider) {
        if (
          !authentication ||
          !validateAuthentication(authentication) ||
          authentication.previousAuthenticationTag !== previousAuthenticationTag
        ) {
          return false;
        }
        const keyRecord = this.#keyProvider.keyFor(authentication.keyId);
        if (
          !keyRecord ||
          keyRecord.keyVersion !== authentication.keyVersion ||
          authentication.keyVersion < previousKeyVersion ||
          (authentication.keyVersion === previousKeyVersion &&
            previousKeyId !== authentication.keyId)
        ) {
          return false;
        }
        validateKey(authentication.keyId, keyRecord.key);
        const expected = authenticationTag(
          keyRecord.key,
          event,
          authentication.keyId,
          authentication.keyVersion,
          previousAuthenticationTag,
        );
        if (!tagsEqual(expected, authentication.tag)) return false;
        previousAuthenticationTag = authentication.tag;
        previousKeyVersion = authentication.keyVersion;
        previousKeyId = authentication.keyId;
      } else if (authentication !== undefined) {
        return false;
      }
    }
    return true;
  }
}
