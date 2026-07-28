import { createHash, randomBytes, timingSafeEqual } from "node:crypto";

export interface AuthenticatedPrincipal {
  principalId: string;
  tenantId: string;
  roles: readonly string[];
}

export interface BootstrapCredential extends AuthenticatedPrincipal {
  token: string;
}

export interface SessionBoundaryOptions {
  credentials?: readonly BootstrapCredential[];
  absoluteTtlMs?: number;
  idleTtlMs?: number;
  maxSessions?: number;
  maxSessionsPerPrincipal?: number;
  clock?: () => number;
}

export interface AuthenticatedSession {
  sessionId: string;
  csrfToken: string;
  principal: AuthenticatedPrincipal;
  createdAt: number;
  lastSeenAt: number;
  expiresAt: number;
}

function digest(value: string): Buffer {
  return createHash("sha256").update(value, "utf8").digest();
}

function opaqueToken(bytes = 32): string {
  return randomBytes(bytes).toString("base64url");
}

const ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const ALLOWED_ROLES = new Set(["operator", "viewer"]);

export class SessionBoundary {
  readonly #credentials: Array<{ digest: Buffer; principal: AuthenticatedPrincipal }>;
  readonly #sessions = new Map<string, AuthenticatedSession>();
  readonly #absoluteTtlMs: number;
  readonly #idleTtlMs: number;
  readonly #maxSessions: number;
  readonly #maxSessionsPerPrincipal: number;
  readonly #clock: () => number;

  constructor(options: SessionBoundaryOptions) {
    this.#absoluteTtlMs = options.absoluteTtlMs ?? 8 * 60 * 60_000;
    this.#idleTtlMs = options.idleTtlMs ?? 30 * 60_000;
    this.#maxSessions = options.maxSessions ?? 1_000;
    this.#maxSessionsPerPrincipal = options.maxSessionsPerPrincipal ?? 5;
    this.#clock = options.clock ?? Date.now;
    for (const value of [
      this.#absoluteTtlMs,
      this.#idleTtlMs,
      this.#maxSessions,
      this.#maxSessionsPerPrincipal,
    ]) {
      if (!Number.isSafeInteger(value) || value <= 0) {
        throw new Error("session bounds must be positive safe integers");
      }
    }
    const seen = new Set<string>();
    this.#credentials = (options.credentials ?? []).map((credential) => {
      if (
        credential.token.length < 32 ||
        !ID_PATTERN.test(credential.principalId) ||
        !ID_PATTERN.test(credential.tenantId) ||
        !credential.roles.length ||
        credential.roles.some((role) => !ALLOWED_ROLES.has(role))
      ) throw new Error("invalid authentication credential");
      const key = digest(credential.token).toString("hex");
      if (seen.has(key)) throw new Error("duplicate authentication credential");
      seen.add(key);
      return {
        digest: Buffer.from(key, "hex"),
        principal: Object.freeze({
          principalId: credential.principalId,
          tenantId: credential.tenantId,
          roles: Object.freeze([...credential.roles]),
        }),
      };
    });
  }

  login(bearerToken: string): AuthenticatedSession | undefined {
    const candidate = digest(bearerToken);
    let principal: AuthenticatedPrincipal | undefined;
    for (const credential of this.#credentials) {
      if (timingSafeEqual(candidate, credential.digest)) principal = credential.principal;
    }
    if (!principal) return undefined;
    return this.issue(principal);
  }

  issue(
    principal: AuthenticatedPrincipal,
    maximumExpiresAt?: number,
  ): AuthenticatedSession {
    if (
      !ID_PATTERN.test(principal.principalId) ||
      !ID_PATTERN.test(principal.tenantId) ||
      !principal.roles.length ||
      principal.roles.some((role) => !ALLOWED_ROLES.has(role))
    ) {
      throw new Error("invalid authenticated principal");
    }
    this.#prune();
    const principalSessions = [...this.#sessions.values()].filter(
      (session) => session.principal.principalId === principal!.principalId &&
        session.principal.tenantId === principal!.tenantId,
    ).length;
    if (
      this.#sessions.size >= this.#maxSessions ||
      principalSessions >= this.#maxSessionsPerPrincipal
    ) throw new Error("session limit reached");
    const now = this.#clock();
    const expiresAt = Math.min(
      now + this.#absoluteTtlMs,
      maximumExpiresAt ?? Number.POSITIVE_INFINITY,
    );
    if (!Number.isFinite(expiresAt) || expiresAt <= now) {
      throw new Error("identity already expired");
    }
    const session: AuthenticatedSession = {
      sessionId: opaqueToken(),
      csrfToken: opaqueToken(),
      principal,
      createdAt: now,
      lastSeenAt: now,
      expiresAt,
    };
    this.#sessions.set(session.sessionId, session);
    return structuredClone(session);
  }

  authenticate(sessionId: string): AuthenticatedSession | undefined {
    const session = this.#sessions.get(sessionId);
    if (!session) return undefined;
    const now = this.#clock();
    if (
      now >= session.expiresAt ||
      now - session.lastSeenAt >= this.#idleTtlMs
    ) {
      this.#sessions.delete(sessionId);
      return undefined;
    }
    session.lastSeenAt = now;
    return structuredClone(session);
  }

  verifyCsrf(session: AuthenticatedSession, value: string | undefined): boolean {
    if (!value) return false;
    const expected = Buffer.from(session.csrfToken);
    const candidate = Buffer.from(value);
    return expected.length === candidate.length && timingSafeEqual(expected, candidate);
  }

  revoke(sessionId: string): boolean {
    return this.#sessions.delete(sessionId);
  }

  #prune(): void {
    const now = this.#clock();
    for (const [id, session] of this.#sessions) {
      if (
        now >= session.expiresAt ||
        now - session.lastSeenAt >= this.#idleTtlMs
      ) this.#sessions.delete(id);
    }
  }
}
