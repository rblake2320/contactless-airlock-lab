import {
  createLocalJWKSet,
  decodeProtectedHeader,
  errors as joseErrors,
  jwtVerify,
  type JSONWebKeySet,
  type JWTPayload,
} from "jose";

export type IdentityFailureCode =
  | "invalid_token"
  | "jwks_unavailable"
  | "jwks_invalid"
  | "claim_invalid"
  | "replay_rejected";

export class IdentityVerificationError extends Error {
  readonly code: IdentityFailureCode;

  constructor(code: IdentityFailureCode) {
    super("access token rejected");
    this.code = code;
  }
}

export interface VerifiedIdentity {
  principalId: string;
  tenantId: string;
  roles: readonly string[];
  issuer: string;
  audience: readonly string[];
  tokenId?: string;
  issuedAt: number;
  expiresAt: number;
}

export interface JtiReplayStore {
  consume(input: {
    issuer: string;
    tenantId: string;
    jti: string;
    expiresAt: number;
  }): Promise<boolean>;
}

export interface OidcVerifierOptions {
  issuer: string;
  audience: string | readonly string[];
  jwksUri: string;
  algorithms: readonly ("RS256" | "PS256" | "ES256")[];
  allowedRoles: readonly string[];
  tenantClaim?: string;
  rolesClaim?: string;
  maxTokenAgeSeconds: number;
  clockToleranceSeconds?: number;
  requireJtiReplayProtection?: boolean;
  replayStore?: JtiReplayStore;
  jwksCacheTtlMs?: number;
  jwksRefreshCooldownMs?: number;
  jwksFetchTimeoutMs?: number;
  maxJwksBytes?: number;
  maxJwksKeys?: number;
  maxTokenBytes?: number;
  fetcher?: typeof fetch;
  clock?: () => number;
}

const CLAIM_NAME = /^[A-Za-z][A-Za-z0-9_.:-]{0,127}$/;
const ID_VALUE = /^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,255}$/;
const KID = /^[\x21-\x7e]{1,256}$/;

function exactHttpsUrl(value: string, label: string): string {
  const parsed = new URL(value);
  if (
    parsed.protocol !== "https:" ||
    parsed.username ||
    parsed.password ||
    parsed.search ||
    parsed.hash ||
    value !== parsed.href
  ) throw new Error(`${label} must be an exact HTTPS URL`);
  return value;
}

async function boundedResponseBody(
  response: Response,
  maximum: number,
): Promise<string> {
  const declared = response.headers.get("content-length");
  if (declared !== null && (!/^\d+$/.test(declared) || Number(declared) > maximum)) {
    throw new IdentityVerificationError("jwks_invalid");
  }
  if (!response.body) throw new IdentityVerificationError("jwks_invalid");
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let length = 0;
  try {
    while (true) {
      const part = await reader.read();
      if (part.done) break;
      length += part.value.byteLength;
      if (length > maximum) {
        await reader.cancel();
        throw new IdentityVerificationError("jwks_invalid");
      }
      chunks.push(part.value);
    }
  } finally {
    reader.releaseLock();
  }
  const joined = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) {
    joined.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return new TextDecoder("utf-8", { fatal: true }).decode(joined);
}

export class OidcAccessTokenVerifier {
  readonly #options: Required<Pick<
    OidcVerifierOptions,
    "tenantClaim" | "rolesClaim" | "clockToleranceSeconds" |
    "jwksCacheTtlMs" | "jwksRefreshCooldownMs" | "jwksFetchTimeoutMs" |
    "maxJwksBytes" | "maxJwksKeys" | "maxTokenBytes"
  >> & OidcVerifierOptions;
  readonly #allowedRoles: ReadonlySet<string>;
  readonly #fetcher: typeof fetch;
  readonly #clock: () => number;
  #jwks?: JSONWebKeySet;
  #jwksExpiresAt = 0;
  #lastJwksFetchAt = Number.NEGATIVE_INFINITY;

  constructor(options: OidcVerifierOptions) {
    exactHttpsUrl(options.issuer, "issuer");
    exactHttpsUrl(options.jwksUri, "jwksUri");
    if (
      !options.algorithms.length ||
      new Set(options.algorithms).size !== options.algorithms.length ||
      (typeof options.audience === "string"
        ? !ID_VALUE.test(options.audience)
        : options.audience.length < 1 ||
          options.audience.length > 16 ||
          new Set(options.audience).size !== options.audience.length ||
          options.audience.some((audience) => !ID_VALUE.test(audience))) ||
      !Number.isSafeInteger(options.maxTokenAgeSeconds) ||
      options.maxTokenAgeSeconds <= 0
    ) throw new Error("invalid OIDC verification policy");
    const tenantClaim = options.tenantClaim ?? "tid";
    const rolesClaim = options.rolesClaim ?? "roles";
    if (!CLAIM_NAME.test(tenantClaim) || !CLAIM_NAME.test(rolesClaim)) {
      throw new Error("invalid signed-claim mapping");
    }
    this.#allowedRoles = new Set(options.allowedRoles);
    if (!this.#allowedRoles.size || [...this.#allowedRoles].some((role) => !ID_VALUE.test(role))) {
      throw new Error("invalid role allowlist");
    }
    if (options.requireJtiReplayProtection && !options.replayStore) {
      throw new Error("jti replay protection requires a replay store");
    }
    this.#options = {
      ...options,
      tenantClaim,
      rolesClaim,
      clockToleranceSeconds: options.clockToleranceSeconds ?? 5,
      jwksCacheTtlMs: options.jwksCacheTtlMs ?? 5 * 60_000,
      jwksRefreshCooldownMs: options.jwksRefreshCooldownMs ?? 5_000,
      jwksFetchTimeoutMs: options.jwksFetchTimeoutMs ?? 5_000,
      maxJwksBytes: options.maxJwksBytes ?? 256 * 1024,
      maxJwksKeys: options.maxJwksKeys ?? 32,
      maxTokenBytes: options.maxTokenBytes ?? 16 * 1024,
    };
    for (const value of [
      this.#options.clockToleranceSeconds,
      this.#options.jwksCacheTtlMs,
      this.#options.jwksRefreshCooldownMs,
      this.#options.jwksFetchTimeoutMs,
      this.#options.maxJwksBytes,
      this.#options.maxJwksKeys,
      this.#options.maxTokenBytes,
    ]) {
      if (!Number.isSafeInteger(value) || value < 0) throw new Error("invalid verifier bound");
    }
    for (const value of [
      this.#options.jwksCacheTtlMs,
      this.#options.jwksFetchTimeoutMs,
      this.#options.maxJwksBytes,
      this.#options.maxJwksKeys,
      this.#options.maxTokenBytes,
    ]) {
      if (value === 0) throw new Error("invalid verifier bound");
    }
    this.#fetcher = options.fetcher ?? fetch;
    this.#clock = options.clock ?? Date.now;
  }

  async verify(token: string): Promise<VerifiedIdentity> {
    if (!token || Buffer.byteLength(token, "utf8") > this.#options.maxTokenBytes) {
      throw new IdentityVerificationError("invalid_token");
    }
    let header: ReturnType<typeof decodeProtectedHeader>;
    try {
      header = decodeProtectedHeader(token);
    } catch {
      throw new IdentityVerificationError("invalid_token");
    }
    if (
      typeof header.alg !== "string" ||
      !this.#options.algorithms.includes(header.alg as "RS256" | "PS256" | "ES256") ||
      header.typ !== "at+jwt" ||
      typeof header.kid !== "string" ||
      !KID.test(header.kid)
    ) throw new IdentityVerificationError("invalid_token");

    let payload: JWTPayload;
    try {
      payload = await this.#verifyWithCachedKeys(token, false);
    } catch (error) {
      if (
        error instanceof joseErrors.JWKSNoMatchingKey &&
        this.#clock() - this.#lastJwksFetchAt >= this.#options.jwksRefreshCooldownMs
      ) {
        payload = await this.#verifyWithCachedKeys(token, true);
      } else if (error instanceof IdentityVerificationError) {
        throw error;
      } else {
        throw new IdentityVerificationError("invalid_token");
      }
    }
    return this.#identityFromPayload(payload);
  }

  async #verifyWithCachedKeys(token: string, forceRefresh: boolean): Promise<JWTPayload> {
    const jwks = await this.#getJwks(forceRefresh);
    const local = createLocalJWKSet(jwks);
    const result = await jwtVerify(token, local, {
      issuer: this.#options.issuer,
      audience: typeof this.#options.audience === "string"
        ? this.#options.audience
        : [...this.#options.audience],
      algorithms: [...this.#options.algorithms],
      requiredClaims: ["sub", "iat", "exp", this.#options.tenantClaim, this.#options.rolesClaim],
      maxTokenAge: `${this.#options.maxTokenAgeSeconds}s`,
      clockTolerance: this.#options.clockToleranceSeconds,
      currentDate: new Date(this.#clock()),
    });
    return result.payload;
  }

  async #getJwks(forceRefresh: boolean): Promise<JSONWebKeySet> {
    const now = this.#clock();
    if (!forceRefresh && this.#jwks && now < this.#jwksExpiresAt) return this.#jwks;
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.#options.jwksFetchTimeoutMs);
    timeout.unref?.();
    let response: Response;
    try {
      response = await this.#fetcher(this.#options.jwksUri, {
        method: "GET",
        headers: { accept: "application/json" },
        redirect: "error",
        signal: controller.signal,
      });
    } catch {
      throw new IdentityVerificationError("jwks_unavailable");
    } finally {
      clearTimeout(timeout);
    }
    if (!response.ok) throw new IdentityVerificationError("jwks_unavailable");
    const contentType = response.headers.get("content-type")?.split(";", 1)[0]?.trim().toLowerCase();
    if (contentType !== "application/json") {
      throw new IdentityVerificationError("jwks_invalid");
    }
    let value: unknown;
    try {
      value = JSON.parse(await boundedResponseBody(response, this.#options.maxJwksBytes));
    } catch (error) {
      if (error instanceof IdentityVerificationError) throw error;
      throw new IdentityVerificationError("jwks_invalid");
    }
    if (
      !value ||
      typeof value !== "object" ||
      !Array.isArray((value as { keys?: unknown }).keys) ||
      (value as JSONWebKeySet).keys.length < 1 ||
      (value as JSONWebKeySet).keys.length > this.#options.maxJwksKeys
    ) throw new IdentityVerificationError("jwks_invalid");
    const kids = new Set<string>();
    for (const key of (value as JSONWebKeySet).keys) {
      const algorithm = key.alg;
      const validShape = key &&
        typeof key === "object" &&
        typeof key.kid === "string" &&
        KID.test(key.kid) &&
        typeof algorithm === "string" &&
        this.#options.algorithms.includes(algorithm as "RS256" | "PS256" | "ES256") &&
        key.use === "sig" &&
        !("d" in key) &&
        !("k" in key) &&
        (
          (algorithm === "ES256" && key.kty === "EC" && key.crv === "P-256") ||
          ((algorithm === "RS256" || algorithm === "PS256") && key.kty === "RSA")
        );
      if (!validShape || kids.has(key.kid!)) {
        throw new IdentityVerificationError("jwks_invalid");
      }
      kids.add(key.kid!);
    }
    this.#jwks = structuredClone(value as JSONWebKeySet);
    this.#lastJwksFetchAt = now;
    this.#jwksExpiresAt = now + this.#options.jwksCacheTtlMs;
    return this.#jwks;
  }

  async #identityFromPayload(payload: JWTPayload): Promise<VerifiedIdentity> {
    const tenant = payload[this.#options.tenantClaim];
    const roles = payload[this.#options.rolesClaim];
    if (
      typeof payload.sub !== "string" ||
      !ID_VALUE.test(payload.sub) ||
      typeof tenant !== "string" ||
      !ID_VALUE.test(tenant) ||
      !Array.isArray(roles) ||
      roles.length < 1 ||
      roles.length > 32 ||
      roles.some((role) => typeof role !== "string" || !this.#allowedRoles.has(role)) ||
      new Set(roles).size !== roles.length ||
      typeof payload.iat !== "number" ||
      typeof payload.exp !== "number"
    ) throw new IdentityVerificationError("claim_invalid");
    const audiences = typeof payload.aud === "string" ? [payload.aud] : payload.aud;
    if (!audiences?.length) throw new IdentityVerificationError("claim_invalid");
    if (this.#options.requireJtiReplayProtection) {
      if (typeof payload.jti !== "string" || !ID_VALUE.test(payload.jti)) {
        throw new IdentityVerificationError("claim_invalid");
      }
      let accepted: boolean;
      try {
        accepted = await this.#options.replayStore!.consume({
          issuer: this.#options.issuer,
          tenantId: tenant,
          jti: payload.jti,
          expiresAt: payload.exp,
        });
      } catch {
        throw new IdentityVerificationError("replay_rejected");
      }
      if (!accepted) throw new IdentityVerificationError("replay_rejected");
    }
    return Object.freeze({
      principalId: payload.sub,
      tenantId: tenant,
      roles: Object.freeze([...roles] as string[]),
      issuer: this.#options.issuer,
      audience: Object.freeze([...audiences]),
      ...(payload.jti ? { tokenId: payload.jti } : {}),
      issuedAt: payload.iat,
      expiresAt: payload.exp,
    });
  }
}
