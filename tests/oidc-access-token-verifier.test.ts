import assert from "node:assert/strict";
import test from "node:test";
import {
  exportJWK,
  generateKeyPair,
  SignJWT,
  type JWK,
} from "jose";
import {
  IdentityVerificationError,
  OidcAccessTokenVerifier,
  type JtiReplayStore,
} from "../packages/identity/oidcAccessTokenVerifier.ts";

const ISSUER = "https://identity.example/issuer";
const JWKS_URI = "https://identity.example/.well-known/jwks.json";
const AUDIENCE = "airlock-api";
const nowSeconds = 2_000_000_000;

async function key(kid: string) {
  const pair = await generateKeyPair("ES256", { extractable: true });
  const jwk = await exportJWK(pair.publicKey);
  return {
    kid,
    privateKey: pair.privateKey,
    publicJwk: { ...jwk, kid, alg: "ES256", use: "sig" } as JWK,
  };
}

async function token(
  privateKey: CryptoKey,
  kid: string,
  claims: Record<string, unknown> = {},
) {
  const {
    iss = ISSUER,
    aud = AUDIENCE,
    sub = "principal-a",
    iat = nowSeconds - 10,
    nbf = nowSeconds - 10,
    exp = nowSeconds + 300,
    ...privateClaims
  } = claims;
  return new SignJWT({
    tid: "tenant-a",
    roles: ["operator"],
    jti: "token-1",
    ...privateClaims,
  })
    .setProtectedHeader({ alg: "ES256", kid, typ: "at+jwt" })
    .setSubject(sub as string)
    .setIssuer(iss as string)
    .setAudience(aud as string)
    .setIssuedAt(iat as number)
    .setNotBefore(nbf as number)
    .setExpirationTime(exp as number)
    .sign(privateKey);
}

function jwksFetch(current: () => JWK[], status = 200) {
  let calls = 0;
  const fetcher: typeof fetch = async () => {
    calls += 1;
    return new Response(JSON.stringify({ keys: current() }), {
      status,
      headers: { "content-type": "application/json" },
    });
  };
  return { fetcher, calls: () => calls };
}

function verifier(fetcher: typeof fetch, overrides = {}) {
  return new OidcAccessTokenVerifier({
    issuer: ISSUER,
    audience: AUDIENCE,
    jwksUri: JWKS_URI,
    algorithms: ["ES256"],
    allowedRoles: ["operator", "viewer"],
    maxTokenAgeSeconds: 120,
    clock: () => nowSeconds * 1_000,
    fetcher,
    ...overrides,
  });
}

async function rejected(
  promise: Promise<unknown>,
  code: IdentityVerificationError["code"],
) {
  await assert.rejects(promise, (error: unknown) =>
    error instanceof IdentityVerificationError &&
    error.code === code &&
    error.message === "access token rejected");
}

test("real asymmetric JWT and JWKS produce identity only from verified claims", async () => {
  const signing = await key("key-1");
  const remote = jwksFetch(() => [signing.publicJwk]);
  const identity = await verifier(remote.fetcher).verify(
    await token(signing.privateKey, signing.kid),
  );
  assert.deepEqual(identity, {
    principalId: "principal-a",
    tenantId: "tenant-a",
    roles: ["operator"],
    issuer: ISSUER,
    audience: [AUDIENCE],
    tokenId: "token-1",
    issuedAt: nowSeconds - 10,
    expiresAt: nowSeconds + 300,
  });
  assert.equal(remote.calls(), 1);
});

test("issuer, audience, algorithm, signature, expiry, nbf, and max age fail closed", async () => {
  const signing = await key("key-1");
  const other = await key("key-2");
  const remote = jwksFetch(() => [signing.publicJwk, other.publicJwk]);
  const check = verifier(remote.fetcher);
  await rejected(check.verify(await token(signing.privateKey, signing.kid, {
    iss: "https://attacker.example/",
  })), "invalid_token");
  await rejected(check.verify(await token(signing.privateKey, signing.kid, {
    aud: "other-api",
  })), "invalid_token");
  await rejected(check.verify(await token(signing.privateKey, signing.kid, {
    exp: nowSeconds - 10,
  })), "invalid_token");
  await rejected(check.verify(await token(signing.privateKey, signing.kid, {
    nbf: nowSeconds + 60,
  })), "invalid_token");
  await rejected(check.verify(await token(signing.privateKey, signing.kid, {
    iat: nowSeconds - 130,
  })), "invalid_token");
  await rejected(check.verify(await token(other.privateKey, signing.kid)), "invalid_token");

  const rs = await generateKeyPair("RS256");
  const wrongAlgorithm = await new SignJWT({ tid: "tenant-a", roles: ["operator"] })
    .setProtectedHeader({ alg: "RS256", kid: "key-1" })
    .setIssuer(ISSUER).setAudience(AUDIENCE).setSubject("principal-a")
    .setIssuedAt(nowSeconds).setExpirationTime(nowSeconds + 60)
    .sign(rs.privateKey);
  await rejected(check.verify(wrongAlgorithm), "invalid_token");
});

test("unsigned or malformed tenant, principal, and role claims never become identity", async () => {
  const signing = await key("key-1");
  const remote = jwksFetch(() => [signing.publicJwk]);
  const check = verifier(remote.fetcher);
  for (const claims of [
    { tid: "" },
    { tid: "../tenant" },
    { sub: "" },
    { roles: ["admin"] },
    { roles: ["operator", "operator"] },
    { roles: "operator" },
    { roles: [] },
  ]) {
    await rejected(
      check.verify(await token(signing.privateKey, signing.kid, claims)),
      "claim_invalid",
    );
  }
  await rejected(check.verify("not-a-jwt"), "invalid_token");
});

test("bounded JWKS cache rotates by kid and never uses stale keys after outage", async () => {
  const first = await key("key-1");
  const second = await key("key-2");
  let keys = [first.publicJwk];
  let now = nowSeconds * 1_000;
  let unavailable = false;
  let calls = 0;
  const fetcher: typeof fetch = async () => {
    calls += 1;
    if (unavailable) throw new Error("synthetic IdP outage secret");
    return new Response(JSON.stringify({ keys }), {
      status: 200,
      headers: { "content-type": "application/json" },
    });
  };
  const check = verifier(fetcher, {
    clock: () => now,
    jwksCacheTtlMs: 1_000,
    jwksRefreshCooldownMs: 10,
  });
  await check.verify(await token(first.privateKey, first.kid));
  keys = [second.publicJwk];
  now += 11;
  await check.verify(await token(second.privateKey, second.kid));
  assert.equal(calls, 2);
  unavailable = true;
  await check.verify(await token(second.privateKey, second.kid));
  now += 1_001;
  await rejected(check.verify(await token(second.privateKey, second.kid)), "jwks_unavailable");
});

test("JWKS response byte/key bounds and unknown kid fail closed", async () => {
  const signing = await key("key-1");
  const unknown = await key("unknown");
  const oversized = verifier(async () =>
    new Response(JSON.stringify({ keys: [signing.publicJwk] }), {
      headers: { "content-length": "999999" },
    }), { maxJwksBytes: 128 });
  await rejected(oversized.verify(await token(signing.privateKey, signing.kid)), "jwks_invalid");

  const tooMany = jwksFetch(() => [signing.publicJwk, unknown.publicJwk]);
  await rejected(
    verifier(tooMany.fetcher, { maxJwksKeys: 1 }).verify(
      await token(signing.privateKey, signing.kid),
    ),
    "jwks_invalid",
  );
  const privateJwk = {
    ...await exportJWK(signing.privateKey),
    kid: signing.kid,
    alg: "ES256",
    use: "sig",
  };
  const privateMaterial = jwksFetch(() => [privateJwk]);
  await rejected(
    verifier(privateMaterial.fetcher).verify(
      await token(signing.privateKey, signing.kid),
    ),
    "jwks_invalid",
  );
  const duplicate = jwksFetch(() => [signing.publicJwk, signing.publicJwk]);
  await rejected(
    verifier(duplicate.fetcher).verify(
      await token(signing.privateKey, signing.kid),
    ),
    "jwks_invalid",
  );
  const one = jwksFetch(() => [signing.publicJwk]);
  await rejected(
    verifier(one.fetcher).verify(await token(unknown.privateKey, unknown.kid)),
    "invalid_token",
  );
});

test("required jti replay consumption is atomic at the adapter boundary", async () => {
  const signing = await key("key-1");
  const remote = jwksFetch(() => [signing.publicJwk]);
  const consumed = new Set<string>();
  const replayStore: JtiReplayStore = {
    async consume(input) {
      const key = `${input.issuer}|${input.tenantId}|${input.jti}`;
      if (consumed.has(key)) return false;
      consumed.add(key);
      return true;
    },
  };
  const check = verifier(remote.fetcher, {
    requireJtiReplayProtection: true,
    replayStore,
  });
  const signed = await token(signing.privateKey, signing.kid);
  await check.verify(signed);
  await rejected(check.verify(signed), "replay_rejected");
  await rejected(check.verify(await token(signing.privateKey, signing.kid, {
    jti: undefined,
  })), "claim_invalid");
  const unavailable = verifier(remote.fetcher, {
    requireJtiReplayProtection: true,
    replayStore: { async consume() { throw new Error("secret backend detail"); } },
  });
  await rejected(
    unavailable.verify(await token(signing.privateKey, signing.kid, { jti: "token-2" })),
    "replay_rejected",
  );
});

test("configuration rejects insecure issuers and missing replay policy without fallback", () => {
  const base = {
    issuer: ISSUER,
    audience: AUDIENCE,
    jwksUri: JWKS_URI,
    algorithms: ["ES256"] as const,
    allowedRoles: ["operator"],
    maxTokenAgeSeconds: 120,
  };
  assert.throws(
    () => new OidcAccessTokenVerifier({ ...base, issuer: "http://identity.example/" }),
    /exact HTTPS/,
  );
  assert.throws(
    () => new OidcAccessTokenVerifier({
      ...base,
      requireJtiReplayProtection: true,
    }),
    /replay store/,
  );
});
