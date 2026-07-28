import assert from "node:assert/strict";
import type { AddressInfo } from "node:net";
import test from "node:test";
import { exportJWK, generateKeyPair, SignJWT } from "jose";
import { createLabServer } from "../apps/realtime-lab/server.ts";
import {
  OidcAccessTokenVerifier,
  type JtiReplayStore,
} from "../packages/identity/oidcAccessTokenVerifier.ts";

const NOW_SECONDS = 2_000_000_000;
const ORIGIN = "http://localhost";

test("OIDC provider exchanges only verified signed claims into a bounded session", async () => {
  const signing = await generateKeyPair("ES256", { extractable: true });
  const publicJwk = {
    ...await exportJWK(signing.publicKey),
    kid: "oidc-session-key",
    alg: "ES256",
    use: "sig",
  };
  const consumed = new Set<string>();
  const replayStore: JtiReplayStore = {
    async consume({ issuer, tenantId, jti }) {
      const key = `${issuer}\0${tenantId}\0${jti}`;
      if (consumed.has(key)) return false;
      consumed.add(key);
      return true;
    },
  };
  const verifier = new OidcAccessTokenVerifier({
    issuer: "https://identity.example/issuer",
    audience: "airlock-api",
    jwksUri: "https://identity.example/jwks",
    algorithms: ["ES256"],
    allowedRoles: ["operator", "viewer"],
    maxTokenAgeSeconds: 120,
    requireJtiReplayProtection: true,
    replayStore,
    clock: () => NOW_SECONDS * 1_000,
    fetcher: async () => new Response(JSON.stringify({ keys: [publicJwk] }), {
      status: 200,
      headers: { "content-type": "application/json" },
    }),
  });
  const token = await new SignJWT({
    tid: "tenant-from-signed-claim",
    roles: ["operator"],
    jti: "one-time-session-exchange",
  })
    .setProtectedHeader({ alg: "ES256", kid: "oidc-session-key", typ: "at+jwt" })
    .setIssuer("https://identity.example/issuer")
    .setAudience("airlock-api")
    .setSubject("principal-from-signed-claim")
    .setIssuedAt(NOW_SECONDS - 10)
    .setNotBefore(NOW_SECONDS - 10)
    .setExpirationTime(NOW_SECONDS + 60)
    .sign(signing.privateKey);

  const server = createLabServer({
    access: {
      mode: "authenticated",
      identityProvider: { type: "oidc", verifier },
      allowedOrigins: [ORIGIN],
      allowInsecureTestOrigins: true,
      cookieSecure: false,
    },
    clock: () => NOW_SECONDS * 1_000,
    rateLimit: false,
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address() as AddressInfo;
  const baseUrl = `http://127.0.0.1:${port}`;
  try {
    const response = await fetch(`${baseUrl}/api/session/login`, {
      method: "POST",
      headers: { authorization: `Bearer ${token}`, origin: ORIGIN },
    });
    assert.equal(response.status, 200);
    const payload = await response.json() as {
      principal: { principalId: string; tenantId: string; roles: string[] };
      expiresAt: string;
    };
    assert.deepEqual(payload.principal, {
      principalId: "principal-from-signed-claim",
      tenantId: "tenant-from-signed-claim",
      roles: ["operator"],
    });
    assert.equal(
      payload.expiresAt,
      new Date((NOW_SECONDS + 60) * 1_000).toISOString(),
      "the exchanged session must not outlive the verified access token",
    );
    assert.match(response.headers.get("set-cookie") ?? "", /Max-Age=60(?:;|$)/);

    const replay = await fetch(`${baseUrl}/api/session/login`, {
      method: "POST",
      headers: { authorization: `Bearer ${token}`, origin: ORIGIN },
    });
    assert.equal(replay.status, 401);
    assert.deepEqual(await replay.json(), {
      code: "AUTHENTICATION_FAILED",
      error: "Authentication failed.",
    });

    const attacker = await generateKeyPair("ES256");
    const forged = await new SignJWT({
      tid: "attacker-selected-tenant",
      roles: ["operator"],
      jti: "attacker-token",
    })
      .setProtectedHeader({ alg: "ES256", kid: "oidc-session-key", typ: "at+jwt" })
      .setIssuer("https://identity.example/issuer")
      .setAudience("airlock-api")
      .setSubject("attacker")
      .setIssuedAt(NOW_SECONDS - 10)
      .setExpirationTime(NOW_SECONDS + 60)
      .sign(attacker.privateKey);
    const rejected = await fetch(`${baseUrl}/api/session/login`, {
      method: "POST",
      headers: { authorization: `Bearer ${forged}`, origin: ORIGIN },
    });
    assert.equal(rejected.status, 401);
  } finally {
    await new Promise<void>((resolve, reject) =>
      server.close((error) => error ? reject(error) : resolve()));
  }
});

test("identity providers are explicit and OIDC has no bootstrap fallback", async () => {
  assert.throws(
    () => createLabServer({
      access: {
        mode: "authenticated",
        allowedOrigins: ["https://airlock.example"],
      } as never,
    }),
    /requires one supported identity provider/,
  );
  assert.throws(
    () => createLabServer({
      access: {
        mode: "authenticated",
        identityProvider: { type: "oidc" },
        allowedOrigins: ["https://airlock.example"],
      },
    }),
    /exactly one of verifier or options/,
  );
  assert.throws(
    () => createLabServer({
      access: {
        mode: "authenticated",
        identityProvider: {
          type: "bootstrap-controlled-demo",
          credentials: [],
        },
        allowedOrigins: ["https://airlock.example"],
      },
    }),
    /requires credentials/,
  );
});

test("JWKS outage marks identity unready and a verified exchange recovers it", async () => {
  const signing = await generateKeyPair("ES256", { extractable: true });
  const publicJwk = {
    ...await exportJWK(signing.publicKey),
    kid: "recovery-key",
    alg: "ES256",
    use: "sig",
  };
  let outage = true;
  const verifier = new OidcAccessTokenVerifier({
    issuer: "https://identity.example/issuer",
    audience: "airlock-api",
    jwksUri: "https://identity.example/jwks",
    algorithms: ["ES256"],
    allowedRoles: ["operator"],
    maxTokenAgeSeconds: 120,
    clock: () => NOW_SECONDS * 1_000,
    fetcher: async () => {
      if (outage) throw new Error("synthetic JWKS outage");
      return new Response(JSON.stringify({ keys: [publicJwk] }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    },
  });
  const token = await new SignJWT({
    tid: "tenant-a",
    roles: ["operator"],
  })
    .setProtectedHeader({ alg: "ES256", kid: "recovery-key", typ: "at+jwt" })
    .setIssuer("https://identity.example/issuer")
    .setAudience("airlock-api")
    .setSubject("principal-a")
    .setIssuedAt(NOW_SECONDS - 10)
    .setExpirationTime(NOW_SECONDS + 60)
    .sign(signing.privateKey);
  const server = createLabServer({
    access: {
      mode: "authenticated",
      identityProvider: { type: "oidc", verifier },
      allowedOrigins: [ORIGIN],
      allowInsecureTestOrigins: true,
      cookieSecure: false,
    },
    clock: () => NOW_SECONDS * 1_000,
    rateLimit: false,
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address() as AddressInfo;
  const baseUrl = `http://127.0.0.1:${port}`;
  const readiness = async () => {
    const health = await (await fetch(`${baseUrl}/api/health`)).json() as {
      service: { readiness: Record<string, boolean> };
    };
    return health.service.readiness;
  };
  try {
    assert.equal((await readiness()).identityProvider, true);
    const failed = await fetch(`${baseUrl}/api/session/login`, {
      method: "POST",
      headers: { authorization: `Bearer ${token}`, origin: ORIGIN },
    });
    assert.equal(failed.status, 401);
    assert.deepEqual(await readiness(), {
      ready: false,
      database: false,
      identityProvider: false,
      auditCustody: false,
      partnerTransport: false,
    });

    outage = false;
    const recovered = await fetch(`${baseUrl}/api/session/login`, {
      method: "POST",
      headers: { authorization: `Bearer ${token}`, origin: ORIGIN },
    });
    assert.equal(recovered.status, 200);
    const after = await readiness();
    assert.equal(after.identityProvider, true);
    assert.equal(
      after.ready,
      false,
      "uncomposed database/audit/partner dependencies remain honestly unready",
    );
  } finally {
    await new Promise<void>((resolve, reject) =>
      server.close((error) => error ? reject(error) : resolve()));
  }
});
