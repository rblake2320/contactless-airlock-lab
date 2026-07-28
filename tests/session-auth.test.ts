import assert from "node:assert/strict";
import type { AddressInfo } from "node:net";
import test from "node:test";
import { createLabServer } from "../apps/realtime-lab/server.ts";

const ORIGIN = "http://localhost";
const TOKEN_A = "tenant-a-bootstrap-token-000000000000000000000000";
const TOKEN_B = "tenant-b-bootstrap-token-000000000000000000000000";

async function start(overrides: Record<string, unknown> = {}) {
  const server = createLabServer({
    access: {
      mode: "authenticated",
      identityProvider: {
        type: "bootstrap-controlled-demo",
        credentials: [
          { token: TOKEN_A, principalId: "operator-a", tenantId: "tenant-a", roles: ["operator"] },
          { token: TOKEN_B, principalId: "operator-b", tenantId: "tenant-b", roles: ["operator"] },
        ],
      },
      allowedOrigins: [ORIGIN],
      allowInsecureTestOrigins: true,
      cookieSecure: false,
      ...overrides,
    },
    rateLimit: false,
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address() as AddressInfo;
  return {
    baseUrl: `http://127.0.0.1:${port}`,
    close: () => new Promise<void>((resolve, reject) =>
      server.close((error) => error ? reject(error) : resolve())),
  };
}

async function login(baseUrl: string, token: string) {
  const response = await fetch(`${baseUrl}/api/session/login`, {
    method: "POST",
    headers: { origin: ORIGIN, authorization: `Bearer ${token}` },
  });
  const payload = await response.json() as any;
  const cookie = response.headers.get("set-cookie")?.split(";", 1)[0];
  return { response, payload, cookie };
}

function authHeaders(cookie: string, csrf?: string): Record<string, string> {
  return {
    cookie,
    origin: ORIGIN,
    host: "localhost",
    ...(csrf ? { "x-csrf-token": csrf } : {}),
  };
}

test("authenticated mode fails closed, establishes a bounded session, and revokes logout", async () => {
  const lab = await start();
  try {
    const denied = await fetch(`${lab.baseUrl}/api/state`);
    assert.equal(denied.status, 401);
    assert.equal((await denied.json() as any).code, "AUTHENTICATION_REQUIRED");

    const bad = await login(lab.baseUrl, "wrong-token-that-is-at-least-thirty-two-characters");
    assert.equal(bad.response.status, 401);
    assert.equal(bad.payload.code, "AUTHENTICATION_FAILED");

    const established = await login(lab.baseUrl, TOKEN_A);
    assert.equal(established.response.status, 200);
    assert.ok(established.cookie);
    assert.equal(established.payload.principal.tenantId, "tenant-a");
    assert.ok(established.payload.csrfToken.length >= 32);
    assert.match(established.response.headers.get("set-cookie") ?? "", /HttpOnly/);
    assert.match(established.response.headers.get("set-cookie") ?? "", /SameSite=Strict/);

    const current = await fetch(`${lab.baseUrl}/api/session`, {
      headers: { cookie: established.cookie! },
    });
    assert.equal(current.status, 200);
    assert.equal((await current.json() as any).principal.principalId, "operator-a");

    const missingCsrf = await fetch(`${lab.baseUrl}/api/reset`, {
      method: "POST",
      headers: authHeaders(established.cookie!),
    });
    assert.equal(missingCsrf.status, 403);
    assert.equal((await missingCsrf.json() as any).code, "CSRF_INVALID");

    const logout = await fetch(`${lab.baseUrl}/api/session/logout`, {
      method: "POST",
      headers: authHeaders(established.cookie!, established.payload.csrfToken),
    });
    assert.equal(logout.status, 200);
    const afterLogout = await fetch(`${lab.baseUrl}/api/state`, {
      headers: { cookie: established.cookie! },
    });
    assert.equal(afterLogout.status, 401);
  } finally {
    await lab.close();
  }
});

test("tenant sessions cannot observe or mutate another tenant's engine state", async () => {
  const lab = await start();
  try {
    const a = await login(lab.baseUrl, TOKEN_A);
    const b = await login(lab.baseUrl, TOKEN_B);
    const request = await fetch(`${lab.baseUrl}/api/provision/request`, {
      method: "POST",
      headers: authHeaders(a.cookie!, a.payload.csrfToken),
    });
    assert.equal(request.status, 200);

    const aState = await (await fetch(`${lab.baseUrl}/api/state`, {
      headers: { cookie: a.cookie! },
    })).json() as any;
    const bState = await (await fetch(`${lab.baseUrl}/api/state`, {
      headers: { cookie: b.cookie! },
    })).json() as any;
    assert.equal(aState.provisioning.state, "trusted_device_challenge");
    assert.equal(bState.provisioning, undefined);
    assert.equal(bState.token, undefined);
  } finally {
    await lab.close();
  }
});

test("concurrent delayed bodies cannot switch the active tenant binding", async () => {
  const lab = await start();
  try {
    const a = await login(lab.baseUrl, TOKEN_A);
    const b = await login(lab.baseUrl, TOKEN_B);
    const delayedBody = new ReadableStream({
      start(controller) {
        setTimeout(() => {
          controller.enqueue(new TextEncoder().encode("{}"));
          controller.close();
        }, 30);
      },
    });
    const delayedA = fetch(`${lab.baseUrl}/api/provision/request`, {
      method: "POST",
      headers: {
        ...authHeaders(a.cookie!, a.payload.csrfToken),
        "content-type": "application/json",
      },
      body: delayedBody,
      duplex: "half",
    } as RequestInit & { duplex: "half" });
    await new Promise((resolve) => setTimeout(resolve, 5));
    const resetB = await fetch(`${lab.baseUrl}/api/reset`, {
      method: "POST",
      headers: authHeaders(b.cookie!, b.payload.csrfToken),
    });
    assert.equal(resetB.status, 200);
    assert.equal((await delayedA).status, 200);

    const aState = await (await fetch(`${lab.baseUrl}/api/state`, {
      headers: { cookie: a.cookie! },
    })).json() as any;
    const bState = await (await fetch(`${lab.baseUrl}/api/state`, {
      headers: { cookie: b.cookie! },
    })).json() as any;
    assert.equal(aState.provisioning.state, "trusted_device_challenge");
    assert.equal(bState.provisioning, undefined);
  } finally {
    await lab.close();
  }
});

test("idle expiry and per-principal session caps fail closed", async () => {
  let now = 1_000_000;
  const server = createLabServer({
    access: {
      mode: "authenticated",
      identityProvider: {
        type: "bootstrap-controlled-demo",
        credentials: [
          { token: TOKEN_A, principalId: "operator-a", tenantId: "tenant-a", roles: ["operator"] },
        ],
      },
      allowedOrigins: [ORIGIN],
      allowInsecureTestOrigins: true,
      cookieSecure: false,
      idleTtlMs: 1_000,
      absoluteTtlMs: 10_000,
      maxSessionsPerPrincipal: 1,
    },
    clock: () => now,
    rateLimit: false,
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address() as AddressInfo;
  const baseUrl = `http://127.0.0.1:${port}`;
  try {
    const first = await login(baseUrl, TOKEN_A);
    const capped = await login(baseUrl, TOKEN_A);
    assert.equal(capped.response.status, 429);
    assert.equal(capped.payload.code, "SESSION_LIMIT_REACHED");
    now += 1_000;
    const expired = await fetch(`${baseUrl}/api/state`, {
      headers: { cookie: first.cookie! },
    });
    assert.equal(expired.status, 401);
    const replacement = await login(baseUrl, TOKEN_A);
    assert.equal(replacement.response.status, 200);
  } finally {
    await new Promise<void>((resolve, reject) =>
      server.close((error) => error ? reject(error) : resolve()));
  }
});

test("roles authorize viewer reads but forbid viewer mutations", async () => {
  const viewerToken = "viewer-bootstrap-token-0000000000000000000000000";
  const lab = await start({
    identityProvider: {
      type: "bootstrap-controlled-demo",
      credentials: [
        { token: viewerToken, principalId: "viewer", tenantId: "tenant-view", roles: ["viewer"] },
      ],
    },
  });
  try {
    const viewer = await login(lab.baseUrl, viewerToken);
    const readable = await fetch(`${lab.baseUrl}/api/state`, {
      headers: { cookie: viewer.cookie! },
    });
    assert.equal(readable.status, 200);
    const forbidden = await fetch(`${lab.baseUrl}/api/reset`, {
      method: "POST",
      headers: authHeaders(viewer.cookie!, viewer.payload.csrfToken),
    });
    assert.equal(forbidden.status, 403);
    assert.equal((await forbidden.json() as any).code, "TENANT_FORBIDDEN");
  } finally {
    await lab.close();
  }
});

test("authenticated mode refuses the simulator's unscoped persistent database", () => {
  assert.throws(
    () => createLabServer({
      dbPath: "must-not-open.sqlite",
      access: {
        mode: "authenticated",
        identityProvider: {
          type: "bootstrap-controlled-demo",
          credentials: [
            { token: TOKEN_A, principalId: "operator-a", tenantId: "tenant-a", roles: ["operator"] },
          ],
        },
        allowedOrigins: ["https://airlock.example"],
      },
    }),
    /single-tenant simulator database/,
  );
});
