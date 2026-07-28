import assert from "node:assert/strict";
import type { AddressInfo } from "node:net";
import test from "node:test";
import {
  createLabServer,
  REALTIME_LAB_API_ROUTES,
  ROUTE_MANIFEST,
} from "../apps/realtime-lab/server.ts";

// Exhaustive, ROUTE_MANIFEST-driven method-dispatch coverage. This does NOT
// re-verify business logic (already covered by openapi-contract.test.ts,
// engine.test.ts, protocol.test.ts, etc.) — it verifies that method
// dispatch itself is correct for every route the manifest declares: an
// allowed method never gets routed as 404/405, a disallowed method always
// gets exactly 405 with an Allow header matching the manifest, HEAD never
// carries a body, and an unrecognized path stays 404 regardless of method.

const CANDIDATE_METHODS = ["GET", "HEAD", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"] as const;

async function withLab(fn: (baseUrl: string) => Promise<void>): Promise<void> {
  const server = createLabServer();
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address() as AddressInfo;
  try {
    await fn(`http://127.0.0.1:${port}`);
  } finally {
    await new Promise<void>((resolve, reject) =>
      server.close((error) => error ? reject(error) : resolve()));
  }
}

function concretePath(entry: (typeof ROUTE_MANIFEST)[number]): string {
  return entry.isPrefix ? `${entry.path}sample-attack` : entry.path;
}

test("every disallowed method on every known route returns 405 with an accurate Allow header", async () => {
  await withLab(async (baseUrl) => {
    for (const entry of ROUTE_MANIFEST) {
      const path = concretePath(entry);
      for (const method of CANDIDATE_METHODS) {
        if (entry.methods.includes(method)) continue;
        const response = await fetch(`${baseUrl}${path}`, { method });
        assert.equal(
          response.status,
          405,
          `${method} ${path}: expected 405, got ${response.status}`,
        );
        assert.equal(
          response.headers.get("allow"),
          entry.methods.join(", "),
          `${method} ${path}: Allow header`,
        );
        const body = await response.text();
        if (method === "HEAD") {
          assert.equal(body, "", `HEAD ${path}: 405 body must be empty`);
        } else {
          const parsed = JSON.parse(body);
          assert.equal(parsed.code, "METHOD_NOT_ALLOWED");
        }
      }
    }
  });
});

test("every allowed method on every known route is dispatched, never 404/405", async () => {
  await withLab(async (baseUrl) => {
    for (const entry of ROUTE_MANIFEST) {
      const path = concretePath(entry);
      for (const method of entry.methods) {
        if (method === "GET" && entry.path === REALTIME_LAB_API_ROUTES.events) {
          // GET /api/events opens an SSE stream; dispatch correctness is
          // already covered by the realtime-lab SSE tests. Skip firing it
          // here to avoid leaving an open stream/listener behind.
          continue;
        }
        const response = await fetch(`${baseUrl}${path}`, { method });
        assert.notEqual(response.status, 404, `${method} ${path} was routed as unknown`);
        assert.notEqual(response.status, 405, `${method} ${path} was routed as disallowed`);
        await response.body?.cancel();
      }
    }
  });
});

test("HEAD on every HEAD-capable route matches its GET status, headers, and Content-Length, with zero body", async () => {
  await withLab(async (baseUrl) => {
    for (const entry of ROUTE_MANIFEST) {
      if (!entry.methods.includes("HEAD")) continue;
      const path = concretePath(entry);
      const [getResponse, headResponse] = await Promise.all([
        fetch(`${baseUrl}${path}`, { method: "GET" }),
        fetch(`${baseUrl}${path}`, { method: "HEAD" }),
      ]);
      const getBody = await getResponse.text();
      const headBody = await headResponse.text();
      assert.equal(headResponse.status, getResponse.status, `${path}: status parity`);
      assert.equal(
        headResponse.headers.get("content-type"),
        getResponse.headers.get("content-type"),
        `${path}: content-type parity`,
      );
      assert.equal(
        headResponse.headers.get("content-length"),
        String(Buffer.byteLength(getBody)),
        `${path}: HEAD content-length must match GET's real body size`,
      );
      assert.equal(headBody, "", `${path}: HEAD must carry zero body`);
    }
  });
});

test("HEAD /api/events (not HEAD-capable) is 405 with Allow: GET, not a hung stream", async () => {
  await withLab(async (baseUrl) => {
    const response = await fetch(`${baseUrl}${REALTIME_LAB_API_ROUTES.events}`, { method: "HEAD" });
    assert.equal(response.status, 405);
    assert.equal(response.headers.get("allow"), "GET");
    assert.equal(await response.text(), "");
  });
});

test("unrecognized paths stay 404 for every method, HEAD included, with zero body on HEAD", async () => {
  await withLab(async (baseUrl) => {
    for (const path of ["/nonexistent", "/api/nonexistent", "/api/demonstrate", "/../etc/passwd"]) {
      for (const method of CANDIDATE_METHODS) {
        const response = await fetch(`${baseUrl}${path}`, { method });
        assert.equal(response.status, 404, `${method} ${path}`);
        if (method === "HEAD") {
          assert.equal(await response.text(), "", `HEAD ${path}: 404 body must be empty`);
        }
      }
    }
  });
});

test("a 405 response never triggers a mutation: idempotency key and rate limiter both stay untouched", async () => {
  await withLab(async (baseUrl) => {
    const before = await (await fetch(`${baseUrl}/api/state`)).json();
    // GET on a POST-only route: if the manifest 405 check were placed after
    // the POST-preprocessing block instead of before it, this would still
    // be safe for a GET (preprocessing is POST-gated) — the real risk is a
    // wrong-method POST-shaped request never reaching preprocessing at all
    // for a route that isn't POST-only. Exercise the actual risk directly:
    // an unsupported method carrying an Idempotency-Key header must not be
    // able to consume/register that key before the 405 short-circuits.
    const response = await fetch(`${baseUrl}${REALTIME_LAB_API_ROUTES.reset}`, {
      method: "DELETE",
      headers: { "idempotency-key": "11111111-1111-4111-8111-111111111111" },
    });
    assert.equal(response.status, 405);
    const after = await (await fetch(`${baseUrl}/api/state`)).json();
    assert.deepEqual(after.audit.events, before.audit.events);
    // The same idempotency key must still be free to use on a real POST.
    const real = await fetch(`${baseUrl}${REALTIME_LAB_API_ROUTES.reset}`, {
      method: "POST",
      headers: { "idempotency-key": "11111111-1111-4111-8111-111111111111" },
    });
    assert.equal(real.status, 200);
  });
});
