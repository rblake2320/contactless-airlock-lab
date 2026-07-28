import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import {
  createLabServer,
  MutationRateLimiter,
  parseRateLimitEnv,
  type CreateLabServerOptions,
} from "../apps/realtime-lab/server.ts";

// A deterministic, test-controlled clock (ms epoch).
function fakeClock(startMs = 1_000_000) {
  let now = startMs;
  return {
    now: () => now,
    advance: (ms: number) => {
      now += ms;
    },
  };
}

async function listen(options: CreateLabServerOptions = {}) {
  const server = createLabServer(options);
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address() as AddressInfo;
  return {
    baseUrl: `http://127.0.0.1:${port}`,
    close: () =>
      new Promise<void>((resolve, reject) =>
        server.close((error) => (error ? reject(error) : resolve())),
      ),
  };
}

const post = (baseUrl: string, path: string, headers: Record<string, string> = {}) =>
  fetch(`${baseUrl}${path}`, { method: "POST", headers });

// Variant that also exposes the underlying server (for shutdown teardown tests).
async function listenServer(options: CreateLabServerOptions = {}) {
  const server = createLabServer(options);
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address() as AddressInfo;
  return { server, baseUrl: `http://127.0.0.1:${port}` };
}

/** Open an SSE stream and hold it open; returns its status and an aborter. */
async function openStream(baseUrl: string) {
  const controller = new AbortController();
  const res = await fetch(`${baseUrl}/api/events`, { signal: controller.signal });
  // Drain in the background so the socket stays live without buffering forever.
  if (res.body) {
    const reader = res.body.getReader();
    void (async () => {
      try {
        while (!controller.signal.aborted) {
          const { done } = await reader.read();
          if (done) break;
        }
      } catch {
        // aborted
      }
    })();
  }
  return {
    status: res.status,
    retryAfter: res.headers.get("retry-after"),
    abort: () => controller.abort(),
  };
}

const delay = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

// ---------------------------------------------------------------------------
// Unit: token bucket determinism (burst, refill, memory bound)
// ---------------------------------------------------------------------------

test("bucket allows exactly `capacity` bursts then blocks with Retry-After", () => {
  const clock = fakeClock();
  const limiter = new MutationRateLimiter(
    { capacity: 3, refillPerSecond: 1, maxClients: 100 },
    clock.now,
  );
  assert.deepEqual(
    [0, 1, 2].map(() => limiter.take("v4:1.2.3.4").allowed),
    [true, true, true],
  );
  const blocked = limiter.take("v4:1.2.3.4");
  assert.equal(blocked.allowed, false);
  assert.equal(blocked.retryAfterSeconds, 1); // 1 token / 1 per sec = 1s
});

test("tokens refill over time and never exceed capacity", () => {
  const clock = fakeClock();
  const limiter = new MutationRateLimiter(
    { capacity: 2, refillPerSecond: 2, maxClients: 100 },
    clock.now,
  );
  limiter.take("k");
  limiter.take("k");
  assert.equal(limiter.take("k").allowed, false); // drained
  clock.advance(500); // 0.5s * 2/s = 1 token
  assert.equal(limiter.take("k").allowed, true);
  assert.equal(limiter.take("k").allowed, false);
  clock.advance(100_000); // long idle must not overfill beyond capacity
  assert.equal(limiter.take("k").allowed, true);
  assert.equal(limiter.take("k").allowed, true);
  assert.equal(limiter.take("k").allowed, false); // only 2, not 200
});

test("Retry-After grows with the token deficit at slow refill", () => {
  const clock = fakeClock();
  const limiter = new MutationRateLimiter(
    { capacity: 1, refillPerSecond: 0.25, maxClients: 100 },
    clock.now,
  );
  assert.equal(limiter.take("k").allowed, true);
  const blocked = limiter.take("k");
  assert.equal(blocked.allowed, false);
  assert.equal(blocked.retryAfterSeconds, 4); // 1 token / 0.25 per sec = 4s
});

test("distinct clients have independent buckets", () => {
  const clock = fakeClock();
  const limiter = new MutationRateLimiter(
    { capacity: 1, refillPerSecond: 1, maxClients: 100 },
    clock.now,
  );
  assert.equal(limiter.take("a").allowed, true);
  assert.equal(limiter.take("a").allowed, false);
  assert.equal(limiter.take("b").allowed, true); // b is unaffected by a
});

test("memory stays bounded at maxClients under identity churn", () => {
  const clock = fakeClock();
  const limiter = new MutationRateLimiter(
    { capacity: 1, refillPerSecond: 1, maxClients: 2 },
    clock.now,
  );
  // 100 distinct identities arrive with no time passing (nothing refills). The
  // first maxClients are admitted-and-penalized; the rest fail closed. The table
  // must never exceed maxClients regardless. (Eviction of a *safely full* bucket
  // is covered by "a fully-refilled bucket is evictable".)
  for (let i = 0; i < 100; i += 1) limiter.take(`id-${i}`);
  assert.ok(limiter.trackedClients <= 2, "tracked buckets never exceed maxClients");
});

test("invalid configuration is rejected", () => {
  const clock = fakeClock();
  for (const bad of [
    { capacity: 0, refillPerSecond: 1, maxClients: 1 },
    { capacity: 1, refillPerSecond: 0, maxClients: 1 },
    { capacity: 1, refillPerSecond: 1, maxClients: 0 },
    { capacity: 1, refillPerSecond: 1, maxClients: 1.5 },
  ]) {
    assert.throws(() => new MutationRateLimiter(bad, clock.now), /invalid rate-limit/);
  }
});

// ---------------------------------------------------------------------------
// HTTP: 429 shape, no mutation on rejection, GET exemption, reset behavior
// ---------------------------------------------------------------------------

test("HTTP mutations get 429 + Retry-After + RATE_LIMITED after the burst", async () => {
  const clock = fakeClock();
  const lab = await listen({
    rateLimit: { capacity: 2, refillPerSecond: 1, maxClients: 100 },
    clock: clock.now,
  });
  try {
    assert.equal((await post(lab.baseUrl, "/api/reset")).status, 200);
    assert.equal((await post(lab.baseUrl, "/api/reset")).status, 200);
    const limited = await post(lab.baseUrl, "/api/reset");
    assert.equal(limited.status, 429);
    assert.equal(limited.headers.get("retry-after"), "1");
    const body = (await limited.json()) as { code: string; error: string };
    assert.equal(body.code, "RATE_LIMITED");
    assert.match(body.error, /SIMULATOR/);
    assert.deepEqual(Object.keys(body).sort(), ["code", "error"]); // SimpleError shape
  } finally {
    await lab.close();
  }
});

test("a rate-limited mutation does NOT change simulator state", async () => {
  const clock = fakeClock();
  const lab = await listen({
    rateLimit: { capacity: 1, refillPerSecond: 1, maxClients: 100 },
    clock: clock.now,
  });
  try {
    // Burn the single token on a benign state read-through, then attempt a real
    // mutation that would create a provisioning request.
    assert.equal((await post(lab.baseUrl, "/api/reset")).status, 200);
    const before = await (await fetch(`${lab.baseUrl}/api/state`)).json();
    const limited = await post(lab.baseUrl, "/api/provision/request");
    assert.equal(limited.status, 429);
    const after = await (await fetch(`${lab.baseUrl}/api/state`)).json();
    assert.deepEqual(after, before, "state must be untouched after a 429");
  } finally {
    await lab.close();
  }
});

test("GET reads (state, health, events) are never rate limited", async () => {
  const clock = fakeClock();
  const lab = await listen({
    rateLimit: { capacity: 1, refillPerSecond: 1, maxClients: 100 },
    clock: clock.now,
  });
  try {
    await post(lab.baseUrl, "/api/reset"); // drains the single token
    for (let i = 0; i < 5; i += 1) {
      assert.equal((await fetch(`${lab.baseUrl}/api/health`)).status, 200);
      assert.equal((await fetch(`${lab.baseUrl}/api/state`)).status, 200);
    }
  } finally {
    await lab.close();
  }
});

test("refill via injected clock lets a blocked client resume", async () => {
  const clock = fakeClock();
  const lab = await listen({
    rateLimit: { capacity: 1, refillPerSecond: 1, maxClients: 100 },
    clock: clock.now,
  });
  try {
    assert.equal((await post(lab.baseUrl, "/api/reset")).status, 200);
    assert.equal((await post(lab.baseUrl, "/api/reset")).status, 429);
    clock.advance(1_000); // one token refills
    assert.equal((await post(lab.baseUrl, "/api/reset")).status, 200);
  } finally {
    await lab.close();
  }
});

test("reset does not refill the limiter (cannot be used to bypass the ceiling)", async () => {
  const clock = fakeClock();
  const lab = await listen({
    rateLimit: { capacity: 2, refillPerSecond: 1, maxClients: 100 },
    clock: clock.now,
  });
  try {
    assert.equal((await post(lab.baseUrl, "/api/reset")).status, 200);
    assert.equal((await post(lab.baseUrl, "/api/reset")).status, 200);
    // The 2 tokens are gone; a further reset is itself rate limited and must
    // NOT reset/refill the bucket for subsequent mutations.
    assert.equal((await post(lab.baseUrl, "/api/reset")).status, 429);
    assert.equal((await post(lab.baseUrl, "/api/provision/request")).status, 429);
  } finally {
    await lab.close();
  }
});

// ---------------------------------------------------------------------------
// Concurrency: exactly `capacity` of N concurrent mutations succeed
// ---------------------------------------------------------------------------

test("under a burst of concurrent requests exactly `capacity` succeed", async () => {
  const clock = fakeClock();
  const capacity = 5;
  const lab = await listen({
    rateLimit: { capacity, refillPerSecond: 1, maxClients: 100 },
    clock: clock.now, // frozen: no refill mid-burst
  });
  try {
    const results = await Promise.all(
      Array.from({ length: 25 }, () => post(lab.baseUrl, "/api/reset")),
    );
    const ok = results.filter((r) => r.status === 200).length;
    const limited = results.filter((r) => r.status === 429).length;
    assert.equal(ok, capacity, "exactly capacity succeed");
    assert.equal(limited, 25 - capacity, "the rest are 429");
  } finally {
    await lab.close();
  }
});

// ---------------------------------------------------------------------------
// Trust boundary: spoofed X-Forwarded-For must not fragment the bucket
// ---------------------------------------------------------------------------

test("spoofed X-Forwarded-For is ignored when the peer is not a trusted proxy", async () => {
  const clock = fakeClock();
  const lab = await listen({
    rateLimit: { capacity: 2, refillPerSecond: 1, maxClients: 100 },
    clock: clock.now,
    // no trustedProxies -> forwarding headers are ignored, bucket keyed by peer
  });
  try {
    // All three requests share one real peer (127.0.0.1); rotating the spoofed
    // header must NOT grant extra tokens.
    assert.equal(
      (await post(lab.baseUrl, "/api/reset", { "x-forwarded-for": "10.0.0.1" })).status,
      200,
    );
    assert.equal(
      (await post(lab.baseUrl, "/api/reset", { "x-forwarded-for": "10.0.0.2" })).status,
      200,
    );
    const spoofed = await post(lab.baseUrl, "/api/reset", {
      "x-forwarded-for": "10.0.0.3",
    });
    assert.equal(spoofed.status, 429, "spoofed XFF did not fragment the bucket");
  } finally {
    await lab.close();
  }
});

test("X-Forwarded-For IS honored when the direct peer is a trusted proxy", async () => {
  const clock = fakeClock();
  const lab = await listen({
    rateLimit: { capacity: 1, refillPerSecond: 1, maxClients: 100 },
    clock: clock.now,
    trustedProxies: ["127.0.0.1"], // the loopback test peer is trusted
  });
  try {
    // Two different real clients behind the trusted proxy each get their own token.
    assert.equal(
      (await post(lab.baseUrl, "/api/reset", { "x-forwarded-for": "203.0.113.7" })).status,
      200,
    );
    assert.equal(
      (await post(lab.baseUrl, "/api/reset", { "x-forwarded-for": "203.0.113.8" })).status,
      200,
    );
    // The first client, reusing its token, is now limited.
    assert.equal(
      (await post(lab.baseUrl, "/api/reset", { "x-forwarded-for": "203.0.113.7" })).status,
      429,
    );
  } finally {
    await lab.close();
  }
});

// ---------------------------------------------------------------------------
// Idempotent replay semantics: a persisted replay is not rate limited
// ---------------------------------------------------------------------------

test("persistent idempotent replay returns the stored response and bypasses the limiter", async () => {
  const clock = fakeClock();
  const directory = mkdtempSync(join(tmpdir(), "airlock-rl-"));
  const lab = await listen({
    dbPath: join(directory, "lab.sqlite"),
    rateLimit: { capacity: 1, refillPerSecond: 1, maxClients: 100 },
    clock: clock.now,
  });
  try {
    const key = { "idempotency-key": "replay-key-1" };
    const first = await post(lab.baseUrl, "/api/reset", key);
    assert.equal(first.status, 200);
    const firstBody = await first.json();
    // The single token is now spent. A DIFFERENT fresh mutation (its own key, so
    // it clears the persistent idempotency gate) is limited by the bucket...
    assert.equal(
      (await post(lab.baseUrl, "/api/provision/request", {
        "idempotency-key": "fresh-key-2",
      })).status,
      429,
    );
    // ...but replaying the SAME idempotency key still returns its stored 200.
    const replay = await post(lab.baseUrl, "/api/reset", key);
    assert.equal(replay.status, 200, "idempotent replay must not be rate limited");
    assert.deepEqual(await replay.json(), firstBody);
  } finally {
    await lab.close();
    rmSync(directory, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------
// Config: env parsing + disable switch
// ---------------------------------------------------------------------------

test("parseRateLimitEnv handles config, disable, and invalid inputs", () => {
  assert.equal(parseRateLimitEnv(undefined), undefined);
  assert.equal(parseRateLimitEnv(""), undefined);
  assert.equal(parseRateLimitEnv("off"), false);
  assert.equal(parseRateLimitEnv("disabled"), false);
  assert.deepEqual(parseRateLimitEnv("300:150"), {
    capacity: 300,
    refillPerSecond: 150,
    maxClients: 10_000,
  });
  assert.deepEqual(parseRateLimitEnv("10:2:500"), {
    capacity: 10,
    refillPerSecond: 2,
    maxClients: 500,
  });
  assert.throws(() => parseRateLimitEnv("bad"), /AIRLOCK_RATE_LIMIT/);
  assert.throws(() => parseRateLimitEnv("10:0"), /AIRLOCK_RATE_LIMIT/);
});

test("rateLimit:false disables enforcement entirely", async () => {
  const lab = await listen({ rateLimit: false });
  try {
    for (let i = 0; i < 40; i += 1) {
      assert.equal((await post(lab.baseUrl, "/api/reset")).status, 200);
    }
  } finally {
    await lab.close();
  }
});

// ---------------------------------------------------------------------------
// Item 2: attacker identity churn must not refund a penalized bucket
// ---------------------------------------------------------------------------

test("LRU churn never evicts a penalized bucket (fail-closed admission)", () => {
  const clock = fakeClock();
  const limiter = new MutationRateLimiter(
    { capacity: 1, refillPerSecond: 1, maxClients: 2 },
    clock.now,
  );
  // Victim spends its token and is now penalized (tokens < capacity).
  assert.equal(limiter.take("victim").allowed, true);
  assert.equal(limiter.take("victim").allowed, false); // victim throttled
  // A second identity also spends down -> both tracked buckets are penalized.
  assert.equal(limiter.take("filler").allowed, true);
  // Attacker floods NEW identities. With both buckets penalized and the table
  // full, admission must FAIL CLOSED — never evict the victim to make room.
  for (let i = 0; i < 50; i += 1) {
    const d = limiter.take(`attacker-${i}`);
    assert.equal(d.allowed, false, `attacker ${i} must be refused, not admitted`);
  }
  assert.equal(limiter.trackedClients, 2, "table stayed bounded at maxClients");
  assert.ok(limiter.admissionRejections >= 50, "admission rejections were counted");
  // The victim is STILL penalized (its bucket was never wiped by churn).
  assert.equal(limiter.take("victim").allowed, false);
});

test("a fully-refilled bucket is evictable so honest clients still rotate in", () => {
  const clock = fakeClock();
  const limiter = new MutationRateLimiter(
    { capacity: 1, refillPerSecond: 1, maxClients: 1 },
    clock.now,
  );
  assert.equal(limiter.take("a").allowed, true); // a penalized (0 tokens)
  clock.advance(10_000); // a refills fully -> safe to evict
  const b = limiter.take("b"); // evicts the now-full a, admits b
  assert.equal(b.allowed, true);
  assert.equal(limiter.trackedClients, 1);
});

// ---------------------------------------------------------------------------
// Item 1: SSE connection bounding, 429 + Retry-After, deterministic cleanup
// ---------------------------------------------------------------------------

test("per-client SSE cap returns 429 + Retry-After and frees on disconnect", async () => {
  const lab = await listen({
    rateLimit: false,
    sseLimit: { maxPerClient: 2, maxTotal: 100 },
  });
  try {
    const s1 = await openStream(lab.baseUrl);
    const s2 = await openStream(lab.baseUrl);
    assert.equal(s1.status, 200);
    assert.equal(s2.status, 200);
    const rejected = await openStream(lab.baseUrl);
    assert.equal(rejected.status, 429, "third concurrent stream is rejected");
    assert.equal(rejected.retryAfter, "1");
    // Disconnect one; a slot must free up (deterministic cleanup, no leak).
    s1.abort();
    let admitted = false;
    for (let i = 0; i < 40 && !admitted; i += 1) {
      await delay(25);
      const retry = await openStream(lab.baseUrl);
      if (retry.status === 200) {
        admitted = true;
        retry.abort();
      }
    }
    assert.ok(admitted, "a stream slot freed after disconnect");
    s2.abort();
  } finally {
    await lab.close();
  }
});

test("global SSE cap bounds total concurrent streams", async () => {
  const lab = await listen({
    rateLimit: false,
    sseLimit: { maxPerClient: 100, maxTotal: 2 },
  });
  try {
    const a = await openStream(lab.baseUrl);
    const b = await openStream(lab.baseUrl);
    assert.equal(a.status, 200);
    assert.equal(b.status, 200);
    const c = await openStream(lab.baseUrl);
    assert.equal(c.status, 429, "global cap reached");
    a.abort();
    b.abort();
  } finally {
    await lab.close();
  }
});

test("server shutdown tears down live SSE streams without hanging (no timer leak)", async () => {
  const { server, baseUrl } = await listenServer({
    rateLimit: false,
    sseLimit: { maxPerClient: 4, maxTotal: 16 },
  });
  const stream = await openStream(baseUrl);
  assert.equal(stream.status, 200);
  // Force-close sockets so server.close() can complete, then assert teardown
  // runs to completion (if heartbeat timers leaked, the process/test would hang).
  server.closeAllConnections?.();
  await new Promise<void>((resolve, reject) =>
    server.close((error) => (error ? reject(error) : resolve())),
  );
  stream.abort();
  assert.ok(true, "server closed cleanly with a live SSE stream open");
});

test("sseLimit:false disables connection bounding", async () => {
  const lab = await listen({ rateLimit: false, sseLimit: false });
  try {
    const streams = [];
    for (let i = 0; i < 10; i += 1) streams.push(await openStream(lab.baseUrl));
    assert.ok(streams.every((s) => s.status === 200));
    for (const s of streams) s.abort();
  } finally {
    await lab.close();
  }
});

// ---------------------------------------------------------------------------
// Item 4: preflight rejections do NOT consume a token; domain processing does
// ---------------------------------------------------------------------------

test("preflight rejections (415/413/403) do not consume rate-limit tokens", async () => {
  const clock = fakeClock();
  const lab = await listen({
    rateLimit: { capacity: 1, refillPerSecond: 1, maxClients: 100 },
    clock: clock.now,
  });
  try {
    // Several preflight-rejected requests: wrong content-type (415), oversized
    // (413), cross-origin (403). None should spend the single token.
    assert.equal(
      (await fetch(`${lab.baseUrl}/api/transaction/request`, {
        method: "POST",
        headers: { "content-type": "text/plain" },
        body: "{}",
      })).status,
      415,
    );
    assert.equal(
      (await fetch(`${lab.baseUrl}/api/reset`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: "x".repeat(16_385),
      })).status,
      413,
    );
    assert.equal(
      (await post(lab.baseUrl, "/api/reset", { origin: "http://evil.invalid" })).status,
      403,
    );
    // The token is still available: a valid mutation succeeds.
    assert.equal((await post(lab.baseUrl, "/api/reset")).status, 200);
    // ...and only now is the client throttled.
    assert.equal((await post(lab.baseUrl, "/api/reset")).status, 429);
  } finally {
    await lab.close();
  }
});

test("a domain-state 409 DOES consume a token (locked policy)", async () => {
  const clock = fakeClock();
  const lab = await listen({
    rateLimit: { capacity: 2, refillPerSecond: 1, maxClients: 100 },
    clock: clock.now,
  });
  try {
    // First mutation succeeds (token 1). Second is a domain 409 conflict
    // (provisioning already requested) and consumes token 2.
    assert.equal((await post(lab.baseUrl, "/api/provision/request")).status, 200);
    assert.equal((await post(lab.baseUrl, "/api/provision/request")).status, 409);
    // Tokens are now exhausted -> the next request is rate limited, proving the
    // 409 counted against the bucket.
    assert.equal((await post(lab.baseUrl, "/api/reset")).status, 429);
  } finally {
    await lab.close();
  }
});
