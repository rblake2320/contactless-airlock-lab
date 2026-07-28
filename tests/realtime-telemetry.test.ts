import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import type { AddressInfo } from "node:net";
import test from "node:test";
import {
  createLabServer,
  type CreateLabServerOptions,
} from "../apps/realtime-lab/server.ts";
import { parseLaunchPolicy, type LaunchPolicy } from "../packages/operations/launchPolicy.ts";
import {
  assertPrivacySafeServiceMetrics,
  ServiceTelemetry,
} from "../packages/operations/serviceTelemetry.ts";

const baseline = parseLaunchPolicy(JSON.parse(
  readFileSync(new URL("../config/controlled-demo-slo.v1.json", import.meta.url), "utf8"),
));

function policy(
  maximumConcurrentRequests: number,
  maximumConcurrentSseStreams = 4,
): LaunchPolicy {
  return {
    ...baseline,
    traffic: {
      ...baseline.traffic,
      maximumConcurrentRequests,
      maximumConcurrentSseStreams,
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
        server.close((error) => error ? reject(error) : resolve())
      ),
  };
}

const delay = (milliseconds: number) =>
  new Promise<void>((resolve) => setTimeout(resolve, milliseconds));

test("health publishes only privacy-safe service metrics matching the runtime contract", async () => {
  const lab = await listen();
  try {
    const response = await fetch(`${lab.baseUrl}/api/health`);
    assert.equal(response.status, 200);
    const health = await response.json() as Record<string, unknown>;
    const service = health.service as ReturnType<ServiceTelemetry["snapshot"]>;
    assert.equal(service.schemaVersion, "airlock.service-metrics.v1");
    assert.deepEqual(service.readiness, {
      ready: false,
      database: false,
      identityProvider: false,
      auditCustody: false,
      partnerTransport: false,
    });
    assertPrivacySafeServiceMetrics(service);
    const serialized = JSON.stringify(service).toLowerCase();
    for (const forbidden of [
      "tenant", "principal", "subject", "token", "device", "merchant",
      "authorization", "correlation", "cookie", "user-agent",
    ]) {
      assert.equal(serialized.includes(forbidden), false);
    }

    const monitoring = JSON.parse(readFileSync(
      new URL("../contracts/operations/service-monitoring.v1.schema.json", import.meta.url),
      "utf8",
    ));
    assert.deepEqual(monitoring["x-runtime-wiring"], {
      realtimeServerIntegrated: true,
      externalTelemetryExporterConfigured: false,
      externalPagerConfigured: false,
    });
    const openapi = JSON.parse(readFileSync(
      new URL("../contracts/openapi/realtime-lab.openapi.json", import.meta.url),
      "utf8",
    ));
    assert.equal(
      openapi.components.schemas.Health.properties.service.$ref,
      "#/components/schemas/ServiceMetrics",
    );
    assert.equal(
      openapi.paths["/api/health"].get.responses["503"].$ref,
      "#/components/responses/ServiceUnavailable",
    );
  } finally {
    await lab.close();
  }
});

test("request overload fails before body parsing and state mutation with Retry-After", async () => {
  const telemetry = new ServiceTelemetry(policy(1));
  const held = telemetry.enterRequest();
  assert.equal(held.admitted, true);
  const lab = await listen({ telemetry });
  try {
    const before = await (await fetch(`${lab.baseUrl}/api/state`)).json();
    // The read is rejected too while the explicit lease is held, proving
    // process-wide admission. Release briefly to obtain the baseline.
    assert.equal((before as { code?: string }).code, "SERVICE_OVERLOADED");
    held.release?.();
    const stateBefore = await (await fetch(`${lab.baseUrl}/api/state`)).json();
    const secondHold = telemetry.enterRequest();
    const response = await fetch(`${lab.baseUrl}/api/reset`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        host: new URL(lab.baseUrl).host,
        origin: lab.baseUrl,
      },
      body: "{ definitely-not-json",
    });
    assert.equal(response.status, 503);
    assert.equal(response.headers.get("retry-after"), "1");
    assert.deepEqual(await response.json(), {
      code: "SERVICE_OVERLOADED",
      error: "Service admission is saturated. Retry after the indicated delay.",
    });
    secondHold.release?.();
    const stateAfter = await (await fetch(`${lab.baseUrl}/api/state`)).json();
    assert.deepEqual(stateAfter, stateBefore);
    assert.equal(telemetry.snapshot().saturation.currentRequests, 0);
    assert.equal(telemetry.snapshot().counters.overloadRejectionsTotal, 2);
  } finally {
    await lab.close();
  }
});

test("SSE telemetry admission and cleanup are exact and independent of legacy limits", async () => {
  const telemetry = new ServiceTelemetry(policy(8, 1));
  const lab = await listen({ telemetry, sseLimit: false, sseHeartbeatMs: 25 });
  try {
    const held = telemetry.enterSse();
    const rejected = await fetch(`${lab.baseUrl}/api/events`);
    assert.equal(rejected.status, 503);
    assert.equal(rejected.headers.get("retry-after"), "1");
    held.release?.();

    const controller = new AbortController();
    const stream = await fetch(`${lab.baseUrl}/api/events`, {
      signal: controller.signal,
    });
    assert.equal(stream.status, 200);
    assert.equal(telemetry.snapshot().saturation.currentRequests, 0);
    assert.equal(telemetry.snapshot().saturation.currentSseStreams, 1);
    controller.abort();
    await delay(50);
    const snapshot = telemetry.snapshot();
    assert.equal(snapshot.saturation.currentRequests, 0);
    assert.equal(snapshot.saturation.currentSseStreams, 0);
    assert.equal(snapshot.saturation.peakSseStreams, 1);
  } finally {
    await lab.close();
  }
});

test("request outcomes and read/mutation latency are observed and all leases release", async () => {
  let now = 1_000;
  const telemetry = new ServiceTelemetry(policy(8), new Date(now));
  const lab = await listen({ telemetry, clock: () => ++now });
  try {
    assert.equal((await fetch(`${lab.baseUrl}/api/state`)).status, 200);
    assert.equal((await fetch(`${lab.baseUrl}/missing`)).status, 404);
    assert.equal((await fetch(`${lab.baseUrl}/api/reset`, {
      method: "POST",
      headers: { host: new URL(lab.baseUrl).host, origin: lab.baseUrl },
    })).status, 200);
    await delay(10);
    const snapshot = telemetry.snapshot(new Date(now));
    assert.equal(snapshot.saturation.currentRequests, 0);
    assert.equal(snapshot.counters.requestsTotal, 3);
    assert.equal(snapshot.counters.successfulRequestsTotal, 3);
    assert.equal(snapshot.counters.clientErrorsTotal, 1);
    assert.equal(snapshot.sampleCounts.readLatency, 1);
    assert.equal(snapshot.sampleCounts.mutationLatency, 1);
    assert.ok(snapshot.latencyMilliseconds.readP95 > 0);
    assert.ok(snapshot.latencyMilliseconds.mutationP95 > 0);
  } finally {
    await lab.close();
  }
});
