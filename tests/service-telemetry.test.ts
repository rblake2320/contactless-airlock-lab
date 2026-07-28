import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { parseLaunchPolicy } from "../packages/operations/launchPolicy.ts";
import {
  ServiceTelemetry,
  assertPrivacySafeServiceMetrics,
  evaluateServiceAlerts,
  type ServiceMetricsSnapshot,
} from "../packages/operations/serviceTelemetry.ts";

const start = new Date("2026-07-28T12:00:00.000Z");

async function policy() {
  return parseLaunchPolicy(JSON.parse(await readFile(
    new URL("../config/controlled-demo-slo.v1.json", import.meta.url),
    "utf8",
  )));
}

test("metrics are bounded, label-free, and conform to the repository schema keys", async () => {
  const telemetry = new ServiceTelemetry(await policy(), start);
  telemetry.setReadiness({
    database: true,
    identityProvider: true,
    auditCustody: true,
    partnerTransport: true,
  });
  for (let index = 0; index < 2_100; index += 1) {
    telemetry.recordRequest("read", "success", index % 100);
  }
  telemetry.recordRequest("mutation", "client_error", 125);
  telemetry.recordRequest("mutation", "server_error", 250);
  telemetry.recordDependencyFailure();
  const snapshot = telemetry.snapshot(new Date(start.getTime() + 300_000));
  assertPrivacySafeServiceMetrics(snapshot);
  assert.equal(snapshot.sampleCounts.readLatency, 2_048);
  assert.equal(snapshot.sampleCounts.mutationLatency, 2);
  assert.equal(snapshot.counters.requestsTotal, 2_102);
  assert.equal(snapshot.counters.successfulRequestsTotal, 2_101);
  assert.equal(snapshot.counters.clientErrorsTotal, 1);
  assert.equal(snapshot.counters.serverErrorsTotal, 1);
  assert.equal(snapshot.counters.dependencyFailuresTotal, 1);
  assert.equal(snapshot.readiness.ready, true);

  const schema = JSON.parse(await readFile(
    new URL(
      "../contracts/operations/service-monitoring.v1.schema.json",
      import.meta.url,
    ),
    "utf8",
  ));
  assert.deepEqual(
    Object.keys(snapshot).sort(),
    [...schema.required].sort(),
  );
  assert.deepEqual(
    Object.keys(snapshot.counters).sort(),
    [...schema.properties.counters.required].sort(),
  );
  assert.equal(schema["x-privacy"].labelsAllowed, false);
  assert.equal(
    schema["x-runtime-wiring"].externalTelemetryExporterConfigured,
    false,
  );
  assert.equal(schema["x-runtime-wiring"].externalPagerConfigured, false);
});

test("request and SSE admission fail closed at exact policy limits", async () => {
  const launch = await policy();
  const telemetry = new ServiceTelemetry(launch, start);
  const requestLeases = Array.from(
    { length: launch.traffic.maximumConcurrentRequests },
    () => telemetry.enterRequest(),
  );
  assert.ok(requestLeases.every((lease) => lease.admitted));
  const requestRejected = telemetry.enterRequest();
  assert.deepEqual(requestRejected, {
    admitted: false,
    status: 503,
    retryAfterSeconds: launch.traffic.retryAfterSeconds,
  });
  requestLeases[0].release!();
  requestLeases[0].release!();
  assert.equal(telemetry.enterRequest().admitted, true);

  const sseLeases = Array.from(
    { length: launch.traffic.maximumConcurrentSseStreams },
    () => telemetry.enterSse(),
  );
  assert.ok(sseLeases.every((lease) => lease.admitted));
  assert.equal(telemetry.enterSse().status, 503);
  sseLeases.forEach((lease) => lease.release!());

  const snapshot = telemetry.snapshot(start);
  assert.equal(
    snapshot.saturation.peakRequests,
    launch.traffic.maximumConcurrentRequests,
  );
  assert.equal(
    snapshot.saturation.peakSseStreams,
    launch.traffic.maximumConcurrentSseStreams,
  );
  assert.equal(snapshot.counters.overloadRejectionsTotal, 2);
});

test("SLO evaluator distinguishes insufficient evidence from real breaches", async () => {
  const launch = await policy();
  const telemetry = new ServiceTelemetry(launch, start);
  let alerts = evaluateServiceAlerts(
    launch,
    telemetry.snapshot(new Date(start.getTime() + 1_000)),
  );
  assert.deepEqual(
    alerts.map((alert) => alert.code).sort(),
    ["INSUFFICIENT_WINDOW", "SERVICE_NOT_READY"],
  );

  telemetry.setReadiness({
    database: true,
    identityProvider: true,
    auditCustody: true,
    partnerTransport: true,
  });
  for (let index = 0; index < 998; index += 1) {
    telemetry.recordRequest("read", "success", 101);
  }
  telemetry.recordRequest("read", "server_error", 101);
  telemetry.recordRequest("mutation", "server_error", 251);
  const snapshot = telemetry.snapshot(
    new Date(start.getTime() + launch.reliability.measurementWindowSeconds * 1_000),
  );
  alerts = evaluateServiceAlerts(launch, snapshot);
  assert.deepEqual(
    new Set(alerts.map((alert) => alert.code)),
    new Set([
      "SUCCESS_RATIO_BREACH",
      "READ_LATENCY_BREACH",
      "MUTATION_LATENCY_BREACH",
    ]),
  );
  assert.ok(alerts.every((alert) =>
    !JSON.stringify(alert).includes("tenant")
  ));
});

test("overload and saturation alerts are derived from the same launch policy", async () => {
  const launch = await policy();
  const telemetry = new ServiceTelemetry(launch, start);
  telemetry.setReadiness({
    database: true,
    identityProvider: true,
    auditCustody: true,
    partnerTransport: true,
  });
  const requests = Array.from(
    { length: launch.traffic.maximumConcurrentRequests },
    () => telemetry.enterRequest(),
  );
  const streams = Array.from(
    { length: launch.traffic.maximumConcurrentSseStreams },
    () => telemetry.enterSse(),
  );
  telemetry.enterRequest();
  const alerts = evaluateServiceAlerts(
    launch,
    telemetry.snapshot(new Date(start.getTime() + 1_000)),
  );
  assert.ok(alerts.some((alert) => alert.code === "REQUEST_SATURATION"));
  assert.ok(alerts.some((alert) => alert.code === "SSE_SATURATION"));
  assert.ok(alerts.some((alert) => alert.code === "OVERLOAD_REJECTIONS"));
  requests.forEach((lease) => lease.release!());
  streams.forEach((lease) => lease.release!());
});

test("invalid observations and forged/inconsistent snapshots fail closed", async () => {
  const launch = await policy();
  const telemetry = new ServiceTelemetry(launch, start);
  assert.throws(
    () => telemetry.recordRequest("mutation", "success", -1),
    /invalid/,
  );
  assert.throws(
    () => telemetry.recordRequest("tenant-a" as never, "success", 1),
    /invalid/,
  );
  const snapshot = telemetry.snapshot(start);
  const inconsistent: ServiceMetricsSnapshot = {
    ...snapshot,
    counters: {
      ...snapshot.counters,
      requestsTotal: 1,
      successfulRequestsTotal: 2,
    },
  };
  assert.throws(
    () => evaluateServiceAlerts(launch, inconsistent),
    /invalid/,
  );
  assert.throws(
    () => assertPrivacySafeServiceMetrics({
      ...snapshot,
      tenantId: "forbidden",
    } as never),
    /forbidden/,
  );
});
