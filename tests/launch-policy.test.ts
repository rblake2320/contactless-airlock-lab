import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import {
  evaluateMeasurement,
  parseLaunchPolicy,
} from "../packages/operations/launchPolicy.ts";

const rawPolicy = JSON.parse(
  readFileSync("config/controlled-demo-slo.v1.json", "utf8"),
) as unknown;

test("controlled-demo launch policy is strict, bounded, and non-production", () => {
  const policy = parseLaunchPolicy(rawPolicy);
  assert.equal(policy.profile, "controlled-single-user-demo");
  assert.equal(policy.scope.syntheticDataOnly, true);
  assert.equal(policy.scope.realPaymentTrafficAllowed, false);
  assert.equal(policy.scope.publicInternetAllowed, false);
  assert.equal(policy.scope.maximumTenants, 1);
  assert.equal(policy.traffic.overloadStatus, 503);
});

test("launch policy rejects unknown fields and production authorization", () => {
  const base = structuredClone(rawPolicy) as Record<string, unknown>;
  assert.throws(() => parseLaunchPolicy({ ...base, surprise: true }), /unknown or missing/);

  const publicPolicy = structuredClone(rawPolicy) as {
    scope: { publicInternetAllowed: boolean };
  };
  publicPolicy.scope.publicInternetAllowed = true;
  assert.throws(() => parseLaunchPolicy(publicPolicy), /synthetic, non-public/);

  const paymentPolicy = structuredClone(rawPolicy) as {
    scope: { realPaymentTrafficAllowed: boolean };
  };
  paymentPolicy.scope.realPaymentTrafficAllowed = true;
  assert.throws(() => parseLaunchPolicy(paymentPolicy), /synthetic, non-public/);
});

test("measurement evaluation passes only inside every declared boundary", () => {
  const policy = parseLaunchPolicy(rawPolicy);
  assert.deepEqual(
    evaluateMeasurement(policy, {
      totalRequests: 10_000,
      successfulRequests: 10_000,
      readP95Milliseconds: 20,
      mutationP95Milliseconds: 40,
      completeSyntheticCycleP95Milliseconds: 100,
      peakConcurrentRequests: 100,
      peakConcurrentSseStreams: 4,
    }),
    { passed: true, failures: [] },
  );

  const failed = evaluateMeasurement(policy, {
    totalRequests: 2_000,
    successfulRequests: 1_990,
    readP95Milliseconds: 101,
    mutationP95Milliseconds: 251,
    completeSyntheticCycleP95Milliseconds: 501,
    peakConcurrentRequests: 129,
    peakConcurrentSseStreams: 65,
  });
  assert.equal(failed.passed, false);
  assert.deepEqual(failed.failures, [
    "success ratio is below the declared minimum",
    "read p95 exceeds the declared SLO",
    "mutation p95 exceeds the declared SLO",
    "complete synthetic cycle p95 exceeds the declared SLO",
    "peak request concurrency exceeds the approved profile",
    "peak SSE concurrency exceeds the approved profile",
  ]);
});
