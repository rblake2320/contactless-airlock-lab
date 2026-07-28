import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import {
  buildCapacityEvidence,
  percentile95,
} from "../packages/operations/capacityEvidence.ts";
import { parseLaunchPolicy } from "../packages/operations/launchPolicy.ts";

const policy = parseLaunchPolicy(JSON.parse(
  readFileSync("config/controlled-demo-slo.v1.json", "utf8"),
));
const metadata = {
  commit: "0123456789abcdef0123456789abcdef01234567",
  buildId: "capacity-test-build",
  hardware: "synthetic test hardware descriptor",
  processCount: 1,
  concurrency: 16,
  warmState: "warm" as const,
  durationSeconds: policy.reliability.measurementWindowSeconds,
  targetUrl: "http://127.0.0.1:8788",
};

test("capacity evidence records required context and delegates pass/fail to policy", () => {
  const evidence = buildCapacityEvidence({
    policy,
    metadata,
    generatedAt: "2026-07-28T12:00:00.000Z",
    measurement: {
      totalRequests: 1_000,
      successfulRequests: 1_000,
      readP95Milliseconds: 20,
      mutationP95Milliseconds: 40,
      completeSyntheticCycleP95Milliseconds: 100,
      peakConcurrentRequests: 16,
      peakConcurrentSseStreams: 0,
    },
  });
  assert.equal(evidence.evaluation.passed, true);
  assert.deepEqual(evidence.metadata, metadata);

  const failed = buildCapacityEvidence({
    policy,
    metadata,
    measurement: {
      ...evidence.measurement,
      successfulRequests: 998,
      mutationP95Milliseconds: 251,
    },
  });
  assert.equal(failed.evaluation.passed, false);
  assert.deepEqual(failed.evaluation.failures, [
    "success ratio is below the declared minimum",
    "mutation p95 exceeds the declared SLO",
  ]);
});

test("capacity evidence rejects short, unidentified, excessive, or remote runs", () => {
  const measurement = {
    totalRequests: 1_000,
    successfulRequests: 1_000,
    readP95Milliseconds: 1,
    mutationP95Milliseconds: 1,
    completeSyntheticCycleP95Milliseconds: 1,
    peakConcurrentRequests: 1,
    peakConcurrentSseStreams: 0,
  };
  assert.throws(
    () => buildCapacityEvidence({
      policy,
      metadata: { ...metadata, durationSeconds: 299 },
      measurement,
    }),
    /shorter than the policy measurement window/,
  );
  assert.throws(
    () => buildCapacityEvidence({
      policy,
      metadata: { ...metadata, commit: "unknown" },
      measurement,
    }),
    /explicit commit hash/,
  );
  assert.throws(
    () => buildCapacityEvidence({
      policy,
      metadata: { ...metadata, concurrency: 129 },
      measurement,
    }),
    /exceeds the controlled-demo policy/,
  );
  assert.throws(
    () => buildCapacityEvidence({
      policy,
      metadata: { ...metadata, targetUrl: "https://public.example" },
      measurement,
    }),
    /loopback HTTP/,
  );
});

test("p95 uses deterministic nearest-rank semantics", () => {
  assert.equal(percentile95(Array.from({ length: 100 }, (_, index) => index + 1)), 95);
  assert.throws(() => percentile95([]), /at least one sample/);
});
