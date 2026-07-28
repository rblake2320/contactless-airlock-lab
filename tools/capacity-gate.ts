#!/usr/bin/env node
import { readFileSync, writeFileSync } from "node:fs";
import { cpus, hostname, platform, release, totalmem } from "node:os";
import { resolve } from "node:path";
import {
  buildCapacityEvidence,
  percentile95,
} from "../packages/operations/capacityEvidence.ts";
import { parseLaunchPolicy } from "../packages/operations/launchPolicy.ts";

if (process.env.AIRLOCK_CAPACITY_GATE !== "true") {
  throw new Error(
    "capacity gate is opt-in; set AIRLOCK_CAPACITY_GATE=true against an isolated local simulator",
  );
}

const policy = parseLaunchPolicy(JSON.parse(
  readFileSync(
    resolve(process.env.AIRLOCK_CAPACITY_POLICY ?? "config/controlled-demo-slo.v1.json"),
    "utf8",
  ),
));
const targetUrl = process.env.AIRLOCK_CAPACITY_URL ?? "http://127.0.0.1:8788";
const target = new URL(targetUrl);
if (
  target.protocol !== "http:" ||
  !["127.0.0.1", "localhost", "::1"].includes(target.hostname)
) {
  throw new Error("capacity gate refuses non-loopback targets");
}
const commit = process.env.AIRLOCK_COMMIT;
if (!commit) throw new Error("AIRLOCK_COMMIT is required; do not infer it after the run");
const processCount = Number(process.env.AIRLOCK_PROCESS_COUNT ?? "1");
const concurrency = Number(process.env.AIRLOCK_CAPACITY_CONCURRENCY ?? "16");
const warmState = process.env.AIRLOCK_WARM_STATE;
if (warmState !== "warm" && warmState !== "cold") {
  throw new Error("AIRLOCK_WARM_STATE must explicitly be warm or cold");
}
if (
  !Number.isSafeInteger(concurrency) ||
  concurrency < 1 ||
  concurrency > policy.traffic.maximumConcurrentRequests
) {
  throw new Error("AIRLOCK_CAPACITY_CONCURRENCY is outside policy");
}

const readLatencies: number[] = [];
const mutationLatencies: number[] = [];
const cycleLatencies: number[] = [];
let totalRequests = 0;
let successfulRequests = 0;
let active = 0;
let peakConcurrentRequests = 0;

async function request(path: string, init?: RequestInit, bucket?: number[]): Promise<boolean> {
  active += 1;
  peakConcurrentRequests = Math.max(peakConcurrentRequests, active);
  const started = performance.now();
  try {
    const response = await fetch(new URL(path, target), init);
    const success = response.status >= 200 && response.status < 300;
    await response.arrayBuffer();
    totalRequests += 1;
    if (success) successfulRequests += 1;
    bucket?.push(performance.now() - started);
    return success;
  } catch {
    totalRequests += 1;
    bucket?.push(performance.now() - started);
    return false;
  } finally {
    active -= 1;
  }
}

const jsonPost = (body = "{}"): RequestInit => ({
  method: "POST",
  headers: { "content-type": "application/json" },
  body,
});

async function completeCycle(): Promise<void> {
  const started = performance.now();
  const steps: [string, RequestInit][] = [
    ["/api/reset", jsonPost()],
    ["/api/provision/request", jsonPost()],
    ["/api/provision/approve", jsonPost()],
    ["/api/transaction/request", jsonPost(JSON.stringify({
      amount: "12.34",
      merchantId: "capacity-gate-synthetic",
    }))],
    ["/api/transaction/confirm", jsonPost()],
  ];
  for (const [path, init] of steps) {
    if (!await request(path, init, mutationLatencies)) return;
  }
  cycleLatencies.push(performance.now() - started);
}

// Warm/cold is declared evidence, not inferred. Record real complete protocol
// cycles before throughput traffic so shared simulator state cannot race.
for (let index = 0; index < 20; index += 1) await completeCycle();

const measurementStarted = Date.now();
const deadline = measurementStarted +
  policy.reliability.measurementWindowSeconds * 1_000;
let sequence = 0;
while (Date.now() < deadline) {
  const batchStarted = Date.now();
  const batch = Array.from({ length: concurrency }, async () => {
    sequence += 1;
    if (sequence % 5 === 0) {
      return request("/api/reset", jsonPost(), mutationLatencies);
    }
    return request("/api/health", undefined, readLatencies);
  });
  await Promise.all(batch);
  const targetBatchMilliseconds =
    (concurrency / policy.traffic.sustainedRequestsPerSecond) * 1_000;
  const remaining = targetBatchMilliseconds - (Date.now() - batchStarted);
  if (remaining > 0) await new Promise((resolveDelay) => setTimeout(resolveDelay, remaining));
}

const health = await (await fetch(new URL("/api/health", target))).json() as {
  buildId?: unknown;
};
if (typeof health.buildId !== "string") {
  throw new Error("target health did not expose a runtime buildId");
}
const durationSeconds = Math.ceil((Date.now() - measurementStarted) / 1_000);
const measurement = {
  totalRequests,
  successfulRequests,
  readP95Milliseconds: percentile95(readLatencies),
  mutationP95Milliseconds: percentile95(mutationLatencies),
  completeSyntheticCycleP95Milliseconds: percentile95(cycleLatencies),
  peakConcurrentRequests,
  peakConcurrentSseStreams: 0,
};
const evidence = buildCapacityEvidence({
  policy,
  metadata: {
    commit,
    buildId: health.buildId,
    hardware:
      `${hostname()} ${platform()} ${release()} ${cpus().length}cpu ${totalmem()}bytes`,
    processCount,
    concurrency,
    warmState,
    durationSeconds,
    targetUrl: target.origin,
  },
  measurement,
});
const serialized = JSON.stringify(evidence, null, 2) + "\n";
const output = process.env.AIRLOCK_CAPACITY_OUTPUT;
if (output) writeFileSync(resolve(output), serialized, { flag: "wx" });
process.stdout.write(serialized);
if (!evidence.evaluation.passed) process.exitCode = 1;
