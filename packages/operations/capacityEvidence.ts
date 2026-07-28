import type {
  LaunchEvaluation,
  LaunchPolicy,
  Measurement,
} from "./launchPolicy.ts";
import { evaluateMeasurement } from "./launchPolicy.ts";

export interface CapacityRunMetadata {
  commit: string;
  buildId: string;
  hardware: string;
  processCount: number;
  concurrency: number;
  warmState: "cold" | "warm";
  durationSeconds: number;
  targetUrl: string;
}

export interface CapacityEvidence {
  schemaVersion: "airlock.capacity-evidence.v1";
  generatedAt: string;
  policySchemaVersion: string;
  policyProfile: string;
  metadata: CapacityRunMetadata;
  measurement: Measurement;
  evaluation: LaunchEvaluation;
}

export function percentile95(samples: readonly number[]): number {
  if (samples.length === 0) throw new Error("p95 requires at least one sample");
  if (samples.some((value) => !Number.isFinite(value) || value < 0)) {
    throw new Error("p95 samples must be finite non-negative milliseconds");
  }
  const ordered = [...samples].sort((left, right) => left - right);
  return ordered[Math.ceil(ordered.length * 0.95) - 1]!;
}

function boundedMetadata(metadata: CapacityRunMetadata): CapacityRunMetadata {
  if (!/^[a-f0-9]{7,64}$/i.test(metadata.commit)) {
    throw new Error("capacity evidence requires an explicit commit hash");
  }
  if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/.test(metadata.buildId)) {
    throw new Error("capacity evidence buildId is invalid");
  }
  if (metadata.hardware.length < 1 || metadata.hardware.length > 256) {
    throw new Error("capacity evidence hardware must be 1-256 characters");
  }
  for (const [name, value] of [
    ["processCount", metadata.processCount],
    ["concurrency", metadata.concurrency],
    ["durationSeconds", metadata.durationSeconds],
  ] as const) {
    if (!Number.isSafeInteger(value) || value <= 0) {
      throw new Error(`capacity evidence ${name} must be a positive integer`);
    }
  }
  const target = new URL(metadata.targetUrl);
  if (
    target.protocol !== "http:" ||
    !["127.0.0.1", "localhost", "::1"].includes(target.hostname)
  ) {
    throw new Error("capacity gate target must be loopback HTTP");
  }
  return { ...metadata, targetUrl: target.origin };
}

export function buildCapacityEvidence(input: {
  policy: LaunchPolicy;
  metadata: CapacityRunMetadata;
  measurement: Measurement;
  generatedAt?: string;
}): CapacityEvidence {
  const metadata = boundedMetadata(input.metadata);
  if (metadata.concurrency > input.policy.traffic.maximumConcurrentRequests) {
    throw new Error("declared concurrency exceeds the controlled-demo policy");
  }
  if (
    metadata.durationSeconds <
    input.policy.reliability.measurementWindowSeconds
  ) {
    throw new Error("capacity run is shorter than the policy measurement window");
  }
  return {
    schemaVersion: "airlock.capacity-evidence.v1",
    generatedAt: input.generatedAt ?? new Date().toISOString(),
    policySchemaVersion: input.policy.schemaVersion,
    policyProfile: input.policy.profile,
    metadata,
    measurement: { ...input.measurement },
    evaluation: evaluateMeasurement(input.policy, input.measurement),
  };
}
