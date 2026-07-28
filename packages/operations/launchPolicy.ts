export const LAUNCH_POLICY_SCHEMA_VERSION = "airlock.launch-policy.v1" as const;

export interface LaunchPolicy {
  schemaVersion: typeof LAUNCH_POLICY_SCHEMA_VERSION;
  profile: string;
  scope: {
    syntheticDataOnly: boolean;
    realPaymentTrafficAllowed: boolean;
    publicInternetAllowed: boolean;
    maximumTenants: number;
  };
  traffic: {
    sustainedRequestsPerSecond: number;
    burstRequestsPerSecond: number;
    maximumConcurrentRequests: number;
    maximumConcurrentSseStreams: number;
    overloadStatus: 503;
    retryAfterSeconds: number;
  };
  latencyMilliseconds: {
    readP95: number;
    mutationP95: number;
    completeSyntheticCycleP95: number;
  };
  reliability: {
    minimumSuccessRatio: number;
    measurementWindowSeconds: number;
    minimumRequestsPerWindow: number;
  };
  dependencyTimeoutMilliseconds: {
    database: number;
    partnerApi: number;
    webhookConsumer: number;
  };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function exactKeys(
  value: Record<string, unknown>,
  expected: readonly string[],
  location: string,
): void {
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (
    actual.length !== wanted.length ||
    actual.some((key, index) => key !== wanted[index])
  ) {
    throw new Error(`${location} has unknown or missing fields`);
  }
}

function positiveInteger(value: unknown, location: string, maximum = 1_000_000): number {
  if (!Number.isSafeInteger(value) || (value as number) <= 0 || (value as number) > maximum) {
    throw new Error(`${location} must be a positive safe integer <= ${maximum}`);
  }
  return value as number;
}

function boolean(value: unknown, location: string): boolean {
  if (typeof value !== "boolean") throw new Error(`${location} must be boolean`);
  return value;
}

export function parseLaunchPolicy(input: unknown): LaunchPolicy {
  if (!isRecord(input)) throw new Error("launch policy must be an object");
  exactKeys(
    input,
    [
      "schemaVersion",
      "profile",
      "scope",
      "traffic",
      "latencyMilliseconds",
      "reliability",
      "dependencyTimeoutMilliseconds",
    ],
    "launch policy",
  );
  if (input.schemaVersion !== LAUNCH_POLICY_SCHEMA_VERSION) {
    throw new Error("unsupported launch-policy schemaVersion");
  }
  if (
    typeof input.profile !== "string" ||
    input.profile.length < 1 ||
    input.profile.length > 64 ||
    !/^[a-z0-9-]+$/.test(input.profile)
  ) {
    throw new Error("profile must be a bounded lowercase identifier");
  }
  if (
    !isRecord(input.scope) ||
    !isRecord(input.traffic) ||
    !isRecord(input.latencyMilliseconds) ||
    !isRecord(input.reliability) ||
    !isRecord(input.dependencyTimeoutMilliseconds)
  ) {
    throw new Error("launch policy sections must be objects");
  }

  exactKeys(
    input.scope,
    [
      "syntheticDataOnly",
      "realPaymentTrafficAllowed",
      "publicInternetAllowed",
      "maximumTenants",
    ],
    "scope",
  );
  exactKeys(
    input.traffic,
    [
      "sustainedRequestsPerSecond",
      "burstRequestsPerSecond",
      "maximumConcurrentRequests",
      "maximumConcurrentSseStreams",
      "overloadStatus",
      "retryAfterSeconds",
    ],
    "traffic",
  );
  exactKeys(
    input.latencyMilliseconds,
    ["readP95", "mutationP95", "completeSyntheticCycleP95"],
    "latencyMilliseconds",
  );
  exactKeys(
    input.reliability,
    ["minimumSuccessRatio", "measurementWindowSeconds", "minimumRequestsPerWindow"],
    "reliability",
  );
  exactKeys(
    input.dependencyTimeoutMilliseconds,
    ["database", "partnerApi", "webhookConsumer"],
    "dependencyTimeoutMilliseconds",
  );

  const successRatio = input.reliability.minimumSuccessRatio;
  if (
    typeof successRatio !== "number" ||
    !Number.isFinite(successRatio) ||
    successRatio <= 0 ||
    successRatio > 1
  ) {
    throw new Error("reliability.minimumSuccessRatio must be > 0 and <= 1");
  }
  if (input.traffic.overloadStatus !== 503) {
    throw new Error("traffic.overloadStatus must fail closed with HTTP 503");
  }

  const policy: LaunchPolicy = {
    schemaVersion: LAUNCH_POLICY_SCHEMA_VERSION,
    profile: input.profile,
    scope: {
      syntheticDataOnly: boolean(input.scope.syntheticDataOnly, "scope.syntheticDataOnly"),
      realPaymentTrafficAllowed: boolean(
        input.scope.realPaymentTrafficAllowed,
        "scope.realPaymentTrafficAllowed",
      ),
      publicInternetAllowed: boolean(
        input.scope.publicInternetAllowed,
        "scope.publicInternetAllowed",
      ),
      maximumTenants: positiveInteger(input.scope.maximumTenants, "scope.maximumTenants", 10_000),
    },
    traffic: {
      sustainedRequestsPerSecond: positiveInteger(
        input.traffic.sustainedRequestsPerSecond,
        "traffic.sustainedRequestsPerSecond",
      ),
      burstRequestsPerSecond: positiveInteger(
        input.traffic.burstRequestsPerSecond,
        "traffic.burstRequestsPerSecond",
      ),
      maximumConcurrentRequests: positiveInteger(
        input.traffic.maximumConcurrentRequests,
        "traffic.maximumConcurrentRequests",
      ),
      maximumConcurrentSseStreams: positiveInteger(
        input.traffic.maximumConcurrentSseStreams,
        "traffic.maximumConcurrentSseStreams",
      ),
      overloadStatus: 503,
      retryAfterSeconds: positiveInteger(
        input.traffic.retryAfterSeconds,
        "traffic.retryAfterSeconds",
        3600,
      ),
    },
    latencyMilliseconds: {
      readP95: positiveInteger(input.latencyMilliseconds.readP95, "latencyMilliseconds.readP95"),
      mutationP95: positiveInteger(
        input.latencyMilliseconds.mutationP95,
        "latencyMilliseconds.mutationP95",
      ),
      completeSyntheticCycleP95: positiveInteger(
        input.latencyMilliseconds.completeSyntheticCycleP95,
        "latencyMilliseconds.completeSyntheticCycleP95",
      ),
    },
    reliability: {
      minimumSuccessRatio: successRatio,
      measurementWindowSeconds: positiveInteger(
        input.reliability.measurementWindowSeconds,
        "reliability.measurementWindowSeconds",
        86_400,
      ),
      minimumRequestsPerWindow: positiveInteger(
        input.reliability.minimumRequestsPerWindow,
        "reliability.minimumRequestsPerWindow",
      ),
    },
    dependencyTimeoutMilliseconds: {
      database: positiveInteger(
        input.dependencyTimeoutMilliseconds.database,
        "dependencyTimeoutMilliseconds.database",
        60_000,
      ),
      partnerApi: positiveInteger(
        input.dependencyTimeoutMilliseconds.partnerApi,
        "dependencyTimeoutMilliseconds.partnerApi",
        60_000,
      ),
      webhookConsumer: positiveInteger(
        input.dependencyTimeoutMilliseconds.webhookConsumer,
        "dependencyTimeoutMilliseconds.webhookConsumer",
        60_000,
      ),
    },
  };

  if (policy.traffic.burstRequestsPerSecond < policy.traffic.sustainedRequestsPerSecond) {
    throw new Error("burstRequestsPerSecond must be >= sustainedRequestsPerSecond");
  }
  if (policy.latencyMilliseconds.mutationP95 < policy.latencyMilliseconds.readP95) {
    throw new Error("mutationP95 must be >= readP95");
  }
  if (
    policy.latencyMilliseconds.completeSyntheticCycleP95 <
    policy.latencyMilliseconds.mutationP95
  ) {
    throw new Error("completeSyntheticCycleP95 must be >= mutationP95");
  }
  if (
    policy.scope.realPaymentTrafficAllowed ||
    policy.scope.publicInternetAllowed ||
    !policy.scope.syntheticDataOnly
  ) {
    throw new Error(
      "the repository-controlled launch policy may authorize only synthetic, non-public traffic",
    );
  }
  return policy;
}

export interface Measurement {
  totalRequests: number;
  successfulRequests: number;
  readP95Milliseconds: number;
  mutationP95Milliseconds: number;
  completeSyntheticCycleP95Milliseconds: number;
  peakConcurrentRequests: number;
  peakConcurrentSseStreams: number;
}

export interface LaunchEvaluation {
  passed: boolean;
  failures: string[];
}

export function evaluateMeasurement(
  policy: LaunchPolicy,
  measurement: Measurement,
): LaunchEvaluation {
  const failures: string[] = [];
  const total = positiveInteger(measurement.totalRequests, "measurement.totalRequests");
  if (
    !Number.isSafeInteger(measurement.successfulRequests) ||
    measurement.successfulRequests < 0 ||
    measurement.successfulRequests > total
  ) {
    throw new Error("measurement.successfulRequests is invalid");
  }
  if (total < policy.reliability.minimumRequestsPerWindow) {
    failures.push("insufficient request count for the declared measurement window");
  }
  if (measurement.successfulRequests / total < policy.reliability.minimumSuccessRatio) {
    failures.push("success ratio is below the declared minimum");
  }
  if (measurement.readP95Milliseconds > policy.latencyMilliseconds.readP95) {
    failures.push("read p95 exceeds the declared SLO");
  }
  if (measurement.mutationP95Milliseconds > policy.latencyMilliseconds.mutationP95) {
    failures.push("mutation p95 exceeds the declared SLO");
  }
  if (
    measurement.completeSyntheticCycleP95Milliseconds >
    policy.latencyMilliseconds.completeSyntheticCycleP95
  ) {
    failures.push("complete synthetic cycle p95 exceeds the declared SLO");
  }
  if (measurement.peakConcurrentRequests > policy.traffic.maximumConcurrentRequests) {
    failures.push("peak request concurrency exceeds the approved profile");
  }
  if (measurement.peakConcurrentSseStreams > policy.traffic.maximumConcurrentSseStreams) {
    failures.push("peak SSE concurrency exceeds the approved profile");
  }
  return { passed: failures.length === 0, failures };
}
