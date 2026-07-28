import type { LaunchPolicy } from "./launchPolicy.ts";
import { percentile95 } from "./capacityEvidence.ts";

export const SERVICE_METRICS_VERSION = "airlock.service-metrics.v1" as const;
const MAX_SAMPLES = 2_048;

export type RequestClass = "read" | "mutation" | "static" | "sse";
export type RequestOutcome =
  | "success"
  | "client_error"
  | "server_error"
  | "overload";

export interface ServiceMetricsSnapshot {
  schemaVersion: typeof SERVICE_METRICS_VERSION;
  windowStartedAt: string;
  generatedAt: string;
  counters: {
    requestsTotal: number;
    successfulRequestsTotal: number;
    clientErrorsTotal: number;
    serverErrorsTotal: number;
    overloadRejectionsTotal: number;
    dependencyFailuresTotal: number;
  };
  latencyMilliseconds: {
    readP95: number;
    mutationP95: number;
  };
  saturation: {
    currentRequests: number;
    peakRequests: number;
    currentSseStreams: number;
    peakSseStreams: number;
  };
  readiness: {
    ready: boolean;
    database: boolean;
    identityProvider: boolean;
    auditCustody: boolean;
    partnerTransport: boolean;
  };
  sampleCounts: {
    readLatency: number;
    mutationLatency: number;
  };
}

export interface AdmissionDecision {
  admitted: boolean;
  status?: 503;
  retryAfterSeconds?: number;
  release?: () => void;
}

export interface ServiceAlert {
  code:
    | "SERVICE_NOT_READY"
    | "SUCCESS_RATIO_BREACH"
    | "READ_LATENCY_BREACH"
    | "MUTATION_LATENCY_BREACH"
    | "REQUEST_SATURATION"
    | "SSE_SATURATION"
    | "OVERLOAD_REJECTIONS"
    | "INSUFFICIENT_WINDOW";
  severity: "warning" | "critical";
  value: number;
  threshold: number;
  summary: string;
}

function boundedCounter(value: number): number {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new Error("invalid service metric counter");
  }
  return value === Number.MAX_SAFE_INTEGER ? value : value + 1;
}

function validNow(now: Date): void {
  if (!(now instanceof Date) || !Number.isFinite(now.getTime())) {
    throw new Error("invalid service metrics time");
  }
}

export class ServiceTelemetry {
  readonly #policy: LaunchPolicy;
  readonly #windowStartedAt: Date;
  readonly #readLatencies: number[] = [];
  readonly #mutationLatencies: number[] = [];
  #requestsTotal = 0;
  #successfulRequestsTotal = 0;
  #clientErrorsTotal = 0;
  #serverErrorsTotal = 0;
  #overloadRejectionsTotal = 0;
  #dependencyFailuresTotal = 0;
  #currentRequests = 0;
  #peakRequests = 0;
  #currentSseStreams = 0;
  #peakSseStreams = 0;
  #readiness = {
    database: false,
    identityProvider: false,
    auditCustody: false,
    partnerTransport: false,
  };

  constructor(policy: LaunchPolicy, startedAt = new Date()) {
    validNow(startedAt);
    this.#policy = policy;
    this.#windowStartedAt = new Date(startedAt);
  }

  setReadiness(
    readiness: {
      database: boolean;
      identityProvider: boolean;
      auditCustody: boolean;
      partnerTransport: boolean;
    },
  ): void {
    if (Object.values(readiness).some((value) => typeof value !== "boolean")) {
      throw new Error("invalid service readiness");
    }
    this.#readiness = { ...readiness };
  }

  enterRequest(): AdmissionDecision {
    if (
      this.#currentRequests >=
      this.#policy.traffic.maximumConcurrentRequests
    ) {
      this.#overloadRejectionsTotal =
        boundedCounter(this.#overloadRejectionsTotal);
      this.#requestsTotal = boundedCounter(this.#requestsTotal);
      return {
        admitted: false,
        status: 503,
        retryAfterSeconds: this.#policy.traffic.retryAfterSeconds,
      };
    }
    this.#currentRequests += 1;
    this.#peakRequests = Math.max(this.#peakRequests, this.#currentRequests);
    let released = false;
    return {
      admitted: true,
      release: () => {
        if (released) return;
        released = true;
        this.#currentRequests = Math.max(0, this.#currentRequests - 1);
      },
    };
  }

  enterSse(): AdmissionDecision {
    if (
      this.#currentSseStreams >=
      this.#policy.traffic.maximumConcurrentSseStreams
    ) {
      this.#overloadRejectionsTotal =
        boundedCounter(this.#overloadRejectionsTotal);
      this.#requestsTotal = boundedCounter(this.#requestsTotal);
      return {
        admitted: false,
        status: 503,
        retryAfterSeconds: this.#policy.traffic.retryAfterSeconds,
      };
    }
    this.#currentSseStreams += 1;
    this.#peakSseStreams = Math.max(
      this.#peakSseStreams,
      this.#currentSseStreams,
    );
    let released = false;
    return {
      admitted: true,
      release: () => {
        if (released) return;
        released = true;
        this.#currentSseStreams = Math.max(0, this.#currentSseStreams - 1);
      },
    };
  }

  recordRequest(
    requestClass: RequestClass,
    outcome: RequestOutcome,
    durationMilliseconds: number,
  ): void {
    if (
      !["read", "mutation", "static", "sse"].includes(requestClass) ||
      !["success", "client_error", "server_error", "overload"].includes(outcome) ||
      !Number.isFinite(durationMilliseconds) ||
      durationMilliseconds < 0 ||
      durationMilliseconds > 3_600_000
    ) {
      throw new Error("invalid service metric observation");
    }
    this.#requestsTotal = boundedCounter(this.#requestsTotal);
    if (outcome === "success" || outcome === "client_error") {
      this.#successfulRequestsTotal =
        boundedCounter(this.#successfulRequestsTotal);
    }
    if (outcome === "client_error") {
      this.#clientErrorsTotal = boundedCounter(this.#clientErrorsTotal);
    } else if (outcome === "server_error") {
      this.#serverErrorsTotal = boundedCounter(this.#serverErrorsTotal);
    } else if (outcome === "overload") {
      this.#overloadRejectionsTotal =
        boundedCounter(this.#overloadRejectionsTotal);
    }
    const samples = requestClass === "mutation"
      ? this.#mutationLatencies
      : requestClass === "read" ? this.#readLatencies : undefined;
    if (samples) {
      if (samples.length === MAX_SAMPLES) samples.shift();
      samples.push(durationMilliseconds);
    }
  }

  recordDependencyFailure(): void {
    this.#dependencyFailuresTotal =
      boundedCounter(this.#dependencyFailuresTotal);
  }

  snapshot(now = new Date()): ServiceMetricsSnapshot {
    validNow(now);
    const ready = Object.values(this.#readiness).every(Boolean);
    return {
      schemaVersion: SERVICE_METRICS_VERSION,
      windowStartedAt: this.#windowStartedAt.toISOString(),
      generatedAt: now.toISOString(),
      counters: {
        requestsTotal: this.#requestsTotal,
        successfulRequestsTotal: this.#successfulRequestsTotal,
        clientErrorsTotal: this.#clientErrorsTotal,
        serverErrorsTotal: this.#serverErrorsTotal,
        overloadRejectionsTotal: this.#overloadRejectionsTotal,
        dependencyFailuresTotal: this.#dependencyFailuresTotal,
      },
      latencyMilliseconds: {
        readP95: this.#readLatencies.length
          ? percentile95(this.#readLatencies)
          : 0,
        mutationP95: this.#mutationLatencies.length
          ? percentile95(this.#mutationLatencies)
          : 0,
      },
      saturation: {
        currentRequests: this.#currentRequests,
        peakRequests: this.#peakRequests,
        currentSseStreams: this.#currentSseStreams,
        peakSseStreams: this.#peakSseStreams,
      },
      readiness: { ready, ...this.#readiness },
      sampleCounts: {
        readLatency: this.#readLatencies.length,
        mutationLatency: this.#mutationLatencies.length,
      },
    };
  }
}

export function evaluateServiceAlerts(
  policy: LaunchPolicy,
  metrics: ServiceMetricsSnapshot,
): ServiceAlert[] {
  if (metrics.schemaVersion !== SERVICE_METRICS_VERSION) {
    throw new Error("unsupported service metrics version");
  }
  const started = Date.parse(metrics.windowStartedAt);
  const generated = Date.parse(metrics.generatedAt);
  const counters = Object.values(metrics.counters);
  const saturation = Object.values(metrics.saturation);
  const sampleCounts = Object.values(metrics.sampleCounts);
  if (
    !Number.isFinite(started) ||
    !Number.isFinite(generated) ||
    generated < started ||
    [...counters, ...saturation, ...sampleCounts].some((value) =>
      !Number.isSafeInteger(value) || value < 0
    ) ||
    metrics.counters.successfulRequestsTotal >
      metrics.counters.requestsTotal ||
    sampleCounts.some((value) => value > MAX_SAMPLES) ||
    [
      metrics.latencyMilliseconds.readP95,
      metrics.latencyMilliseconds.mutationP95,
    ].some((value) =>
      !Number.isFinite(value) || value < 0 || value > 3_600_000
    ) ||
    metrics.readiness.ready !== [
      metrics.readiness.database,
      metrics.readiness.identityProvider,
      metrics.readiness.auditCustody,
      metrics.readiness.partnerTransport,
    ].every(Boolean)
  ) {
    throw new Error("invalid service metrics snapshot");
  }
  const alerts: ServiceAlert[] = [];
  const elapsedSeconds = Math.max(
    0,
    (generated - started) / 1_000,
  );
  if (!metrics.readiness.ready) {
    alerts.push({
      code: "SERVICE_NOT_READY",
      severity: "critical",
      value: 0,
      threshold: 1,
      summary: "One or more required service dependencies are not ready.",
    });
  }
  if (
    elapsedSeconds < policy.reliability.measurementWindowSeconds ||
    metrics.counters.requestsTotal < policy.reliability.minimumRequestsPerWindow
  ) {
    alerts.push({
      code: "INSUFFICIENT_WINDOW",
      severity: "warning",
      value: metrics.counters.requestsTotal,
      threshold: policy.reliability.minimumRequestsPerWindow,
      summary: "The metrics window is not yet sufficient for an SLO decision.",
    });
  } else {
    const ratio = metrics.counters.requestsTotal === 0
      ? 0
      : metrics.counters.successfulRequestsTotal /
        metrics.counters.requestsTotal;
    if (ratio < policy.reliability.minimumSuccessRatio) {
      alerts.push({
        code: "SUCCESS_RATIO_BREACH",
        severity: "critical",
        value: ratio,
        threshold: policy.reliability.minimumSuccessRatio,
        summary: "Service success ratio is below the repository policy.",
      });
    }
  }
  if (
    metrics.sampleCounts.readLatency > 0 &&
    metrics.latencyMilliseconds.readP95 > policy.latencyMilliseconds.readP95
  ) {
    alerts.push({
      code: "READ_LATENCY_BREACH",
      severity: "warning",
      value: metrics.latencyMilliseconds.readP95,
      threshold: policy.latencyMilliseconds.readP95,
      summary: "Read p95 exceeds the repository policy.",
    });
  }
  if (
    metrics.sampleCounts.mutationLatency > 0 &&
    metrics.latencyMilliseconds.mutationP95 >
      policy.latencyMilliseconds.mutationP95
  ) {
    alerts.push({
      code: "MUTATION_LATENCY_BREACH",
      severity: "critical",
      value: metrics.latencyMilliseconds.mutationP95,
      threshold: policy.latencyMilliseconds.mutationP95,
      summary: "Mutation p95 exceeds the repository policy.",
    });
  }
  if (
    metrics.saturation.currentRequests >=
    policy.traffic.maximumConcurrentRequests
  ) {
    alerts.push({
      code: "REQUEST_SATURATION",
      severity: "critical",
      value: metrics.saturation.currentRequests,
      threshold: policy.traffic.maximumConcurrentRequests,
      summary: "HTTP request admission is saturated.",
    });
  }
  if (
    metrics.saturation.currentSseStreams >=
    policy.traffic.maximumConcurrentSseStreams
  ) {
    alerts.push({
      code: "SSE_SATURATION",
      severity: "warning",
      value: metrics.saturation.currentSseStreams,
      threshold: policy.traffic.maximumConcurrentSseStreams,
      summary: "SSE admission is saturated.",
    });
  }
  if (metrics.counters.overloadRejectionsTotal > 0) {
    alerts.push({
      code: "OVERLOAD_REJECTIONS",
      severity: "warning",
      value: metrics.counters.overloadRejectionsTotal,
      threshold: 0,
      summary: "The service has rejected work under its fail-closed overload policy.",
    });
  }
  return alerts;
}

export function assertPrivacySafeServiceMetrics(
  metrics: ServiceMetricsSnapshot,
): void {
  const serialized = JSON.stringify(metrics);
  for (const forbidden of [
    "tenantId", "tenant_id", "subjectId", "tokenId", "deviceId",
    "authorization", "cookie", "email", "merchantId", "correlationId",
  ]) {
    if (serialized.toLowerCase().includes(forbidden.toLowerCase())) {
      throw new Error("service metrics contain a forbidden identity label");
    }
  }
}
