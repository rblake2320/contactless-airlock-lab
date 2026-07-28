export interface PartnerTransportMetrics {
  schemaVersion: "airlock.partner-transport.metrics.v1";
  generatedAt: string;
  counters: {
    claimedTotal: number;
    deliveredTotal: number;
    retryScheduledTotal: number;
    rejectedTotal: number;
    signatureRejectedTotal: number;
    replayRejectedTotal: number;
  };
  gauges: {
    inFlight: number;
    oldestPendingAgeSeconds: number;
  };
}

export interface PartnerTransportReadiness {
  schemaVersion: "airlock.partner-transport.readiness.v1";
  ready: boolean;
  checks: {
    signingKeyConfigured: boolean;
    replayStoreReachable: boolean;
    outboxReachable: boolean;
    partnerAdapterConfigured: boolean;
  };
}

export function partnerTransportReadiness(
  checks: PartnerTransportReadiness["checks"],
): PartnerTransportReadiness {
  return {
    schemaVersion: "airlock.partner-transport.readiness.v1",
    ready: Object.values(checks).every(Boolean),
    checks: { ...checks },
  };
}

export function emptyPartnerTransportMetrics(now: Date): PartnerTransportMetrics {
  if (!Number.isFinite(now.getTime())) throw new Error("invalid metrics time");
  return {
    schemaVersion: "airlock.partner-transport.metrics.v1",
    generatedAt: now.toISOString(),
    counters: {
      claimedTotal: 0,
      deliveredTotal: 0,
      retryScheduledTotal: 0,
      rejectedTotal: 0,
      signatureRejectedTotal: 0,
      replayRejectedTotal: 0,
    },
    gauges: {
      inFlight: 0,
      oldestPendingAgeSeconds: 0,
    },
  };
}
