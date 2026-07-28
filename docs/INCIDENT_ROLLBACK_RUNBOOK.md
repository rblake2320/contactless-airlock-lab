# Service Monitoring, Incident, and Rollback Runbook

## Current boundary

`ServiceTelemetry` is a composable repository package. It is not currently
wired into the real-time server while identity integration is changing that
file. No Prometheus, OpenTelemetry collector, SIEM, cloud monitor, paging
service, status page, or notification channel is configured. Alert evaluation
returns data only; it never pages or sends.

The machine-readable metrics contract is
[`contracts/operations/service-monitoring.v1.schema.json`](../contracts/operations/service-monitoring.v1.schema.json).
It forbids tenant, customer, subject, device, token, merchant, authorization,
correlation, IP, user-agent, or credential labels. Only bounded service-wide
counters, p95 latency, saturation, and readiness booleans are represented.

## Admission and overload

Apply request admission before request-body processing. When the configured
request or SSE ceiling is reached, fail closed with HTTP 503 and the policy's
`Retry-After`. Never bypass authentication, signature checks, durable writes,
replay protection, or audit custody to increase throughput.

An admission rejection is already counted by `enterRequest`/`enterSse`; do not
also call `recordRequest(..., "overload", ...)` for the same rejected request.
Release admitted leases exactly once in `finally`/connection-close handling.
The release closures are idempotent.

Shed in this order:

1. optional/static and diagnostic work;
2. new SSE streams;
3. nonessential reads;
4. new mutations with explicit retry guidance.

Never partially accept a mutation. Dependency timeouts and circuit breakers
remain fail-closed.

## Readiness and SLO alerts

Liveness means only that the process can answer. Readiness requires the
configured database, identity provider, audit custody, and partner transport
boundaries. A composition that intentionally omits a dependency needs a
separate versioned profile; it must not mark an absent production dependency
healthy.

`evaluateServiceAlerts` derives:

- readiness critical;
- success-ratio critical after the full request/time window;
- read-latency warning and mutation-latency critical;
- request saturation critical and SSE saturation warning;
- overload-rejection warning; and
- insufficient-window warning when evidence is too short.

The controlled-demo thresholds are acceptance policy, not measured production
SLOs. External operations owners must approve production windows, burn rates,
maintenance exclusions, and paging severity.

## Incident declaration

Declare an incident for sustained readiness failure, mutation error/SLO breach,
replay/signature acceptance concern, audit anchor mismatch, cross-tenant
exposure concern, overload that prevents critical work, or suspected credential
compromise. Assign incident commander, operations lead, security lead, and
scribe. Record UTC timestamps and build ID without copying tokens, request
bodies, PAN, customer identifiers, or secrets into chat/tickets.

Immediate safety actions:

1. stop new mutations or set readiness false;
2. preserve audit state, independent anchors, build identity, and bounded
   service metrics;
3. isolate the failing dependency or build;
4. do not retry non-idempotent external operations blindly;
5. communicate only verified scope; and
6. choose rollback or forward fix using the gates below.

## Rollback

Rollback is allowed only to a previously signed/approved build whose database
schema, snapshot schema, key versions, and partner contract remain compatible.
Never roll back active credential/audit key versions or restore an older trust
anchor.

Before rollback:

- capture current build and migration versions;
- verify a restorable backup and external audit anchor;
- stop or drain writers;
- reconcile in-flight outbox leases and partner idempotency;
- prove the older build understands all committed records; and
- predefine abort criteria.

After rollback, run health/readiness, audit-chain/anchor verification,
tenant-isolation checks, a synthetic mutation/idempotent replay, outbox
reconciliation, and bounded capacity smoke tests. If any check fails, keep
mutations disabled.

## Credential compromise

For suspected OIDC, WebAuthn administration, partner HMAC, audit KMS/HSM,
database, or notification credential compromise:

1. disable the credential/key ID and affected workload identity;
2. set the dependent readiness check false;
3. preserve provider and application audit evidence without secret values;
4. rotate through the provider's monotonic versioned process;
5. retain old audit keys for verify-only historical validation where required;
6. revoke sessions/tokens through the authoritative provider;
7. reconcile operations performed inside the suspected window; and
8. restore only after independent verification and two-person approval.

Do not paste credentials into logs, tickets, metrics, command lines, or incident
chat. Do not replace strong recovery with SMS or transferable codes.

## External gaps

Production still requires:

- server middleware wiring and response/status integration;
- process-safe or distributed concurrency admission across replicas;
- a real metrics exporter with transport encryption and access control;
- dashboard definitions and retention/downsampling policy;
- paging/escalation provider, schedules, acknowledgements, and drills;
- privacy review of telemetry storage and regional flow;
- approved production SLOs and multi-window burn-rate alerts;
- deploy orchestrator rollback controls and signed artifact provenance;
- credential inventory, ownership, automated rotation, and emergency revocation;
- incident command tooling, legal/regulatory procedures, and customer
  communications; and
- exercised backup/restore, regional failure, dependency outage, and
  credential-compromise game days.

None of those external capabilities is claimed by the package or tests.
