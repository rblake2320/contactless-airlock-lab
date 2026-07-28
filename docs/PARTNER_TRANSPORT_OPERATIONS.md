# Partner Transport and Operations

## Status and boundary

This repository contains a candidate issuer-to-processor webhook boundary, not
a live processor integration. No issuer, processor, network, wallet, or merchant
has accepted the contract. `UnconfiguredPartnerWebhookAdapter` fails closed.
Production work requires a partner-owned adapter, endpoint, credentials,
certification fixtures, agreement on the candidate event-specific payloads,
and operational approval. The schemas intentionally use token references and
authorization identifiers, never PAN or CVV.

The versioned candidate schema is
[`contracts/partner/issuer-processor-webhook.v1.schema.json`](../contracts/partner/issuer-processor-webhook.v1.schema.json).
The internal SQLite record remains governed separately by the simulator
AsyncAPI contract. An outbox record is not itself a partner message.

## Authentication, replay, and idempotency

The sender signs the exact raw UTF-8 body with HMAC-SHA256. The canonical input
is the signature version, epoch-second timestamp, nonce, idempotency key, and
SHA-256 body digest separated by line feeds. Key identifiers support rotation;
receivers must resolve keys from a secret manager and retain old verification
keys for the agreed overlap period.

Verification is fail-closed:

- reject bodies over 1 MiB and unknown signature versions or key IDs;
- reject timestamps outside the configured window (default five minutes);
- compare the complete signature in constant time;
- atomically consume `keyId:nonce` only after signature verification; and
- independently retain the `Idempotency-Key` and first result for the
  partner-agreed retention window.

The in-memory replay store is deterministic test infrastructure only. A
production receiver needs an atomic shared store. HMAC proves possession of a
shared secret; it does not provide non-repudiation.

## Delivery behavior

`PartnerOutboxDispatcher` claims real leased records through the
`OutboxLeaseSource` interface, validates the v1 envelope, signs the request, and
calls an adapter. Any 2xx is acknowledged. HTTP 429, 5xx, transport errors, and
timeouts are released for retry while the retry budget remains. Every request
has an `AbortSignal` and a hard deadline shorter than the lease. Repeated
failures open a cooldown circuit so a failing partner is not hammered.

Non-retryable responses and exhausted retries go to `PartnerDeadLetterSink`.
The source event is acknowledged only after that sink succeeds. The provided
unconfigured sink fails closed, so no event is silently discarded. Exact
permanent-status, retry-budget, and recovery policy still require partner
agreement. Delivery is at least once and consumers must deduplicate.

## Health and readiness

The versioned operational schema defines metrics and readiness views. Liveness
should mean only that the process event loop is responsive. Readiness requires
all four checks: signing key configured, replay store reachable, outbox
reachable, and a real partner adapter configured. The stub adapter must keep
readiness false.

Required alerts:

- signature or replay rejection rate above baseline;
- oldest pending event age approaching the delivery SLO;
- sustained retry/rejection growth;
- lease conflicts or zero delivery throughput with pending work;
- readiness false for more than two probes; and
- key expiry or rotation overlap approaching its deadline.

## Candidate SLOs and overload policy

These are internal launch targets, not partner commitments:

- 99.9% monthly dispatcher availability;
- 99% of eligible events attempted within 60 seconds;
- 99.9% of successful-partner responses acknowledged within the active lease;
- zero accepted invalid signatures or replayed nonces; and
- recovery point objective of zero committed outbox records, subject to
  SQLite/filesystem durability evidence.

Overload must shed or defer nonessential work before security controls. Never
disable verification, replay checks, body limits, or durable enqueue. Bound
claim batches and concurrency, honor 429, use exponential backoff plus jitter
once agreed, and alert before oldest-pending age breaches the SLO.

## Incident and disaster recovery

For suspected key compromise: stop readiness, disable the key ID, preserve
signed request/audit metadata without secrets or full sensitive payloads,
rotate the secret, notify the partner, and replay only records whose effects
are reconciled. For replay-store loss: fail readiness and reject incoming
requests until atomic replay protection is restored.

Back up the outbox database and external audit anchors using encrypted,
access-controlled storage. Restore into isolation, verify integrity, inventory
undelivered and leased records, expire stale leases, reconcile idempotency with
the partner, then resume bounded delivery. Quarterly exercises must measure
RTO/RPO and include corrupted backup, unavailable partner, compromised key,
and duplicate-delivery scenarios. No DR claim is complete until a restore
exercise has produced retained evidence.
