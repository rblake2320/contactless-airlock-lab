# Controlled-demo service levels

`config/controlled-demo-slo.v1.json` is the first explicit, executable launch
profile for this repository. It converts the July 2026 local load observations
into conservative admission and latency requirements for a **controlled,
single-user, synthetic-data demonstration**.

It does not authorize public hosting, real payment traffic, multiple tenants,
or a partner pilot. The parser rejects any repository-controlled profile that
attempts to enable those uses. Those decisions require authentication,
tenant-isolated durable state, partner contracts, operations ownership, and the
external approvals listed in `docs/PRODUCTION_READINESS.md`.

## Initial targets

- 100 sustained requests/second and a 250 requests/second controlled burst;
- no more than 128 concurrent HTTP requests or 64 SSE streams;
- fail-closed overload response: HTTP 503 plus `Retry-After: 1`;
- read p95 no greater than 100 ms;
- mutation p95 no greater than 250 ms;
- complete synthetic protocol-cycle p95 no greater than 500 ms;
- at least 99.9% successful requests over a five-minute, 1,000-request minimum
  measurement window; and
- explicit database and partner dependency deadlines.

These are acceptance targets, not measurements. A run passes only when its
machine-readable measurement stays inside every target. Hardware, commit,
process count, warm/cold state, concurrency, duration, and proxy topology must
travel with the evidence.

The previous single burst of 2,000 simultaneous TCP connections is outside this
profile. Its one refused connection is therefore recorded as an unapproved
capacity boundary, not silently counted as either a pass or a product defect.

## Next composition step

The production composition must enforce the profile at the edge and service:

1. authenticated per-tenant admission;
2. bounded global and per-tenant concurrency;
3. distributed rate limiting where more than one service instance exists;
4. dependency deadlines and circuit breakers that never default to approval;
5. privacy-safe RED metrics (rate, errors, duration) and saturation metrics;
6. alerts and rollback criteria derived from the same versioned policy; and
7. a reproducible load gate that emits the measurement format consumed by
   `evaluateMeasurement` (implemented as the explicit opt-in
   `npm run capacity:gate`; see `docs/CAPACITY_GATE.md`).

Until those controls are wired and tested, this document defines the target but
does not close the corresponding production-readiness checkboxes.
