# Controlled-demo capacity gate

`npm run capacity:gate` is an explicit, opt-in local load gate for the
synthetic realtime lab. It consumes
`config/controlled-demo-slo.v1.json`, exercises real HTTP reads and mutations,
runs complete synthetic provisioning/transaction cycles, and passes or fails
by calling the same `evaluateMeasurement()` used by policy tests.

It is intentionally absent from `npm test`, `npm run check`, and CI. Performance
depends on hardware and process topology; turning it into a default assertion
would produce flaky evidence.

Start an isolated simulator with an immutable build identity, then run:

```powershell
$env:AIRLOCK_SIMULATOR_MODE = "true"
$env:AIRLOCK_BUILD_ID = "<release-commit-or-artifact-id>"
npm run lab

$env:AIRLOCK_CAPACITY_GATE = "true"
$env:AIRLOCK_COMMIT = "<40-hex-tested-commit>"
$env:AIRLOCK_WARM_STATE = "warm" # or cold; declare, never infer
$env:AIRLOCK_PROCESS_COUNT = "1"
$env:AIRLOCK_CAPACITY_CONCURRENCY = "16"
$env:AIRLOCK_CAPACITY_OUTPUT = "capacity-evidence.json"
npm run capacity:gate
```

The gate refuses non-loopback targets and requires the full policy measurement
window. Evidence records the commit, health-reported build ID, bounded hardware
description, process count, requested and observed concurrency, warm/cold
state, duration, request counts, success ratio inputs, read/mutation/full-cycle
p95, and the complete policy evaluation. Output creation uses no-overwrite
semantics when a file is requested.

This validates only the controlled, single-user, synthetic-data profile. It is
not evidence for public traffic, production payment traffic, multiple tenants,
distributed admission control, partner dependencies, or certification.
