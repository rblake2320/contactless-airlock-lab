# Realtime lab — per-client mutation rate limiting

**Scope and honesty boundary.** This is an **in-process, single-instance** abuse
control for one `realtime-lab` simulator process. It is **not** distributed or
production enforcement. Horizontal scaling, edge/CDN throttling, and shared-state
limiting (Redis, an API gateway, a WAF) are explicitly **external** and out of
scope for this component. Do not represent this limiter as production or
payment-rail rate control.

## What it does

Every `POST /api/*` mutation consumes one token from a per-client
[token bucket](https://en.wikipedia.org/wiki/Token_bucket). A client that has
tokens proceeds normally; a client that is out of tokens receives:

- HTTP status `429`
- `Retry-After: <whole seconds>` — time until at least one token refills
- JSON body `{"code":"RATE_LIMITED","error":"…"}` (the standard `SimpleError`
  shape; `RATE_LIMITED` is part of the closed `ReasonCode` vocabulary)

A rejected request **does not mutate simulator state** and is **not persisted**
as an idempotent response — the client may retry the same request after backing
off.

## What is exempt

- **`GET` reads** — `/api/state`, `/api/health`, `/api/events` are never limited.
- **Persisted idempotent replays** — when persistence is enabled, replaying a
  previously completed request with the same `Idempotency-Key` returns the stored
  response and does not consume a token. Rate limiting is evaluated *after* the
  replay short-circuit and *before* any state snapshot, so replay semantics and
  the "no mutation on rejection" guarantee both hold.

## Ordering of mutation controls

For a `POST /api/*` request the server applies, in order: same-origin/
`Sec-Fetch-Site` check → 16 KiB body bound → JSON content-type/shape →
`Idempotency-Key` validation and (persistent) replay lookup → **rate limit** →
state snapshot → domain handler. Because the limit is enforced before the
snapshot, a `429` can never leave partial state behind.

## Client identity and the proxy trust boundary

The bucket is keyed by client identity derived from the connection:

- **Default (no trusted proxies):** the direct socket peer address is used and
  any `X-Forwarded-For` header is **ignored**. A spoofed forwarding header
  therefore cannot fragment an attacker's bucket to evade the limit.
- **With `trustedProxies` configured:** if — and only if — the direct peer is a
  trusted proxy, the limiter reads `X-Forwarded-For` and uses the right-most
  address that is not itself a trusted proxy (the real client as seen by the
  outermost trusted hop). If you deploy behind a proxy and do **not** configure
  `trustedProxies`, every request keys to the proxy's address and the whole
  world shares one bucket — configure it, or the limit is meaningless.
- **IPv6 `/64` aggregation — an honest trade-off.** IPv6 clients are keyed by
  their `/64` prefix, not the full address. This is deliberate: a single
  assigned IPv6 network is typically a `/64` (or larger), so an attacker with
  one allocation can otherwise mint effectively unlimited distinct `/128`
  addresses and get a fresh bucket for each. Aggregating to `/64` closes that
  bypass — but the cost is **collateral throttling**: distinct hosts sharing a
  `/64` (e.g. behind one residential/CGNAT allocation) share one bucket and can
  throttle each other. This is the standard IPv6 rate-limiting compromise; it is
  a fixed `/64` here, not tunable, and not claimed to be per-host precise.
  **IPv4** clients are keyed by exact address. v4-mapped IPv6
  (`::ffff:a.b.c.d`) is normalized to its IPv4 form and IPv6 zone identifiers
  are stripped before keying.

## Memory bounds and fail-closed admission

The number of tracked client buckets is capped by `maxClients` (default
`10000`), stored in an LRU structure. Admission past the cap is **fail-closed
and never refunds a penalty**:

- A **new** identity is admitted only if a currently-tracked bucket has fully
  refilled (carries no penalty) and can be safely evicted — evicting a
  fully-refilled bucket and letting its owner re-create it later is a no-op.
- If **every** tracked bucket is partially drained ("penalized"), a new identity
  is **rejected** (`429`) without allocating a bucket. The table never grows past
  `maxClients`, and — critically — a throttled victim's penalty is **never**
  wiped to make room. This defeats the LRU-churn attack where a flood of
  attacker-created identities would otherwise evict and reset a victim's
  throttled bucket. The trade-off is that, under sustained saturation of the
  bucket table, genuinely new clients are refused rather than served at the
  expense of an existing penalty. Eviction only ever discards rate-limit
  accounting, never simulator state.

## SSE (`GET /api/events`) connection bounding

Each open event stream pins a socket and a heartbeat timer, so concurrent
streams are bounded independently of the mutation limiter:

- `maxPerClient` (default `4`) concurrent streams per client identity (same
  identity normalization and proxy trust boundary as above) and `maxTotal`
  (default `64`) across all clients.
- A stream that would exceed either cap is rejected with `429` + `Retry-After`
  **before** the SSE response head is sent, so it surfaces as a normal
  `EventSource` `onerror` rather than a half-open stream. `Retry-After` here is
  advisory — capacity frees as clients disconnect, not on a fixed schedule.
- Cleanup is deterministic and idempotent: a stream's heartbeat timer is cleared
  and its registry/per-client counters are decremented on `req`/`res` `close`
  **or** `error` (whichever fires first). Heartbeat timers are `unref`-ed so they
  cannot by themselves keep the process alive, and on server shutdown every live
  stream is torn down (timer cleared, response ended) so nothing leaks past
  `close`.
- Configure via `sseLimit` (`{ maxPerClient, maxTotal }` or `false` to disable);
  the heartbeat interval is overridable via `sseHeartbeatMs` for tests.

## Metering policy — what consumes a token

The mutation limiter sits **after** cheap preflight validation and **before**
the domain handler. The line is locked by tests:

- **Not metered (rejected before the limiter):** same-origin/`Sec-Fetch-Site`
  (`403`), body-size (`413`), content-type/JSON shape (`400`/`415`), and
  `Idempotency-Key` validation including the reuse-conflict (`428`/`431`/`409`).
  Malformed or abusive junk that never reaches mutation processing does not
  spend a client's tokens.
- **Metered (reaches mutation processing):** every request that passes preflight,
  including successful `200`s **and** domain-state conflicts (`409`, e.g.
  "provisioning already requested"). A client cannot hammer a `409`-producing
  endpoint for free.
- A persisted idempotent **replay** returns its stored response and consumes no
  token (it short-circuits before the limiter).

## Reset behavior

`POST /api/reset` is itself a rate-limited mutation and does **not** clear or
refill the limiter buckets. This is deliberate: resetting the lab must not be a
way to refill your own token allowance and bypass the ceiling.

## Configuration

`createLabServer(options)` accepts:

| Option | Meaning | Default |
|---|---|---|
| `rateLimit` | `{ capacity, refillPerSecond, maxClients }`, or `false` to disable | `{ capacity: 300, refillPerSecond: 150, maxClients: 10000 }` |
| `sseLimit` | `{ maxPerClient, maxTotal }`, or `false` to disable SSE bounding | `{ maxPerClient: 4, maxTotal: 64 }` |
| `clock` | `() => number` (ms epoch) — deterministic clock injection for tests | `Date.now` |
| `sseHeartbeatMs` | SSE heartbeat interval override (tests) | `15000` |
| `trustedProxies` | socket peer addresses whose `X-Forwarded-For` is trusted | `[]` |

- **`capacity`** is the maximum burst; **`refillPerSecond`** is the sustained
  rate. The generous default is invisible to normal functional use while still
  bounding abuse.

### CLI / environment

The `npm run lab` entrypoint reads:

- `AIRLOCK_RATE_LIMIT` — `"capacity:refillPerSecond[:maxClients]"`
  (e.g. `300:150` or `10:2:500`), or `off` / `disabled` to turn enforcement off.
  Unset uses the default.
- `AIRLOCK_TRUSTED_PROXIES` — comma-separated peer addresses to trust for
  `X-Forwarded-For` (e.g. a local reverse proxy).

## Tests

`tests/rate-limit.test.ts` covers: burst-then-block, deterministic refill,
`Retry-After` scaling with the token deficit, per-client isolation, bounded
memory under identity churn, config validation, the `429` body/header shape,
no-mutation-on-rejection, `GET` exemption, reset-does-not-refill,
exactly-`capacity`-of-N under concurrent requests, the spoofed-`X-Forwarded-For`
trust boundary (ignored without a trusted proxy, honored with one), persistent
idempotent-replay bypass, env parsing, and the disable switch. Plus, from the
hardening review: fail-closed admission never evicting a penalized bucket under
attacker churn (and a fully-refilled bucket remaining evictable), SSE
per-client and global caps returning `429`+`Retry-After` with slots freeing on
disconnect, server-shutdown teardown of live streams without a timer leak, the
SSE disable switch, and the metering-policy line (preflight `415`/`413`/`403`
do not consume a token; a domain `409` does).
