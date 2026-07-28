# HEAD Requests and Method Semantics

## What HEAD does here

`apps/realtime-lab/server.ts` accepts `HEAD` on the static routes (`/`,
`/app.js`, `/styles.css`) and on `/api/health` and `/api/state`. A `HEAD`
request to any of these returns the identical status code and headers a
`GET` to the same path would at that instant — including a `Content-Length`
reflecting the real body size, not an estimate — with no response body, per
RFC 7231 §4.3.2. This includes the 404 case: `HEAD /missing` returns the
same `404` status and the same `Content-Length` the `GET 404` JSON error
body would have had, just without writing that body.

For `/api/health` and `/api/state`, "identical to GET" means identical to
the GET response for the *same instant* the request was handled — both are
computed from one synchronous read of live in-memory state, so a `HEAD`
and a concurrent `GET` can never observe two different snapshots. There is
no caching implication either way: `cache-control: no-store` is set on
every response from this server regardless of method, so a client is never
entitled to treat a `HEAD` result as valid for any request after it.

Security headers are unaffected either way: `applySecurityHeaders(res)` runs
unconditionally at the top of the request handler before any method
branching, so `HEAD` already inherits identical security headers to `GET`.

## Scope decision: not `/api/events`

`HEAD` is deliberately **not** extended to `/api/events`: it is an
open-ended Server-Sent Events stream, not a bounded response with a
describable length at all. There is no meaningful "GET response this HEAD
summarizes" for a stream; `EventSource` itself never issues HEAD. `HEAD
/api/events` returns `405` with `Allow: GET` (see below), not a hung or
empty stream.

## 405 dispatch: every known route, every wrong method

`ROUTE_MANIFEST` in `apps/realtime-lab/server.ts` is the single source of
truth for which methods each route accepts. Before any request body is
read, before idempotency-key lookup, and before rate-limiting, the
dispatcher checks the request's path and method against this manifest:

- **Known path, disallowed method** (e.g. `DELETE /api/health`, `GET
  /api/reset`, `HEAD /api/events`) → `405 Method Not Allowed`, with an
  `Allow` header listing exactly that route's manifest methods — never a
  hand-maintained or generic list, so `Allow` cannot drift from what the
  dispatcher itself enforces. This check runs early enough that a 405 is
  always fully side-effect-free: no idempotency key is consumed, no rate
  limit is charged, no state snapshot is taken.
- **Unknown path** → falls through unchanged to the existing routing,
  ending in `404`, for any method including `HEAD` (zero body).

`tests/openapi-contract.test.ts` derives its OpenAPI-vs-runtime route
comparison directly from `ROUTE_MANIFEST` (not a hand-listed set), so a
route added to the manifest without a matching contract entry fails that
test automatically. `tests/method-semantics.test.ts` exhaustively exercises
every manifest entry against every candidate method.

## Known, accepted gap

An extremely unlikely runtime failure reading `index.html`/`app.js`/
`styles.css` from disk (files that are always present in a normal checkout)
falls through to the shared error handler shared with the mutating `/api/*`
routes. That shared path was not restructured to also suppress the body for
`HEAD` in this pass — it's a body-bearing error response on a path that, in
practice, requires the static asset to disappear from disk mid-request to
ever trigger. The realistic `200` and `404` paths — the ones an uptime
check, `curl -I`, or a browser prefetch would actually exercise — are fully
correct. Documented here rather than silently left unmentioned.
