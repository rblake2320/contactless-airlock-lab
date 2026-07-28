# Authentication and tenant/session boundary

The realtime lab has two explicit access profiles: `simulator` preserves the
local synthetic demonstration, while `authenticated` requires an authenticated
principal and isolates each tenant in a distinct in-memory engine state.

The CLI has no implicit profile. It starts only when exactly one of
`AIRLOCK_SIMULATOR_MODE=true` or `AIRLOCK_AUTH_CONFIG_PATH` is set, so an
accidental shared launch fails closed. The programmatic factory retains its
test-compatible simulator default; production embedding must pass an explicit
access profile.

Authenticated configuration requires exactly one explicit identity provider
and an exact origin allowlist:

- `bootstrap-controlled-demo` contains opaque local credentials and is limited
  to controlled synthetic demonstrations. Each credential binds a principal,
  tenant, and roles, and is compared by SHA-256 digest in constant time.
- `oidc` verifies the bearer access token through
  `OidcAccessTokenVerifier`, then derives principal, tenant, and roles only from
  signed verified claims. There is no bootstrap fallback in this mode.

`operator` can read and mutate; `viewer` can read. Raw bearer tokens never
enter cookies, responses, state, audit, or storage.

A successful login issues a random 256-bit session cookie with `HttpOnly`,
`SameSite=Strict`, `Path=/`, and `Secure` by default. It separately returns a
random CSRF token. Every authenticated mutation requires that token and an
exact configured Origin. Production origins must be HTTPS; an explicit
loopback-only HTTP exception exists for tests.

Sessions have idle and absolute expiry, global and per-principal caps, and
explicit logout revocation. `GET /api/session` returns only the current
principal and expiry. Tenant identity is taken only from the authenticated
session—not from a body, path, query, or client-selected tenant header.
Tenant-tagged SSE listeners receive broadcasts only for their tenant.
An OIDC-exchanged session is additionally capped at the verified token's
expiration, even when the configured absolute session TTL is longer.

Authenticated mode intentionally rejects `dbPath`: the current SQLite snapshot
is single-tenant, and silently sharing it would violate isolation. Durable
tenant-scoped persistence belongs to the storage design. Process-local sessions
also do not replace a production identity provider, distributed
session/revocation store, secret manager, TLS termination, or access audit.
OIDC composition does not by itself prove real-IdP readiness; the operational
gates in `docs/OIDC_IDENTITY_PROVIDER_BOUNDARY.md` remain open.

Service readiness is composition-aware. An absent database, identity provider,
remote audit-custody adapter, or partner transport is reported `false`, never
assumed healthy. In OIDC mode, invalid credentials remain a normal `401` and do
not imply an IdP outage. A JWKS unavailable/invalid failure marks the identity
dependency unready; a later successfully verified token exchange is the
explicit recovery signal. Other absent dependencies remain unready.
