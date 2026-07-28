# OIDC access-token identity-provider boundary

`packages/identity/oidcAccessTokenVerifier.ts` is composed into the realtime
server through the explicit `oidc` authenticated identity-provider mode.
Successful verification exchanges signed claims for bounded process-local
session state. This executable composition does not make the lab a
production-ready identity-provider integration.

The adapter verifies real asymmetric JWT signatures with the pinned `jose`
library. Configuration fixes one exact HTTPS issuer, an audience or audience
set, an exact HTTPS JWKS URI, and an explicit asymmetric algorithm allowlist
(`ES256`, `RS256`, or `PS256`). It rejects unsigned tokens, symmetric-algorithm
substitution, missing or malformed `kid`, issuer/audience substitution,
signature failure, expiry, future `nbf`, stale/future `iat`, and tokens beyond
the configured maximum age.

Principal ID, tenant ID, and roles are created only after signature and
registered-claim validation. Their signed claim names are configured locally;
request headers, query parameters, paths, and unsigned metadata are not
identity sources. Roles must be members of the configured allowlist. The
returned identity is immutable and contains no raw token.

JWKS retrieval is fail-closed and bounded by HTTPS-only configuration, redirect
rejection, timeout, response-byte limit, key-count limit, cache TTL, and
unknown-key refresh cooldown. An unexpired cache can tolerate a temporary IdP
outage; once it expires, outage is rejection rather than stale-key fallback.
Unknown `kid` can trigger one controlled refresh after cooldown so signing-key
rotation converges without unbounded fetching.

Some deployments require one-time use of a JWT ID. When
`requireJtiReplayProtection` is enabled, construction requires a
`JtiReplayStore`, and verification succeeds only if its atomic `consume`
operation accepts the issuer/tenant/`jti` tuple through token expiry. There is
no in-memory or bootstrap-credential fallback hidden inside the adapter.

Executable tests generate real EC key pairs, publish local JWKS responses, sign
real JWTs, rotate keys, simulate cache expiry and IdP outage, enforce response
bounds, and exercise replay rejection. Production integration still requires:

- discovery/metadata policy and an approved issuer onboarding process;
- TLS, DNS, egress, proxy, and certificate policy;
- a durable distributed replay store where one-time access tokens are required;
- IdP availability objectives, monitoring, incident response, and key rollover
  coordination;
- durable/distributed session revocation and a reviewed token-to-session
  exchange policy.
