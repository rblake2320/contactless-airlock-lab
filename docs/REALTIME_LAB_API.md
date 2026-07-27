# Realtime lab HTTP contract

The OpenAPI 3.1 document at
`contracts/openapi/realtime-lab.openapi.json` describes the current local
realtime-lab server exactly.

This is a simulator contract, not a proposed production issuer, processor,
wallet, TSP, network, or merchant API. It uses fixed synthetic identities,
creates synthetic ECDSA keys in the lab, and has no partner authentication or
payment-rail connection. A production partner contract remains a separate P1/P4
deliverable.

## Mutation controls

Every `POST /api/*` request is limited to 16,384 body bytes. Browser requests
must be same-origin; requests without `Origin` remain available to CLI test
harnesses. When `Sec-Fetch-Site` is present, only `same-origin` and `none` are
accepted.

`Idempotency-Key` is optional in ephemeral mode and mandatory when
`AIRLOCK_DB_PATH` enables persistence. It is 1–128 characters, begins with an
ASCII letter or digit, and thereafter permits letters, digits, dots,
underscores, colons, and hyphens. Reusing a key with a different canonical
method/path/query/body returns `409`.

Only `/api/transaction/request` requires a body. Its amount is a positive
decimal string with at most two fractional digits and must fit in JavaScript's
safe-integer minor-unit range. Its merchant ID is 1–64 characters in the
documented ASCII set. Other mutations require no body; if a body is supplied,
the current server accepts any JSON object and ignores its properties.

## Events

`GET /api/events` is an SSE stream. It immediately sends a `state` event whose
data is a `PublicState`, broadcasts another after committed mutations, and sends
comment heartbeats every 15 seconds.

## Executable contract evidence

`tests/openapi-contract.test.ts` checks route/method parity against server
source, shared mutation controls, schema references, live success responses,
SSE framing, and representative `400`, `403`, `409`, `413`, `415`, `428`,
`431`, and `404` negative responses. It runs in the default test suite without
network services or schema-validator dependencies.
