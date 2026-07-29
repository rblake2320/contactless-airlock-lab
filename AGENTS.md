# Repository Scope

This repository contains only the Contactless Airlock Lab payment-security
reference implementation, simulators, tests, and partner documentation.

Do not import, copy, or modify Beast Studio, SelfConnect, Spark fleet, Unreal,
or unrelated project code from this repository. SelfConnect may coordinate
agents externally, but it is not a runtime or source dependency.

Never commit real PAN, CVV, payment tokens, biometric data, production
credentials, issuer data, or customer information. Use synthetic identifiers
and deterministic fixtures.

Claims must distinguish:

- behavior proven by executable local tests;
- behavior simulated at a partner boundary;
- behavior requiring issuer, processor, wallet/TSP, network, or merchant
  integration and certification.

Approval followed by reversal is not a settlement-prevention guarantee.

## Approved local PostgreSQL integration target

On this Windows machine, run real PostgreSQL integration tests only through
`tools/run-local-postgres-test.ps1`. It consumes
`C:\Users\techai\.airlock.env` without printing the connection URL and targets
the dedicated loopback-only `airlock-postgres-test` Docker container on port
`5544`.

Never use `C:\Users\techai\.pg.env`, native PostgreSQL port `5434`, Windows
port `5432`, or either Spark's PostgreSQL services for this repository. Those
belong to other projects. Never commit the secret file or copy its value into
documentation, prompts, logs, test output, or GitHub.
