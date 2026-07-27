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

