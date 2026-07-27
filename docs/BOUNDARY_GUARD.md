# Boundary Guard — what it is and is not

`scripts/no-test-verifier-in-prod.mjs` (npm script `guard:boundaries`, wired into
`npm run check`) exists to keep the WebAuthn test double
(`DeterministicTestCredentialVerifier`, and its helper
`createDeterministicTestAssertion`) out of non-test sources. See
`docs/WEBAUTHN_BOUNDARY.md` for why that double must never reach production.

## What it is

A **static architectural regression gate**. It walks every JS/TS source variant
(`.ts .mts .cts .tsx .js .mjs .cjs .jsx`) outside `tests/`, `node_modules/`,
`.git/`, and `scripts/`, and fails the build (exit 1) if any of them contains a
forbidden token. Its purpose is to catch the **realistic accidental case**: a
refactor or copy-paste that statically imports or names the test double in
production code.

- Dependency-free, deterministic, fast.
- Runs in CI via `npm run check`.
- The definition file itself
  (`packages/credentials/deterministicTestVerifier.ts`) is allow-listed.

## What it is NOT — do not overclaim

This guard is **not a security control and not a sandbox.** It performs a
**substring scan of source text**; it does not parse the module graph, resolve
imports, or execute code. It therefore **cannot** stop a determined or malicious
author. All of the following slip past it **by design**, and that is acceptable
because defending against them is a different problem:

- a computed/dynamic import: `import("./deterministic" + "TestVerifier.ts")`
- a computed require: `require(someVariableHoldingThePath)`
- `eval` / `new Function` constructed references
- aliasing the class through an intermediate re-export under a different name
- reflection or a plugin loader resolving the module at runtime

A green run means **"no accidental static reference,"** never "the double is
provably unreachable under adversarial conditions." The regression test
`tests/boundary-guard.test.ts` includes a case that *documents* this limitation
by asserting the guard does **not** flag an obfuscated dynamic reference — so the
gap is proven and honest, not hidden.

## The production-grade alternative (follow-up, not yet implemented)

The robust control is a **dependency-graph / import-allowlist check** that starts
from the production entry points, resolves the real import graph, and asserts the
test-double module is unreachable — optionally paired with a runtime composition
assertion that the selected `CredentialVerifier` is never the test class. That is
tracked as follow-up; it is deliberately **not** claimed here to avoid a brittle
false assurance. Until it exists, treat this guard as accident-prevention plus
`npm audit` / review for the rest.
