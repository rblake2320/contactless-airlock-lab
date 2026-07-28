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
forbidden token. It also resolves and traverses literal relative imports and
re-exports from every production source and fails if any path reaches the test
double. Its purpose is to catch the **realistic accidental case**: a refactor
or copy-paste that imports, re-exports, or names the test double in production.

- Dependency-free, deterministic, fast.
- Runs in CI via `npm run check`.
- The definition file itself
  (`packages/credentials/deterministicTestVerifier.ts`) is allow-listed.

## What it is NOT — do not overclaim

This guard is **not a security control and not a sandbox.** It performs a
**substring and literal-import static analysis**; it does not execute code. It
therefore **cannot** stop a determined or malicious author. The following can
slip past it **by design**, and defending against them is a different problem:

- a computed/dynamic import: `import("./deterministic" + "TestVerifier.ts")`
- a computed require: `require(someVariableHoldingThePath)`
- `eval` / `new Function` constructed references
- reflection or a plugin loader resolving the module at runtime

A green run means **"no accidental static reference,"** never "the double is
provably unreachable under adversarial conditions." The regression test
`tests/boundary-guard.test.ts` includes a case that *documents* this limitation
by asserting the guard does **not** flag an obfuscated dynamic reference — so the
gap is proven and honest, not hidden.

This is still accident prevention, not an adversarial sandbox. Packaging the
production application from an explicit dependency allowlist and adding a
runtime composition assertion remain worthwhile defense-in-depth controls.
