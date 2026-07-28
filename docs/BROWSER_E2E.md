# Browser E2E gate

A deterministic real-browser end-to-end gate for the simulator realtime-lab UI
(`apps/realtime-lab/public/`). It drives the actual `index.html` + `app.js` +
`styles.css` in headless Chromium and asserts browser-observable behavior the
plain Node contract tests cannot.

## What it covers

- **DOM controls & capability gating** — buttons drive the flow; disabled state
  tracks `state.actions`.
- **Responsive 320px** — no horizontal overflow at a 320px viewport.
- **Keyboard operation/focus** — a control is reachable by focus and activates on
  Enter.
- **aria-live result announcement** — the result region is `role="status"`,
  `aria-live="polite"`, `aria-atomic="true"`, and its content updates on action.
- **Immutable confirmation** — editing the amount field cannot change the stored
  confirmation binding.
- **Replay/negative demonstration** — "Reuse signature" is rejected and audited.
- **Frontend network-error feedback** — an aborted request surfaces a network
  error without a stuck UI.
- **SSE-rendered updates** — a server-side mutation reaches an open page purely
  via the SSE broadcast.
- **Confirmed UI-defect regressions** — a state-less HTTP error (e.g. `429`) is
  shown as a real `Blocked` decision with its stable code (never mislabeled as a
  network error) and never throws an uncaught page error; a rapid double-click
  issues only one request (in-flight suppression); connection status is an
  aria-live region.

## Portability — no hidden global dependency

Playwright is a **pinned, exact repository devDependency** (`playwright` in
`package.json`, locked in `package-lock.json`). The Chromium binary is **not**
bundled; it is installed **explicitly** and is cacheable, pinned to the repo's
Playwright version. The gate therefore runs from a pristine checkout — locally
and in CI — with no reliance on a globally installed browser stack.

The default suite stays dependency-free: `npm test` runs `tests/*.test.ts`
(non-recursive), and this gate lives at `tests/e2e/browser.e2e.ts`, so a browser
is never pulled in implicitly.

### Local

```
npm ci
npm run e2e:install   # explicit, one-time, cacheable Chromium download
npm run e2e
```

If the Chromium binary has not been installed the gate **skips** (it does not
fail), so a checkout that skipped `playwright install` is not a hard failure.

### CI

`.github/workflows/e2e.yml` runs on pull requests to `main`:

1. `actions/checkout` and `actions/setup-node` — pinned by commit SHA, least
   privilege (`contents: read`), `persist-credentials: false`.
2. `npm ci --ignore-scripts` — locked install, no lifecycle scripts.
3. `actions/cache` (pinned by SHA) keyed on the resolved Playwright version.
4. `npm run e2e:install` — explicit, deterministic Chromium download pinned to
   the repo's Playwright version.
5. `npm run e2e` — runs the gate.

All third-party action pins are verified by `tests/e2e-workflow-config.test.ts`,
which fails if any action is not pinned by a full commit SHA, if the workflow
gains write scope, if the browser install becomes implicit, or if Playwright
stops being an exact-pinned devDependency.

## Isolation

Each test starts its own realtime-lab server on an ephemeral port backed by a
fresh temp SQLite database, in its own browser context. The server, browser
context, and temp directory are torn down after every test; the browser process
is launched once and closed at the end. Rate and SSE limits are disabled by
default so low-volume interaction is never throttled; individual tests override
them (e.g. to exercise the `429` path).

## Scope

This is a UI-behavior gate for the **simulator** lab only. It does not exercise
real devices, real browsers-at-scale, cross-browser matrices, or production
integration — those remain out of scope, consistent with the project's
simulator/single-host boundary.
