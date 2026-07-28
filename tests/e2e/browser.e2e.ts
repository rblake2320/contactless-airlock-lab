/**
 * Deterministic real-browser E2E gate for the simulator realtime-lab UI.
 *
 * Runs the actual `apps/realtime-lab` frontend (index.html + app.js + styles.css)
 * in headless Chromium and asserts the browser-observable behavior the plain
 * Node contract tests cannot: DOM controls and capability gating, 320px
 * responsive overflow, keyboard operation/focus, the aria-live result
 * announcement, immutable confirmation rendering, a replay/negative demo,
 * frontend network-error feedback, and SSE-rendered state updates.
 *
 * PORTABILITY: Playwright is a PINNED repo devDependency (`playwright@1.58.2`,
 * see package.json/package-lock.json); the pinned Chromium binary is installed
 * explicitly and cacheably via `npx playwright install --with-deps chromium`
 * (locally and in `.github/workflows/e2e.yml`) — no hidden global dependency, so
 * the gate runs from a pristine checkout. It is intentionally OUTSIDE the
 * `tests/*.test.ts` glob so the default dependency-free `npm test` never pulls a
 * browser in implicitly. Run it explicitly:
 *
 *   npm ci && npx playwright install --with-deps chromium
 *   node --experimental-strip-types --test tests/e2e/browser.e2e.ts
 *
 * If the Chromium binary has not been installed the suite SKIPS (not fails), so a
 * checkout that skipped `playwright install` is not a hard failure. See
 * docs/BROWSER_E2E.md.
 *
 * Isolation: each test starts its own realtime-lab server on an ephemeral port
 * backed by a fresh temp SQLite database, in its own browser context; server,
 * context, and temp dir are torn down after every test. The browser process is
 * launched once and closed at the end.
 */
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test, { after, before } from "node:test";
import { createLabServer } from "../../apps/realtime-lab/server.ts";

// Resolve Playwright from wherever it is installed (global/host), tolerating its
// absence so this file is a no-op skip rather than a hard failure off-browser.
let chromium: any;
let browser: any;
let unavailable: string | undefined;

before(async () => {
  try {
    ({ chromium } = await import("playwright"));
  } catch {
    unavailable = "playwright is not installed (host/global dependency)";
    return;
  }
  try {
    browser = await chromium.launch({ headless: true });
  } catch (error) {
    unavailable = `Chromium binary unavailable: ${
      error instanceof Error ? error.message.split("\n")[0] : String(error)
    }`;
  }
});

after(async () => {
  await browser?.close();
});

interface Lab {
  baseUrl: string;
  page: any;
  /** Fire a mutation directly at the server (not via the page UI). */
  serverPost: (path: string, body?: unknown) => Promise<Response>;
  /** Uncaught page-side JS errors captured during the test. */
  pageErrors: Error[];
}

/** Start an isolated server + browser context + page, run `body`, tear down. */
async function withLab(
  body: (lab: Lab) => Promise<void>,
  serverOptions: Record<string, unknown> = {},
): Promise<void> {
  const dir = mkdtempSync(join(tmpdir(), "airlock-e2e-"));
  // Rate/SSE limits disabled by default so low-volume E2E interaction is never
  // throttled; individual tests override (e.g. to exercise the 429 path).
  const server = createLabServer({
    dbPath: join(dir, "lab.sqlite"),
    rateLimit: false,
    sseLimit: false,
    ...serverOptions,
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address() as AddressInfo;
  const baseUrl = `http://127.0.0.1:${port}`;
  const context = await browser.newContext();
  const page = await context.newPage();
  const pageErrors: Error[] = [];
  page.on("pageerror", (err: Error) => pageErrors.push(err));

  const serverPost = (path: string, jsonBody?: unknown) =>
    fetch(`${baseUrl}${path}`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "idempotency-key": `e2e-${crypto.randomUUID()}`,
      },
      body: JSON.stringify(jsonBody ?? {}),
    });

  try {
    await page.goto(baseUrl, { waitUntil: "domcontentloaded" });
    // Wait for the SSE 'state' event to land and the app to render "Live".
    await page.waitForFunction(
      () => document.getElementById("connection")?.textContent === "Live",
      undefined,
      { timeout: 10_000 },
    );
    await body({ baseUrl, page, serverPost, pageErrors });
  } finally {
    await context.close();
    await new Promise<void>((resolve) => server.close(() => resolve()));
    rmSync(dir, { recursive: true, force: true });
  }
}

const text = (page: any, id: string) =>
  page.$eval(`#${id}`, (el: Element) => el.textContent?.trim() ?? "");

// A test wrapper that skips cleanly when no browser stack is present.
function e2e(
  name: string,
  fn: (lab: Lab) => Promise<void>,
  serverOptions: Record<string, unknown> = {},
) {
  test(name, async (t) => {
    if (unavailable) return t.skip(unavailable);
    await withLab(fn, serverOptions);
  });
}

// ---------------------------------------------------------------------------

e2e("SSE renders initial state and marks the connection Live", async ({ page }) => {
  assert.equal(await text(page, "connection"), "Live");
  // The SSE-rendered initial (reset) state drives capability gating: requesting
  // provisioning is available, approving it is not yet.
  assert.equal(await page.$eval('[data-capability="requestProvisioning"]',
    (b: HTMLButtonElement) => b.disabled), false);
  assert.equal(await page.$eval('[data-capability="approveProvisioning"]',
    (b: HTMLButtonElement) => b.disabled), true);
  // A rendered result title is present (not the pre-render placeholder).
  assert.notEqual(await text(page, "result-title"), "");
});

e2e("DOM controls drive the flow and capability gating updates", async ({ page }) => {
  await page.click('[data-capability="requestProvisioning"]');
  await page.waitForFunction(
    () => {
      const t = document.getElementById("request-state")?.textContent;
      return !!t && t !== "not requested";
    },
    undefined, { timeout: 5_000 },
  );
  assert.notEqual(await text(page, "request-state"), "not requested");
  // Approving is now enabled; requesting again is gated off.
  assert.equal(await page.$eval('[data-capability="approveProvisioning"]',
    (b: HTMLButtonElement) => b.disabled), false);
  assert.equal(await page.$eval('[data-capability="requestProvisioning"]',
    (b: HTMLButtonElement) => b.disabled), true);
});

e2e("no horizontal overflow at a 320px viewport", async ({ page }) => {
  await page.setViewportSize({ width: 320, height: 800 });
  const overflow = await page.evaluate(() => {
    const doc = document.documentElement;
    return {
      docScroll: doc.scrollWidth,
      client: doc.clientWidth,
      bodyScroll: document.body.scrollWidth,
    };
  });
  // The layout must not force horizontal scrolling at 320px.
  assert.ok(overflow.docScroll <= overflow.client,
    `document overflows: scrollWidth ${overflow.docScroll} > clientWidth ${overflow.client}`);
  assert.ok(overflow.bodyScroll <= 320,
    `body overflows 320px: ${overflow.bodyScroll}`);
});

e2e("keyboard focus and Enter activate a control", async ({ page }) => {
  const button = await page.$('[data-capability="requestProvisioning"]');
  await button.focus();
  // Focus actually lands on that button.
  assert.equal(
    await page.evaluate(() =>
      document.activeElement?.getAttribute("data-capability")),
    "requestProvisioning",
  );
  await page.keyboard.press("Enter");
  await page.waitForFunction(
    () => {
      const t = document.getElementById("request-state")?.textContent;
      return !!t && t !== "not requested";
    },
    undefined, { timeout: 5_000 },
  );
  assert.notEqual(await text(page, "request-state"), "not requested");
});

e2e("the result is announced through an aria-live status region", async ({ page }) => {
  // The announcement container is a polite, atomic status live region.
  const live = await page.$eval(".result", (el: Element) => ({
    role: el.getAttribute("role"),
    ariaLive: el.getAttribute("aria-live"),
    ariaAtomic: el.getAttribute("aria-atomic"),
    containsTitle: !!el.querySelector("#result-title"),
    containsMessage: !!el.querySelector("#result-message"),
  }));
  assert.equal(live.role, "status");
  assert.equal(live.ariaLive, "polite");
  assert.equal(live.ariaAtomic, "true");
  assert.ok(live.containsTitle && live.containsMessage);
  // A protocol action updates the announced content inside that region.
  await page.click('[data-capability="requestProvisioning"]');
  await page.waitForFunction(
    () => document.getElementById("result-title")?.textContent === "Accepted",
    undefined, { timeout: 5_000 },
  );
  assert.equal(await text(page, "result-title"), "Accepted");
  assert.ok((await text(page, "result-message")).length > 0);
});

e2e("editing the amount field cannot change the immutable confirmation", async ({ page }) => {
  await page.click('[data-capability="requestProvisioning"]');
  await page.click('[data-capability="approveProvisioning"]');
  await page.fill("#amount", "25.00");
  await page.fill("#merchant", "synthetic-merchant-001");
  await page.click('[data-capability="requestTransaction"]');
  await page.waitForFunction(
    () => document.getElementById("bound-amount")?.textContent?.includes("25.00"),
    undefined, { timeout: 5_000 },
  );
  assert.match(await text(page, "bound-amount"), /25\.00/);
  // Now tamper with the editable field. The stored/confirmed binding must NOT
  // follow it — the editable request field cannot rewrite the stored challenge.
  await page.fill("#amount", "999.99");
  assert.equal(await page.$eval("#amount", (i: HTMLInputElement) => i.value), "999.99");
  assert.match(await text(page, "bound-amount"), /25\.00/);
  assert.doesNotMatch(await text(page, "bound-amount"), /999\.99/);
});

e2e("a replay/negative demonstration is rejected and audited", async ({ page }) => {
  await page.click('[data-capability="requestProvisioning"]');
  await page.click('[data-capability="approveProvisioning"]');
  await page.click('[data-capability="requestTransaction"]');
  await page.waitForFunction(
    () => document.getElementById("transaction-state")?.textContent !== "absent",
    undefined, { timeout: 5_000 },
  );
  const beforeCount = await text(page, "event-count");
  // "Reuse signature" replays previously valid evidence; it must be blocked.
  await page.click('[data-action="/api/demonstrate/reused-signature"]');
  await page.waitForFunction(
    () => document.getElementById("result-title")?.textContent === "Blocked",
    undefined, { timeout: 5_000 },
  );
  assert.equal(await text(page, "result-title"), "Blocked");
  // The rejection is recorded in the tamper-evident audit stream.
  await page.waitForFunction(
    (prev: string) => document.getElementById("event-count")?.textContent !== prev,
    beforeCount, { timeout: 5_000 },
  );
  assert.notEqual(await text(page, "event-count"), beforeCount);
});

e2e("a frontend network error is surfaced without a stuck UI", async ({ page }) => {
  // Abort the reset request at the network layer to simulate a server outage,
  // exercising app.js's catch-path feedback (no server code involved).
  await page.route("**/api/reset", (route: any) => route.abort());
  await page.click('[data-action="/api/reset"]');
  await page.waitForFunction(
    () => document.getElementById("result-title")?.textContent === "Network error",
    undefined, { timeout: 5_000 },
  );
  assert.equal(await text(page, "result-title"), "Network error");
  assert.equal(await text(page, "connection"), "Connection error");
  assert.match(await text(page, "result-message"), /did not complete/i);
  // The busy flag must be cleared (finally-block), i.e. the UI is not stuck.
  assert.equal(
    await page.evaluate(() => document.body.dataset.busy ?? "cleared"),
    "cleared",
  );
});

e2e("SSE pushes a server-side mutation into the DOM without a local click", async ({ page, serverPost }) => {
  assert.equal(await text(page, "request-state"), "not requested");
  // Mutate via a DIRECT server call (a different client). The open page must
  // update purely from the SSE broadcast, proving server -> SSE -> DOM.
  const res = await serverPost("/api/provision/request");
  assert.equal(res.status, 200);
  await page.waitForFunction(
    () => {
      const t = document.getElementById("request-state")?.textContent;
      return !!t && t !== "not requested";
    },
    undefined, { timeout: 5_000 },
  );
  // The open page reflects the server-side mutation purely via SSE broadcast.
  assert.notEqual(await text(page, "request-state"), "not requested");
});

// ---------------------------------------------------------------------------
// Confirmed UI-defect coverage: state-less HTTP errors must not crash render()
// or be mislabeled as a network error; in-flight controls disabled; connection
// status announced.
// ---------------------------------------------------------------------------

e2e("a 429 rate-limit is shown as Blocked, not a network error, with no JS crash",
  async ({ page }) => {
    // First mutation consumes the single token and succeeds.
    await page.click('[data-capability="requestProvisioning"]');
    await page.waitForFunction(
      () => {
      const t = document.getElementById("request-state")?.textContent;
      return !!t && t !== "not requested";
    },
      undefined, { timeout: 5_000 },
    );
    // A second, distinct mutation is rate limited (429, state-less body).
    await page.click('[data-action="/api/reset"]');
    await page.waitForFunction(
      () => document.getElementById("result-title")?.textContent === "Blocked",
      undefined, { timeout: 5_000 },
    );
    assert.equal(await text(page, "result-title"), "Blocked");
    assert.match(await text(page, "result-message"), /RATE_LIMITED/);
    // The critical regression assertions: NOT mislabeled as a network error...
    assert.notEqual(await text(page, "result-title"), "Network error");
    assert.notEqual(await text(page, "connection"), "Connection error");
  },
  // Tiny bucket so the second request is deterministically rejected.
  { rateLimit: { capacity: 1, refillPerSecond: 1, maxClients: 100 } },
);

e2e("render() never throws on a state-less rejection body (no uncaught page error)",
  async ({ page, pageErrors }) => {
    await page.click('[data-capability="requestProvisioning"]');
    await page.waitForFunction(
      () => {
      const t = document.getElementById("request-state")?.textContent;
      return !!t && t !== "not requested";
    },
      undefined, { timeout: 5_000 },
    );
    await page.click('[data-action="/api/reset"]'); // 429, state-less
    await page.waitForFunction(
      () => document.getElementById("result-title")?.textContent === "Blocked",
      undefined, { timeout: 5_000 },
    );
    // The old code dereferenced state.audit on the error body and threw; assert
    // no uncaught JS error reached the page.
    assert.deepEqual(pageErrors, [], `unexpected page errors: ${pageErrors.map(String)}`);
  },
  { rateLimit: { capacity: 1, refillPerSecond: 1, maxClients: 100 } },
);

e2e("a rapid double-click issues only one request (in-flight suppression)",
  async ({ page }) => {
    let requests = 0;
    await page.route("**/api/provision/request", (route: any) => {
      requests += 1;
      return route.continue();
    });
    // Fire two clicks synchronously, before the first request settles.
    await page.$eval('[data-capability="requestProvisioning"]', (b: HTMLButtonElement) => {
      b.click();
      b.click();
    });
    await page.waitForFunction(
      () => {
      const t = document.getElementById("request-state")?.textContent;
      return !!t && t !== "not requested";
    },
      undefined, { timeout: 5_000 },
    );
    // A short settle window; no second request may appear.
    await page.waitForTimeout(300);
    assert.equal(requests, 1, `expected exactly one request, saw ${requests}`);
    // The initiating control was disabled during the in-flight window (it is now
    // capability-gated off because provisioning is already requested).
    assert.equal(await page.$eval('[data-capability="requestProvisioning"]',
      (b: HTMLButtonElement) => b.disabled), true);
  },
);

e2e("connection status is an aria-live region and announces error state",
  async ({ page }) => {
    assert.equal(
      await page.$eval("#connection", (el: Element) => el.getAttribute("aria-live")),
      "polite",
    );
    // Force a genuine transport failure and confirm the announced text changes.
    await page.route("**/api/reset", (route: any) => route.abort());
    await page.click('[data-action="/api/reset"]');
    await page.waitForFunction(
      () => document.getElementById("connection")?.textContent === "Connection error",
      undefined, { timeout: 5_000 },
    );
    assert.equal(await text(page, "connection"), "Connection error");
  },
);

// ---------------------------------------------------------------------------
// Regression: non-capability triggers must not stay disabled after success; the
// form submit handler must return an awaitable promise.
// ---------------------------------------------------------------------------

e2e("a successful non-capability action (Reset lab) re-enables its button", async ({ page }) => {
  const reset = '[data-action="/api/reset"]';
  // Reset has no data-capability, so render()'s gating never manages it.
  assert.equal(await page.$eval(reset, (b: HTMLButtonElement) => b.disabled), false);
  await page.click(reset);
  // After the successful reset renders, the in-flight disable must be lifted.
  await page.waitForFunction(
    (sel: string) => {
      const b = document.querySelector(sel);
      return b instanceof HTMLButtonElement && b.disabled === false;
    },
    reset, { timeout: 5_000 },
  );
  assert.equal(await page.$eval(reset, (b: HTMLButtonElement) => b.disabled), false);
  // And it remains clickable a second time (not stuck disabled forever).
  await page.click(reset);
  await page.waitForFunction(
    (sel: string) => {
      const b = document.querySelector(sel);
      return b instanceof HTMLButtonElement && b.disabled === false;
    },
    reset, { timeout: 5_000 },
  );
  assert.equal(await page.$eval(reset, (b: HTMLButtonElement) => b.disabled), false);
});


e2e("submitting the transaction form runs the request to completion (B1)", async ({ page }) => {
  // Drive the flow with explicit enabled-waits between stages so the in-flight
  // busy guard never suppresses the next step (each control is disabled while a
  // request is in flight and re-enabled by gating once it settles).
  await page.click('[data-capability="requestProvisioning"]');
  await page.waitForSelector('[data-capability="approveProvisioning"]:not([disabled])',
    { timeout: 5_000 });
  await page.click('[data-capability="approveProvisioning"]');
  await page.waitForSelector('[data-capability="requestTransaction"]:not([disabled])',
    { timeout: 5_000 });
  await page.fill("#amount", "25.00");
  // Clicking the type="submit" control submits the form; the submit handler
  // returns action()'s promise (B1) and drives the request to completion.
  await page.click('[data-capability="requestTransaction"]');
  await page.waitForFunction(
    () => document.getElementById("transaction-state")?.textContent !== "absent",
    undefined, { timeout: 5_000 },
  );
  assert.notEqual(await text(page, "transaction-state"), "absent");
  assert.match(await text(page, "bound-amount"), /25\.00/);
});
