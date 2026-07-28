import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import test from "node:test";

// Guards the browser-E2E workflow's supply-chain posture against silent
// weakening. Text-based (no YAML dependency) since the default suite is
// zero-runtime-dep. Every third-party action MUST be pinned by full commit SHA.
const wf = readFileSync(
  join(process.cwd(), ".github", "workflows", "e2e.yml"),
  "utf8",
);
const pkg = JSON.parse(
  readFileSync(join(process.cwd(), "package.json"), "utf8"),
) as {
  devDependencies?: Record<string, string>;
  scripts?: Record<string, string>;
};

test("every third-party action is pinned by a 40-hex commit SHA with a version comment", () => {
  const uses = [...wf.matchAll(/uses:\s*(\S+)/g)].map((m) => m[1]);
  assert.ok(uses.length >= 3, "expected checkout, setup-node, and cache actions");
  for (const ref of uses) {
    assert.match(
      ref,
      /@[0-9a-f]{40}$/,
      `action is not pinned by full commit SHA: ${ref}`,
    );
  }
  // Each pin carries a human-readable version comment for auditability.
  assert.match(wf, /actions\/checkout@[0-9a-f]{40}\s*#\s*v\d/);
  assert.match(wf, /actions\/setup-node@[0-9a-f]{40}\s*#\s*v\d/);
  assert.match(wf, /actions\/cache@[0-9a-f]{40}\s*#\s*v\d/);
});

test("checkout pins match the rest of the repository and do not persist credentials", () => {
  // Same checkout SHA the other hardened workflows already use.
  assert.match(wf, /actions\/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd/);
  assert.match(wf, /persist-credentials:\s*false/);
});

test("workflow runs least privilege: read-only, no write scope anywhere", () => {
  assert.match(wf, /permissions:\s*\n\s*contents:\s*read/);
  assert.doesNotMatch(wf, /:\s*write/);
});

test("dependencies install locked and without lifecycle scripts", () => {
  assert.match(wf, /npm ci --ignore-scripts/);
});

test("the workflow runs the gate through portable npm scripts, not ad-hoc commands", () => {
  assert.match(wf, /run:\s*npm run e2e:install/, "must install the browser via npm run e2e:install");
  assert.match(wf, /run:\s*npm run e2e\b/, "must run the gate via npm run e2e");
});

test("portable e2e scripts exist and do the explicit, pinned browser install", () => {
  const scripts = pkg.scripts ?? {};
  assert.ok(scripts.e2e, "package.json must define an `e2e` script");
  assert.match(scripts.e2e, /tests\/e2e\/browser\.e2e\.ts/);
  assert.ok(scripts["e2e:install"], "package.json must define an `e2e:install` script");
  // Explicit, non-implicit Chromium install (no hidden global dependency).
  assert.match(scripts["e2e:install"], /playwright install --with-deps chromium/);
  // Cacheable by the resolved, repo-pinned Playwright version.
  assert.match(wf, /~\/\.cache\/ms-playwright/);
  assert.match(wf, /require\('\.\/node_modules\/playwright\/package\.json'\)\.version/);
});

test("Playwright is a pinned (exact, no range) repository devDependency", () => {
  const pinned = pkg.devDependencies?.playwright;
  assert.ok(pinned, "playwright must be a devDependency");
  assert.match(pinned!, /^\d+\.\d+\.\d+$/, `playwright must be exact-pinned, got ${pinned}`);
});

test("it is a pull-request gate, not a push gate", () => {
  assert.match(wf, /on:\s*\n\s*pull_request:/);
  assert.doesNotMatch(wf, /^\s*push:/m);
});

test("the E2E gate lives outside the default dependency-free test glob", () => {
  // The default `npm test` runs tests/*.test.ts (non-recursive); the browser
  // gate is tests/e2e/*.e2e.ts so it never pulls a browser in implicitly.
  const testScript = (JSON.parse(
    readFileSync(join(process.cwd(), "package.json"), "utf8"),
  ) as { scripts: Record<string, string> }).scripts.test;
  assert.match(testScript, /tests\/\*\.test\.ts/);
  assert.doesNotMatch(testScript, /e2e/);
});

test("boundary doc exists and states the portable-but-separate posture", () => {
  const doc = readFileSync(
    join(process.cwd(), "docs", "BROWSER_E2E.md"),
    "utf8",
  );
  assert.match(doc, /playwright/i);
  assert.match(doc, /chromium/i);
  assert.match(doc, /pristine checkout|pinned|devDependency/i);
});
