import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import test from "node:test";

// Guards the security posture of the dependency-review workflow against silent
// weakening. Text-based (no YAML dependency) since the repo is zero-runtime-dep.
const wf = readFileSync(
  join(process.cwd(), ".github", "workflows", "dependency-review.yml"),
  "utf8",
);

test("dependency-review action is pinned by 40-hex commit SHA", () => {
  const m = wf.match(
    /actions\/dependency-review-action@([0-9a-f]{40})\s*#\s*(v\d+\.\d+\.\d+)/,
  );
  assert.ok(m, "action must be pinned by full commit SHA with a version comment");
  assert.equal(m[1], "a1d282b36b6f3519aa1f3fc636f609c47dddb294");
  assert.equal(m[2], "v5.0.0");
});

test("checkout is pinned and does not persist credentials", () => {
  assert.match(wf, /actions\/checkout@[0-9a-f]{40}\s*#\s*v\d/);
  assert.match(wf, /persist-credentials:\s*false/);
});

test("runs least-privilege: no write scope anywhere", () => {
  assert.match(wf, /permissions:\s*\n\s*contents:\s*read/);
  assert.doesNotMatch(wf, /:\s*write/);
});

test("fails on high or critical advisories", () => {
  assert.match(wf, /fail-on-severity:\s*high/);
});

test("is a pull-request gate (its documented scope), not a push gate", () => {
  assert.match(wf, /on:\s*\n\s*pull_request:/);
  assert.doesNotMatch(wf, /^\s*push:/m);
});

test("boundary doc exists and disclaims runtime/baseline/transitive overclaim", () => {
  const doc = readFileSync(
    join(process.cwd(), "docs", "DEPENDENCY_REVIEW_BOUNDARY.md"),
    "utf8",
  );
  assert.match(doc, /not a runtime/i);
  assert.match(doc, /does not scan the existing baseline/i);
  assert.match(doc, /[Tt]ransitive coverage/);
});
