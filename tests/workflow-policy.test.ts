import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import test from "node:test";

// Policy-as-code across EVERY workflow, so a future edit to any of them cannot
// silently drop SHA pinning, leak checkout credentials, or widen token scope.
// Text-based (repo is zero-runtime-dep). The only write scope permitted anywhere
// is `security-events: write`, which CodeQL requires to upload SARIF.
const WF_DIR = join(process.cwd(), ".github", "workflows");
const ALLOWED_WRITE = new Set(["security-events: write"]);

const files = readdirSync(WF_DIR).filter(
  (f) => f.endsWith(".yml") || f.endsWith(".yaml"),
);

test("workflow directory is non-empty (sanity)", () => {
  assert.ok(files.length >= 2, `expected workflows, found ${files.length}`);
});

for (const file of files) {
  const text = readFileSync(join(WF_DIR, file), "utf8");
  const lines = text.split("\n");

  test(`${file}: every 'uses:' is pinned to a 40-hex commit SHA with a version comment`, () => {
    const uses = lines
      .map((l) => l.trim())
      .filter((l) => l.startsWith("- uses:") || l.startsWith("uses:"));
    assert.ok(uses.length > 0, `${file} has no 'uses:' steps to check`);
    for (const u of uses) {
      assert.match(
        u,
        /uses:\s*[\w.-]+\/[\w./-]+@[0-9a-f]{40}\s*#\s*v?\d/,
        `${file}: unpinned or unlabeled action -> ${u}`,
      );
    }
  });

  test(`${file}: every checkout disables credential persistence`, () => {
    if (!text.includes("actions/checkout@")) return; // no checkout in this file
    const checkoutCount = (text.match(/actions\/checkout@/g) ?? []).length;
    const persistFalse = (text.match(/persist-credentials:\s*false/g) ?? [])
      .length;
    assert.ok(
      persistFalse >= checkoutCount,
      `${file}: ${checkoutCount} checkout(s) but ${persistFalse} persist-credentials:false`,
    );
  });

  test(`${file}: no write token scope except the allowlisted security-events:write`, () => {
    const writes = lines
      .map((l) => l.trim())
      .filter((l) => /^[a-z-]+:\s*write$/.test(l));
    for (const w of writes) {
      assert.ok(
        ALLOWED_WRITE.has(w),
        `${file}: unexpected write scope '${w}' (only security-events:write is allowed)`,
      );
    }
  });

  test(`${file}: declares an explicit least-privilege top-level or job permissions block`, () => {
    assert.match(
      text,
      /permissions:\s*\n\s*[a-z-]+:\s*(read|write)/,
      `${file}: no explicit permissions block found`,
    );
  });
}
