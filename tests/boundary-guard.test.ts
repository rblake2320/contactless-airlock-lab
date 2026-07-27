import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

const GUARD = join(process.cwd(), "scripts", "no-test-verifier-in-prod.mjs");

function runGuard(root: string): { status: number; stderr: string } {
  const r = spawnSync(process.execPath, [GUARD, root], { encoding: "utf8" });
  return { status: r.status ?? -1, stderr: r.stderr };
}

function fixture(): string {
  const dir = mkdtempSync(join(tmpdir(), "airlock-guard-"));
  mkdirSync(join(dir, "apps"), { recursive: true });
  mkdirSync(join(dir, "tests"), { recursive: true });
  mkdirSync(join(dir, "packages", "credentials"), { recursive: true });
  // the definition file itself is allowed to name the class
  writeFileSync(
    join(dir, "packages", "credentials", "deterministicTestVerifier.ts"),
    "export class DeterministicTestCredentialVerifier {}\n",
  );
  return dir;
}

test("guard passes when the test verifier is confined to tests/", () => {
  const dir = fixture();
  try {
    // a test file MAY import it — allowed
    writeFileSync(
      join(dir, "tests", "x.test.ts"),
      'import { DeterministicTestCredentialVerifier } from "../packages/credentials/deterministicTestVerifier.ts";\n',
    );
    // production code that does NOT reference it
    writeFileSync(join(dir, "apps", "engine.ts"), "export const ok = true;\n");
    assert.equal(runGuard(dir).status, 0);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("guard fails when a non-test source references the test verifier", () => {
  const dir = fixture();
  try {
    writeFileSync(
      join(dir, "apps", "leak.ts"),
      'import { DeterministicTestCredentialVerifier } from "../packages/credentials/deterministicTestVerifier.ts";\n',
    );
    const r = runGuard(dir);
    assert.equal(r.status, 1);
    assert.match(r.stderr, /BOUNDARY VIOLATION/);
    assert.match(r.stderr, /leak\.ts/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("guard flags every forbidden token, not just the class name", () => {
  const dir = fixture();
  try {
    writeFileSync(
      join(dir, "apps", "helper.ts"),
      'import { createDeterministicTestAssertion } from "../packages/credentials/deterministicTestVerifier.ts";\n',
    );
    const r = runGuard(dir);
    assert.equal(r.status, 1);
    assert.match(r.stderr, /createDeterministicTestAssertion/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// A leak is exactly as dangerous in an emitted/hand-written .js/.mjs/.cjs as in
// a .ts source. Prove every JS/TS variant is scanned.
for (const ext of [".js", ".mjs", ".cjs", ".cts", ".tsx", ".jsx", ".mts"]) {
  test(`guard scans ${ext} sources`, () => {
    const dir = fixture();
    try {
      writeFileSync(
        join(dir, "apps", `leak${ext}`),
        'const x = "DeterministicTestCredentialVerifier";\n',
      );
      const r = runGuard(dir);
      assert.equal(r.status, 1);
      assert.match(r.stderr, new RegExp(`leak\\${ext}`));
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
}

// DOCUMENTED LIMITATION (intentional, not a bug): the guard is a static
// substring gate, not an adversarial control. An obfuscated dynamic import is
// NOT detected. This test pins that honest boundary so the guard is never
// mistaken for a security sandbox — see docs/BOUNDARY_GUARD.md.
test("guard does NOT catch an obfuscated dynamic import (known, documented gap)", () => {
  const dir = fixture();
  try {
    // Reaches the double at runtime, but no forbidden token appears verbatim.
    writeFileSync(
      join(dir, "apps", "evasion.ts"),
      'const mod = "deterministic" + "TestVerifier.ts";\n' +
        "const load = (p: string) => import(`../packages/credentials/${p}`);\n" +
        "export const v = () => load(mod);\n",
    );
    const r = runGuard(dir);
    // Passes (exit 0): the guard cannot and does not claim to catch this.
    assert.equal(r.status, 0);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
