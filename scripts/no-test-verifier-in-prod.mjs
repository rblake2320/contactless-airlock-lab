#!/usr/bin/env node
/**
 * Architectural REGRESSION gate (NOT a security sandbox).
 *
 * The DeterministicTestCredentialVerifier is a protocol test double (HMAC,
 * JSON-shaped authenticator data) and is NOT WebAuthn. Per
 * docs/WEBAUTHN_BOUNDARY.md the production composition must never select it.
 * This script is a cheap, static, dependency-free regression gate that catches
 * the realistic ACCIDENTAL case — a normal static import/reference of the test
 * double sneaking into a non-test source during refactoring.
 *
 * SCOPE / LIMITATION — read before trusting this for more than it is
 * (see docs/BOUNDARY_GUARD.md):
 *   - It does a SUBSTRING scan of source text. It does NOT parse the module
 *     graph, resolve imports, or evaluate code.
 *   - It therefore does NOT and CANNOT defeat a determined adversary: an
 *     obfuscated or dynamic import (string concatenation, a computed
 *     `import()`/`require()`, `eval`, or aliasing through a re-export) will
 *     slip past it. That is out of scope by design; the true production-grade
 *     control is a dependency-graph/allowlist check from the production entry
 *     points, noted as follow-up in docs/BOUNDARY_GUARD.md.
 *   - Its job is to fail CI on an honest mistake, not to sandbox a malicious
 *     author. Do not represent a green run here as proof the double is
 *     unreachable under adversarial conditions.
 *
 * Exit 0 = no accidental static reference found. Exit 1 = a non-test source
 * statically references the test double.
 */
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, sep } from "node:path";

// Scan root defaults to CWD; an explicit arg lets tests point at a fixture tree
// so the guard is verifiable without mutating the shared worktree.
const ROOT = process.argv[2] ? process.argv[2] : process.cwd();
// Directories never scanned (their contents are allowed to reference the double).
const ALLOWED_DIRS = new Set(["tests", "node_modules", ".git", "scripts"]);
// The definition file itself is allowed to name the class.
const ALLOWED_FILES = new Set([
  join("packages", "credentials", "deterministicTestVerifier.ts"),
]);
// Every JS/TS source variant is scanned — a leak in a .js/.mjs/.cjs emit or
// hand-written module is exactly as dangerous as one in a .ts source.
const SOURCE_EXT = [
  ".ts", ".mts", ".cts", ".tsx",
  ".js", ".mjs", ".cjs", ".jsx",
];
// Any reference to these tokens outside the allowed set is a boundary breach.
const FORBIDDEN = [
  "deterministicTestVerifier",
  "DeterministicTestCredentialVerifier",
  "createDeterministicTestAssertion",
];

function walk(dir) {
  const out = [];
  for (const entry of readdirSync(dir)) {
    const abs = join(dir, entry);
    const rel = abs.slice(ROOT.length + 1);
    const top = rel.split(sep)[0];
    if (ALLOWED_DIRS.has(top)) continue;
    if (statSync(abs).isDirectory()) out.push(...walk(abs));
    else if (SOURCE_EXT.some((ext) => entry.endsWith(ext))) out.push(abs);
  }
  return out;
}

const violations = [];
for (const file of walk(ROOT)) {
  const rel = file.slice(ROOT.length + 1);
  if (ALLOWED_FILES.has(rel)) continue;
  const text = readFileSync(file, "utf8");
  for (const token of FORBIDDEN) {
    if (text.includes(token)) {
      const line = text.split("\n").findIndex((l) => l.includes(token)) + 1;
      violations.push(`${rel}:${line} references '${token}'`);
    }
  }
}

if (violations.length > 0) {
  console.error(
    "BOUNDARY VIOLATION: the WebAuthn test double is reachable from a " +
      "non-test source.\n" +
      "Per docs/WEBAUTHN_BOUNDARY.md it must never be selectable by a " +
      "production composition.\n",
  );
  for (const v of violations) console.error(`  - ${v}`);
  process.exit(1);
}

console.log("boundary guard: test WebAuthn verifier is confined to tests/ — ok");
