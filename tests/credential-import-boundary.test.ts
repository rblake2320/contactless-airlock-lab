import assert from "node:assert/strict";
import { readFile, readdir } from "node:fs/promises";
import { relative, resolve } from "node:path";
import test from "node:test";

const ROOT = resolve(import.meta.dirname, "..");
const TEST_DOUBLE_FILE = resolve(
  ROOT,
  "packages/credentials/deterministicTestVerifier.ts",
);

test("the deterministic credential verifier cannot enter runtime code", async () => {
  const roots = ["apps", "packages", "tools"];
  const violations: string[] = [];

  for (const sourceRoot of roots) {
    const directory = resolve(ROOT, sourceRoot);
    const entries = await readdir(directory, {
      recursive: true,
      withFileTypes: true,
    });
    for (const entry of entries) {
      if (!entry.isFile() || !entry.name.endsWith(".ts")) continue;
      const path = resolve(entry.parentPath, entry.name);
      if (path === TEST_DOUBLE_FILE) continue;
      const source = await readFile(path, "utf8");
      if (
        source.includes("deterministicTestVerifier") ||
        source.includes("DeterministicTestCredentialVerifier")
      ) {
        violations.push(relative(ROOT, path));
      }
    }
  }

  assert.deepEqual(
    violations,
    [],
    "the deterministic HMAC credential verifier is test-only and must not be imported by runtime code",
  );
});
