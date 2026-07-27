import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import test from "node:test";
import { join } from "node:path";
import { tmpdir } from "node:os";
import {
  generateReleaseEvidence,
  resolveCommandInvocation,
  type CommandRunner,
} from "../tools/release-evidence.ts";

const COMMIT = "a".repeat(40);
const TAP = [
  "ℹ tests 71",
  "ℹ pass 71",
  "ℹ fail 0",
  "ℹ cancelled 0",
  "ℹ skipped 0",
  "ℹ todo 0",
  "",
].join("\n");
const SCENARIOS = `npm output
{
  "passed": true,
  "results": [
    {"scenario":"synthetic one","passed":true},
    {"scenario":"synthetic two","passed":true}
  ]
}
`;

function fixtureRunner(status = "") {
  const calls: string[] = [];
  const runner: CommandRunner = (command, args) => {
    calls.push(`${command} ${args.join(" ")}`);
    const key = `${command} ${args.join(" ")}`;
    if (key === "git rev-parse HEAD") return { status: 0, stdout: COMMIT, stderr: "" };
    if (key.startsWith("git status --porcelain")) {
      return { status: 0, stdout: status, stderr: "" };
    }
    if (key.startsWith("git show -s")) {
      return { status: 0, stdout: "2026-07-27T12:00:00-05:00", stderr: "" };
    }
    if (key === "npm run typecheck") return { status: 0, stdout: "", stderr: "" };
    if (key === "npm test") return { status: 0, stdout: TAP, stderr: "" };
    if (key === "npm run scenarios") {
      return { status: 0, stdout: SCENARIOS, stderr: "" };
    }
    if (key === "python --version") {
      return { status: 0, stdout: "Python 3.12.10", stderr: "" };
    }
    throw new Error(`unexpected command: ${key}`);
  };
  return { runner, calls };
}

function withFixture(fn: (directory: string) => void) {
  const directory = mkdtempSync(join(tmpdir(), "airlock-evidence-"));
  try {
    writeFileSync(join(directory, "package-lock.json"), "{\"lockfileVersion\":3}\n");
    fn(directory);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
}

test("release evidence is bounded, deterministic, and labels simulation honestly", () => {
  withFixture((directory) => {
    const first = fixtureRunner();
    const bundle = generateReleaseEvidence({
      repoRoot: directory,
      expectedCommit: COMMIT,
      runner: first.runner,
      outputPath: "evidence/release.json",
    });
    const serialized = readFileSync(join(directory, "evidence/release.json"), "utf8");
    assert.ok(Buffer.byteLength(serialized) < 256 * 1024);
    assert.equal(bundle.source.commit, COMMIT);
    assert.equal(bundle.source.cleanWorktree, true);
    assert.deepEqual(bundle.verification.tests, {
      tests: 71,
      pass: 71,
      fail: 0,
      cancelled: 0,
      skipped: 0,
      todo: 0,
    });
    assert.equal(bundle.verification.scenarios.count, 2);
    assert.equal(bundle.provenance.signed, false);
    assert.match(bundle.provenance.statement, /not signed provenance/);
    assert.ok(bundle.boundary.simulated.includes("issuer and risk decisioning"));
    assert.equal(
      bundle.source.lockfileSha256,
      createHash("sha256")
        .update("{\"lockfileVersion\":3}\n")
        .digest("hex"),
    );

    const second = fixtureRunner();
    const repeated = generateReleaseEvidence({
      repoRoot: directory,
      expectedCommit: COMMIT,
      runner: second.runner,
    });
    assert.deepEqual(repeated, bundle);
    assert.equal(
      first.calls.filter((call) => call === "npm test").length,
      1,
      "generator test uses an injected runner; it must not recursively spawn npm test",
    );
  });
});
test("release evidence refuses dirty trees and mismatched commits", () => {
  withFixture((directory) => {
    assert.throws(
      () => generateReleaseEvidence({
        repoRoot: directory,
        runner: fixtureRunner(" M changed.ts").runner,
      }),
      /clean Git worktree/,
    );
    assert.throws(
      () => generateReleaseEvidence({
        repoRoot: directory,
        expectedCommit: "b".repeat(40),
        runner: fixtureRunner().runner,
      }),
      /commit mismatch/,
    );
  });
});

test("Windows npm commands bypass cmd wrappers without changing arguments", () => {
  withFixture((directory) => {
    const npmCli = join(directory, "npm-cli.js");
    writeFileSync(npmCli, "// synthetic npm CLI entry point\n");
    const args = [
      "run",
      "typecheck",
      "--",
      "--literal=a&b",
      "space preserved",
      "\"quoted\"",
    ];

    const invocation = resolveCommandInvocation(
      "npm",
      args,
      "win32",
      npmCli,
    );

    assert.equal(invocation.executable, process.execPath);
    assert.deepEqual(invocation.args, [npmCli, ...args]);
    assert.notEqual(invocation.executable.toLowerCase(), "npm.cmd");
    assert.deepEqual(args, [
      "run",
      "typecheck",
      "--",
      "--literal=a&b",
      "space preserved",
      "\"quoted\"",
    ], "resolver must not mutate or shell-quote caller arguments");
  });
});
