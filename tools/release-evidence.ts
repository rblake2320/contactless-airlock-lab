import { createHash } from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";

const SCHEMA_VERSION = "airlock.release-evidence.v1";
const MAX_BUNDLE_BYTES = 256 * 1024;

export interface CommandResult {
  status: number;
  stdout: string;
  stderr: string;
}
export type CommandRunner = (
  command: string,
  args: readonly string[],
  cwd: string,
) => CommandResult;

export interface GenerateEvidenceOptions {
  repoRoot: string;
  outputPath?: string;
  expectedCommit?: string;
  allowDirty?: boolean;
  runner?: CommandRunner;
}

function sha256(value: string | Buffer): string {
  return createHash("sha256").update(value).digest("hex");
}

function defaultRunner(
  command: string,
  args: readonly string[],
  cwd: string,
): CommandResult {
  const executable = process.platform === "win32" && command === "npm"
    ? "npm.cmd"
    : command;
  const result = spawnSync(executable, [...args], {
    cwd,
    encoding: "utf8",
    windowsHide: true,
    maxBuffer: 2 * 1024 * 1024,
  });
  if (result.error) throw result.error;
  return {
    status: result.status ?? 1,
    stdout: (result.stdout ?? "").replaceAll("\r\n", "\n"),
    stderr: (result.stderr ?? "").replaceAll("\r\n", "\n"),
  };
}

function requireSuccess(
  runner: CommandRunner,
  cwd: string,
  command: string,
  args: readonly string[],
): string {
  const result = runner(command, args, cwd);
  if (result.status !== 0) {
    throw new Error(
      `${command} ${args.join(" ")} failed (${result.status}): ${result.stderr.slice(-2_000)}`,
    );
  }
  return result.stdout.trim();
}

function parseTapSummary(output: string) {
  const field = (name: string): number => {
    const match = new RegExp(`^ℹ ${name} (\\d+)$`, "m").exec(output);
    if (!match) throw new Error(`test output is missing ${name} summary`);
    return Number(match[1]);
  };
  return {
    tests: field("tests"),
    pass: field("pass"),
    fail: field("fail"),
    cancelled: field("cancelled"),
    skipped: field("skipped"),
    todo: field("todo"),
  };
}

function parseScenarioSummary(output: string) {
  const start = output.indexOf("{\n  \"passed\"");
  if (start < 0) throw new Error("scenario output is missing JSON result");
  const parsed = JSON.parse(output.slice(start)) as {
    passed: boolean;
    results: Array<{ scenario: string; passed: boolean }>;
  };
  if (
    typeof parsed.passed !== "boolean" ||
    !Array.isArray(parsed.results) ||
    parsed.results.some(
      (result) =>
        typeof result.scenario !== "string" || typeof result.passed !== "boolean",
    )
  ) {
    throw new Error("scenario output shape is invalid");
  }
  return {
    passed: parsed.passed,
    count: parsed.results.length,
    results: parsed.results.map(({ scenario, passed }) => ({ scenario, passed })),
  };
}

function pythonVersion(runner: CommandRunner, cwd: string): string {
  for (const command of ["python", "python3"]) {
    const result = runner(command, ["--version"], cwd);
    if (result.status === 0) {
      return `${result.stdout}\n${result.stderr}`.trim();
    }
  }
  return "unavailable";
}

export function generateReleaseEvidence(options: GenerateEvidenceOptions) {
  const repoRoot = resolve(options.repoRoot);
  const runner = options.runner ?? defaultRunner;
  const commit = requireSuccess(runner, repoRoot, "git", ["rev-parse", "HEAD"]);
  if (options.expectedCommit && commit !== options.expectedCommit) {
    throw new Error(
      `commit mismatch: expected ${options.expectedCommit}, checked out ${commit}`,
    );
  }
  const initialStatus = requireSuccess(
    runner,
    repoRoot,
    "git",
    ["status", "--porcelain", "--untracked-files=all"],
  );
  if (initialStatus && !options.allowDirty) {
    throw new Error("release evidence requires a clean Git worktree");
  }

  const lockfile = readFileSync(resolve(repoRoot, "package-lock.json"));
  const commitTimestamp = requireSuccess(
    runner,
    repoRoot,
    "git",
    ["show", "-s", "--format=%cI", commit],
  );
  const typecheck = runner("npm", ["run", "typecheck"], repoRoot);
  if (typecheck.status !== 0) throw new Error("typecheck failed");
  const tests = runner("npm", ["test"], repoRoot);
  if (tests.status !== 0) throw new Error("test suite failed");
  const scenarios = runner("npm", ["run", "scenarios"], repoRoot);
  if (scenarios.status !== 0) throw new Error("scenario suite failed");

  const finalStatus = requireSuccess(
    runner,
    repoRoot,
    "git",
    ["status", "--porcelain", "--untracked-files=all"],
  );
  if (finalStatus !== initialStatus) {
    throw new Error("quality commands changed the Git worktree");
  }

  const body = {
    schemaVersion: SCHEMA_VERSION,
    source: {
      commit,
      commitTimestamp,
      expectedCommit: options.expectedCommit ?? null,
      cleanWorktree: initialStatus.length === 0,
      lockfile: "package-lock.json",
      lockfileSha256: sha256(lockfile),
    },
    environment: {
      node: process.version,
      python: pythonVersion(runner, repoRoot),
    },
    verification: {
      typecheck: { passed: true },
      tests: parseTapSummary(tests.stdout),
      scenarios: parseScenarioSummary(scenarios.stdout),
    },
    boundary: {
      realLocalEvidence: [
        "TypeScript typecheck and Node test execution",
        "local protocol cryptography and state-machine behavior",
        "single-host SQLite durability and separate-process race tests",
      ],
      simulated: [
        "issuer and risk decisioning",
        "wallet and token-service-provider integration",
        "processor, network, clearing, and settlement integration",
        "exportable synthetic device keys",
      ],
      notConnected: [
        "real cardholder data or payment credentials",
        "production issuer, processor, wallet, network, merchant, or payment rail",
      ],
    },
    provenance: {
      signed: false,
      attested: false,
      statement:
        "This JSON is reproducible release evidence, not signed provenance or an artifact attestation.",
    },
  };
  const canonicalBody = `${JSON.stringify(body, null, 2)}\n`;
  const bundle = {
    ...body,
    evidenceSha256: sha256(canonicalBody),
  };
  const serialized = `${JSON.stringify(bundle, null, 2)}\n`;
  if (Buffer.byteLength(serialized) > MAX_BUNDLE_BYTES) {
    throw new Error(`release evidence exceeds ${MAX_BUNDLE_BYTES} bytes`);
  }
  if (options.outputPath) {
    const outputPath = resolve(repoRoot, options.outputPath);
    mkdirSync(dirname(outputPath), { recursive: true });
    writeFileSync(outputPath, serialized, { encoding: "utf8", flag: "wx" });
  }
  return bundle;
}

function parseArguments(args: readonly string[]) {
  const options: Omit<GenerateEvidenceOptions, "repoRoot"> = {};
  for (let index = 0; index < args.length; index += 1) {
    const argument = args[index];
    if (argument === "--output") options.outputPath = args[++index];
    else if (argument === "--expected-commit") options.expectedCommit = args[++index];
    else if (argument === "--allow-dirty") options.allowDirty = true;
    else throw new Error(`unknown argument: ${argument}`);
  }
  return options;
}

if (
  process.argv[1] &&
  import.meta.url === pathToFileURL(resolve(process.argv[1])).href
) {
  const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
  const bundle = generateReleaseEvidence({
    repoRoot,
    ...parseArguments(process.argv.slice(2)),
  });
  if (!process.argv.includes("--output")) {
    process.stdout.write(`${JSON.stringify(bundle, null, 2)}\n`);
  }
}
