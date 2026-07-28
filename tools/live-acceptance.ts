import assert from "node:assert/strict";
import { spawn, type ChildProcess } from "node:child_process";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const childPath = fileURLToPath(
  new URL("./acceptance-server-child.ts", import.meta.url),
);
const backupCreatePath = fileURLToPath(
  new URL("./backup-create.ts", import.meta.url),
);
const backupRestorePath = fileURLToPath(
  new URL("./backup-restore.ts", import.meta.url),
);

interface ServerHandle {
  child: ChildProcess;
  baseUrl: string;
  close(): Promise<void>;
}

interface CommandOutput {
  stdout: string;
  stderr: string;
}

export interface AcceptanceReport {
  passed: true;
  isolatedRoot: true;
  restartPersistence: {
    passed: true;
    challengeId: string;
  };
  rateLimit: {
    passed: true;
    status: 429;
    retryAfter: string;
    stateUnchanged: true;
  };
  sseLimit: {
    passed: true;
    acceptedBeforeLimit: 4;
    rejectedStatus: 429;
    reopenedAfterDisconnect: true;
  };
  backupRestore: {
    passed: true;
    verifyOnly: true;
    materializedRestore: true;
    restoredStateVerified: true;
  };
  auditTamper: {
    passed: true;
    blocked: true;
    authoritativeAuditValid: true;
  };
}

function wait(ms: number) {
  return new Promise((resolvePromise) => setTimeout(resolvePromise, ms));
}

async function startServer(
  options: {
    dbPath?: string;
    rateLimit?: { capacity: number; refillPerSecond: number; maxClients: number } | false;
  },
  children: Set<ChildProcess>,
): Promise<ServerHandle> {
  const encoded = Buffer.from(JSON.stringify(options)).toString("base64url");
  const child = spawn(
    process.execPath,
    ["--experimental-strip-types", childPath, encoded],
    { stdio: ["ignore", "pipe", "pipe", "ipc"], windowsHide: true },
  );
  children.add(child);
  let output = "";
  child.stdout?.on("data", (chunk) => { output += chunk.toString(); });
  child.stderr?.on("data", (chunk) => { output += chunk.toString(); });
  const port = await new Promise<number>((resolvePromise, reject) => {
    const timeout = setTimeout(
      () => reject(new Error(`acceptance server startup timed out: ${output}`)),
      10_000,
    );
    child.once("error", reject);
    child.once("exit", (code) => {
      clearTimeout(timeout);
      reject(new Error(`acceptance server exited during startup (${code}): ${output}`));
    });
    child.on("message", (message: { type?: string; port?: number; error?: string }) => {
      if (message.type === "error") {
        clearTimeout(timeout);
        reject(new Error(`acceptance server error: ${message.error}`));
      }
      if (message.type === "ready" && Number.isInteger(message.port)) {
        clearTimeout(timeout);
        resolvePromise(message.port!);
      }
    });
  });
  let closed = false;
  return {
    child,
    baseUrl: `http://127.0.0.1:${port}`,
    async close() {
      if (closed) return;
      closed = true;
      if (child.exitCode !== null) {
        children.delete(child);
        return;
      }
      child.send({ type: "close" });
      await new Promise<void>((resolvePromise) => {
        const timeout = setTimeout(() => {
          if (child.exitCode === null) child.kill();
        }, 5_000);
        timeout.unref?.();
        child.once("exit", () => {
          clearTimeout(timeout);
          resolvePromise();
        });
      });
      children.delete(child);
    },
  };
}

async function runCommand(script: string, args: string[]): Promise<CommandOutput> {
  return new Promise((resolvePromise, reject) => {
    const child = spawn(
      process.execPath,
      ["--experimental-strip-types", script, ...args],
      { stdio: ["ignore", "pipe", "pipe"], windowsHide: true },
    );
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (chunk) => { stdout += chunk.toString(); });
    child.stderr.on("data", (chunk) => { stderr += chunk.toString(); });
    child.once("error", reject);
    child.once("exit", (code) => {
      if (code === 0) resolvePromise({ stdout, stderr });
      else reject(new Error(
        `${script} exited ${code}: ${(stderr || stdout).slice(-4_000)}`,
      ));
    });
  });
}

async function jsonPost(
  baseUrl: string,
  path: string,
  idempotencyKey?: string,
  body?: unknown,
) {
  const response = await fetch(`${baseUrl}${path}`, {
    method: "POST",
    headers: {
      ...(idempotencyKey ? { "idempotency-key": idempotencyKey } : {}),
      ...(body === undefined ? {} : { "content-type": "application/json" }),
    },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
  return { response, body: await response.json() as Record<string, any> };
}

async function state(baseUrl: string) {
  const response = await fetch(`${baseUrl}/api/state`);
  assert.equal(response.status, 200);
  return response.json() as Promise<Record<string, any>>;
}

async function openSse(baseUrl: string) {
  const controller = new AbortController();
  const response = await fetch(`${baseUrl}/api/events`, {
    signal: controller.signal,
  });
  return {
    response,
    async close() {
      controller.abort();
      try {
        await response.body?.cancel();
      } catch {
        // Abort races with stream cancellation; both close the same socket.
      }
    },
  };
}

export async function runLiveAcceptance(): Promise<AcceptanceReport> {
  const directory = await mkdtemp(join(tmpdir(), "airlock-live-acceptance-"));
  const children = new Set<ChildProcess>();
  const dbPath = join(directory, "source", "lab.sqlite");
  let server: ServerHandle | undefined;
  const streams: Awaited<ReturnType<typeof openSse>>[] = [];
  try {
    server = await startServer({ dbPath, rateLimit: false }, children);
    const provisioned = await jsonPost(
      server.baseUrl,
      "/api/provision/request",
      "acceptance-provision",
    );
    assert.equal(provisioned.response.status, 200);
    const challengeId = provisioned.body.provisioning.challenge.challengeId as string;
    await server.close();

    server = await startServer({ dbPath, rateLimit: false }, children);
    const restarted = await state(server.baseUrl);
    assert.equal(restarted.provisioning.challenge.challengeId, challengeId);
    assert.equal(restarted.token.state, "pending");
    await server.close();

    server = await startServer({
      rateLimit: { capacity: 1, refillPerSecond: 0.1, maxClients: 16 },
    }, children);
    const allowed = await jsonPost(server.baseUrl, "/api/reset");
    assert.equal(allowed.response.status, 200);
    const beforeLimited = await state(server.baseUrl);
    const limited = await jsonPost(server.baseUrl, "/api/provision/request");
    assert.equal(limited.response.status, 429);
    const retryAfter = limited.response.headers.get("retry-after");
    assert.ok(retryAfter && Number(retryAfter) >= 1);
    assert.equal(limited.body.code, "RATE_LIMITED");
    assert.deepEqual(await state(server.baseUrl), beforeLimited);
    await server.close();

    server = await startServer({ rateLimit: false }, children);
    for (let index = 0; index < 4; index += 1) {
      const stream = await openSse(server.baseUrl);
      assert.equal(stream.response.status, 200);
      streams.push(stream);
    }
    const fifth = await openSse(server.baseUrl);
    assert.equal(fifth.response.status, 429);
    assert.ok(fifth.response.headers.get("retry-after"));
    await fifth.close();
    await streams.shift()!.close();
    let reopened: Awaited<ReturnType<typeof openSse>> | undefined;
    for (let attempt = 0; attempt < 20; attempt += 1) {
      await wait(25);
      const candidate = await openSse(server.baseUrl);
      if (candidate.response.status === 200) {
        reopened = candidate;
        streams.push(candidate);
        break;
      }
      await candidate.close();
    }
    assert.ok(reopened, "SSE slot did not free after disconnect");
    await Promise.all(streams.splice(0).map((stream) => stream.close()));
    await server.close();

    const backup = JSON.parse((await runCommand(backupCreatePath, [
      "--db", dbPath,
      "--out", join(directory, "backups"),
      "--label", "acceptance",
    ])).stdout) as { ok: boolean; sqlitePath: string };
    assert.equal(backup.ok, true);
    const verified = JSON.parse((await runCommand(backupRestorePath, [
      "--backup", backup.sqlitePath,
      "--verify-only",
    ])).stdout) as { ok: boolean; restoredPath?: string };
    assert.equal(verified.ok, true);
    assert.equal(verified.restoredPath, undefined);
    const restoredDb = join(directory, "restored", "lab.sqlite");
    const materialized = JSON.parse((await runCommand(backupRestorePath, [
      "--backup", backup.sqlitePath,
      "--into", restoredDb,
    ])).stdout) as { ok: boolean; restoredPath?: string };
    assert.equal(materialized.ok, true);
    assert.equal(resolve(materialized.restoredPath!), resolve(restoredDb));

    server = await startServer({ dbPath: restoredDb, rateLimit: false }, children);
    const restoredState = await state(server.baseUrl);
    assert.equal(restoredState.provisioning.challenge.challengeId, challengeId);
    const tamper = await jsonPost(
      server.baseUrl,
      "/api/demonstrate/audit-tamper",
      "acceptance-audit-tamper",
    );
    assert.equal(tamper.response.status, 200);
    assert.equal(tamper.body.demonstration.blocked, true);
    assert.equal(tamper.body.demonstration.auditCopyValid, false);
    assert.equal(tamper.body.audit.valid, true);
    await server.close();

    return {
      passed: true,
      isolatedRoot: true,
      restartPersistence: { passed: true, challengeId },
      rateLimit: {
        passed: true,
        status: 429,
        retryAfter,
        stateUnchanged: true,
      },
      sseLimit: {
        passed: true,
        acceptedBeforeLimit: 4,
        rejectedStatus: 429,
        reopenedAfterDisconnect: true,
      },
      backupRestore: {
        passed: true,
        verifyOnly: true,
        materializedRestore: true,
        restoredStateVerified: true,
      },
      auditTamper: {
        passed: true,
        blocked: true,
        authoritativeAuditValid: true,
      },
    };
  } finally {
    await Promise.allSettled(streams.splice(0).map((stream) => stream.close()));
    await server?.close().catch(() => {});
    for (const child of children) {
      if (child.exitCode === null) child.kill();
    }
    await rm(directory, { recursive: true, force: true });
  }
}

if (
  process.argv[1] &&
  import.meta.url === pathToFileURL(resolve(process.argv[1])).href
) {
  runLiveAcceptance().then(
    (report) => process.stdout.write(`${JSON.stringify(report, null, 2)}\n`),
    (error) => {
      process.stderr.write(
        `acceptance failed: ${error instanceof Error ? error.stack : String(error)}\n`,
      );
      process.exitCode = 1;
    },
  );
}
