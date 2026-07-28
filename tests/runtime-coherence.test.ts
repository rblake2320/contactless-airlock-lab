import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import type { Server } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import {
  createLabServer,
  parseBuildId,
} from "../apps/realtime-lab/server.ts";

async function listen(server: Server): Promise<string> {
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  assert.ok(address && typeof address !== "string");
  return `http://127.0.0.1:${address.port}`;
}

async function close(server: Server): Promise<void> {
  await new Promise<void>((resolve, reject) =>
    server.close((error) => error ? reject(error) : resolve()),
  );
}

function digest(assets: ReadonlyMap<string, Buffer>): string {
  const hash = createHash("sha256");
  for (const name of ["index.html", "app.js", "styles.css"]) {
    const bytes = assets.get(name)!;
    hash.update(name).update("\0").update(String(bytes.length)).update("\0").update(bytes);
  }
  return hash.digest("hex");
}

test("server snapshots one coherent static build and exposes its bounded identity", async () => {
  const directory = await mkdtemp(join(tmpdir(), "airlock-assets-"));
  const initial = new Map([
    ["index.html", Buffer.from("<p>build-one</p>")],
    ["app.js", Buffer.from("globalThis.build='one';")],
    ["styles.css", Buffer.from("body{color:blue}")],
  ]);
  for (const [name, bytes] of initial) {
    await writeFile(join(directory, name), bytes);
  }

  const server = createLabServer({
    buildId: "release-2026.07.28",
    staticAssetDirectory: directory,
  });
  const baseUrl = await listen(server);
  try {
    const before = await fetch(`${baseUrl}/app.js`);
    assert.equal(await before.text(), initial.get("app.js")!.toString());

    // Simulate a deployment replacing only one file while this process lives.
    await writeFile(join(directory, "app.js"), "globalThis.build='two';");

    const after = await fetch(`${baseUrl}/app.js`);
    assert.equal(
      await after.text(),
      initial.get("app.js")!.toString(),
      "a running process must never mix fresh disk bytes into its startup snapshot",
    );
    const health = await (await fetch(`${baseUrl}/api/health`)).json() as {
      ok: boolean;
      simulator: boolean;
      buildId: string;
      staticAssetDigest: string;
      service: {
        schemaVersion: string;
        readiness: { ready: boolean };
      };
    };
    assert.deepEqual({
      ok: health.ok,
      simulator: health.simulator,
      buildId: health.buildId,
      staticAssetDigest: health.staticAssetDigest,
    }, {
      ok: true,
      simulator: true,
      buildId: "release-2026.07.28",
      staticAssetDigest: digest(initial),
    });
    assert.equal(health.service.schemaVersion, "airlock.service-metrics.v1");
    assert.equal(
      health.service.readiness.ready,
      false,
      "absent external dependencies must not be reported ready",
    );
  } finally {
    await close(server);
    await rm(directory, { recursive: true, force: true });
  }
});

test("build identity has a safe default and rejects unbounded or secret-shaped input", () => {
  assert.equal(parseBuildId(undefined), "development-unversioned");
  assert.equal(parseBuildId("  release_42  "), "release_42");
  for (const value of ["contains space", "../escape", "x".repeat(65), "token:value"]) {
    assert.throws(() => parseBuildId(value), /AIRLOCK_BUILD_ID/);
  }
});
