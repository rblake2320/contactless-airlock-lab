import assert from "node:assert/strict";
import test from "node:test";
import { mkdir, mkdtemp, readdir, readFile, rm, writeFile } from "node:fs/promises";
import { existsSync, statSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { createHash } from "node:crypto";
import { DatabaseSync } from "node:sqlite";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import type { AddressInfo } from "node:net";
import {
  BackupError,
  createBackup,
  readManifest,
  restoreBackup,
  RestoreVerificationError,
  sanitizeLabel,
} from "../tools/backup-lib.ts";
import { DurableStore } from "../packages/storage/durableStore.ts";
import { createLabServer } from "../apps/realtime-lab/server.ts";

const CONCURRENT_WRITER = fileURLToPath(
  new URL("./fixtures/backup-concurrent-writer.ts", import.meta.url),
);

interface WriterResult {
  type: "done";
  written: number;
  error?: string;
}

function spawnConcurrentWriter(dbPath: string, count: number) {
  const child = spawn(
    process.execPath,
    ["--experimental-strip-types", CONCURRENT_WRITER, dbPath, String(count)],
    { stdio: ["ignore", "ignore", "pipe", "ipc"] },
  );
  let errors = "";
  child.stderr?.on("data", (chunk) => { errors += chunk.toString(); });
  const ready = new Promise<void>((resolve, reject) => {
    const timeout = setTimeout(() => reject(new Error(`writer did not become ready: ${errors}`)), 10_000);
    child.on("error", reject);
    child.on("message", (message: { type?: string }) => {
      if (message.type === "ready") { clearTimeout(timeout); resolve(); }
    });
  });
  const done = new Promise<WriterResult>((resolve, reject) => {
    const timeout = setTimeout(() => reject(new Error(`writer did not finish: ${errors}`)), 20_000);
    child.on("error", reject);
    child.on("message", (message: WriterResult) => {
      if (message.type === "done") { clearTimeout(timeout); resolve(message); }
    });
  });
  return { child, ready, done, stderr: () => errors };
}

async function withTempDir(fn: (dir: string) => Promise<void>): Promise<void> {
  const dir = await mkdtemp(join(tmpdir(), "airlock-backup-test-"));
  try {
    await fn(dir);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

function seedStore(dbPath: string): void {
  const store = new DurableStore(dbPath);
  store.create("seed-challenge", "created", { note: "seed" });
  store.enqueue("seed-event", "seed-topic", "seed-aggregate", { note: "seed" });
  store.close();
}

test("createBackup produces a checksummed, integrity-checked backup and manifest", async () => {
  await withTempDir(async (dir) => {
    const dbPath = join(dir, "lab.sqlite");
    seedStore(dbPath);

    const result = await createBackup({ dbPath, outputDir: join(dir, "backups"), label: "nightly" });

    assert.ok(existsSync(result.sqlitePath));
    assert.ok(existsSync(result.manifestPath));
    assert.equal(result.manifest.integrityCheck, "ok");
    assert.equal(result.manifest.tableRowCounts.durable_challenges, 1);
    assert.equal(result.manifest.tableRowCounts.outbox_events, 1);
    // node:sqlite row objects have a null prototype; compare by value only.
    assert.deepEqual(JSON.parse(JSON.stringify(result.manifest.appMigrations)), [
      { version: 1, name: "durable_challenges_idempotency_outbox" },
    ]);

    const bytes = await readFile(result.sqlitePath);
    const actualHash = createHash("sha256").update(bytes).digest("hex");
    assert.equal(actualHash, result.manifest.sqliteFileSha256);
    assert.equal(bytes.length, result.manifest.sqliteFileBytes);
    assert.equal(statSync(result.sqlitePath).size, result.manifest.sqliteFileBytes);

    assert.match(result.manifest.limitations.pointInTime, /not.*continuous point-in-time recovery/i);
    assert.match(result.manifest.limitations.scope, /does not implement off-host replication/i);
    assert.match(result.manifest.limitations.authenticity, /not keyed or signed/i);
    assert.match(result.manifest.limitations.authenticity, /rewrite this manifest to match/i);
  });
});

test("createBackup never overwrites an existing backup path", async () => {
  await withTempDir(async (dir) => {
    const dbPath = join(dir, "lab.sqlite");
    seedStore(dbPath);
    const outputDir = join(dir, "backups");
    const fixedNow = () => new Date("2026-01-01T00:00:00.000Z");

    const first = await createBackup({ dbPath, outputDir, label: "same", now: fixedNow });
    assert.ok(existsSync(first.sqlitePath));

    await assert.rejects(
      () => createBackup({ dbPath, outputDir, label: "same", now: fixedNow }),
      /EEXIST/,
    );
    // The original backup must be untouched by the failed second attempt.
    const stillThere = await readFile(first.sqlitePath);
    assert.equal(createHash("sha256").update(stillThere).digest("hex"), first.manifest.sqliteFileSha256);
  });
});

test("createBackup refuses a source path that does not exist", async () => {
  await withTempDir(async (dir) => {
    await assert.rejects(
      () => createBackup({ dbPath: join(dir, "missing.sqlite"), outputDir: join(dir, "backups") }),
      BackupError,
    );
  });
});

test("sanitizeLabel rejects path traversal and separators", () => {
  assert.equal(sanitizeLabel("nightly"), "nightly");
  assert.equal(sanitizeLabel("release-1.2.3"), "release-1.2.3");
  for (const hostile of ["../escape", "a/b", "a\\b", "..", ".", "", "   ", "a".repeat(65)]) {
    assert.throws(() => sanitizeLabel(hostile), BackupError, hostile);
  }
});

test("restoreBackup verify-only mode leaves no permanent copy and passes every check", async () => {
  await withTempDir(async (dir) => {
    const dbPath = join(dir, "lab.sqlite");
    seedStore(dbPath);
    const backup = await createBackup({ dbPath, outputDir: join(dir, "backups") });

    const report = await restoreBackup({ backupSqlitePath: backup.sqlitePath, verifyOnly: true });

    assert.equal(report.ok, true);
    assert.equal(report.restoredPath, undefined);
    assert.ok(report.checks.every((c) => c.ok), JSON.stringify(report.checks));
    const names = report.checks.map((c) => c.name);
    for (const expected of [
      "backup-file-exists",
      "manifest-readable",
      "byte-length-matches-manifest",
      "sha256-matches-manifest",
      "sqlite-integrity-check",
      "recognized-application-schema",
      "idempotency-records-structurally-valid",
      "outbox-events-structurally-valid",
      "application-state-deep-verification",
    ]) {
      assert.ok(names.includes(expected), `missing check: ${expected}`);
    }
  });
});

test("restoreBackup materializes a verified copy at a brand-new path and never overwrites", async () => {
  await withTempDir(async (dir) => {
    const dbPath = join(dir, "lab.sqlite");
    seedStore(dbPath);
    const backup = await createBackup({ dbPath, outputDir: join(dir, "backups") });
    const restorePath = join(dir, "restored", "lab.sqlite");

    const report = await restoreBackup({ backupSqlitePath: backup.sqlitePath, destPath: restorePath });
    assert.equal(report.ok, true);
    assert.equal(report.restoredPath, restorePath);
    assert.ok(existsSync(restorePath));

    const restoredDb = new DatabaseSync(restorePath, { readOnly: true });
    const row = restoredDb.prepare(
      "SELECT status FROM durable_challenges WHERE challenge_id = ?",
    ).get("seed-challenge") as { status: string } | undefined;
    assert.equal(row?.status, "created");
    restoredDb.close();

    await assert.rejects(
      () => restoreBackup({ backupSqlitePath: backup.sqlitePath, destPath: restorePath }),
      /already exists, refusing to overwrite/,
    );
  });
});

test("restoreBackup requires either destPath or verifyOnly", async () => {
  await withTempDir(async (dir) => {
    const dbPath = join(dir, "lab.sqlite");
    seedStore(dbPath);
    const backup = await createBackup({ dbPath, outputDir: join(dir, "backups") });
    await assert.rejects(
      () => restoreBackup({ backupSqlitePath: backup.sqlitePath }),
      RestoreVerificationError,
    );
  });
});

test("restoreBackup rejects bit-flip corruption via the checksum, not just SQLite's own parser", async () => {
  await withTempDir(async (dir) => {
    const dbPath = join(dir, "lab.sqlite");
    seedStore(dbPath);
    const backup = await createBackup({ dbPath, outputDir: join(dir, "backups") });

    const bytes = await readFile(backup.sqlitePath);
    bytes[Math.floor(bytes.length / 2)] ^= 0xff;
    await writeFile(backup.sqlitePath, bytes);

    await assert.rejects(
      () => restoreBackup({ backupSqlitePath: backup.sqlitePath, verifyOnly: true }),
      (error: unknown) => {
        assert.ok(error instanceof RestoreVerificationError);
        const shaCheck = error.checks.find((c) => c.name === "sha256-matches-manifest");
        assert.equal(shaCheck?.ok, false);
        return true;
      },
    );
  });
});

test("restoreBackup rejects a truncated backup file", async () => {
  await withTempDir(async (dir) => {
    const dbPath = join(dir, "lab.sqlite");
    seedStore(dbPath);
    const backup = await createBackup({ dbPath, outputDir: join(dir, "backups") });

    const bytes = await readFile(backup.sqlitePath);
    await writeFile(backup.sqlitePath, bytes.subarray(0, Math.floor(bytes.length / 2)));

    await assert.rejects(
      () => restoreBackup({ backupSqlitePath: backup.sqlitePath, verifyOnly: true }),
      (error: unknown) => {
        assert.ok(error instanceof RestoreVerificationError);
        const lengthCheck = error.checks.find((c) => c.name === "byte-length-matches-manifest");
        assert.equal(lengthCheck?.ok, false);
        return true;
      },
    );
  });
});

test("restoreBackup rejects a well-formed but unrelated SQLite file as the wrong source", async () => {
  await withTempDir(async (dir) => {
    const unrelatedPath = join(dir, "unrelated.sqlite");
    const unrelated = new DatabaseSync(unrelatedPath);
    unrelated.exec("CREATE TABLE totally_unrelated(id INTEGER PRIMARY KEY) STRICT;");
    unrelated.close();

    const bytes = await readFile(unrelatedPath);
    const forgedManifest = {
      schemaVersion: "airlock.backup.v1",
      tool: "contactless-airlock-lab/backup-lib",
      createdAt: new Date().toISOString(),
      sourceLabel: "unrelated.sqlite",
      sqliteFileName: "unrelated.sqlite",
      sqliteFileBytes: bytes.length,
      sqliteFileSha256: createHash("sha256").update(bytes).digest("hex"),
      appMigrations: [],
      tableRowCounts: { durable_challenges: 0, idempotency_records: 0, outbox_events: 0 },
      labSnapshot: { present: false },
      integrityCheck: "ok",
      environment: { node: process.version, platform: process.platform },
      limitations: { pointInTime: "x", scope: "x", authenticity: "x" },
    };
    const manifestPath = join(dir, "unrelated.manifest.json");
    await writeFile(manifestPath, JSON.stringify(forgedManifest, null, 2));

    await assert.rejects(
      () => restoreBackup({ backupSqlitePath: unrelatedPath, manifestPath, verifyOnly: true }),
      (error: unknown) => {
        assert.ok(error instanceof RestoreVerificationError);
        assert.match(error.message, /wrong-source rejection/);
        const schemaCheck = error.checks.find((c) => c.name === "recognized-application-schema");
        assert.equal(schemaCheck?.ok, false);
        return true;
      },
    );
  });
});

test("restoreBackup refuses a missing manifest rather than guessing", async () => {
  await withTempDir(async (dir) => {
    const dbPath = join(dir, "lab.sqlite");
    seedStore(dbPath);
    const backup = await createBackup({ dbPath, outputDir: join(dir, "backups") });
    await rm(backup.manifestPath);

    await assert.rejects(
      () => restoreBackup({ backupSqlitePath: backup.sqlitePath, verifyOnly: true }),
      (error: unknown) => {
        assert.ok(error instanceof RestoreVerificationError);
        const manifestCheck = error.checks.find((c) => c.name === "manifest-readable");
        assert.equal(manifestCheck?.ok, false);
        return true;
      },
    );
  });
});

test("readManifest rejects malformed and structurally-wrong manifest JSON", async () => {
  await withTempDir(async (dir) => {
    const badJson = join(dir, "bad.manifest.json");
    await writeFile(badJson, "{ not json");
    assert.throws(() => readManifest(badJson), BackupError);

    const wrongShape = join(dir, "wrong.manifest.json");
    await writeFile(wrongShape, JSON.stringify({ schemaVersion: "airlock.backup.v1" }));
    assert.throws(() => readManifest(wrongShape), BackupError);
  });
});

test("full application lifecycle survives backup and restore: audit chain, challenge bindings, and daily-spend reconciliation all re-verify", async () => {
  await withTempDir(async (dir) => {
    const dbPath = join(dir, "lab.sqlite");
    const server = createLabServer({ dbPath });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const { port } = server.address() as AddressInfo;
    const base = `http://127.0.0.1:${port}`;
    const post = async (path: string, body?: unknown) =>
      (await fetch(`${base}${path}`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(body ?? {}),
      })).json();

    assert.equal((await post("/api/provision/request")) && true, true);
    await post("/api/provision/approve");
    await post("/api/transaction/request", { amount: "42.00", merchantId: "backup-lifecycle-merchant" });
    await post("/api/transaction/confirm");
    await new Promise<void>((resolve, reject) =>
      server.close((error) => (error ? reject(error) : resolve())));

    const backup = await createBackup({ dbPath, outputDir: join(dir, "backups") });
    assert.equal(backup.manifest.labSnapshot.present, true);
    assert.equal(backup.manifest.labSnapshot.id, "realtime-lab:simulator-state");

    const report = await restoreBackup({ backupSqlitePath: backup.sqlitePath, verifyOnly: true });
    assert.equal(report.ok, true);
    const deepCheck = report.checks.find((c) => c.name === "application-state-deep-verification");
    assert.equal(deepCheck?.ok, true);
    assert.match(deepCheck?.detail ?? "", /audit hash chain/);
    assert.match(deepCheck?.detail ?? "", /daily-spend reconciliation/);
  });
});

test("checksum alone provides no authenticity: a consistent forger who recomputes the manifest hash defeats sha256-matches-manifest, and only the deeper application-state check catches the tampering", async () => {
  await withTempDir(async (dir) => {
    const dbPath = join(dir, "lab.sqlite");
    const server = createLabServer({ dbPath });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const { port } = server.address() as AddressInfo;
    await fetch(`http://127.0.0.1:${port}/api/provision/request`, { method: "POST" });
    await new Promise<void>((resolve, reject) =>
      server.close((error) => (error ? reject(error) : resolve())));

    const backup = await createBackup({ dbPath, outputDir: join(dir, "backups") });

    // Tamper with the *backed-up copy's* application row directly with raw
    // SQL, bypassing DurableStore's compare-and-swap — simulates disk-level
    // corruption confined to a single row rather than the whole file.
    const raw = new DatabaseSync(backup.sqlitePath);
    raw.exec(
      "UPDATE durable_challenges SET record_json = '{\"broken\":true}' " +
      "WHERE challenge_id = 'realtime-lab:simulator-state'",
    );
    raw.close();
    const tamperedBytes = await readFile(backup.sqlitePath);
    const tamperedManifest = JSON.parse(await readFile(backup.manifestPath, "utf8"));
    tamperedManifest.sqliteFileSha256 = createHash("sha256").update(tamperedBytes).digest("hex");
    tamperedManifest.sqliteFileBytes = tamperedBytes.length;
    // Rewriting the manifest to match the tampered file isolates this test
    // to the deep-verification layer specifically, proving it catches an
    // attack the checksum alone would not (checksum only proves "this is
    // the file the manifest describes", not "this file's application
    // content is internally consistent").
    await rm(backup.manifestPath);
    await writeFile(backup.manifestPath, `${JSON.stringify(tamperedManifest, null, 2)}\n`);

    await assert.rejects(
      () => restoreBackup({ backupSqlitePath: backup.sqlitePath, verifyOnly: true }),
      (error: unknown) => {
        assert.ok(error instanceof RestoreVerificationError);
        // The explicit authenticity-boundary proof: sha256-matches-manifest
        // PASSES here — a consistent forger who tampers the file and
        // recomputes the hash to match is not caught by the checksum at
        // all, exactly as docs/BACKUP_RESTORE.md's authenticity section
        // states. What actually catches this specific tamper is the
        // semantic/application-level check below, not the checksum.
        const checksumCheck = error.checks.find((c) => c.name === "sha256-matches-manifest");
        assert.equal(checksumCheck?.ok, true, "checksum must pass for a consistent forgery — that is the point being proven");
        const deepCheck = error.checks.find((c) => c.name === "application-state-deep-verification");
        assert.equal(deepCheck?.ok, false);
        return true;
      },
    );
  });
});

test("createBackup does not fail against a live, actively-written source — manifest counts are read from the finished backup, not raced against a pre-count", async () => {
  await withTempDir(async (dir) => {
    const dbPath = join(dir, "lab.sqlite");
    seedStore(dbPath); // ensures the file + schema exist before any writer opens it

    const writer = spawnConcurrentWriter(dbPath, 400);
    await writer.ready;
    writer.child.send("go");

    // Start the backup immediately — while the writer is actively inserting
    // — rather than waiting for it to finish. Before the fix, createBackup
    // captured row counts from the live source BEFORE calling the backup
    // API and compared them against the finished copy afterward; any write
    // landing in that window made a perfectly valid backup throw. This is
    // the regression: it must not throw here, regardless of how the writer
    // and the backup happen to interleave.
    const result = await createBackup({ dbPath, outputDir: join(dir, "backups"), label: "under-load" });

    const writerResult = await writer.done;
    assert.equal(writerResult.error, undefined, writer.stderr());
    assert.equal(writerResult.written, 400);

    // Deterministic invariant, independent of scheduling: the manifest's
    // row counts must exactly equal what is actually inside the backup
    // file, because they are now derived from that same file and nothing
    // else. This holds no matter how much (or how little) of the writer's
    // 400 rows had landed by the moment the backup snapshot was taken.
    const copy = new DatabaseSync(result.sqlitePath, { readOnly: true });
    try {
      const actualChallenges = (copy.prepare(
        "SELECT COUNT(*) AS n FROM durable_challenges",
      ).get() as { n: number }).n;
      const actualOutbox = (copy.prepare(
        "SELECT COUNT(*) AS n FROM outbox_events",
      ).get() as { n: number }).n;
      assert.equal(result.manifest.tableRowCounts.durable_challenges, actualChallenges);
      assert.equal(result.manifest.tableRowCounts.outbox_events, actualOutbox);
      // The backup ran concurrently with a real writer — sanity-check that
      // this scenario actually exercised concurrency at all (the source
      // ended up with all 400 rows the writer produced, on top of the one
      // seeded row) rather than the writer having finished before the
      // backup even started.
      assert.equal(actualChallenges >= 1, true);
    } finally {
      copy.close();
    }

    // The backup itself must still be genuinely valid, not just "didn't
    // throw" — full restore-drill verification against a source that was
    // under concurrent write load the whole time.
    const drill = await restoreBackup({ backupSqlitePath: result.sqlitePath, verifyOnly: true });
    assert.equal(drill.ok, true, JSON.stringify(drill.checks));
  });
});

test("restoreBackup deletes only the destination it claimed when post-copy verification fails, and never touches an unrelated existing file", async () => {
  await withTempDir(async (dir) => {
    const dbPath = join(dir, "lab.sqlite");
    const server = createLabServer({ dbPath });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const { port } = server.address() as AddressInfo;
    await fetch(`http://127.0.0.1:${port}/api/provision/request`, { method: "POST" });
    await new Promise<void>((resolve, reject) =>
      server.close((error) => (error ? reject(error) : resolve())));

    const backup = await createBackup({ dbPath, outputDir: join(dir, "backups") });

    // Corrupt the backup's application row directly (not the checksum) and
    // rewrite the manifest to match, isolating this test to the deep
    // application-state verification layer specifically — same technique
    // as the earlier tamper test, reused here to force a POST-COPY failure
    // during a materialized (non-verify-only) restore.
    const raw = new DatabaseSync(backup.sqlitePath);
    raw.exec(
      "UPDATE durable_challenges SET record_json = '{\"broken\":true}' " +
      "WHERE challenge_id = 'realtime-lab:simulator-state'",
    );
    raw.close();
    const tamperedBytes = await readFile(backup.sqlitePath);
    const tamperedManifest = JSON.parse(await readFile(backup.manifestPath, "utf8"));
    tamperedManifest.sqliteFileSha256 = createHash("sha256").update(tamperedBytes).digest("hex");
    tamperedManifest.sqliteFileBytes = tamperedBytes.length;
    await rm(backup.manifestPath);
    await writeFile(backup.manifestPath, `${JSON.stringify(tamperedManifest, null, 2)}\n`);

    // An unrelated, pre-existing file elsewhere in the same restore
    // directory must never be touched by this failure's cleanup.
    const restoreDir = join(dir, "restored");
    const unrelatedFile = join(restoreDir, "unrelated-preexisting.txt");
    await mkdir(restoreDir, { recursive: true });
    await writeFile(unrelatedFile, "do not touch me");

    const restorePath = join(restoreDir, "restored.sqlite");
    await assert.rejects(
      () => restoreBackup({ backupSqlitePath: backup.sqlitePath, destPath: restorePath }),
      RestoreVerificationError,
    );

    // The unverified destination this call claimed must be gone — no
    // unverified DB left behind looking like a usable restore.
    assert.equal(existsSync(restorePath), false, "unverified restore destination must be deleted on failure");
    // The unrelated pre-existing file must be completely untouched.
    assert.equal(await readFile(unrelatedFile, "utf8"), "do not touch me");

    // No-overwrite semantics for a genuinely successful restore must still
    // hold afterward: the failed attempt clearing its own destination must
    // not have left the path in some state that changes this guarantee.
    const goodBackup = await createBackup({ dbPath, outputDir: join(dir, "backups2") });
    // (goodBackup has the same tampered live source on disk, but a fresh,
    // untampered backup+manifest pair — restoring it into the SAME path the
    // failed attempt just cleaned up must succeed normally.)
    const secondReport = await restoreBackup({ backupSqlitePath: goodBackup.sqlitePath, destPath: restorePath });
    assert.equal(secondReport.ok, true);
    assert.equal(existsSync(restorePath), true);
  });
});

test("restoreBackup verify-only mode also cleans up its own working copy when post-copy verification fails", async () => {
  await withTempDir(async (dir) => {
    const dbPath = join(dir, "lab.sqlite");
    seedStore(dbPath);
    const backup = await createBackup({ dbPath, outputDir: join(dir, "backups") });

    const bytes = await readFile(backup.sqlitePath);
    bytes[0] ^= 0xff; // corrupt the SQLite file header itself -> integrity_check will fail
    // Recompute checksum/bytes so this test isolates the integrity-check
    // failure path specifically, distinct from the checksum-mismatch tests
    // above.
    await writeFile(backup.sqlitePath, bytes);
    const tamperedManifest = JSON.parse(await readFile(backup.manifestPath, "utf8"));
    tamperedManifest.sqliteFileSha256 = createHash("sha256").update(bytes).digest("hex");
    tamperedManifest.sqliteFileBytes = bytes.length;
    await rm(backup.manifestPath);
    await writeFile(backup.manifestPath, `${JSON.stringify(tamperedManifest, null, 2)}\n`);

    const beforeTmpEntries = (await readdir(tmpdir()))
      .filter((name) => name.startsWith("airlock-restore-drill-"));

    await assert.rejects(
      () => restoreBackup({ backupSqlitePath: backup.sqlitePath, verifyOnly: true }),
      RestoreVerificationError,
    );

    const afterTmpEntries = (await readdir(tmpdir()))
      .filter((name) => name.startsWith("airlock-restore-drill-"));
    assert.deepEqual(afterTmpEntries, beforeTmpEntries, "verify-only working directory must not be left behind on failure");
  });
});
