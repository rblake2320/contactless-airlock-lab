/**
 * Backup / restore library for the Contactless Airlock durable lab store.
 *
 * Scope and honesty statement (read this before trusting the output):
 *
 * - This produces POINT-SNAPSHOT backups using SQLite's Online Backup API
 *   (`node:sqlite`'s `backup()`), which is WAL-consistent: it captures every
 *   transaction committed up to the instant the backup runs, including
 *   committed WAL frames not yet checkpointed into the main file. It does
 *   NOT provide continuous point-in-time recovery. Any write committed
 *   after a backup completes and before the next one is NOT recoverable
 *   through this tool if the live database is lost. Operators who need true
 *   PITR need WAL archiving/shipping, which this tool does not implement.
 * - This is local-disk backup/restore only. It does not implement, and does
 *   not claim to implement, off-host replication, encrypted retention, or
 *   disaster-recovery orchestration. That remains explicitly open work.
 * - Every backup is written to a brand-new path (`wx` exclusive create) and
 *   restores are written to a brand-new path by default. Nothing in this
 *   module overwrites an existing file.
 */
import { createHash } from "node:crypto";
import {
  closeSync,
  copyFileSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  openSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { basename, dirname, join, resolve } from "node:path";
import { DatabaseSync, backup as sqliteBackup } from "node:sqlite";
import { DurableStore } from "../packages/storage/durableStore.ts";
import { MIGRATIONS } from "../packages/storage/migrations.ts";
import { AirlockEngine, type AirlockEngineSnapshot } from "../apps/issuer-simulator/airlockEngine.ts";

export const BACKUP_SCHEMA_VERSION = "airlock.backup.v1" as const;
export const TOOL_NAME = "contactless-airlock-lab/backup-lib" as const;

export const POINT_IN_TIME_LIMITATION =
  "Snapshot backup only. Captures every transaction committed at the moment " +
  "this backup ran (WAL-consistent via SQLite's Online Backup API). Does " +
  "NOT provide continuous point-in-time recovery — writes committed after " +
  "this backup and before the next one are unrecoverable through this tool " +
  "if the source database is lost.";

export const SCOPE_LIMITATION =
  "Local-disk backup/restore only. Does not implement off-host replication, " +
  "encrypted retention, or disaster-recovery orchestration; that remains " +
  "explicitly open work, not covered by this tool.";

export const AUTHENTICITY_LIMITATION =
  "The sha256 in this manifest detects ACCIDENTAL corruption (bit rot, " +
  "truncation, a bad copy) — it is not keyed or signed. Anyone who can " +
  "write to the location holding this .sqlite file can also rewrite this " +
  "manifest to match, so this checksum provides NO protection against a " +
  "storage-level attacker: it does not prove who produced this backup or " +
  "that it has not been deliberately substituted. Authenticity (as opposed " +
  "to accidental-corruption detection) requires a keyed MAC or signature " +
  "verified against a secret/key held separately from the backup storage, " +
  "which this tool does not implement.";

export interface BackupManifest {
  schemaVersion: typeof BACKUP_SCHEMA_VERSION;
  tool: typeof TOOL_NAME;
  createdAt: string;
  sourceLabel: string;
  sqliteFileName: string;
  sqliteFileBytes: number;
  sqliteFileSha256: string;
  appMigrations: Array<{ version: number; name: string }>;
  tableRowCounts: {
    durable_challenges: number;
    idempotency_records: number;
    outbox_events: number;
  };
  labSnapshot: {
    present: boolean;
    id?: string;
    version?: number;
    status?: string;
  };
  integrityCheck: "ok";
  environment: { node: string; platform: NodeJS.Platform };
  limitations: {
    pointInTime: string;
    scope: string;
    authenticity: string;
  };
}

export class BackupError extends Error {}
export class RestoreVerificationError extends Error {
  readonly checks: RestoreCheck[];
  constructor(message: string, checks: RestoreCheck[]) {
    super(message);
    this.checks = checks;
  }
}

/** Only safe filesystem-label characters; rejects path separators and `..`. */
export function sanitizeLabel(label: string): string {
  const trimmed = label.trim();
  if (!trimmed) throw new BackupError("label must not be empty");
  if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/.test(trimmed)) {
    throw new BackupError(
      "label must be 1-64 letters, numbers, dots, underscores, or hyphens",
    );
  }
  if (trimmed === "." || trimmed === "..") {
    throw new BackupError("label must not be a path-traversal token");
  }
  return trimmed;
}

/** Resolves a caller-given directory to an absolute path and ensures a
 * candidate file path built under it cannot escape it, regardless of
 * platform path-separator conventions. */
function resolveWithinDirectory(directory: string, fileName: string): string {
  const absoluteDirectory = resolve(directory);
  const candidate = resolve(absoluteDirectory, fileName);
  const prefix = absoluteDirectory.endsWith(pathSep()) ? absoluteDirectory : absoluteDirectory + pathSep();
  if (candidate !== absoluteDirectory && !candidate.startsWith(prefix)) {
    throw new BackupError(`resolved path escapes its directory: ${fileName}`);
  }
  return candidate;
}

function pathSep(): string {
  return process.platform === "win32" ? "\\" : "/";
}

function sha256File(path: string): string {
  return createHash("sha256").update(readFileSync(path)).digest("hex");
}

/** Atomically claims `path`: fails if anything already exists there. Used
 * for every artifact this module writes so "no overwrite" is enforced by
 * the filesystem, not by a check-then-write race. */
function claimNewFile(path: string): void {
  mkdirSync(dirname(path), { recursive: true });
  const fd = openSync(path, "wx");
  closeSync(fd);
}

function countRows(db: DatabaseSync, table: string): number {
  const row = db.prepare(`SELECT COUNT(*) AS n FROM ${table}`).get() as { n: number };
  return row.n;
}

function readAppliedMigrations(db: DatabaseSync): Array<{ version: number; name: string }> {
  return (db.prepare(
    "SELECT version, name FROM schema_migrations ORDER BY version",
  ).all() as Array<{ version: number; name: string }>);
}

function readLabSnapshotInfo(db: DatabaseSync): BackupManifest["labSnapshot"] {
  const row = db.prepare(
    "SELECT challenge_id, status, version FROM durable_challenges WHERE challenge_id = ?",
  ).get("realtime-lab:simulator-state") as
    | { challenge_id: string; status: string; version: number }
    | undefined;
  if (!row) return { present: false };
  return { present: true, id: row.challenge_id, version: row.version, status: row.status };
}

export interface CreateBackupOptions {
  /** Path to the live (or any) DurableStore SQLite file to back up. */
  dbPath: string;
  /** Directory the backup artifacts are written into. Created if missing. */
  outputDir: string;
  /** Optional label folded into the generated file name; sanitized. */
  label?: string;
  /** Injectable clock for deterministic tests. */
  now?: () => Date;
}

export interface CreateBackupResult {
  sqlitePath: string;
  manifestPath: string;
  manifest: BackupManifest;
}

/**
 * Creates a WAL-consistent, checksummed, exclusively-created backup of a
 * DurableStore SQLite file, plus a sidecar manifest. Never overwrites an
 * existing file. Verifies the *written copy* (not just the live source)
 * with `PRAGMA integrity_check` before reporting success — a backup that
 * fails that check is deleted and the call throws, so a caller never walks
 * away believing a corrupt backup succeeded.
 */
export async function createBackup(options: CreateBackupOptions): Promise<CreateBackupResult> {
  const dbPath = resolve(options.dbPath);
  if (!existsSync(dbPath)) throw new BackupError(`source database does not exist: ${dbPath}`);
  const outputDir = resolve(options.outputDir);
  mkdirSync(outputDir, { recursive: true });

  const now = options.now?.() ?? new Date();
  const stamp = now.toISOString().replace(/[:.]/g, "-");
  const label = options.label ? sanitizeLabel(options.label) : "backup";
  const baseName = `${stamp}_${label}`;
  const sqliteFileName = `${baseName}.sqlite`;
  const manifestFileName = `${baseName}.manifest.json`;
  const sqlitePath = resolveWithinDirectory(outputDir, sqliteFileName);
  const manifestPath = resolveWithinDirectory(outputDir, manifestFileName);

  // Opening the source once through DurableStore first guarantees any
  // not-yet-applied migration runs (idempotently — see packages/storage's
  // #migrate, which is a no-op once already applied) under the same
  // BEGIN IMMEDIATE + busy_timeout protection the live application uses,
  // before this module reads it directly.
  new DurableStore(dbPath).close();

  const raw = new DatabaseSync(dbPath, { readOnly: true });
  let manifest: BackupManifest;
  // Only ever delete sqlitePath on failure if THIS call is the one that
  // claimed it — never touch a file that was already there, which for a
  // duplicate backup attempt (claimNewFile below throws EEXIST) is another,
  // already-successful backup that must be left completely alone.
  let claimedSqlitePath = false;
  try {
    raw.exec("PRAGMA busy_timeout=5000;");

    claimNewFile(sqlitePath);
    claimedSqlitePath = true;
    const pagesCopied = await sqliteBackup(raw, sqlitePath);
    if (!Number.isFinite(pagesCopied)) {
      throw new BackupError("SQLite backup API returned an unexpected result");
    }

    // Every manifest field below is read from the COMPLETED BACKUP COPY
    // ONLY — never compared against a separately-timed read of the live
    // source. The live source keeps accepting writes for the entire
    // duration of sqliteBackup() (that concurrency is the point of SQLite's
    // Online Backup API); a row/migration count taken from `raw` before
    // calling it, then compared against the finished copy afterward, races
    // every concurrent writer and produces a false "mismatch" failure — and
    // a deleted, perfectly valid backup — purely because more data landed
    // in between the two reads. Reading everything from one connection to
    // the finished copy removes the second timepoint entirely: there is
    // nothing left to race against, and a busy source can never make a
    // valid backup fail this check.
    const copy = new DatabaseSync(sqlitePath, { readOnly: true });
    let appliedMigrations: Array<{ version: number; name: string }>;
    let tableRowCounts: BackupManifest["tableRowCounts"];
    let labSnapshot: BackupManifest["labSnapshot"];
    try {
      const result = copy.prepare("PRAGMA integrity_check").get() as { integrity_check: string };
      if (result.integrity_check !== "ok") {
        throw new BackupError(`backup copy failed integrity_check: ${result.integrity_check}`);
      }
      appliedMigrations = readAppliedMigrations(copy);
      tableRowCounts = {
        durable_challenges: countRows(copy, "durable_challenges"),
        idempotency_records: countRows(copy, "idempotency_records"),
        outbox_events: countRows(copy, "outbox_events"),
      };
      labSnapshot = readLabSnapshotInfo(copy);
    } finally {
      copy.close();
    }

    const sqliteFileBytes = statSync(sqlitePath).size;
    manifest = {
      schemaVersion: BACKUP_SCHEMA_VERSION,
      tool: TOOL_NAME,
      createdAt: now.toISOString(),
      sourceLabel: basename(dbPath),
      sqliteFileName,
      sqliteFileBytes,
      sqliteFileSha256: sha256File(sqlitePath),
      appMigrations: appliedMigrations,
      tableRowCounts,
      labSnapshot,
      integrityCheck: "ok",
      environment: { node: process.version, platform: process.platform },
      limitations: {
        pointInTime: POINT_IN_TIME_LIMITATION,
        scope: SCOPE_LIMITATION,
        authenticity: AUTHENTICITY_LIMITATION,
      },
    };
  } catch (error) {
    // A backup that didn't fully verify must not be left behind looking
    // like a usable artifact.
    if (claimedSqlitePath && existsSync(sqlitePath)) rmSync(sqlitePath, { force: true });
    raw.close();
    throw error;
  }
  raw.close();

  claimNewFile(manifestPath);
  writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`, { encoding: "utf8", flag: "r+" });

  return { sqlitePath, manifestPath, manifest };
}

export function readManifest(manifestPath: string): BackupManifest {
  if (!existsSync(manifestPath)) {
    throw new BackupError(`manifest not found: ${manifestPath}`);
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(readFileSync(manifestPath, "utf8"));
  } catch {
    throw new BackupError(`manifest is not valid JSON: ${manifestPath}`);
  }
  const manifest = parsed as Partial<BackupManifest>;
  if (
    manifest.schemaVersion !== BACKUP_SCHEMA_VERSION ||
    typeof manifest.sqliteFileName !== "string" ||
    typeof manifest.sqliteFileBytes !== "number" ||
    typeof manifest.sqliteFileSha256 !== "string" ||
    !/^[0-9a-f]{64}$/.test(manifest.sqliteFileSha256) ||
    !Array.isArray(manifest.appMigrations) ||
    !manifest.tableRowCounts ||
    !manifest.labSnapshot ||
    manifest.integrityCheck !== "ok"
  ) {
    throw new BackupError(`manifest is missing required fields or is the wrong shape: ${manifestPath}`);
  }
  return manifest as BackupManifest;
}

export interface RestoreCheck {
  name: string;
  ok: boolean;
  detail: string;
}

export interface RestoreReport {
  ok: boolean;
  restoredPath?: string;
  checks: RestoreCheck[];
  manifest: BackupManifest;
}

export interface RestoreOptions {
  /** Path to the backed-up .sqlite file. */
  backupSqlitePath: string;
  /** Path to its manifest. Defaults to `<backupSqlitePath>` with
   * `.sqlite` replaced by `.manifest.json`. */
  manifestPath?: string;
  /** Where to materialize the restored copy. Required unless
   * `verifyOnly` is set, in which case a throwaway temp path is used and
   * cleaned up automatically. Must not already exist. */
  destPath?: string;
  /** Verify the backup end-to-end without leaving a permanent restored
   * copy on disk — the "restore drill" mode for CI / periodic checks. */
  verifyOnly?: boolean;
}

/**
 * Restores a backup to a brand-new path (never overwrites) and runs a full
 * verification pass: checksum, byte-length, SQLite-level integrity, schema
 * fingerprint ("wrong source" detection), and the same deep application
 * consistency checks the running application enforces on its own restart
 * (AirlockEngine.restore, which internally verifies the audit hash chain,
 * every cross-record challenge binding, and daily-spend reconciliation),
 * plus direct structural checks on the idempotency and outbox tables.
 *
 * Throws RestoreVerificationError with every individual check result if
 * anything fails — nothing here silently reports partial success.
 */
export async function restoreBackup(options: RestoreOptions): Promise<RestoreReport> {
  const backupSqlitePath = resolve(options.backupSqlitePath);
  const manifestPath = resolve(
    options.manifestPath ?? backupSqlitePath.replace(/\.sqlite$/, ".manifest.json"),
  );
  const checks: RestoreCheck[] = [];
  const record = (name: string, ok: boolean, detail: string) => {
    checks.push({ name, ok, detail });
    return ok;
  };

  if (!existsSync(backupSqlitePath)) {
    throw new RestoreVerificationError(
      `backup file does not exist: ${backupSqlitePath}`,
      [{ name: "backup-file-exists", ok: false, detail: backupSqlitePath }],
    );
  }
  record("backup-file-exists", true, backupSqlitePath);

  let manifest: BackupManifest;
  try {
    manifest = readManifest(manifestPath);
    record("manifest-readable", true, manifestPath);
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error);
    record("manifest-readable", false, detail);
    throw new RestoreVerificationError(`manifest verification failed: ${detail}`, checks);
  }

  const actualBytes = statSync(backupSqlitePath).size;
  if (!record(
    "byte-length-matches-manifest",
    actualBytes === manifest.sqliteFileBytes,
    `expected ${manifest.sqliteFileBytes}, found ${actualBytes}`,
  )) {
    throw new RestoreVerificationError("backup file is truncated or grew unexpectedly", checks);
  }

  const actualHash = sha256File(backupSqlitePath);
  if (!record(
    "sha256-matches-manifest",
    actualHash === manifest.sqliteFileSha256,
    actualHash === manifest.sqliteFileSha256 ? actualHash : `expected ${manifest.sqliteFileSha256}, found ${actualHash}`,
  )) {
    throw new RestoreVerificationError(
      "backup file content does not match its manifest checksum — corrupted or substituted",
      checks,
    );
  }

  let workingDir: string | undefined;
  let restoredPath: string;
  if (options.verifyOnly) {
    workingDir = mkdtempSync(join(tmpdir(), "airlock-restore-drill-"));
    restoredPath = join(workingDir, "restored.sqlite");
  } else {
    if (!options.destPath) {
      throw new RestoreVerificationError(
        "destPath is required unless verifyOnly is set",
        checks,
      );
    }
    restoredPath = resolve(options.destPath);
    if (existsSync(restoredPath)) {
      throw new RestoreVerificationError(
        `restore destination already exists, refusing to overwrite: ${restoredPath}`,
        checks,
      );
    }
  }

  // Only ever delete restoredPath on failure if THIS call is the one that
  // claimed it — claimNewFile is exclusive-create, so if it throws (e.g. a
  // narrow TOCTOU race against the existsSync check above), restoredPath
  // was never ours to begin with and must not be touched.
  let claimedRestorePath = false;
  try {
    claimNewFile(restoredPath);
    claimedRestorePath = true;
    copyFileSync(backupSqlitePath, restoredPath);
    record("copied-to-restore-target", true, restoredPath);

    const db = new DatabaseSync(restoredPath, { readOnly: true });
    try {
      let integrityResult: string;
      try {
        integrityResult = (db.prepare("PRAGMA integrity_check").get() as { integrity_check: string }).integrity_check;
      } catch (error) {
        record("sqlite-opens-and-integrity-check", false, error instanceof Error ? error.message : String(error));
        throw new RestoreVerificationError("restored file is not a valid SQLite database", checks);
      }
      if (!record("sqlite-integrity-check", integrityResult === "ok", integrityResult)) {
        throw new RestoreVerificationError("restored database failed PRAGMA integrity_check", checks);
      }

      const knownMigrationNames = new Set(MIGRATIONS.map((m) => `${m.version}:${m.name}`));
      let appliedMigrations: Array<{ version: number; name: string }> = [];
      let hasKnownSchema = false;
      let schemaDetail: string;
      try {
        appliedMigrations = readAppliedMigrations(db);
        hasKnownSchema =
          appliedMigrations.length > 0 &&
          appliedMigrations.every((m) => knownMigrationNames.has(`${m.version}:${m.name}`));
        schemaDetail = hasKnownSchema
          ? JSON.stringify(appliedMigrations)
          : `unrecognized or missing schema_migrations: ${JSON.stringify(appliedMigrations)}`;
      } catch (error) {
        // A file that isn't this application's database at all (e.g. an
        // unrelated valid SQLite file) may not even have a schema_migrations
        // table — that is itself the wrong-source signal, not a crash.
        schemaDetail = `not a recognizable application database: ${
          error instanceof Error ? error.message : String(error)
        }`;
      }
      if (!record("recognized-application-schema", hasKnownSchema, schemaDetail)) {
        throw new RestoreVerificationError(
          "wrong-source rejection: this file's schema_migrations does not match this application",
          checks,
        );
      }

      const idempotencyRows = db.prepare(
        "SELECT scope, idempotency_key, response_json FROM idempotency_records",
      ).all() as Array<{ scope: string; idempotency_key: string; response_json: string }>;
      let idempotencyParseFailures = 0;
      for (const row of idempotencyRows) {
        try {
          JSON.parse(row.response_json);
        } catch {
          idempotencyParseFailures += 1;
        }
      }
      if (!record(
        "idempotency-records-structurally-valid",
        idempotencyParseFailures === 0,
        `${idempotencyRows.length} rows, ${idempotencyParseFailures} with unparsable response_json`,
      )) {
        throw new RestoreVerificationError("idempotency_records verification failed", checks);
      }

      const outboxRows = db.prepare(
        "SELECT payload_json, created_at, delivered_at, claimed_until FROM outbox_events",
      ).all() as Array<{
        payload_json: string;
        created_at: string;
        delivered_at: string | null;
        claimed_until: string | null;
      }>;
      let outboxIssues = 0;
      let delivered = 0, claimed = 0, pending = 0;
      for (const row of outboxRows) {
        try {
          JSON.parse(row.payload_json);
        } catch {
          outboxIssues += 1;
        }
        if (row.delivered_at) {
          if (Date.parse(row.delivered_at) < Date.parse(row.created_at)) outboxIssues += 1;
          delivered += 1;
        } else if (row.claimed_until) claimed += 1;
        else pending += 1;
      }
      if (!record(
        "outbox-events-structurally-valid",
        outboxIssues === 0,
        `${outboxRows.length} rows (delivered=${delivered}, claimed=${claimed}, pending=${pending}), ${outboxIssues} issues`,
      )) {
        throw new RestoreVerificationError("outbox_events verification failed", checks);
      }

      if (manifest.labSnapshot.present && manifest.labSnapshot.id) {
        const snapshotRow = db.prepare(
          "SELECT record_json FROM durable_challenges WHERE challenge_id = ?",
        ).get(manifest.labSnapshot.id) as { record_json: string } | undefined;
        if (!record(
          "lab-snapshot-row-present",
          Boolean(snapshotRow),
          snapshotRow ? "found" : "expected by manifest but missing after restore",
        )) {
          throw new RestoreVerificationError("lab snapshot row missing after restore", checks);
        }
        try {
          const persisted = JSON.parse(snapshotRow!.record_json) as { engine: AirlockEngineSnapshot };
          AirlockEngine.restore(persisted.engine);
          record(
            "application-state-deep-verification",
            true,
            "AirlockEngine.restore succeeded: audit hash chain, every cross-record challenge " +
            "binding, and daily-spend reconciliation all verified",
          );
        } catch (error) {
          const detail = error instanceof Error ? error.message : String(error);
          record("application-state-deep-verification", false, detail);
          throw new RestoreVerificationError(`application-level state verification failed: ${detail}`, checks);
        }
      } else {
        record("application-state-deep-verification", true, "no lab snapshot present in this backup; skipped");
      }
    } finally {
      db.close();
    }

    return { ok: true, restoredPath: options.verifyOnly ? undefined : restoredPath, checks, manifest };
  } catch (error) {
    // Any failure after claiming restoredPath means an unverified, possibly
    // partial or corrupt database is sitting at that path — delete it so no
    // unverified DB is ever left behind looking like a usable restore. This
    // never touches a pre-existing file: claimNewFile's exclusive create is
    // what makes claimedRestorePath true only when this call is the sole
    // owner of that path, so an older legitimate destination (which could
    // only exist if a caller reused a path outside this function's control)
    // and the no-overwrite guarantee above are both preserved.
    if (claimedRestorePath && existsSync(restoredPath)) rmSync(restoredPath, { force: true });
    throw error;
  } finally {
    if (workingDir) rmSync(workingDir, { recursive: true, force: true });
  }
}
