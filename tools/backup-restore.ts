#!/usr/bin/env node
/**
 * CLI: restore + verify a backup produced by tools/backup-create.ts. See
 * tools/backup-lib.ts and docs/BACKUP_RESTORE.md for full behavior.
 *
 * Verification-only "restore drill" (no permanent copy left behind, safe
 * for CI or a scheduled health check):
 *   node --experimental-strip-types tools/backup-restore.ts \
 *     --backup backups/2026-...-nightly.sqlite --verify-only
 *
 * Full restore to a brand-new path (never overwrites):
 *   node --experimental-strip-types tools/backup-restore.ts \
 *     --backup backups/2026-...-nightly.sqlite --into restored/lab.sqlite
 *
 * This never touches, and cannot be pointed at, a live application
 * database path implicitly — --into always names a brand-new file, and the
 * tool refuses if anything already exists there. Promoting a verified
 * restore into place for the running application is a deliberate, separate,
 * manual step this tool does not automate.
 */
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { restoreBackup, RestoreVerificationError } from "./backup-lib.ts";

interface Args {
  backup: string;
  manifest?: string;
  into?: string;
  verifyOnly: boolean;
}

function parseArgs(argv: readonly string[]): Args {
  let backup: string | undefined;
  let manifest: string | undefined;
  let into: string | undefined;
  let verifyOnly = false;
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--backup") backup = argv[++i];
    else if (arg === "--manifest") manifest = argv[++i];
    else if (arg === "--into") into = argv[++i];
    else if (arg === "--verify-only") verifyOnly = true;
    else if (arg === "--help" || arg === "-h") {
      printUsage();
      process.exit(0);
    } else throw new Error(`unknown argument: ${arg}`);
  }
  if (!backup) throw new Error("--backup <path-to-sqlite-backup> is required");
  if (!into && !verifyOnly) {
    throw new Error("either --into <new-path> or --verify-only is required");
  }
  if (into && verifyOnly) {
    throw new Error("--into and --verify-only are mutually exclusive");
  }
  return { backup, manifest, into, verifyOnly };
}

function printUsage(): void {
  process.stdout.write(`Usage:
  backup-restore --backup <sqlite-file> --verify-only
  backup-restore --backup <sqlite-file> --into <new-path> [--manifest <path>]

Restores a backup to a brand-new path (never overwrites) and runs a full
verification pass: checksum, byte length, SQLite integrity, application
schema recognition, and deep application-state checks (audit hash chain,
challenge cross-references, daily-spend reconciliation, idempotency and
outbox table structure).

--verify-only runs every check against a throwaway temp copy and leaves
nothing behind — the "restore drill" mode for CI or a scheduled health
check. Without it, --into is required and the verified copy is left at
that path for inspection.

This is a snapshot restore, not point-in-time recovery. See
docs/BACKUP_RESTORE.md.
`);
}

export async function main(argv: readonly string[]): Promise<number> {
  let args: Args;
  try {
    args = parseArgs(argv);
  } catch (error) {
    process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
    printUsage();
    return 2;
  }
  try {
    const report = await restoreBackup({
      backupSqlitePath: resolve(args.backup),
      manifestPath: args.manifest ? resolve(args.manifest) : undefined,
      destPath: args.into ? resolve(args.into) : undefined,
      verifyOnly: args.verifyOnly,
    });
    process.stdout.write(`${JSON.stringify({
      ok: report.ok,
      restoredPath: report.restoredPath,
      checks: report.checks,
    }, null, 2)}\n`);
    return 0;
  } catch (error) {
    if (error instanceof RestoreVerificationError) {
      process.stderr.write(`${JSON.stringify({
        ok: false,
        error: error.message,
        checks: error.checks,
      }, null, 2)}\n`);
      return 1;
    }
    process.stderr.write(`restore failed: ${error instanceof Error ? error.message : String(error)}\n`);
    return 1;
  }
}

if (
  process.argv[1] &&
  import.meta.url === pathToFileURL(resolve(process.argv[1])).href
) {
  main(process.argv.slice(2)).then((code) => process.exit(code));
}
