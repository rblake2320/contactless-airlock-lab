#!/usr/bin/env node
/**
 * CLI: create a WAL-consistent, checksummed backup of a DurableStore
 * SQLite file. See tools/backup-lib.ts and docs/BACKUP_RESTORE.md for the
 * full behavior and its honestly-stated limitations.
 *
 *   node --experimental-strip-types tools/backup-create.ts \
 *     --db studio-data/lab.sqlite --out backups [--label nightly]
 */
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { createBackup } from "./backup-lib.ts";

interface Args {
  db: string;
  out: string;
  label?: string;
}

function parseArgs(argv: readonly string[]): Args {
  let db: string | undefined;
  let out: string | undefined;
  let label: string | undefined;
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--db") db = argv[++i];
    else if (arg === "--out") out = argv[++i];
    else if (arg === "--label") label = argv[++i];
    else if (arg === "--help" || arg === "-h") {
      printUsage();
      process.exit(0);
    } else throw new Error(`unknown argument: ${arg}`);
  }
  if (!db) throw new Error("--db <path-to-sqlite-file> is required");
  if (!out) throw new Error("--out <output-directory> is required");
  return { db, out, label };
}

function printUsage(): void {
  process.stdout.write(`Usage: backup-create --db <sqlite-file> --out <directory> [--label <name>]

Creates a new, checksummed, WAL-consistent backup of a DurableStore SQLite
file. Never overwrites an existing file — every run writes to a fresh,
timestamped path under --out and refuses to run if that path is somehow
already taken.

This is a SNAPSHOT, not continuous point-in-time recovery. See
docs/BACKUP_RESTORE.md for exactly what is and is not covered.
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
    const result = await createBackup({
      dbPath: resolve(args.db),
      outputDir: resolve(args.out),
      label: args.label,
    });
    process.stdout.write(`${JSON.stringify({
      ok: true,
      sqlitePath: result.sqlitePath,
      manifestPath: result.manifestPath,
      sqliteFileBytes: result.manifest.sqliteFileBytes,
      sqliteFileSha256: result.manifest.sqliteFileSha256,
      tableRowCounts: result.manifest.tableRowCounts,
      labSnapshotPresent: result.manifest.labSnapshot.present,
    }, null, 2)}\n`);
    return 0;
  } catch (error) {
    process.stderr.write(`backup failed: ${error instanceof Error ? error.message : String(error)}\n`);
    return 1;
  }
}

if (
  process.argv[1] &&
  import.meta.url === pathToFileURL(resolve(process.argv[1])).href
) {
  main(process.argv.slice(2)).then((code) => process.exit(code));
}
