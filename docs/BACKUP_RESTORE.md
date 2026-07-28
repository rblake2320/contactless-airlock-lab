# Backup and restore for the durable lab store

This closes the "backup/restore exercises" item named as required, but not
yet built, in `packages/storage/README.md`'s Production gap section. It
covers the single-host SQLite `DurableStore` used by the realtime lab
(`apps/realtime-lab/server.ts`) and any other `DurableStore` consumer.

## What this is

- A **point-snapshot** backup taken via SQLite's Online Backup API
  (`node:sqlite`'s `backup()`), which is WAL-consistent: it captures every
  transaction committed at the instant the backup runs, including committed
  WAL frames not yet checkpointed into the main database file. Confirmed
  empirically as part of this work: the API correctly copies a live,
  actively-written WAL-mode database without requiring writers to stop.
- A **checksummed, self-describing artifact**: every backup is a `.sqlite`
  file plus a sidecar `.manifest.json` recording its SHA-256, byte length,
  applied schema migrations, per-table row counts, and — if present — the
  realtime lab's application snapshot identity. The manifest also embeds
  the honesty statements below directly, so they travel with the backup
  even if this document is lost.
- A **restore drill**, not just a copy: restoring re-verifies checksum,
  byte length, SQLite-level integrity (`PRAGMA integrity_check` on the
  *actual restored bytes*, not the live source), that the schema is one
  this application recognizes, and then runs the same deep
  application-level checks the running server enforces on its own restart —
  `AirlockEngine.restore()` (audit hash-chain verification, every
  cross-record challenge binding, daily-spend reconciliation) — plus direct
  structural checks on the `idempotency_records` and `outbox_events` tables.

## What this is **not**

- **Not continuous point-in-time recovery.** This is snapshot backup.
  Anything committed after a backup runs and before the next one is
  unrecoverable through this tool if the source database is lost. If you
  need PITR, you need WAL archiving/shipping, which this does not
  implement.
- **Not off-host, encrypted, or disaster-recovery-orchestrated retention.**
  This tool reads and writes local disk paths only. Where backups are
  stored, how long they're kept, whether they're encrypted at rest, and how
  a real DR failover would work are all explicitly open — not addressed
  here, not implied to be addressed here.
- **Not an in-place upgrade path.** Restoring always writes to a brand-new
  path. This tool will never overwrite an existing file, including the live
  application's own database path. Promoting a verified restore to replace
  a live database is a deliberate, manual operational step outside this
  tool's scope — automating that safely (stopping the service, swapping the
  file, restarting under supervision) is future work, not something this
  release does for you.
- **Not an authenticity guarantee — the manifest checksum is unkeyed.**
  `sqliteFileSha256` detects *accidental* corruption: bit rot, truncation, a
  bad copy across a network or disk. It is a plain, unkeyed SHA-256, not a
  MAC or signature. **Anyone who can write to the location holding a backup
  can also rewrite its manifest to match** — the restore path has no way to
  tell "this checksum matches because nothing changed" from "this checksum
  matches because an attacker regenerated it after tampering with both
  files together." Do not read a passing `sha256-matches-manifest` check as
  proof of who produced a backup, or that it hasn't been deliberately
  substituted by someone with write access to backup storage. Real
  authenticity — as opposed to accidental-corruption detection — needs a
  keyed MAC or a signature checked against a key held somewhere other than
  the backup storage itself (e.g. an HSM-held signing key, or a separate,
  access-controlled verification service). This tool does not implement
  that; it is explicitly open work, same as the off-host/DR items above.
  This limitation is embedded directly in every manifest's
  `limitations.authenticity` field, not only stated here, so it travels
  with the artifact.

## Usage

Create a backup:

```
node --experimental-strip-types tools/backup-create.ts \
  --db path/to/lab.sqlite --out backups [--label nightly]
```

Every run writes a new, timestamped `<timestamp>_<label>.sqlite` and
`.manifest.json` pair under `--out`. It refuses to run if, somehow, that
exact path is already taken (this can only realistically happen if you
force the same label and clock instant twice — the tool has a test proving
that case fails cleanly and does not touch the pre-existing file).

Run a restore drill (verifies everything, leaves nothing behind — safe for
CI or a scheduled health check):

```
node --experimental-strip-types tools/backup-restore.ts \
  --backup backups/<timestamp>_<label>.sqlite --verify-only
```

Materialize a verified restore for inspection:

```
node --experimental-strip-types tools/backup-restore.ts \
  --backup backups/<timestamp>_<label>.sqlite --into restored/lab.sqlite
```

Both commands print a JSON report; `backup-restore` includes every
individual check it ran and whether it passed, whether the overall result
was success or failure.

## What "wrong-source rejection" means concretely

Restoring a file that is a valid SQLite database but not a `DurableStore`
database — because it has no `schema_migrations` table, or one that
doesn't match this application's migrations — fails the
`recognized-application-schema` check with a clear message rather than
either silently "succeeding" against unrelated data or crashing with a raw
SQLite error. This was specifically probed with a well-formed, unrelated
SQLite file carrying a manifest whose checksum was forged to match it
(isolating the schema check from the checksum check) — see
`tests/backup-restore.test.ts`.

## Design notes for reviewers

- Every artifact this module writes uses an OS-level exclusive create
  (`open(path, "wx")`) as its *only* overwrite guard — never a
  check-then-write race. `node:sqlite`'s `backup()` itself does **not**
  refuse to write into a pre-existing file (confirmed empirically: pointed
  at an existing, valid, unrelated SQLite database, it silently replaces
  its contents) — the exclusive-create-empty-placeholder-first pattern used
  here is a real, necessary guard, not decoration.
- All connections this module opens are read-only except the momentary
  target of the backup write itself, minimizing any chance this tooling
  could itself mutate a live database.
- The deep application-state check reuses `AirlockEngine.restore()`
  directly rather than re-implementing its validation — the same code path
  the live server already runs on every restart, so backup verification
  and server-restart verification can never drift apart silently.
- Every manifest field (row counts, applied migrations, the lab-snapshot
  identity) is read from **one connection to the completed backup copy**,
  never compared against an earlier read of the live source. An earlier
  version of this tool captured counts from the live source *before*
  calling the backup API and compared them to the finished copy afterward —
  that races every concurrent writer: a busy source legitimately has more
  rows by the time the comparison runs, and the old code treated that as
  corruption and deleted a perfectly valid backup. There is deliberately
  nothing left to race against now — see the concurrent-writer regression
  test in `tests/backup-restore.test.ts`, which spawns a real second
  process writing throughout the backup call and asserts it never fails.
- Restore verification failure after the destination is claimed (any check
  from `sqlite-integrity-check` onward) deletes exactly the path this
  specific call created — never a pre-existing file, since `claimNewFile`'s
  exclusive create means a call can only reach that cleanup path if it was
  the sole owner of what's there. No unverified database is ever left
  behind looking like a usable restore, in both verify-only and
  materialized-destination modes.
