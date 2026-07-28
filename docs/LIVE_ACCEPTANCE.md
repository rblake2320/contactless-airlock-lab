# Isolated live acceptance gate

Run the repeatable black-box acceptance gate with:

```powershell
npm run acceptance
```

The harness starts real realtime-lab HTTP servers in child processes. Every
server binds port `0`, so the operating system selects an available loopback
port. All SQLite databases, backup artifacts, and restored copies live under a
new operating-system temporary directory. The harness never reads or writes a
configured/live lab database.

The gate proves:

- a mutation persists across a complete server-process stop and restart;
- live mutation throttling returns `429`, a positive `Retry-After`, and leaves
  public state byte-structurally unchanged;
- the default SSE per-client limit accepts four streams, rejects the fifth,
  and frees a slot after disconnect;
- the real backup-create CLI produces an artifact, verify-only restore passes
  without a permanent copy, materialized restore succeeds, and a server opened
  on that restored database exposes the original challenge;
- audit-copy tampering is reported as blocked while the authoritative audit
  chain remains valid.

All streams, server children, and temporary directories are closed in a
`finally` path on success or failure. This remains a single-host local
simulator acceptance gate. It does not certify production partners, payment
rails, multi-host failover, off-host backups, or external key custody.
