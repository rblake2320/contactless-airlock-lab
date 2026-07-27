# Release Evidence Bundle

Generate a release-candidate evidence file only from a clean checkout:

```powershell
npm ci --ignore-scripts
npm run release:evidence -- `
  --expected-commit <full-commit-sha> `
  --output release-evidence/release.json
```

The generator refuses a dirty worktree by default, rejects a mismatched
expected commit, requires `package-lock.json`, runs type checking, tests, and
scenarios, and refuses success if those commands change the worktree. Output is
bounded to 256 KiB and is created without overwriting an existing evidence
file.

The JSON records:

- the exact commit and its committed timestamp;
- SHA-256 of `package-lock.json`;
- Node and available Python versions;
- normalized typecheck, test-count, and scenario results;
- the simulator-versus-real boundary; and
- a digest of the evidence body.

The bundle deliberately excludes nondeterministic test timings and unbounded
command logs. Given the same commit, lockfile, tool versions, and normalized
verification results, its JSON content is deterministic.

This is not signed provenance, an attestation, a signed build, PCI evidence, or
partner certification. The `provenance` object states `signed:false` and
`attested:false`. CI retains the JSON as a short-lived workflow artifact only.

`--allow-dirty` exists for local diagnostics. Any resulting bundle records
`cleanWorktree:false` and is not release-candidate evidence.
