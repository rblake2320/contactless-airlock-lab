# Runtime build coherence

The realtime lab snapshots `index.html`, `app.js`, and `styles.css` into memory
when `createLabServer()` composes the process. Requests never read mutable asset
files again. A deployment that replaces files underneath an old process
therefore cannot serve a fresh frontend with a stale backend (or a partial mix
of asset generations). Restarting the process is the activation boundary.

`GET /api/health` returns:

- `buildId`: `AIRLOCK_BUILD_ID`, bounded to 1–64 non-secret identifier
  characters, or the explicit safe default `development-unversioned`; and
- `staticAssetDigest`: SHA-256 over the ordered asset names, lengths, and bytes
  captured by that process.

The build ID is an opaque deployment label, not a secret and not proof that a
commit was reviewed. Deployment automation should set it to the release commit
or immutable artifact identifier. Invalid or oversized values fail startup.
The asset digest identifies the exact in-memory frontend snapshot; it is not a
code-signing or supply-chain attestation.

`tests/runtime-coherence.test.ts` starts a real HTTP server over temporary
assets, changes an asset on disk after startup, and proves both the served bytes
and reported digest remain the original startup snapshot.
