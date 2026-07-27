# Dependency Review Boundary

`.github/workflows/dependency-review.yml` adds a pull-request supply-chain gate.
This document states precisely what it does and — as importantly — what it does
**not** do, so it is never mis-cited as deeper coverage than it provides.

## What it does

- Runs **only on `pull_request` to `main`**. It compares the dependency graph of
  the PR head against the base branch and inspects the **dependencies the PR
  adds or changes**.
- **Fails the PR** when a newly introduced dependency has a known advisory of
  severity **high or critical** (`fail-on-severity: high`).
- Uses `actions/dependency-review-action` **pinned by commit SHA**
  (`a1d282b3…`, v5.0.0) under **least privilege** (`permissions: contents:
  read`; the action reads the PR dependency diff via the GitHub Dependency
  Review API and needs no write scope), with `persist-credentials: false` on
  checkout.

## What it explicitly does NOT do — do not overclaim

- **It is not a runtime or dynamic scanner.** It inspects declared dependency
  metadata at PR time; it does not execute code, instrument the running
  simulator, or observe runtime behavior.
- **It does not scan the existing baseline.** Only dependencies **added or
  changed by the PR** are reviewed. A vulnerable dependency already on `main`
  before this workflow existed is not surfaced by this gate — a separate
  scheduled `npm audit` / advisory sweep is required for baseline coverage.
- **Transitive coverage is only as complete as the committed lockfile and the
  GitHub dependency graph.** It is not a guarantee that every transitive package
  is evaluated; a dependency not represented in the resolved graph is not
  reviewed.
- **It is advisory-focused here.** This workflow asserts the severity gate only.
  It does not enforce a license policy — that would require a stated, tested
  `allow`/`deny` license list, which is intentionally omitted rather than
  claimed and unenforced.
- **It runs on pull requests, not on direct pushes.** Changes that reach `main`
  outside the PR flow are not gated by this workflow.

## Relationship to the other supply-chain controls

- `npm ci --ignore-scripts` (ci.yml) blocks dependency lifecycle-script
  execution during install.
- `npm run security:audit` (`npm audit --audit-level=high`) covers the
  **installed** dependency set, including the baseline this PR gate does not.
- CycloneDX SBOM generation (ci.yml) produces evidence; it is not itself a
  vulnerability gate.
- This dependency-review gate adds **PR-time prevention** of newly introduced
  high/critical advisories — complementary to, not a replacement for, the audit
  sweep.

Together these are prevention (this gate + `--ignore-scripts`), detection
(`npm audit`), and evidence (SBOM). None of them proves runtime safety.
