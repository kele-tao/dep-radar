# Roadmap and deliberate cuts

This file records what v1.0 does **not** do, so nobody has to guess whether a missing
feature is a bug or a decision.

## Cut from v1.0

- **Live advisory feed.** The advisory snapshot
  (`src/dep_radar/data/advisories.json`) is 25 hand-curated public incidents, committed
  to git, matched by version range. It is not OSV and it is not complete. Shipping a
  half-working network client that fails in CI would have been worse than an honest
  snapshot; `dep-radar db import` to load an OSV export offline is the top roadmap item.
- **pnpm-lock.yaml, uv.lock, Pipfile.lock, Cargo.lock.** Only npm lockfiles, yarn v1,
  requirements.txt, pyproject.toml and poetry.lock are parsed. An unparsed ecosystem gets
  a clear "no supported manifest" error rather than a wrong answer.
- **Transitive vulnerability scanning.** Only direct declarations are matched against the
  advisory snapshot's ranges plus the deprecated list; matching every transitive package
  against a real CVE database needs a database.
- **Licence detection from licence *files* inside packages.** Licences come from lockfile
  metadata (`license` field) only, because reading every package's LICENSE file requires
  the packages to be installed - and then you have already run the install scripts.
- **SBOM signing and in-toto attestations.** The document is valid JSON with purls and
  hashes; provenance is out of scope for v1.0.
- **A Rust/Go implementation for sub-100 ms scans.** Python with the current algorithm is
  fast enough that the CLI start-up dominates for small trees.

## Next

1. `dep-radar db import --format osv path/to/osv.json` to use a real advisory export
   while staying offline at scan time.
2. `dep-radar diff <old-lock> <new-lock>`: new packages, new install scripts, score delta
   between two branches. The graph layer already supports it; only the CLI and a
   comparator are missing.
3. `pnpm-lock.yaml` support. The format is YAML, and the parser would be a sibling of
   `parsers/npm.py`, reusing the same resolution rules.
4. Rule configuration: `dep-radar.toml` to disable a category (for example, allow a
   GPL dependency in a GPL project) without changing the code.
5. SARIF output for GitHub code scanning annotations, so findings appear inline on a PR.
