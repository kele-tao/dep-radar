# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- `pyproject.toml` and `poetry.lock` are now parsed on Python 3.10. The stdlib `tomllib`
  module only exists from 3.11, and dep-radar advertises `requires-python >=3.10`, so
  `src/dep_radar/toml_lite.py` now implements the TOML subset manifests use (tables,
  arrays of tables, dotted and quoted keys, all four string forms, integers, floats,
  booleans, arrays, inline tables) and the parser falls back to it when `tomllib` is
  missing. A document outside that subset still fails with the file name and line number
  instead of a traceback. `tests/test_toml_lite.py` exercises both paths and asserts they
  build the same graph.

## [1.0.0] - 2026-01-20

First public release.

### Added

- `dep-radar scan <path>`: dependency graph statistics (packages, direct, transitive,
  max/mean depth, depth histogram, duplicate versions), nine risk checks, and a 0-100
  supply-chain score with grades A-F.
- `dep-radar explain <package>`: shortest dependency paths from the project root, the
  parent packages, depth and licence - text or `--json`.
- `dep-radar sbom`: CycloneDX-like and SPDX-like JSON with Package URLs, licences from
  lockfile metadata, hashes from the lockfile `integrity` field, and `--validate`.
- Parsers: `package.json`, `package-lock.json` v1/v2/v3, `yarn.lock` v1,
  `pyproject.toml` (PEP 621 and Poetry), `requirements.txt` (`-r` includes, extras,
  PEP 508 markers, hashes, editable installs), `poetry.lock`.
- Risk checks: unpinned and unbounded version specs, duplicate versions, licence
  classification (56 SPDX identifiers, six risk classes, OR/AND expressions), committed
  advisory snapshot matching, Damerau-Levenshtein typosquat detection against 282 popular
  packages, install-script detection, git/tarball/file source references, deprecated
  packages, and direct dependencies never imported by the source tree.
- Output: prioritised terminal report with ANSI colours and an ASCII fallback, stable
  `--json` schema (`dep-radar/scan@1`), self-contained `--html` report.
- `--fail-under` for CI gating; exit codes 0/1/2 documented in the README.
- `benchmarks/run.py` generating deterministic lockfiles and writing
  `benchmarks/results.json` plus `benchmarks/RESULTS.md`.
- Zero runtime dependencies; Python 3.10+.

[1.0.0]: https://github.com/kele-tao/dep-radar/releases/tag/v1.0.0