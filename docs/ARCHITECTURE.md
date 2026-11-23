# Architecture

```
src/dep_radar/
  model.py        Package / Edge / Project / Severity; version comparison
  semver.py       version-spec classification, PEP 440 and npm range matching
  parsers/
    npm.py        package.json, package-lock v1/v2/v3, yarn.lock v1
    python.py     pyproject (PEP 621 + Poetry), requirements.txt (-r, extras, markers), poetry.lock
  graph.py        BFS depth, path enumeration, duplicate detection, explain()
  licenses.py     SPDX-ish offline table, expression evaluation
  typosquat.py    Damerau-Levenshtein with length bucketing, popular-name list
  advisories.py   committed advisory snapshot matching
  source_scan.py  Python AST + JS/TS import extraction, unused direct deps
  analyzer.py     findings, categories, score
  report.py       terminal / JSON / HTML rendering
  sbom.py         CycloneDX-like and SPDX-like documents
  cli.py          argparse CLI, exit codes, friendly errors
  data/           committed snapshots: popular.json, licenses.json, advisories.json
```

## Layering rules

1. `model.py` imports nothing from the rest of the package; everything can import it.
2. `parsers/` only produces graphs. It never scores, renders or reaches the network.
3. `analyzer.py` is the only place that decides severity and score.
4. `report.py` and `sbom.py` are pure renderers: `Analysis -> str`. That is what makes
   `tests/test_report.py` able to assert on output without touching the filesystem.
5. `cli.py` is the only module that prints to stdout, writes files or exits.

## Determinism

- Dict iteration is sorted wherever it can leak into output.
- Findings are sorted by `(severity rank, category, package)`.
- CycloneDX `serialNumber` is `uuid5` over the project path, not `uuid4`.
- SBOM `timestamp` is `SOURCE_DATE_EPOCH` when set, otherwise a fixed constant
  (`2026-01-01T00:00:00Z`), not `datetime.now()`.
- The benchmark generator uses no randomness.

`test_cli.py::test_scan_is_deterministic` runs the same scan twice and compares the JSON
byte for byte.

## Performance notes

The hot path for a 1000-package tree is typosquat distance computation. Three prefilters
make it cheap:

1. names shorter than 5 characters are skipped (they generate noise anyway);
2. names in the popular list or in the reviewed `BENIGN_LOOKALIKES` list are skipped;
3. candidate popular names are bucketed by *length*, and only lengths within
   `max_distance` are compared.

The remaining distance computations strip the common prefix/suffix before running the
three-row banded DP with an early row-minimum bailout. Measured effect on the 1000-package
benchmark, in this order of landing: 1941 ms (full DP over the full popular list) ->
1226 ms (length bucketing) -> 732 ms (banded DP, prefix stripping, pre-normalised names).
Absolute numbers move by roughly +-30% with machine load; the ratios are what matter.
See `benchmarks/RESULTS.md` for the current committed run.
