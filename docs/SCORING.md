# Scoring: how the 0-100 supply-chain score is computed

The score is a pure function of the findings, implemented in
`dep_radar.analyzer.compute_score`. It is deterministic: the same tree always produces
the same number, and there are no random components.

## Weights

Each finding has a severity; severities map to raw penalty points:

| Severity | Raw points | Typical cause |
| --- | ---: | --- |
| critical | 30 | typosquat, malicious release in the advisory snapshot |
| high | 12 | copyleft/proprietary licence, unpinned dependency, known vulnerable version |
| medium | 5 | unbounded range, install script, git/tarball source, duplicate versions |
| low | 2 | weak copyleft, missing licence metadata, 0.x caret range |
| info | 0 | unused direct dependency (reported, never scored) |

## Per-category caps and diminishing returns

Raw points are summed **per category**, then each category's total is compressed through

```
penalty(category) = cap(category) * (1 - e^(-raw / cap(category)))
score             = round(100 - sum(penalty))   clamped to [0, 100]
```

The caps live in `CATEGORY_CAPS`:

| Category | Cap |
| --- | ---: |
| advisory | 40 |
| typosquat | 32 |
| version-pin | 18 |
| licence | 16 |
| install-script | 14 |
| source-ref | 12 |
| duplicate | 8 |
| abandoned | 8 |
| unused | 6 |

Why the exponential rather than `min(raw, cap)`: a requirements.txt with 60 unbounded
ranges should not score the same as one with 8. With a hard `min`, categories saturate
immediately and the ninth problem becomes free - the score stops responding to real
improvements. With the exponential curve the first finding in a category costs about
63% of the cap, the fifth about 99% of it, and the difference between 8 and 60 problems
is still visible (a few tenths of a point) without letting one category take the whole
score.

## Grade bands

| Score | Grade | Verdict shown |
| ---: | :---: | --- |
| 90-100 | A | ship it |
| 80-89 | B | minor cleanup |
| 70-79 | C | needs work |
| 60-69 | D | risky |
| 0-59 | F | do not ship |

## Worked example: the bundled `examples/node-app`

That fixture deliberately contains two typosquats, an AGPL package, an unlicensed
tarball package, an install script, duplicate versions and deprecated packages. The raw
points per category are:

| Category | Findings | Raw | Cap | Penalty |
| --- | ---: | ---: | ---: | ---: |
| typosquat | 2 | 60 | 32 | 27.09 |
| licence | 2 | 24 | 16 | 12.43 |
| version-pin | 1 | 12 | 18 | 8.76 |
| abandoned | 2 | 10 | 8 | 5.71 |
| source-ref | 2 | 7 | 12 | 5.30 |
| duplicate | 3 | 6 | 8 | 4.22 |
| install-script | 1 | 5 | 14 | 4.20 |
| advisory | 2 | 4 | 40 | 3.81 |
| unused | 6 | 0 | 6 | 0.00 |
| **total** | | | | **71.52** |

`round(100 - 71.52) = 28`, so the report prints `28/100 grade F`. The table is
reproducible with:

```bash
python - <<'PY'
import sys; sys.path.insert(0, "src")
from collections import defaultdict
from pathlib import Path
from dep_radar.analyzer import CATEGORY_CAPS, analyze, category_penalty
from dep_radar.parsers import parse_ecosystem

root = Path("examples/node-app")
analysis = analyze(parse_ecosystem(root, "npm"), root=root)
raw, counts = defaultdict(int), defaultdict(int)
for finding in analysis.findings:
    raw[finding.category] += finding.severity.weight
    counts[finding.category] += 1
for category, points in sorted(raw.items(), key=lambda kv: -category_penalty(*kv)):
    print(category, counts[category], points, CATEGORY_CAPS[category],
          round(category_penalty(category, points), 2))
print("score", analysis.score)
PY
```

Removing both typosquats alone would move the score above 50; that ordering is
intentional, since a lookalike package is the one finding that can compromise a machine
during `npm install`.

## What the score is not

It is not a probability of compromise, and it is not comparable across ecosystems:
a Python tree cannot be flagged for install scripts because PEP 517 does not run package
code at install time, so its ceiling is structurally higher. Compare a project against
its own history, not against another project.
