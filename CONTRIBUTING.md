# Contributing to dep-radar

Thanks for taking the time. This project is small on purpose: one CLI, one graph, one
score. Contributions that keep it that way are the easiest to merge.

## Setup

```bash
git clone https://github.com/kele-tao/dep-radar.git
cd dep-radar
python -m venv .venv
# Windows: .venv\Scripts\activate    POSIX: source .venv/bin/activate
pip install -e ".[dev]"
```

## The quality bar

Any change must keep these green:

```bash
ruff check .          # line length 100, imports sorted, modern syntax
pytest -q             # offline, no network, no sleeps
python -m dep_radar scan examples/node-app
python benchmarks/run.py --sizes 1000 --repeats 3
```

House rules:

- **No network at scan time or in tests.** If a feature needs a registry, it belongs in a
  separate, explicitly-invoked command and must be mocked in tests.
- **Every output number must be reproducible.** If you add a table to the README, it must
  come from a script in the repository.
- **User errors are not tracebacks.** Raise `UsageError` in `cli.py` with a sentence that
  tells the user what to do next.
- **Fixtures are generated.** `examples/` is produced by `scripts/gen_examples.py`; edit
  the generator and re-run it instead of hand-editing a lockfile.
- **Determinism is a feature.** Sort anything that reaches the output; no `uuid4`, no
  `datetime.now()` in generated documents.

## Adding a check

1. Add a `_your_check(project, findings)` function in `src/dep_radar/analyzer.py`.
2. Pick a category and a severity; if you add a category, add it to `CATEGORY_CAPS` and
   document the cap in `docs/SCORING.md`.
3. Add fixtures to the tests that are *known* to trigger and *known* to not trigger.
4. Add one line to the README "What it does" list and to `CHANGELOG.md`.

## Adding a parser

Create `src/dep_radar/parsers/<format>.py` exposing `parse_<format>_project(root) ->
Project | None`, and wire it into `parsers/__init__.py`. Parsers must never raise on
missing optional fields; they should append a warning to `project.warnings`. A malformed
file raises `ValueError` with the file name and position, which `cli.py` turns into a
usage error.

## Pull requests

- One logical change per PR, with a short description of the behaviour change.
- Tests for the new behaviour, and a note in `CHANGELOG.md` under "Unreleased".
- If you change the score formula, include the before/after numbers in the PR body.

## Reporting security issues

See [SECURITY.md](SECURITY.md). Do not open a public issue for a vulnerability in
dep-radar itself.
