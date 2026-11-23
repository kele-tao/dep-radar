"""Typosquat detection with Damerau-Levenshtein distance.

A typosquat is a package whose name is one or two edits away from a very
popular package it does not belong to: ``lodahs`` (transposition),
``expresss`` (insertion), ``reqeusts`` (typo in a top PyPI package).
We only report a hit when the candidate is *not itself* popular, so real
packages that happen to sit close to each other stay quiet.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

DATA_DIR = Path(__file__).with_name("data")

# Names shorter than this produce too many false positives (e.g. 'ws' vs 'qs').
MIN_NAME_LENGTH = 5
# Real packages whose names sit one edit from an unrelated popular name. Every
# entry here was a false positive found by scanning the bundled npm example;
# keeping the list short and reviewed beats silently lowering recall.
BENIGN_LOOKALIKES = {
    "acorn",
    "ansi-regex",
    "array-flatten",
    "balanced-match",
    "brace-expansion",
    "bytes",
    "combined-stream",
    "concat-map",
    "content-type",
    "cookie",
    "deep-is",
    "delayed-stream",
    "depd",
    "doctrine",
    "encodeurl",
    "es-errors",
    "escape-html",
    "esquery",
    "esutils",
    "etag",
    "fill-range",
    "finalhandler",
    "forwarded",
    "fresh",
    "has-flag",
    "has-symbols",
    "iconv-lite",
    "ignore",
    "inflight",
    "inherits",
    "is-number",
    "isexe",
    "js-tokens",
    "levn",
    "media-typer",
    "methods",
    "mime",
    "mime-db",
    "mime-types",
    "negotiator",
    "object-inspect",
    "on-finished",
    "once",
    "parseurl",
    "path-key",
    "path-to-regexp",
    "prelude-ls",
    "proxy-addr",
    "proxy-from-env",
    "punycode",
    "range-parser",
    "safe-buffer",
    "safer-buffer",
    "scheduler",
    "set-function-length",
    "setprototypeof",
    "shebang-regex",
    "statuses",
    "text-table",
    "to-regex-range",
    "toidentifier",
    "type-check",
    "type-is",
    "unpipe",
    "utils-merge",
    "vary",
    "which",
    "word-wrap",
    "wrappy",
}


@dataclass
class TyposquatHit:
    """One suspicious name and the popular package it resembles."""

    package: str
    target: str
    distance: int
    ecosystem: str
    edit_kind: str

    @property
    def message(self) -> str:
        return (
            self.package
            + " is "
            + str(self.distance)
            + " edit(s) from the popular package "
            + self.target
            + " ("
            + self.edit_kind
            + ")"
        )


@lru_cache(maxsize=1)
def popular_packages() -> dict[str, str]:
    """The committed popular-package list, name -> ecosystem."""
    path = DATA_DIR / "popular.json"
    return json.loads(path.read_text(encoding="utf-8"))


@lru_cache(maxsize=1)
def popular_by_ecosystem() -> dict[str, tuple[str, ...]]:
    table: dict[str, list[str]] = {}
    for name, ecosystem in popular_packages().items():
        table.setdefault(ecosystem, []).append(name)
    return {key: tuple(sorted(values)) for key, values in table.items()}


@lru_cache(maxsize=1)
def popular_by_length() -> dict[str, dict[int, tuple[tuple[str, str], ...]]]:
    """ecosystem -> name length -> (normalised, original) popular names.

    Two prefilters keep the O(packages * popular) product small: names are
    bucketed by length (only lengths within max_distance can match) and are
    stored pre-normalised, so the inner loop is pure integer DP.
    """
    table: dict[str, dict[int, list[tuple[str, str]]]] = {}
    for name, ecosystem in popular_packages().items():
        base = normalise(name)
        table.setdefault(ecosystem, {}).setdefault(len(base), []).append((base, name))
    return {
        eco: {length: tuple(sorted(entries)) for length, entries in buckets.items()}
        for eco, buckets in table.items()
    }


def normalise(name: str) -> str:
    """Normalise a package name for distance comparison."""
    lowered = name.strip().lower()
    if lowered.startswith("@") and "/" in lowered:
        # '@scope/name' -> compare only the final segment, the scope is deliberate.
        lowered = lowered.split("/", 1)[1]
    return re.sub(r"[-_.]+", "-", lowered)


def damerau_levenshtein(left: str, right: str, max_distance: int = 2) -> int:
    """Optimal-string-alignment distance, cut off at *max_distance* + 1.

    The edit distance is invariant under deleting a common prefix and suffix,
    so those are stripped first: on real package names that removes almost all
    of the O(n*m) work before it starts. The remaining matrices are computed
    with three rolling rows and an early row-minimum bailout.
    """
    if left == right:
        return 0
    start = 0
    limit = min(len(left), len(right))
    while start < limit and left[start] == right[start]:
        start += 1
    end_left, end_right = len(left), len(right)
    while end_left > start and end_right > start and left[end_left - 1] == right[end_right - 1]:
        end_left -= 1
        end_right -= 1
    left = left[start:end_left]
    right = right[start:end_right]
    if left == right:
        return 0
    if abs(len(left) - len(right)) > max_distance:
        return max_distance + 1
    if not left:
        return len(right)
    if not right:
        return len(left)
    width = len(right)
    over = max_distance + 1
    previous_previous: list[int] = [over] * (width + 1)
    previous: list[int] = [over] * (width + 1)
    for j in range(0, min(width, max_distance) + 1):
        previous[j] = j
    for i in range(1, len(left) + 1):
        current: list[int] = [over] * (width + 1)
        low = max(1, i - max_distance)
        high = min(width, i + max_distance)
        if low == 1:
            current[0] = i
        row_min = over
        for j in range(low, high + 1):
            cost = 0 if left[i - 1] == right[j - 1] else 1
            value = previous[j - 1] + cost
            insertion = current[j - 1] + 1
            if insertion < value:
                value = insertion
            deletion = previous[j] + 1
            if deletion < value:
                value = deletion
            if (
                i > 1
                and j > 1
                and left[i - 1] == right[j - 2]
                and left[i - 2] == right[j - 1]
            ):
                transposed = previous_previous[j - 2] + 1
                if transposed < value:
                    value = transposed
            current[j] = value
            if value < row_min:
                row_min = value
        if row_min > max_distance:
            return over
        previous_previous, previous = previous, current
    result = previous[width]
    return result if result <= max_distance else over


def _edit_kind(source: str, target: str) -> str:
    """Name the edit that separates the candidate from the popular package."""
    if len(source) == len(target):
        diffs = [(i, a, b) for i, (a, b) in enumerate(zip(source, target, strict=True)) if a != b]
        if len(diffs) == 2 and diffs[0][0] + 1 == diffs[1][0]:
            return "adjacent transposition"
        return "substitution"
    return "insertion" if len(source) > len(target) else "deletion"


def find_typosquats(
    names: list[str] | dict[str, str],
    ecosystem: str = "npm",
    max_distance: int = 2,
) -> list[TyposquatHit]:
    """Return suspicious names, sorted by distance then name.

    *names* is either a list of names or a mapping of name -> ecosystem. Names
    that are themselves in the popular list are never reported.
    """
    if isinstance(names, dict):
        candidates = sorted({(name, eco) for name, eco in names.items()})
    else:
        candidates = sorted({(name, ecosystem) for name in names})
    popular = popular_packages()
    by_length = popular_by_length()
    hits: list[TyposquatHit] = []
    seen: set[tuple[str, str]] = set()
    for name, eco in candidates:
        base = normalise(name)
        if not base or len(base) < MIN_NAME_LENGTH:
            continue
        if name.lower() in popular or base in popular or base in BENIGN_LOOKALIKES:
            continue
        best: TyposquatHit | None = None
        buckets = by_length.get(eco, {})
        candidates_of_len: list[tuple[str, str]] = []
        for length in range(len(base) - max_distance, len(base) + max_distance + 1):
            candidates_of_len.extend(buckets.get(length, ()))
        for target_base, target in candidates_of_len:
            if target_base == base:
                continue
            distance = damerau_levenshtein(base, target_base, max_distance)
            if distance == 0 or distance > max_distance:
                continue
            hit = TyposquatHit(
                package=name,
                target=target,
                distance=distance,
                ecosystem=eco,
                edit_kind=_edit_kind(base, target_base),
            )
            if best is None or (hit.distance, hit.target) < (best.distance, best.target):
                best = hit
        if best is not None and (best.package, best.target) not in seen:
            seen.add((best.package, best.target))
            hits.append(best)
    hits.sort(key=lambda h: (h.distance, h.package))
    return hits
