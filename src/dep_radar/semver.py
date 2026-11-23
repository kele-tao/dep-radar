"""Version-range classification and offline range matching.

dep-radar never resolves versions from the network: it classifies the spec a
manifest declares (so it can flag '>=1.0.0' as unbounded) and matches resolved
versions against the small range language used by the advisory snapshot.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from .model import compare_versions, version_tuple

EXACT_PREFIXES = ("==", "===")
WILDCARD_CHARS = ("*", "x", "X")
_URL_PREFIXES = (
    "http://",
    "https://",
    "git+",
    "git://",
    "ssh://",
    "file:",
    "git@",
    "github:",
    "gitlab:",
    "bitbucket:",
    "workspace:",
    "link:",
    "portal:",
)


@dataclass(frozen=True)
class VersionSpec:
    """A declared version constraint, classified."""

    raw: str
    kind: str  # url | any | exact | wildcard | caret | tilde | compatible | range
    lower: str = ""
    upper: str = ""

    @property
    def is_floating(self) -> bool:
        """True when the spec does not pin a single version."""
        return self.kind not in {"exact", "url"}

    @property
    def is_unbounded(self) -> bool:
        """True when the spec admits arbitrarily high future versions."""
        if self.kind in {"any", "wildcard"}:
            return True
        if self.kind == "range":
            return not self.upper
        return self.kind in {"caret", "tilde", "compatible"} and not self.upper

    def describe(self) -> str:
        """A short human explanation used in findings."""
        return {
            "any": "accepts any version, including future major releases",
            "wildcard": "wildcard spec, any matching major is accepted",
            "range": "range spec without an upper bound",
            "caret": "caret range permits non-breaking upgrades",
            "tilde": "tilde range permits patch upgrades",
            "compatible": "PEP 440 compatible-release operator",
            "exact": "pinned",
            "url": "source dependency outside the registry",
        }.get(self.kind, self.kind)


def _strip_trailing_star(raw: str) -> str:
    return raw.replace(" ", "")


def classify(spec: str) -> VersionSpec:
    """Classify a version spec from package.json, requirements.txt or pyproject."""
    raw = (spec or "").strip()
    if not raw:
        return VersionSpec(raw="", kind="any")
    lowered = raw.lower()
    if lowered.startswith(_URL_PREFIXES):
        return VersionSpec(raw=raw, kind="url")
    if raw in {"*", "latest", "x", "X"} or lowered == "":
        return VersionSpec(raw=raw, kind="any")
    if raw.startswith("^"):
        body = raw[1:].strip()
        if _has_wildcard(body):
            return VersionSpec(raw=raw, kind="wildcard", lower=body)
        return VersionSpec(raw=raw, kind="caret", lower=body)
    if raw.startswith("~") and not raw.startswith("~="):
        body = raw[1:].strip()
        if _has_wildcard(body):
            return VersionSpec(raw=raw, kind="wildcard", lower=body)
        return VersionSpec(raw=raw, kind="tilde", lower=body)
    if raw.startswith("~="):
        return VersionSpec(raw=raw, kind="compatible", lower=raw[2:].strip())
    if raw.startswith(EXACT_PREFIXES):
        return VersionSpec(raw=raw, kind="exact", lower=raw.lstrip("=").strip())
    if raw.startswith("=") and len(raw) > 1:
        return VersionSpec(raw=raw, kind="exact", lower=raw[1:].strip())
    if _has_wildcard(raw):
        return VersionSpec(raw=raw, kind="wildcard", lower=raw)
    if any(op in raw for op in (">=", "<=", ">", "<", "!=")):
        lower, upper = _bounds(raw)
        return VersionSpec(raw=raw, kind="range", lower=lower, upper=upper)
    if re.fullmatch(r"[vV]?\d+(?:\.\d+)*", raw):
        return VersionSpec(raw=raw, kind="exact", lower=raw)
    # PEP 440 arbitrary equality, epochs and local versions are treated as exact.
    if re.fullmatch(r"[vV]?\d[\w.+-]*", raw):
        return VersionSpec(raw=raw, kind="exact", lower=raw)
    return VersionSpec(raw=raw, kind="range", lower=raw)


def _has_wildcard(text: str) -> bool:
    return any(ch in text for ch in WILDCARD_CHARS)


def _bounds(raw: str) -> tuple[str, str]:
    lower = ""
    upper = ""
    for clause in re.split(r",|\s+", raw.strip()):
        clause = clause.strip()
        if not clause:
            continue
        if clause.startswith(">=") or clause.startswith(">"):
            value = clause.lstrip(">=")
            if not lower or compare_versions(value, lower) > 0:
                lower = value
        elif clause.startswith("<=") or clause.startswith("<"):
            value = clause.lstrip("<=")
            if not upper or compare_versions(value, upper) < 0:
                upper = value
    return lower, upper


def satisfies(version: str, spec: str) -> bool:
    """Match a concrete version against the small range language used offline.

    Supports '*', exact versions, '<X', '<=X', '>X', '>=X', comma or space
    separated conjunctions, and 'a - b' hyphen ranges. Anything it cannot
    parse is treated as non-matching so the tool never invents a CVE hit.
    """
    raw = (spec or "").strip()
    if not raw or raw == "*":
        return True
    hyphen = re.fullmatch(r"([\w.+-]+)\s+-\s+([\w.+-]+)", raw)
    if hyphen:
        return compare_versions(version, hyphen.group(1)) >= 0 and (
            compare_versions(version, hyphen.group(2)) <= 0
        )
    for clause in re.split(r",", raw):
        clause = clause.strip()
        if not clause:
            continue
        match = re.fullmatch(r"(<=|>=|<|>|=)?\s*([\w.+*-]+)", clause)
        if not match:
            return False
        op = match.group(1) or "="
        target = match.group(2)
        if target in {"*", "x", "X"}:
            continue
        cmp = compare_versions(version, target)
        ok = {
            "=": cmp == 0,
            "==": cmp == 0,
            ">": cmp > 0,
            ">=": cmp >= 0,
            "<": cmp < 0,
            "<=": cmp <= 0,
        }.get(op, False)
        if not ok:
            return False
    return True


def is_pinned(spec: str) -> bool:
    """True when the spec names exactly one version."""
    return classify(spec).kind == "exact" and bool(spec.strip())

def _node_range_clause(version: str, clause: str) -> bool:
    """Match one npm semver comparator clause against a concrete version."""
    clause = clause.strip()
    if not clause or clause == "*" or clause in {"x", "X"}:
        return True
    if clause.startswith("^"):
        base_version = clause[1:].strip()
        if not re.search(r"\d", base_version):
            return True
        major, minor, patch = _triple(base_version)
        if major > 0:
            upper = f"{major + 1}.0.0"
        elif minor > 0:
            upper = f"0.{minor + 1}.0"
        else:
            upper = f"0.0.{patch + 1}"
        return compare_versions(version, base_version) >= 0 and compare_versions(version, upper) < 0
    if clause.startswith("~"):
        base_version = clause[1:].strip()
        if not re.search(r"\d", base_version):
            return True
        major, minor, _patch = _triple(base_version)
        upper = f"{major + 1}.0.0" if "." not in base_version else f"{major}.{minor + 1}.0"
        return compare_versions(version, base_version) >= 0 and compare_versions(version, upper) < 0
    wildcard = re.fullmatch(r"(\d+)(?:\.(\d+))?(?:\.(\d+))?\.[xX*]|\*", clause)
    if wildcard and wildcard.group(1):
        prefix = [int(g) for g in wildcard.groups() if g is not None]
        actual = version_tuple(version)
        return list(actual[: len(prefix)]) == prefix
    match = re.fullmatch(r"(<=|>=|<|>|=)?\s*[vV]?(\d[\w.+-]*)", clause)
    if not match:
        return False
    op = match.group(1) or "="
    target = match.group(2)
    cmp = compare_versions(version, target)
    if op == ">=":
        return cmp >= 0
    if op == ">":
        return cmp > 0
    if op == "<=":
        return cmp <= 0
    if op == "<":
        return cmp < 0
    return cmp == 0


def _triple(text: str) -> tuple[int, int, int]:
    parts = [int(p) if p.isdigit() else 0 for p in text.split("-")[0].split(".")]
    while len(parts) < 3:
        parts.append(0)
    return parts[0], parts[1], parts[2]


def satisfies_node_range(version: str, spec: str) -> bool:
    """Match a version against npm's range syntax: ||, ^, ~, x-ranges and comparators."""
    raw = (spec or "").strip()
    if not raw:
        return True
    for alternative in raw.split("||"):
        alternative = alternative.strip()
        hyphen = re.fullmatch(r"([\w.+-]+)\s+-\s+([\w.+-]+)", alternative)
        if hyphen:
            if compare_versions(version, hyphen.group(1)) >= 0 and (
                compare_versions(version, hyphen.group(2)) <= 0
            ):
                return True
            continue
        clauses = [c for c in re.split(r"\s+", alternative) if c]
        if all(_node_range_clause(version, clause) for clause in clauses):
            return True
    return False


def upper_bound_of(spec: str) -> str:
    """Best-effort upper bound of a spec, used for 'unbounded range' findings."""
    return classify(spec).upper
