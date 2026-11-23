"""Offline licence classification from an SPDX-ish table.

The table lives in ``data/licenses.json`` so it can be reviewed and extended
without touching code. Expressions are parsed properly: ``MIT OR GPL-3.0``
keeps both terms, and the weakest branch wins for OR, the worst for AND.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

DATA_DIR = Path(__file__).with_name("data")

RISK_ORDER = ["public-domain", "permissive", "weak-copyleft", "copyleft", "proprietary", "unknown"]

_LICENSE_ALIASES = {
    "mit license": "MIT",
    "the mit license": "MIT",
    "apache license 2.0": "Apache-2.0",
    "apache 2.0": "Apache-2.0",
    "apache-2": "Apache-2.0",
    "bsd": "BSD-3-Clause",
    "bsd license": "BSD-3-Clause",
    "new bsd": "BSD-3-Clause",
    "isc license": "ISC",
    "gpl": "GPL-3.0",
    "gplv3": "GPL-3.0",
    "gplv2": "GPL-2.0",
    "lgpl": "LGPL-3.0",
    "mpl": "MPL-2.0",
    "the unlicense": "Unlicense",
    "unlicensed": "UNLICENSED",
}


@dataclass
class LicenseVerdict:
    """What a declared licence string means for a commercial consumer."""

    declared: str
    terms: list[str] = field(default_factory=list)
    category: str = "unknown"
    detail: str = ""

    @property
    def risk(self) -> int:
        """0 for public domain, 5 for unknown: higher means more review needed."""
        try:
            return RISK_ORDER.index(self.category)
        except ValueError:
            return 5

    @property
    def is_missing(self) -> bool:
        return not self.declared.strip()


@lru_cache(maxsize=1)
def license_table() -> dict[str, tuple[str, str]]:
    """Load the committed licence table, keyed by lower-case SPDX id."""
    path = DATA_DIR / "licenses.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    table: dict[str, tuple[str, str]] = {}
    for key, value in data["licenses"].items():
        category, detail = value
        table[key] = (category, detail)
    return table


def known_licenses() -> list[str]:
    """All SPDX identifiers in the committed table, sorted."""
    return sorted(license_table())


def _normalise_term(term: str) -> str:
    cleaned = term.strip().strip("()").strip()
    if not cleaned:
        return ""
    alias = _LICENSE_ALIASES.get(cleaned.lower())
    if alias is not None:
        return alias
    return re.sub(r"-only$", "", cleaned, flags=re.IGNORECASE)


def parse_expression(declared: str) -> tuple[list[str], list[str]]:
    """Split a SPDX expression into (terms, operators)."""
    text = (declared or "").strip()
    if not text:
        return [], []
    tokens = re.split(r"\s+(AND|OR|WITH)\s+|([()])", text)
    terms: list[str] = []
    operators: list[str] = []
    for token in tokens:
        if token is None:
            continue
        token = token.strip()
        if not token:
            continue
        if token in {"AND", "OR", "WITH", "(", ")"}:
            operators.append(token)
            continue
        normalised = _normalise_term(token)
        if normalised:
            terms.append(normalised)
    return terms, operators


def _risk_of(category: str) -> int:
    try:
        return RISK_ORDER.index(category)
    except ValueError:
        return 5


def classify(declared: str | None) -> LicenseVerdict:
    """Classify a declared licence string for a commercial consumer."""
    raw = (declared or "").strip()
    if not raw:
        return LicenseVerdict(declared="", category="unknown", detail="no licence declared")
    terms, operators = parse_expression(raw)
    if not terms:
        return LicenseVerdict(
            declared=raw,
            category="unknown",
            detail="unrecognised licence text (bespoke or vendor licence)",
        )
    table = license_table()
    categories: list[str] = []
    details: list[str] = []
    for term in terms:
        entry = table.get(term.lower())
        if entry is None:
            categories.append("unknown")
            details.append(term + " is not in the offline table")
        else:
            categories.append(entry[0])
            if entry[0] in {"copyleft", "proprietary", "weak-copyleft"}:
                details.append(term + ": " + entry[1])
    if "OR" in operators and "AND" not in operators:
        category = min(categories, key=_risk_of)
    else:
        category = max(categories, key=_risk_of)
    if not details:
        details.append(terms[0] + " (" + category + ")")
    return LicenseVerdict(
        declared=raw,
        terms=terms,
        category=category,
        detail="; ".join(details),
    )


def classify_project_license(root: Path) -> LicenseVerdict:
    """Best-effort lookup of the project's own licence, for the report header."""
    for name in ("LICENSE", "LICENSE.md", "LICENSE.txt", "COPYING"):
        path = root / name
        if not path.exists():
            continue
        head = path.read_text(encoding="utf-8", errors="replace")[:2000].lower()
        if "mit license" in head:
            return classify("MIT")
        if "apache license" in head:
            return classify("Apache-2.0")
        if "gnu affero" in head:
            return classify("AGPL-3.0")
        if "gnu general public license" in head:
            return classify("GPL-3.0" if "version 3" in head else "GPL-2.0")
        if "mozilla public license" in head:
            return classify("MPL-2.0")
        if "bsd" in head:
            return classify("BSD-3-Clause")
        return classify("")
    return LicenseVerdict(declared="", category="unknown", detail="no LICENSE file found")
