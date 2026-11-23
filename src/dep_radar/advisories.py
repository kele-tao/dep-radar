"""Offline advisory matching against a committed snapshot.

The snapshot (``data/advisories.json``) is a hand-curated list of public npm
and PyPI incidents: malicious releases, well-known CVEs and deprecated
packages. It is deliberately versioned in git so scans are reproducible; it is
not a live feed and the README says so.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

from .model import Package, Severity
from .semver import satisfies

DATA_DIR = Path(__file__).with_name("data")


@dataclass
class Advisory:
    """One entry of the committed advisory snapshot."""

    id: str
    ecosystem: str
    package: str
    kind: str  # malicious | vulnerable | deprecated
    affected: str
    severity: Severity
    summary: str
    cve: str = ""


@dataclass
class AdvisoryHit:
    """A package that matches an advisory."""

    advisory: Advisory
    package: Package


@lru_cache(maxsize=1)
def load_advisories() -> tuple[Advisory, ...]:
    """Load and validate the committed advisory snapshot."""
    path = DATA_DIR / "advisories.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    entries: list[Advisory] = []
    for raw in data["entries"]:
        entries.append(
            Advisory(
                id=str(raw["id"]),
                ecosystem=str(raw["ecosystem"]),
                package=str(raw["package"]).lower(),
                kind=str(raw["kind"]),
                affected=str(raw.get("affected", "*")),
                severity=Severity(str(raw.get("severity", "medium"))),
                summary=str(raw.get("summary", "")),
                cve=str(raw.get("cve", "")),
            )
        )
    entries.sort(key=lambda a: (a.package, a.id))
    return tuple(entries)


@lru_cache(maxsize=1)
def advisories_by_package() -> dict[str, tuple[Advisory, ...]]:
    table: dict[str, list[Advisory]] = {}
    for advisory in load_advisories():
        table.setdefault(advisory.package, []).append(advisory)
    return {key: tuple(value) for key, value in table.items()}


def match_package(package: Package) -> list[AdvisoryHit]:
    """Every advisory whose affected range covers this package instance."""
    table = advisories_by_package()
    candidates = table.get(package.name.lower(), ())
    hits: list[AdvisoryHit] = []
    for advisory in candidates:
        if advisory.ecosystem != package.ecosystem.value:
            continue
        if advisory.kind == "deprecated":
            hits.append(AdvisoryHit(advisory=advisory, package=package))
            continue
        if package.version and satisfies(package.version, advisory.affected):
            hits.append(AdvisoryHit(advisory=advisory, package=package))
    return hits


def scan(project) -> list[AdvisoryHit]:
    """Match every package in *project* against the snapshot."""
    hits: list[AdvisoryHit] = []
    for package in project.packages.values():
        hits.extend(match_package(package))
    hits.sort(key=lambda h: (h.advisory.severity.rank, h.package.name, h.advisory.id))
    return hits


def snapshot_meta() -> dict:
    """Metadata about the committed snapshot, shown in the report footer."""
    path = DATA_DIR / "advisories.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    return {
        "updated": data.get("updated", ""),
        "count": len(load_advisories()),
        "schema": data.get("schema", ""),
    }
