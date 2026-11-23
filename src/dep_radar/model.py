"""Core data model: packages, edges and the project graph."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path


class Ecosystem(str, Enum):
    """The package ecosystem a node belongs to."""

    NPM = "npm"
    PYPI = "pypi"


class Severity(str, Enum):
    """Finding severity, ordered from most to least urgent."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        return {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}[self.value]

    @property
    def weight(self) -> int:
        """Points deducted from the 100-point supply-chain score."""
        return {"critical": 30, "high": 12, "medium": 5, "low": 2, "info": 0}[self.value]


@dataclass
class Dependency:
    """A declared dependency edge, before resolution."""

    name: str
    spec: str = ""
    kind: str = "prod"  # prod | dev | optional | peer
    marker: str = ""  # PEP 508 environment marker, kept verbatim


@dataclass
class Package:
    """One resolved package instance (name + version)."""

    key: str
    name: str
    ecosystem: Ecosystem
    version: str | None = None
    license: str | None = None
    resolved: str = ""
    integrity: str = ""
    dependencies: list[Dependency] = field(default_factory=list)
    source_kind: str = "registry"  # registry | git | url | tarball | file
    source_ref: str = ""
    scripts: dict[str, str] = field(default_factory=dict)
    dev: bool = False
    optional: bool = False
    deprecated: str = ""
    install_path: str = ""  # path inside node_modules or site-packages, used for resolution
    has_install_script: bool = False

    @property
    def display(self) -> str:
        return self.name + ("@" + self.version if self.version else "")

    @property
    def purl(self) -> str:
        """Package URL (https://github.com/package-url/purl-spec)."""
        kind = "npm" if self.ecosystem is Ecosystem.NPM else "pypi"
        version = self.version or ""
        return "pkg:" + kind + "/" + self.name + ("@" + version if version else "")


@dataclass
class Edge:
    """A resolved (or declared) parent -> child edge."""

    parent: str  # package key, or "" for the project root
    child: str  # package key
    spec: str = ""
    kind: str = "prod"


@dataclass
class Project:
    """A scanned project: the graph plus provenance."""

    root: Path
    ecosystem: Ecosystem
    packages: dict[str, Package] = field(default_factory=dict)
    edges: list[Edge] = field(default_factory=list)
    manifests: list[str] = field(default_factory=list)
    lockfile: str = ""
    lockfile_version: int = 0
    warnings: list[str] = field(default_factory=list)

    def direct_dependencies(self) -> list[Dependency]:
        return [d for d in self._root_declared]

    _root_declared: list[Dependency] = field(default_factory=list)

    def children(self, key: str) -> list[Edge]:
        return [e for e in self.edges if e.parent == key]

    def parents(self, key: str) -> list[Edge]:
        return [e for e in self.edges if e.child == key]

    def add_package(self, package: Package) -> Package:
        existing = self.packages.get(package.key)
        if existing is None:
            self.packages[package.key] = package
            return package
        return existing


_VERSION_RE = re.compile(r"^[vV]?\d+(?:\.\d+)*")


def version_tuple(version: str) -> tuple[int, ...]:
    """Turn '1.20.3-beta.1' into a comparable integer tuple.

    Trailing pre-release segments are dropped, which is what an offline audit
    wants: 4.17.21-rc.1 sorts as 4.17.21.
    """
    text = version.strip().lstrip("vV=")
    match = _VERSION_RE.match(text)
    if not match:
        return (0,)
    parts: list[int] = []
    for chunk in match.group(0).lstrip("vV").split("."):
        digits = ""
        for ch in chunk:
            if not ch.isdigit():
                break
            digits += ch
        parts.append(int(digits) if digits else 0)
    while len(parts) > 1 and parts[-1] == 0:
        parts.pop()
    return tuple(parts)


def compare_versions(left: str, right: str) -> int:
    """Return -1, 0 or 1 for left < right, left == right, left > right."""
    a = version_tuple(left)
    b = version_tuple(right)
    width = max(len(a), len(b))
    a = a + (0,) * (width - len(a))
    b = b + (0,) * (width - len(b))
    return (a > b) - (a < b)
