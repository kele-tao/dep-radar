"""Python manifest and requirements parsing (PEP 621, Poetry, requirements.txt).

Supports -r/--requirement includes, extras, PEP 508 environment markers, direct
URL references, editable installs, pip-style hashes and constraints/conversion
metadata. Versions are only resolved when the file pins them - offline means no
PEP 503 index lookups.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

try:  # Python 3.11+
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - exercised only on 3.10
    tomllib = None  # type: ignore[assignment]

from ..model import Dependency, Ecosystem, Edge, Package, Project

TOML_MISSING_MESSAGE = (
    "parsing pyproject.toml needs Python 3.11+ (this interpreter is "
    + ".".join(str(part) for part in sys.version_info[:2])
    + "); requirements.txt is still supported on 3.10 - upgrade Python or scan a "
    "requirements-only project"
)

REQUIREMENT_RE = re.compile(
    r"^\s*(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)"
    r"\s*(?:\[(?P<extras>[^\]]*)\])?"
    r"\s*(?P<spec>[^;@]*?)"
    r"\s*(?:@\s*(?P<url>\S+))?"
    r"\s*(?:;\s*(?P<marker>.+))?\s*$"
)

SKIP_OPTIONS = {
    "-i",
    "--index-url",
    "--extra-index-url",
    "-f",
    "--find-links",
    "--trusted-host",
    "--no-index",
    "--pre",
    "--no-binary",
    "--only-binary",
    "--require-hashes",
    "--use-feature",
}

NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")


class RequirementError(ValueError):
    """Raised when a requirements line cannot be parsed."""


def normalize_name(name: str) -> str:
    """PEP 503 normalisation: lowercase, runs of -_. collapsed to a single '-'."""
    return re.sub(r"[-_.]+", "-", name).lower()


def parse_requirement_line(line: str) -> Dependency | None:
    """Parse one requirements.txt line. Returns None for blanks, comments and options."""
    text = line.strip()
    if not text or text.startswith("#"):
        return None
    text = text.split(" #", 1)[0].strip()
    if not text:
        return None
    if text.startswith(("-", "--")):
        if text.startswith(("-r ", "--requirement ")):
            raise RequirementError(text)
        option = text.split()[0].split("=")[0]
        if option in SKIP_OPTIONS or line.strip().startswith("--hash"):
            return None
        if text.startswith("-e ") or text.startswith("--editable "):
            target = text.split(" ", 1)[1].strip()
            name = _name_from_url(target)
            if not name:
                return None
            return Dependency(name=normalize_name(name), spec=target, kind="prod")
        return None
    if text.startswith("-e"):
        return None
    text = text.split(" --hash", 1)[0].strip()
    match = REQUIREMENT_RE.match(text)
    if not match:
        raise RequirementError(f"cannot parse requirement: {line.strip()!r}")
    raw_name = match.group("name")
    if not NAME_RE.match(raw_name):
        raise RequirementError(f"invalid project name: {raw_name!r}")
    spec = (match.group("spec") or "").strip()
    url = match.group("url")
    if url and not spec:
        spec = url
    marker = (match.group("marker") or "").strip()
    extras = match.group("extras")
    name = normalize_name(raw_name)
    if extras:
        name = name + "[" + ",".join(sorted(e.strip() for e in extras.split(",") if e.strip())) + "]"
    return Dependency(name=name, spec=spec, marker=marker, kind="prod")


def _name_from_url(target: str) -> str:
    if "#egg=" in target:
        return target.split("#egg=", 1)[1].split("&")[0]
    return ""


def parse_requirements_file(path: Path, seen: set[Path] | None = None) -> list[Dependency]:
    """Parse a requirements.txt, following -r includes recursively."""
    seen = seen or set()
    resolved = path.resolve()
    if resolved in seen:
        return []
    seen.add(resolved)
    if not path.exists():
        raise RequirementError(f"requirements include not found: {path}")
    deps: list[Dependency] = []
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        try:
            include = _include_target(line)
            if include:
                deps.extend(parse_requirements_file(path.parent / include, seen))
                continue
            dep = parse_requirement_line(line)
        except RequirementError as exc:
            raise RequirementError(f"{path.name}:{number}: {exc}") from exc
        if dep is not None:
            deps.append(dep)
    return deps


def _include_target(line: str) -> str:
    text = line.strip()
    for prefix in ("-r ", "-r", "--requirement ", "--requirement=", "--requirement"):
        if text.startswith(prefix):
            target = text[len(prefix):].strip()
            if target:
                return target
    return ""


def _spec_from_pep440(raw: str) -> str:
    return raw.strip()


def _dependency_from(value: str, kind: str) -> Dependency | None:
    try:
        dep = parse_requirement_line(value)
    except RequirementError:
        return None
    if dep is None:
        return None
    dep.kind = kind
    return dep


def _parse_pyproject(path: Path) -> tuple[list[Dependency], dict]:
    if tomllib is None:  # pragma: no cover - exercised only on 3.10
        raise RequirementError(TOML_MISSING_MESSAGE)
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except tomllib.TOMLDecodeError as exc:
        raise RequirementError(f"{path.name} is not valid TOML: {exc}") from exc
    deps: list[Dependency] = []
    project = data.get("project") or {}
    for raw in project.get("dependencies", []) or []:
        dep = _dependency_from(str(raw), "prod")
        if dep is not None:
            deps.append(dep)
    optional = project.get("optional-dependencies") or {}
    for items in optional.values():
        for raw in items or []:
            dep = _dependency_from(str(raw), "optional")
            if dep is not None:
                deps.append(dep)
    for raw in project.get("dev-dependencies", []) or []:
        dep = _dependency_from(str(raw), "dev")
        if dep is not None:
            deps.append(dep)
    poetry = ((data.get("tool") or {}).get("poetry") or {})
    for key, kind in (
        ("dependencies", "prod"),
        ("dev-dependencies", "dev"),
    ):
        table = poetry.get(key) or {}
        for name, spec in table.items():
            if str(name).lower() == "python":
                continue
            deps.append(_poetry_dependency(str(name), spec, kind))
    groups = poetry.get("group") or {}
    for group in groups.values():
        for name, spec in (group.get("dependencies") or {}).items():
            if str(name).lower() == "python":
                continue
            deps.append(_poetry_dependency(str(name), spec, "dev"))
    return deps, data


def _poetry_dependency(name: str, spec: object, kind: str) -> Dependency:
    if isinstance(spec, dict):
        version = str(spec.get("version", "*"))
        if spec.get("git") or spec.get("url") or spec.get("path"):
            version = str(spec.get("git") or spec.get("url") or spec.get("path"))
        marker = str(spec.get("markers", ""))
        extras = spec.get("extras") or []
        optional = bool(spec.get("optional"))
        display = normalize_name(name)
        if extras:
            display += "[" + ",".join(sorted(str(e) for e in extras)) + "]"
        return Dependency(
            name=display,
            spec=version,
            marker=marker,
            kind="optional" if optional else kind,
        )
    return Dependency(name=normalize_name(name), spec=str(spec), kind=kind)


def parse_python_project(root: Path) -> Project | None:
    """Parse *root* as a Python project. Returns None when no Python manifest exists."""
    manifests: list[str] = []
    declared: list[Dependency] = []
    resolved: dict[str, str] = {}
    warnings: list[str] = []

    pyproject = root / "pyproject.toml"
    if pyproject.exists():
        manifests.append("pyproject.toml")
        try:
            deps, data = _parse_pyproject(pyproject)
        except RequirementError:
            raise
        declared.extend(deps)
        lock = root / "poetry.lock"
        if lock.exists():
            manifests.append("poetry.lock")
            resolved = _parse_poetry_lock(lock)

    req_files = {
        "requirements.txt": "prod",
        "requirements-dev.txt": "dev",
        "dev-requirements.txt": "dev",
    }
    included: set[Path] = set()
    for filename, kind in req_files.items():
        path = root / filename
        if not path.exists():
            continue
        manifests.append(filename)
        for dep in parse_requirements_file(path, included):
            dep.kind = kind
            declared.append(dep)

    setup_py = root / "setup.py"
    if setup_py.exists() and not pyproject.exists():
        warnings.append("setup.py detected but not parsed; declarative metadata only")
    if not manifests:
        return None
    project = Project(
        root=root,
        ecosystem=Ecosystem.PYPI,
        manifests=manifests,
        warnings=warnings,
        _root_declared=_dedupe(declared),
    )
    if resolved:
        project.lockfile = "poetry.lock"
        for name, version in resolved.items():
            project.add_package(
                Package(
                    key=name + "@" + version,
                    name=name,
                    ecosystem=Ecosystem.PYPI,
                    version=version,
                )
            )
    for dep in project._root_declared:
        base = normalize_name(dep.name.split("[", 1)[0])
        version = resolved.get(base)
        key = None
        if version:
            key = base + "@" + version
        else:
            key = base + "@" + (dep.spec if dep.spec else "unresolved")
        if key not in project.packages:
            project.add_package(
                Package(
                    key=key,
                    name=base,
                    ecosystem=Ecosystem.PYPI,
                    version=version,
                    dev=dep.kind == "dev",
                    optional=dep.kind == "optional",
                )
            )
        project.edges.append(Edge(parent="", child=key, spec=dep.spec, kind=dep.kind))
    return project


_KIND_PRIORITY = {"prod": 0, "optional": 1, "dev": 2}


def _dedupe(deps: list[Dependency]) -> list[Dependency]:
    """One entry per package name, keeping the strictest declaration.

    A package usually appears twice in a Python repo (pyproject and
    requirements.txt); reporting it twice would double every finding.
    """
    seen: dict[str, Dependency] = {}
    for dep in deps:
        key = normalize_name(dep.name.split("[", 1)[0])
        existing = seen.get(key)
        if existing is None or _KIND_PRIORITY.get(dep.kind, 3) < _KIND_PRIORITY.get(
            existing.kind, 3
        ):
            seen[key] = dep
    return list(seen.values())


def _parse_poetry_lock(path: Path) -> dict[str, str]:
    if tomllib is None:  # pragma: no cover - exercised only on 3.10
        return {}
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except tomllib.TOMLDecodeError:
        return {}
    versions: dict[str, str] = {}
    for entry in data.get("package", []) or []:
        name = normalize_name(str(entry.get("name", "")))
        version = str(entry.get("version", ""))
        if name and version:
            versions[name] = version
    return versions


def parse_requirements(root: Path) -> Project | None:
    """Public helper kept for callers that only care about requirements.txt."""
    path = root / "requirements.txt"
    if not path.exists():
        return None
    project = Project(root=root, ecosystem=Ecosystem.PYPI, manifests=["requirements.txt"])
    deps = parse_requirements_file(path)
    project._root_declared = deps
    for dep in deps:
        base = normalize_name(dep.name.split("[", 1)[0])
        key = base + "@" + (dep.spec or "unresolved")
        project.add_package(
            Package(key=key, name=base, ecosystem=Ecosystem.PYPI, version=None, dev=dep.kind == "dev")
        )
        project.edges.append(Edge(parent="", child=key, spec=dep.spec, kind=dep.kind))
    return project
