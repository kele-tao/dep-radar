"""npm manifest and lockfile parsing (package.json, package-lock v2/v3, yarn.lock v1).

This module is pure parsing: no network, no npm invocation. It understands
enough of npm's hoisting rules to rebuild the *logical* dependency graph,
including duplicate copies of the same package at different paths.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from ..model import Dependency, Ecosystem, Edge, Package, Project
from ..semver import satisfies_node_range


class NpmParseError(ValueError):
    """Raised when a package.json or package-lock.json is malformed."""


def _read_json(path: Path) -> dict:
    try:
        text = path.read_text(encoding="utf-8")
    except UnicodeDecodeError as exc:  # pragma: no cover - defensive
        raise NpmParseError(f"{path.name} is not valid UTF-8: {exc}") from exc
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise NpmParseError(
            f"{path.name} is not valid JSON (line {exc.lineno}, column {exc.colno}): {exc.msg}"
        ) from exc
    if not isinstance(data, dict):
        raise NpmParseError(f"{path.name} must contain a JSON object at the top level")
    return data


def _dependency_table(raw: dict, kind: str) -> list[Dependency]:
    deps: list[Dependency] = []
    for name, spec in raw.items():
        if not isinstance(name, str):
            continue
        deps.append(Dependency(name=name, spec=str(spec), kind=kind))
    return deps


def _split_spec(spec: str) -> tuple[str, str]:
    """Split 'name@1.2.3' into ('name', '1.2.3'), honouring scoped names."""
    if spec.startswith("@"):
        body = spec[1:]
        if "@" in body:
            name, _, rest = body.rpartition("@")
            return "@" + name, rest
        return spec, ""
    if "@" in spec:
        name, _, rest = spec.rpartition("@")
        return name, rest
    return spec, ""


def _source_of(spec: str) -> tuple[str, str]:
    """Classify a dependency spec into (source_kind, ref)."""
    raw = (spec or "").strip()
    lowered = raw.lower()
    for prefix in ("git+", "git://", "git@", "github:", "gitlab:", "bitbucket:"):
        if lowered.startswith(prefix):
            return "git", raw
    if lowered.startswith(("http://", "https://")):
        if lowered.endswith((".tgz", ".tar.gz", ".tar")):
            return "tarball", raw
        return "url", raw
    if lowered.startswith(("file:", "link:")):
        return "file", raw
    if lowered.startswith(("workspace:", "portal:", "patch:")):
        return "workspace", raw
    if lowered.startswith(("npm:", "jsr:")):
        return "url", raw
    if re.fullmatch(r"[\w.-]+/[\w.-]+", raw):
        return "git", raw
    return "registry", raw


_REGISTRY_HOSTS = (
    "registry.npmjs.org",
    "registry.yarnpkg.com",
    "registry.npmmirror.com",
    "npm.pkg.github.com",
)


def _classify_resolved(resolved: str) -> tuple[str, str]:
    """A lockfile 'resolved' URL: registry tarballs are normal, anything else is a risk."""
    lowered = resolved.lower()
    if lowered.startswith("git+") or lowered.startswith("git://") or "@" in lowered.split("/")[0]:
        return "git", resolved
    if any(host in lowered for host in _REGISTRY_HOSTS):
        return "registry", resolved
    if lowered.startswith(("http://", "https://")):
        return "tarball", resolved
    if lowered.startswith("file:"):
        return "file", resolved
    return "registry", resolved


def parse_package_json(path: Path) -> tuple[dict, list[Dependency]]:
    """Read a package.json and return (raw data, declared dependencies)."""
    data = _read_json(path)
    deps: list[Dependency] = []
    deps.extend(_dependency_table(data.get("dependencies", {}) or {}, "prod"))
    deps.extend(_dependency_table(data.get("devDependencies", {}) or {}, "dev"))
    deps.extend(_dependency_table(data.get("optionalDependencies", {}) or {}, "optional"))
    deps.extend(_dependency_table(data.get("peerDependencies", {}) or {}, "peer"))
    return data, deps


def _name_from_path(install_path: str) -> str:
    cleaned = install_path.rstrip("/")
    if cleaned.startswith("node_modules/"):
        cleaned = cleaned[len("node_modules/"):]
    tail = cleaned.split("/node_modules/")[-1].rstrip("/")
    if tail.startswith("@"):
        chunks = tail.split("/")
        return "/".join(chunks[:2]) if len(chunks) >= 2 else tail
    return tail.split("/")[0]


def _node_modules_path(parent_path: str, dep_name: str) -> str:
    if not parent_path:
        return "node_modules/" + dep_name
    return parent_path.rstrip("/") + "/node_modules/" + dep_name


def _fallback_key(project: Project, name: str, spec: str) -> str | None:
    candidates = [p for p in project.packages.values() if p.name == name]
    if not candidates:
        return None
    wanted = re.sub(r"^[\^~=<>]+", "", spec.strip())
    for package in candidates:
        if package.version and package.version == wanted:
            return package.key
    candidates.sort(key=lambda p: p.version or "")
    return candidates[-1].key


def parse_package_lock(path: Path, project: Project) -> None:
    """Populate *project* from package-lock.json v2/v3 (the 'packages' map)."""
    data = _read_json(path)
    lockfile_version = data.get("lockfileVersion")
    packages = data.get("packages")
    if not isinstance(packages, dict):
        packages = _flatten_v1(data)
        lockfile_version = 1
    if not isinstance(packages, dict):
        raise NpmParseError("package-lock.json has neither a 'packages' nor a 'dependencies' map")
    project.lockfile = path.name
    project.lockfile_version = int(lockfile_version) if str(lockfile_version).isdigit() else 0

    path_to_key: dict[str, str] = {}
    for install_path, entry in packages.items():
        if not install_path or not isinstance(entry, dict):
            continue  # "" is the root project itself
        name = entry.get("name") or _name_from_path(install_path)
        if not name:
            continue
        version_value = entry.get("version")
        version = str(version_value) if version_value not in (None, "") else None
        key = name + "@" + (version or install_path)
        resolved = str(entry.get("resolved") or "")
        source_kind, source_ref = "registry", ""
        if entry.get("link"):
            source_kind, source_ref = "file", resolved
        elif entry.get("inBundle"):
            source_kind, source_ref = "bundled", resolved
        elif resolved:
            source_kind, source_ref = _classify_resolved(resolved)
        project.add_package(
            Package(
                key=key,
                name=name,
                ecosystem=Ecosystem.NPM,
                version=version,
                license=entry.get("license"),
                resolved=resolved,
                integrity=str(entry.get("integrity") or ""),
                source_kind=source_kind,
                source_ref=source_ref,
                dev=bool(entry.get("dev")),
                optional=bool(entry.get("optional")),
                deprecated=str(entry.get("deprecated") or ""),
                install_path=install_path,
                has_install_script=bool(entry.get("hasInstallScript")),
            )
        )
        path_to_key[install_path] = key

    project._root_declared = _root_declarations_from_lock(packages)

    for install_path, entry in packages.items():
        if not install_path or not isinstance(entry, dict):
            continue
        key = path_to_key.get(install_path)
        if key is None:
            continue
        for dep_name, spec in (entry.get("dependencies") or {}).items():
            child_path = _node_modules_path(install_path, dep_name)
            child_key = path_to_key.get(child_path) or _fallback_key(project, dep_name, str(spec))
            if child_key is None:
                project.warnings.append(f"unresolved dependency {dep_name} (from {key})")
                continue
            project.edges.append(Edge(parent=key, child=child_key, spec=str(spec)))
            project.packages[key].dependencies.append(Dependency(name=dep_name, spec=str(spec)))
        for dep_name, spec in (entry.get("optionalDependencies") or {}).items():
            child_path = _node_modules_path(install_path, dep_name)
            child_key = path_to_key.get(child_path) or _fallback_key(project, dep_name, str(spec))
            if child_key is None:
                continue
            project.edges.append(
                Edge(parent=key, child=child_key, spec=str(spec), kind="optional")
            )

    for dep in project._root_declared:
        target = _resolve_direct(project, path_to_key, dep.name, dep.spec)
        if target is not None:
            project.edges.append(Edge(parent="", child=target, spec=dep.spec, kind=dep.kind))


def _resolve_direct(
    project: Project, path_to_key: dict[str, str], name: str, spec: str
) -> str | None:
    if not spec or spec.startswith(("file:", "link:", "workspace:")):
        return None
    key = path_to_key.get(_node_modules_path("", name))
    if key is not None:
        return key
    return _fallback_key(project, name, spec)


def _root_declarations_from_lock(packages: dict) -> list[Dependency]:
    root = packages.get("")
    if not isinstance(root, dict):
        return []
    deps: list[Dependency] = []
    deps.extend(_dependency_table(root.get("dependencies", {}) or {}, "prod"))
    deps.extend(_dependency_table(root.get("devDependencies", {}) or {}, "dev"))
    deps.extend(_dependency_table(root.get("optionalDependencies", {}) or {}, "optional"))
    deps.extend(_dependency_table(root.get("peerDependencies", {}) or {}, "peer"))
    return deps


def _flatten_v1(data: dict) -> dict:
    """Best-effort conversion of a v1 lockfile's nested 'dependencies' map."""
    flat: dict[str, dict] = {}

    def walk(tree: dict, prefix: str) -> None:
        for name, entry in tree.items():
            if not isinstance(entry, dict):
                continue
            install_path = (prefix + "/node_modules/" + name) if prefix else "node_modules/" + name
            flat[install_path] = entry
            nested = entry.get("dependencies")
            if isinstance(nested, dict):
                walk(nested, install_path)

    walk(data.get("dependencies", {}) or {}, "")
    root = {"dependencies": {}}
    for name, entry in (data.get("dependencies", {}) or {}).items():
        if isinstance(entry, dict):
            root["dependencies"][name] = entry.get("version")
    flat[""] = root
    return flat


_YARN_HEADER = re.compile(r'^"?([^"@\s]+(?:/[^"@\s]+)?|@[^"\s]+)@(.+?)"?\s*:\s*$')


def parse_yarn_lock(path: Path, project: Project) -> None:
    """Parse a yarn v1 lockfile and rebuild its dependency graph offline."""
    text = path.read_text(encoding="utf-8")
    project.lockfile = path.name
    blocks: list[dict] = []
    current: dict | None = None
    section = ""

    for raw in text.splitlines():
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        stripped = raw.strip()
        if indent == 0 and stripped.endswith(":"):
            current = {"headers": [], "fields": {}, "deps": {}, "opt": {}}
            blocks.append(current)
            header = stripped[:-1]
            current["headers"] = [h.strip().strip('"') for h in header.split(", ") if h.strip()]
            section = ""
            continue
        if current is None:
            continue
        if indent <= 2 and stripped.endswith(":"):
            section = stripped[:-1]
            continue
        if indent <= 2 and " " in stripped:
            field, _, value = stripped.partition(" ")
            value = value.strip().strip('"')
            if value:
                current["fields"][field] = value
            elif not value:
                section = field
            continue
        if indent >= 4 and section:
            match = re.match(r'^("[^"]+"|\S+)\s+(.+)$', stripped)
            if not match:
                continue
            dep_name = match.group(1).strip('"')
            dep_range = match.group(2).strip().strip('"')
            if section in {"dependencies", "optionalDependencies"}:
                current["deps"][dep_name] = dep_range

    by_name: dict[str, list[tuple[str, str]]] = {}
    records: list[tuple[str, str, str, dict]] = []
    for block in blocks:
        if not block["headers"]:
            continue
        name, _ = _split_spec(block["headers"][0])
        version = block["fields"].get("version", "")
        key = name + "@" + (version or "unknown")
        resolved = block["fields"].get("resolved", "")
        integrity = block["fields"].get("integrity", "")
        package = Package(
            key=key,
            name=name,
            ecosystem=Ecosystem.NPM,
            version=version or None,
            resolved=resolved,
            integrity=integrity,
            source_kind=_source_of(resolved)[0] if resolved else "registry",
            source_ref=resolved,
        )
        if project.add_package(package) is package:
            by_name.setdefault(name, []).append((version, key))
        records.append((key, name, version, block))

    for key, _name, _version, block in records:
        for dep_name, dep_range in block["deps"].items():
            child_key = _pick_version(by_name, project, dep_name, dep_range)
            if child_key is None:
                project.warnings.append(
                    f"yarn.lock: unresolved range {dep_name}@{dep_range} (from {key})"
                )
                continue
            project.edges.append(Edge(parent=key, child=child_key, spec=dep_range))
            project.packages[key].dependencies.append(
                Dependency(name=dep_name, spec=dep_range)
            )



def _pick_version(
    by_name: dict[str, list[tuple[str, str]]], project: Project, name: str, dep_range: str
) -> str | None:
    candidates = by_name.get(name)
    if not candidates:
        return None
    matching = [key for version, key in candidates if satisfies_node_range(version, dep_range)]
    if matching:
        return matching[0]
    return candidates[-1][1]


def parse_npm_project(root: Path) -> Project | None:
    """Parse *root* as an npm project. Returns None when no npm manifest exists."""
    manifest = root / "package.json"
    if not manifest.exists():
        return None
    data, declared = parse_package_json(manifest)
    project = Project(
        root=root,
        ecosystem=Ecosystem.NPM,
        manifests=["package.json"],
        _root_declared=declared,
    )
    lock = root / "package-lock.json"
    yarn = root / "yarn.lock"
    if lock.exists():
        project.manifests.append("package-lock.json")
        parse_package_lock(lock, project)
    elif yarn.exists():
        project.manifests.append("yarn.lock")
        parse_yarn_lock(yarn, project)
    else:
        project.warnings.append(
            "no package-lock.json or yarn.lock: versions are unresolved and depth is unknown"
        )
        for dep in declared:
            source_kind, ref = _source_of(dep.spec)
            key = dep.name + "@" + ("unresolved" if source_kind == "registry" else ref)
            project.add_package(
                Package(
                    key=key,
                    name=dep.name,
                    ecosystem=Ecosystem.NPM,
                    source_kind=source_kind,
                    source_ref=ref,
                    dev=dep.kind == "dev",
                )
            )
            project.edges.append(Edge(parent="", child=key, spec=dep.spec, kind=dep.kind))
    _merge_manifest_metadata(project, data)
    return project


def _merge_manifest_metadata(project: Project, data: dict) -> None:
    """Record the project's own install-time scripts as project-level warnings."""
    scripts = data.get("scripts") or {}
    for name in ("preinstall", "install", "postinstall", "prepare"):
        command = scripts.get(name)
        if command:
            project.warnings.append(f"root package.json runs '{name}': {command}")
    declared = {dep.name: dep for dep in project._root_declared}
    for package in project.packages.values():
        if package.name in declared and package.version is None:
            spec = declared[package.name].spec.strip()
            if re.fullmatch(r"[\^~>=<v]*\d[\w.+-]*", spec):
                package.version = spec.lstrip("^~=<>v")


def root_install_scripts(root: Path) -> dict[str, str]:
    """Return the install-time scripts declared by the project's own package.json."""
    manifest = root / "package.json"
    if not manifest.exists():
        return {}
    try:
        data = _read_json(manifest)
    except NpmParseError:
        return {}
    scripts = data.get("scripts") or {}
    return {
        str(name): str(cmd)
        for name, cmd in scripts.items()
        if name in {"preinstall", "install", "postinstall", "prepare"}
    }
