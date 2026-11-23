"""Source import scanning: find direct dependencies that nothing imports.

A dependency you never import is dead weight at best and an unreviewed
attack surface at worst. This module extracts imports with small, deliberately
simple parsers (Python's AST is exact, JS/TS uses anchored regexes) and maps
them back to distribution names using a table of known import-name mismatches.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path

SKIP_DIRS = {
    ".git",
    "node_modules",
    ".venv",
    "venv",
    "env",
    "dist",
    "build",
    "out",
    "coverage",
    "__pycache__",
    ".pytest_cache",
    ".ruff_cache",
    ".mypy_cache",
    ".tox",
    ".idea",
    ".vscode",
}
PY_SUFFIXES = {".py", ".pyi"}
JS_SUFFIXES = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".vue", ".svelte"}
MAX_FILE_BYTES = 2 * 1024 * 1024

# Distribution name -> import name, where the two differ (the awkward ones only).
IMPORT_ALIASES = {
    "pyyaml": {"yaml"},
    "pillow": {"pil"},
    "beautifulsoup4": {"bs4"},
    "python-dateutil": {"dateutil"},
    "scikit-learn": {"sklearn"},
    "opencv-python": {"cv2"},
    "opencv-python-headless": {"cv2"},
    "python-dotenv": {"dotenv"},
    "psycopg2-binary": {"psycopg2"},
    "attrs": {"attr", "attrs"},
    "setuptools": {"pkg_resources", "setuptools"},
    "msgpack-python": {"msgpack"},
    "protobuf": {"google"},
    "google-cloud-storage": {"google"},
    "google-api-python-client": {"googleapiclient", "google"},
    "pandas": {"pandas"},
    "django-rest-framework": {"rest_framework"},
    "djangorestframework": {"rest_framework"},
    "pytest-cov": {"pytest_cov"},
    "pytest-mock": {"pytest_mock"},
    "typing-extensions": {"typing_extensions"},
    "@babel/core": {"@babel/core"},
}

_JS_IMPORT_RE = re.compile(
    r"""(?:\bimport\s+(?:[^'"\n]*?\s+from\s+)?|\brequire\s*\(\s*|\bimport\s*\(\s*)['"]([^'"]+)['"]"""
)


@dataclass
class ImportScan:
    """Result of scanning a source tree for imports."""

    files_scanned: int = 0
    python_files: int = 0
    js_files: int = 0
    modules: set[str] = field(default_factory=set)
    errors: list[str] = field(default_factory=list)

    def imported(self, package_name: str, ecosystem: str) -> bool:
        """True when any scanned file imports this distribution."""
        name = package_name.split("[", 1)[0].strip().lower()
        if ecosystem == "pypi":
            candidates = {name.replace("-", "_"), name, *IMPORT_ALIASES.get(name, set())}
        else:
            candidates = {name, *IMPORT_ALIASES.get(name, set())}
            if name.startswith("@") and "/" in name:
                candidates.add(name)
        return bool(candidates & self.modules)


def _iter_files(root: Path, suffixes: set[str], limit: int = 20000) -> list[Path]:
    found: list[Path] = []
    stack = [root]
    while stack and len(found) < limit:
        current = stack.pop()
        try:
            entries = sorted(current.iterdir(), key=lambda p: p.name)
        except (PermissionError, OSError):
            continue
        for entry in entries:
            if entry.is_dir():
                if entry.name in SKIP_DIRS or entry.name.startswith("."):
                    continue
                stack.append(entry)
            elif entry.suffix.lower() in suffixes:
                found.append(entry)
                if len(found) >= limit:
                    break
    return found


def _python_modules(path: Path) -> set[str]:
    try:
        source = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return set()
    try:
        tree = ast.parse(source, filename=str(path))
    except SyntaxError:
        return _python_modules_regex(source)
    modules: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                modules.add(alias.name.split(".")[0].lower())
        elif isinstance(node, ast.ImportFrom):
            if node.level and node.level > 0:
                continue  # relative import, not a distribution
            if node.module:
                modules.add(node.module.split(".")[0].lower())
    return modules


def _python_modules_regex(source: str) -> set[str]:
    modules: set[str] = set()
    for line in source.splitlines():
        match = re.match(r"\s*(?:from\s+([A-Za-z_][\w.]*)|import\s+([A-Za-z_][\w.]*))", line)
        if match:
            modules.add((match.group(1) or match.group(2)).split(".")[0].lower())
    return modules


def _js_module(spec: str) -> str | None:
    raw = spec.strip()
    if not raw or raw.startswith((".", "/", "~", "#")):
        return None
    if raw.startswith("node:"):
        return raw[5:].split("/")[0].lower()
    parts = raw.split("/")
    if parts[0].startswith("@"):
        if len(parts) < 2:
            return None
        return (parts[0] + "/" + parts[1]).lower()
    return parts[0].lower()


def scan_sources(root: Path) -> ImportScan:
    """Scan *root* for Python and JS/TS imports (bounded, offline, fast)."""
    result = ImportScan()
    for path in _iter_files(root, PY_SUFFIXES):
        if path.stat().st_size > MAX_FILE_BYTES:
            continue
        modules = _python_modules(path)
        result.modules.update(modules)
        result.python_files += 1
        result.files_scanned += 1
    for path in _iter_files(root, JS_SUFFIXES):
        if path.stat().st_size > MAX_FILE_BYTES:
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for match in _JS_IMPORT_RE.finditer(text):
            module = _js_module(match.group(1))
            if module:
                result.modules.add(module)
        result.js_files += 1
        result.files_scanned += 1
    return result


def unused_direct_dependencies(project, scan: ImportScan) -> list[str]:
    """Direct, non-dev dependencies that no scanned source file imports."""
    if scan.files_scanned == 0:
        return []
    unused: list[str] = []
    for dep in project._root_declared:
        if dep.kind in {"dev", "peer"}:
            continue
        name = dep.name.split("[", 1)[0]
        if not scan.imported(name, project.ecosystem.value):
            unused.append(name)
    return sorted(set(unused))
