"""Shared pytest fixtures. Everything here is offline and deterministic."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

EXAMPLES = ROOT / "examples"
NODE_APP = EXAMPLES / "node-app"
PY_APP = EXAMPLES / "py-app"


@pytest.fixture(scope="session")
def repo_root() -> Path:
    return ROOT


@pytest.fixture(scope="session")
def node_app() -> Path:
    return NODE_APP


@pytest.fixture(scope="session")
def py_app() -> Path:
    return PY_APP


def write_npm_project(
    root: Path,
    packages: dict,
    manifest_deps: dict[str, str] | None = None,
    lock_version: int = 3,
) -> Path:
    """Create a synthetic npm project from a {name: (version, {deps}, license)} map."""
    lock: dict = {"name": "fixture", "version": "1.0.0", "lockfileVersion": lock_version,
                  "requires": True, "packages": {"": {"name": "fixture", "version": "1.0.0",
                                                       "dependencies": manifest_deps or {}}}}
    for name, (version, deps, license_id) in packages.items():
        entry = {"version": version, "resolved": f"https://registry.npmjs.org/{name}/-/{name}-{version}.tgz",
                 "integrity": "sha512-" + "A" * 86}
        if license_id:
            entry["license"] = license_id
        if deps:
            entry["dependencies"] = deps
        lock["packages"]["node_modules/" + name] = entry
        if manifest_deps is None:
            lock["packages"][""]["dependencies"][name] = "^" + version
    root.mkdir(parents=True, exist_ok=True)
    (root / "package.json").write_text(
        json.dumps({"name": "fixture", "version": "1.0.0",
                    "dependencies": lock["packages"][""]["dependencies"]}, indent=2),
        encoding="utf-8",
    )
    (root / "package-lock.json").write_text(json.dumps(lock, indent=2), encoding="utf-8")
    return root


@pytest.fixture
def npm_builder():
    return write_npm_project
