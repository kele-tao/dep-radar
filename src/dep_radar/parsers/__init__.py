"""Manifest and lockfile parsers.

Every parser is offline and pure: it turns files on disk into a
:class:`dep_radar.model.Project` graph. Nothing here touches the network.
"""

from __future__ import annotations

from pathlib import Path

from ..model import Ecosystem, Project


def parse_requirements(root: Path, include_dev: bool = True) -> Project | None:
    from .python import parse_python_project

    project = parse_python_project(root)
    if project is None:
        return None
    return project


def parse_project(root: Path) -> Project | None:
    """Detect the ecosystem in *root* and parse the strongest available source."""
    from .npm import parse_npm_project
    from .python import parse_python_project

    npm = parse_npm_project(root)
    python = parse_python_project(root)
    if npm and python:
        # A polyglot repo: keep the larger graph, mention the other in warnings.
        primary, secondary = (npm, python) if len(npm.packages) >= len(python.packages) else (python, npm)
        primary.warnings.append(
            "both npm and Python manifests found; scanned "
            + primary.ecosystem.value
            + " and ignored "
            + secondary.ecosystem.value
        )
        return primary
    return npm or python


def parse_ecosystem(root: Path, ecosystem: str) -> Project | None:
    from .npm import parse_npm_project
    from .python import parse_python_project

    if ecosystem == "npm":
        return parse_npm_project(root)
    if ecosystem == "pypi":
        return parse_python_project(root)
    if ecosystem == "auto":
        return parse_project(root)
    return None


__all__ = ["Ecosystem", "Project", "parse_project", "parse_ecosystem"]
