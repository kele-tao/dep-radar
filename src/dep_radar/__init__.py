"""dep-radar: offline supply-chain audit for Python and Node projects.

The public API is small on purpose - most users want the CLI:

    >>> from dep_radar import scan_path
    >>> analysis = scan_path("examples/node-app")
    >>> analysis.score < 40
    True

Everything else (parsers, graph, analyzers, renderers) is importable but is not
covered by a stability promise.
"""

from __future__ import annotations

from pathlib import Path

from .analyzer import Analysis, Finding, analyze, compute_score
from .model import Ecosystem, Project, Severity
from .parsers import parse_ecosystem, parse_project
from .report import analysis_to_dict, render_html, render_json, render_terminal
from .sbom import cyclonedx, spdx
from .version import __version__

__all__ = [
    "Analysis",
    "Ecosystem",
    "Finding",
    "Project",
    "Severity",
    "__version__",
    "analysis_to_dict",
    "analyze",
    "compute_score",
    "cyclonedx",
    "parse_ecosystem",
    "parse_project",
    "render_html",
    "render_json",
    "render_terminal",
    "scan_path",
    "spdx",
]


def scan_path(path: str | Path, ecosystem: str = "auto", source_scan: bool = True) -> Analysis:
    """Parse and analyse a project directory in one call.

    Raises:
        FileNotFoundError: the path does not exist or is not a directory.
        ValueError: no supported manifest was found in the directory.
    """
    root = Path(path).resolve()
    if not root.is_dir():
        raise FileNotFoundError("not a project directory: " + str(root))
    project = parse_ecosystem(root, ecosystem)
    if project is None:
        raise ValueError(
            "no supported manifest found in "
            + str(root)
            + " (expected package.json, package-lock.json, pyproject.toml or requirements.txt)"
        )
    return analyze(project, root=root, scan_sources_flag=source_scan)
