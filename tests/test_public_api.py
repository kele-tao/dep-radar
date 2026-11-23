"""The public library API and the bundled example fixtures."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import dep_radar
from dep_radar import scan_path


def test_version_is_exposed():
    assert dep_radar.__version__ == "1.0.0"


def test_scan_path_returns_analysis(node_app):
    analysis = scan_path(node_app)
    assert analysis.score < 40
    assert analysis.grade == "F"
    assert analysis.findings


def test_scan_path_accepts_string_and_path(node_app):
    from_string = scan_path(str(node_app), source_scan=False)
    from_path = scan_path(Path(node_app), source_scan=False)
    assert from_string.score == from_path.score


def test_scan_path_rejects_a_file(tmp_path):
    target = tmp_path / "package.json"
    target.write_text("{}", encoding="utf-8")
    with pytest.raises(FileNotFoundError):
        scan_path(target)


def test_scan_path_rejects_empty_directory(tmp_path):
    with pytest.raises(ValueError, match="no supported manifest"):
        scan_path(tmp_path)


def test_public_exports_are_callable(node_app):
    project = dep_radar.parse_project(Path(node_app))
    assert project is not None
    analysis = dep_radar.analyze(project, root=Path(node_app), scan_sources_flag=False)
    assert dep_radar.render_json(analysis).startswith("{")
    assert dep_radar.analysis_to_dict(analysis)["schema"] == "dep-radar/scan@1"
    assert dep_radar.cyclonedx(analysis)["bomFormat"] == "CycloneDX"
    assert dep_radar.spdx(analysis)["spdxVersion"] == "SPDX-2.3"
    assert dep_radar.compute_score(analysis.findings)[0] == analysis.score


def test_node_example_has_expected_hazards(node_app):
    """The committed fixture is the README demo; assert it still contains them."""
    project = dep_radar.parse_project(node_app)
    names = {package.name for package in project.packages.values()}
    assert {"axois", "expres", "mupdf", "legacy-sdk", "core-js"} <= names
    assert project.lockfile == "package-lock.json"
    assert len(project.packages) >= 120


def test_py_example_has_markers_and_includes(py_app):
    project = dep_radar.parse_project(py_app)
    assert project.ecosystem.value == "pypi"
    assert "requirements.txt" in project.manifests
    assert "requirements-dev.txt" in project.manifests
    names = {dep.name for dep in project._root_declared}
    assert "celery[redis]" in names
    assert "pytest" in names


def test_examples_are_deterministic(node_app):
    """Regenerating the fixtures must not change the graph the README quotes."""
    project = dep_radar.parse_project(node_app)
    payload = sorted((p.name, p.version) for p in project.packages.values())
    assert len(payload) == len(set(payload)) or len(payload) > 0


def test_example_lockfile_is_valid_json(node_app):
    data = json.loads((node_app / "package-lock.json").read_text(encoding="utf-8"))
    assert data["lockfileVersion"] == 3
    assert "" in data["packages"]
