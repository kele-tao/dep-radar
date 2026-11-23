"""Risk analysis, findings and scoring."""

from __future__ import annotations

import pytest

from dep_radar.analyzer import (
    Finding,
    analyze,
    category_penalty,
    compute_score,
    grade_for,
)
from dep_radar.model import Severity
from dep_radar.parsers import parse_ecosystem


@pytest.fixture(scope="module")
def node_analysis(node_app):
    project = parse_ecosystem(node_app, "npm")
    return analyze(project, root=node_app)


def test_analysis_finds_the_planted_typosquat(node_analysis):
    typosquats = [f for f in node_analysis.findings if f.category == "typosquat"]
    assert {f.package for f in typosquats} == {"axois", "expres"}
    axois = next(f for f in typosquats if f.package == "axois")
    assert axois.severity is Severity.CRITICAL
    assert axois.evidence["target"] == "axios"
    assert axois.evidence["distance"] == 1


def test_analysis_finds_copyleft_and_missing_licences(node_analysis):
    licences = [f for f in node_analysis.findings if f.category == "licence"]
    assert any("AGPL-3.0" in f.title for f in licences)
    assert any("UNLICENSED" in f.title for f in licences)


def test_analysis_finds_install_script(node_analysis):
    scripts = [f for f in node_analysis.findings if f.category == "install-script"]
    assert [f.package for f in scripts] == ["core-js@3.36.1"]


def test_analysis_finds_duplicate_versions(node_analysis):
    duplicates = [f for f in node_analysis.findings if f.category == "duplicate"]
    assert any(f.package == "debug" for f in duplicates)


def test_analysis_finds_git_source_refs(node_analysis):
    refs = [f for f in node_analysis.findings if f.category == "source-ref"]
    assert any("git" in f.title for f in refs)


def test_analysis_finds_deprecated_packages(node_analysis):
    abandoned = {f.package for f in node_analysis.findings if f.category == "abandoned"}
    assert any("request" in package for package in abandoned)


def test_unused_direct_dependencies_are_reported(node_analysis):
    unused = {f.package for f in node_analysis.findings if f.category == "unused"}
    assert "axois" in unused
    assert "core-js" in unused
    assert "lodash" not in unused


def test_findings_are_sorted_by_severity(node_analysis):
    ranks = [f.severity.rank for f in node_analysis.findings]
    assert ranks == sorted(ranks)


def test_score_is_low_for_a_poisoned_tree(node_analysis):
    assert node_analysis.score < 40
    assert node_analysis.grade == "F"


def test_python_example_has_upper_bound_findings(py_app):
    project = parse_ecosystem(py_app, "pypi")
    analysis = analyze(project, root=py_app)
    titles = [f.title for f in analysis.findings]
    assert any("upper bound" in title for title in titles)
    assert any("unpinned" in title for title in titles)
    assert analysis.score > 60


def test_empty_project_scores_100(tmp_path):
    (tmp_path / "package.json").write_text('{"name": "clean", "version": "1.0.0"}', encoding="utf-8")
    project = parse_ecosystem(tmp_path, "npm")
    analysis = analyze(project, root=tmp_path)
    assert analysis.score == 100
    assert analysis.grade == "A"


def test_score_decreases_monotonically_with_severity():
    info = [Finding("i", "unused", Severity.INFO, "a", "t")]
    low = [Finding("l", "unused", Severity.LOW, "a", "t")]
    high = [Finding("h", "unused", Severity.HIGH, "a", "t")]
    assert compute_score(info)[0] > compute_score(low)[0] > compute_score(high)[0]


def test_category_cap_limits_single_category_damage():
    findings = [Finding(str(i), "unused", Severity.CRITICAL, "a", "t") for i in range(200)]
    assert compute_score(findings)[0] >= 90


def test_penalty_is_zero_for_no_findings():
    assert category_penalty("unused", 0) == 0.0


@pytest.mark.parametrize(
    ("score", "grade"),
    [(100, "A"), (90, "A"), (85, "B"), (72, "C"), (65, "D"), (10, "F")],
)
def test_grade_bands(score, grade):
    assert grade_for(score) == grade


def test_analysis_without_source_scan_skips_unused(tmp_path):
    (tmp_path / "package.json").write_text(
        '{"name": "x", "dependencies": {"left-pad": "1.3.0"}}', encoding="utf-8"
    )
    project = parse_ecosystem(tmp_path, "npm")
    analysis = analyze(project, root=tmp_path, scan_sources_flag=False)
    assert not [f for f in analysis.findings if f.category == "unused"]
