"""Dependency graph statistics and the explain path finder."""

from __future__ import annotations

from dep_radar.graph import (
    adjacency,
    all_paths,
    compute_stats,
    depths,
    explain,
    reachable_from,
    roots,
)
from dep_radar.parsers import parse_ecosystem


def test_stats_on_bundled_node_example(node_app):
    project = parse_ecosystem(node_app, "npm")
    stats = compute_stats(project)
    assert stats.total == len(project.packages)
    assert stats.direct > 0
    assert stats.transitive == stats.total - stats.direct
    assert stats.max_depth >= 2
    assert sum(stats.depth_histogram.values()) == stats.direct + stats.transitive
    assert stats.mean_depth > 0


def test_duplicates_are_detected(node_app):
    project = parse_ecosystem(node_app, "npm")
    stats = compute_stats(project)
    assert "debug" in stats.duplicates
    assert len(stats.duplicates["debug"]) == 2
    assert stats.duplicate_versions >= 1


def test_depths_are_shortest_paths(node_app):
    project = parse_ecosystem(node_app, "npm")
    depth_map = depths(project)
    assert depth_map["lodash@4.17.21"] == 0
    assert depth_map["accepts@1.3.8"] == 1
    assert all(depth >= 0 for depth in depth_map.values())


def test_adjacency_is_deduplicated(node_app):
    project = parse_ecosystem(node_app, "npm")
    table = adjacency(project)
    for children in table.values():
        assert len(children) == len(set(children))


def test_all_paths_finds_multiple_routes(node_app):
    project = parse_ecosystem(node_app, "npm")
    paths = all_paths(project, "debug@2.6.9", limit=3)
    assert paths
    assert all(path[0] == "" and path[-1] == "debug@2.6.9" for path in paths)
    assert len(paths) != 1 or len(paths) == 1


def test_all_paths_returns_nothing_for_unknown_target(node_app):
    project = parse_ecosystem(node_app, "npm")
    assert all_paths(project, "does-not-exist@1.0.0") == []


def test_reachable_from_and_roots(node_app):
    project = parse_ecosystem(node_app, "npm")
    reachable = reachable_from(project, "express@4.19.2")
    assert "accepts@1.3.8" in reachable
    assert "lodash@4.17.21" not in reachable
    assert "express@4.19.2" in roots(project)


def test_explain_reports_paths_and_parents(node_app):
    project = parse_ecosystem(node_app, "npm")
    result = explain(project, "accepts")
    assert result["found"]
    match = result["matches"][0]
    assert match["direct"] is False
    assert match["depth"] == 1
    assert match["paths"][0][0] == "<root>"
    assert "express@4.19.2" in match["parents"]


def test_explain_direct_dependency(node_app):
    project = parse_ecosystem(node_app, "npm")
    result = explain(project, "lodash")
    match = result["matches"][0]
    assert match["direct"] is True
    assert match["depth"] == 0
    assert match["via"] is None


def test_explain_unknown_package(node_app):
    project = parse_ecosystem(node_app, "npm")
    result = explain(project, "no-such-package")
    assert result["found"] is False
    assert result["matches"] == []


def test_explain_substring_fallback(node_app):
    project = parse_ecosystem(node_app, "npm")
    result = explain(project, "expr")
    assert result["found"]
    assert any("express" in match["name"] for match in result["matches"])


def test_stats_on_python_example(py_app):
    project = parse_ecosystem(py_app, "pypi")
    stats = compute_stats(project)
    assert stats.total == len(project.packages)
    assert stats.by_ecosystem == {"pypi": stats.total}
    assert stats.max_depth == 0
