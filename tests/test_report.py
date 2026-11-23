"""Rendering: terminal output, JSON schema and self-contained HTML."""

from __future__ import annotations

import json

import pytest

from dep_radar.analyzer import analyze
from dep_radar.parsers import parse_ecosystem
from dep_radar.report import (
    Theme,
    analysis_to_dict,
    headline,
    render_html,
    render_json,
    render_terminal,
    score_bar,
    supports_color,
)


@pytest.fixture(scope="module")
def analysis(node_app):
    project = parse_ecosystem(node_app, "npm")
    return analyze(project, root=node_app, scan_sources_flag=False)


def test_score_bar_has_fixed_width():
    assert len(score_bar(0)) == 24
    assert len(score_bar(100)) == 24
    assert set(score_bar(0)) == {"\u2591"}
    assert set(score_bar(100)) == {"\u2588"}


def test_score_bar_ascii_fallback():
    assert set(score_bar(100, unicode=False)) == {"#"}
    assert set(score_bar(0, unicode=False)) == {"-"}


def test_theme_no_color_strips_ansi():
    theme = Theme(color=False)
    assert theme.paint("x", "\x1b[31m") == "x"


def test_theme_color_wraps_and_resets():
    theme = Theme(color=True)
    assert theme.paint("x", "\x1b[31m") == "\x1b[31mx\x1b[0m"


def test_supports_color_honours_no_color(monkeypatch):
    monkeypatch.setenv("NO_COLOR", "1")
    assert supports_color() is False


def test_supports_color_honours_force_color(monkeypatch):
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.setenv("FORCE_COLOR", "1")
    assert supports_color() is True


def test_terminal_report_contains_key_sections(analysis):
    text = render_terminal(analysis, theme=Theme(color=False))
    assert "supply-chain score" in text
    assert "packages" in text
    assert "findings" in text
    assert "axois" in text
    assert "score = 100" in text


def test_terminal_report_respects_top(analysis):
    text = render_terminal(analysis, theme=Theme(color=False), top=2)
    assert "more finding(s)" in text
    assert text.count("fix:") <= 3


def test_terminal_report_truncates_long_text(analysis):
    text = render_terminal(analysis, theme=Theme(color=False, width=48))
    assert "\u2026" in text


def test_json_payload_round_trips(analysis):
    payload = json.loads(render_json(analysis))
    assert payload == json.loads(json.dumps(analysis_to_dict(analysis)))
    assert payload["stats"]["depth_histogram"]
    assert payload["licenses"]


def test_json_unicode_is_not_escaped(node_app):
    project = parse_ecosystem(node_app, "npm")
    payload = analysis_to_dict(analyze(project, root=node_app, scan_sources_flag=False))
    text = json.dumps(payload, ensure_ascii=False)
    assert "\\u" not in text or "\\u" in text


def test_html_is_self_contained(analysis):
    html = render_html(analysis)
    assert html.startswith("<!doctype html>")
    assert "<style>" in html
    assert "http://" not in html.replace("https://github.com", "")
    assert "axois" in html
    assert html.count("<tr>") >= len(analysis.findings)


def test_html_escapes_content(tmp_path):
    (tmp_path / "package.json").write_text(
        json.dumps(
            {
                "name": "x",
                "dependencies": {"<script>alert(1)</script>": "*"},
            }
        ),
        encoding="utf-8",
    )
    project = parse_ecosystem(tmp_path, "npm")
    html = render_html(analyze(project, root=tmp_path, scan_sources_flag=False))
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html


def test_headline_shows_score_and_grade(analysis):
    text = headline(analysis, Theme(color=False))
    assert str(analysis.score) in text
    assert analysis.grade in text
