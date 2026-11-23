"""Rendering: the prioritised terminal report, JSON output and HTML.

Rendering is pure: it takes an :class:`dep_radar.analyzer.Analysis` and a
:class:`dep_radar.render.Theme` and returns a string. That keeps the CLI thin
and the report snapshottable in tests.
"""

from __future__ import annotations

import json
import os
import sys
from dataclasses import dataclass

from .analyzer import Analysis, Finding
from .model import Severity
from .version import __version__

RESET = "\x1b[0m"
BOLD = "\x1b[1m"
DIM = "\x1b[2m"

SEVERITY_COLORS = {
    Severity.CRITICAL: "\x1b[1;91m",
    Severity.HIGH: "\x1b[1;31m",
    Severity.MEDIUM: "\x1b[1;33m",
    Severity.LOW: "\x1b[36m",
    Severity.INFO: "\x1b[90m",
}

GRADE_COLORS = {
    "A": "\x1b[1;92m",
    "B": "\x1b[1;92m",
    "C": "\x1b[1;33m",
    "D": "\x1b[1;91m",
    "F": "\x1b[1;91m",
}

BAR_WIDTH = 24


@dataclass
class Theme:
    """Colour and width settings for the terminal report."""

    color: bool = True
    width: int = 112
    unicode: bool = True

    def paint(self, text: str, code: str) -> str:
        if not self.color:
            return text
        return code + text + RESET

    def heading(self, text: str) -> str:
        return self.paint(text, BOLD)

    def dim(self, text: str) -> str:
        return self.paint(text, DIM)


def supports_color(stream=None) -> bool:
    """Honour NO_COLOR, FORCE_COLOR and tty detection."""
    stream = stream or sys.stdout
    if os.environ.get("NO_COLOR"):
        return False
    forced = os.environ.get("FORCE_COLOR", "")
    if forced and forced != "0":
        return True
    return bool(getattr(stream, "isatty", lambda: False)())


def score_bar(score: int, unicode: bool = True) -> str:
    """A 24-cell bar; falls back to ASCII on terminals that cannot encode blocks."""
    filled = round(BAR_WIDTH * score / 100)
    full, empty = ("\u2588", "\u2591") if unicode else ("#", "-")
    return full * filled + empty * (BAR_WIDTH - filled)


def headline(analysis: Analysis, theme: Theme | None = None) -> str:
    theme = theme or Theme(color=False)
    score, grade = analysis.score, analysis.grade
    colour = GRADE_COLORS[grade]
    verdict = {
        "A": "ship it",
        "B": "minor cleanup",
        "C": "needs work",
        "D": "risky",
        "F": "do not ship",
    }[grade]
    line = (
        theme.paint(str(score).rjust(3) + "/100", colour)
        + "  "
        + theme.paint(score_bar(score, theme.unicode), colour)
        + "  grade "
        + theme.paint(grade, colour)
        + theme.dim("  " + verdict)
    )
    return line


def display_path(path) -> str:
    """Show a path relative to the working directory when it is inside it."""
    import pathlib

    try:
        return str(pathlib.Path(path).resolve().relative_to(pathlib.Path.cwd()))
    except (ValueError, OSError):
        return str(path)


def _short(text: str, width: int, unicode: bool = True) -> str:
    if len(text) <= width:
        return text
    tail = "\u2026" if unicode else "..."
    return text[: max(0, width - len(tail))] + tail


def render_terminal(analysis: Analysis, theme: Theme | None = None, top: int = 25) -> str:
    """Render the prioritised report shown in the README screenshot."""
    theme = theme or Theme(color=False)
    project = analysis.project
    stats = analysis.stats
    out: list[str] = []
    out.append(theme.heading("dep-radar " + __version__))
    out.append(theme.dim("  target     ") + display_path(project.root))
    lock = project.lockfile or "none"
    if project.lockfile_version:
        lock += " (v" + str(project.lockfile_version) + ")"
    out.append(theme.dim("  manifests  ") + ", ".join(project.manifests) + "  lockfile: " + lock)
    out.append("")
    out.append(
        "  packages "
        + theme.heading(str(stats.total))
        + "   direct "
        + theme.heading(str(stats.direct))
        + "   transitive "
        + theme.heading(str(stats.transitive))
        + "   max depth "
        + theme.heading(str(stats.max_depth))
        + "   duplicates "
        + theme.heading(str(len(stats.duplicates)))
    )
    out.append(
        "  licences "
        + "  ".join(
            key + " " + str(value)
            for key, value in sorted(analysis.licence_summary.items(), key=lambda kv: -kv[1])
        )
        + "   advisories checked "
        + str(analysis.advisories_checked)
    )
    out.append("")
    out.append("  supply-chain score")
    out.append("  " + headline(analysis, theme))
    out.append("")

    if not analysis.findings:
        out.append(theme.paint("  no findings - this tree is clean", "\x1b[92m"))
        return "\n".join(out)

    by_severity: dict[Severity, int] = {}
    for finding in analysis.findings:
        by_severity[finding.severity] = by_severity.get(finding.severity, 0) + 1
    counts = "  ".join(
        theme.paint(sev.value + " " + str(by_severity[sev]), SEVERITY_COLORS[sev])
        for sev in Severity
        if sev in by_severity
    )
    out.append("  findings " + counts)
    out.append("")

    for finding in analysis.findings[:top]:
        out.extend(_render_finding(finding, theme))
    remaining = len(analysis.findings) - top
    if remaining > 0:
        out.append(
            theme.dim(
                "  ... "
                + str(remaining)
                + " more finding(s); raise --top or use --json for the full list"
            )
        )
    out.append("")
    out.append(
        theme.dim(
            "  score = 100 - sum of per-category penalties, each capped and "
            "diminishing (see docs/SCORING.md)"
        )
    )
    for warning in project.warnings[:6]:
        out.append(theme.dim("  note: " + _short(warning, theme.width - 10)))
    return "\n".join(out)


def _render_finding(finding: Finding, theme: Theme) -> list[str]:
    colour = SEVERITY_COLORS[finding.severity]
    label = finding.severity.value.upper().ljust(8)
    lines = [
        "  "
        + theme.paint(label, colour)
        + " "
        + theme.heading(_short(finding.title, theme.width - 14, theme.unicode))
    ]
    if finding.package:
        lines.append("  " + " " * 9 + theme.dim("package  " + finding.package))
    if finding.detail:
        lines.append(
            "  " + " " * 9 + _short(finding.detail, theme.width - 11, theme.unicode)
        )
    if finding.suggestion:
        lines.append(
            "  "
            + " " * 9
            + theme.paint("fix: ", "\x1b[32m")
            + _short(finding.suggestion, theme.width - 16, theme.unicode)
        )
    lines.append("")
    return lines


def analysis_to_dict(analysis: Analysis) -> dict:
    """The stable JSON schema documented in README."""
    project = analysis.project
    stats = analysis.stats
    return {
        "schema": "dep-radar/scan@1",
        "version": __version__,
        "root": str(project.root),
        "ecosystem": project.ecosystem.value,
        "manifests": list(project.manifests),
        "lockfile": project.lockfile,
        "score": analysis.score,
        "grade": analysis.grade,
        "stats": {
            "packages": stats.total,
            "direct": stats.direct,
            "transitive": stats.transitive,
            "max_depth": stats.max_depth,
            "mean_depth": stats.mean_depth,
            "duplicate_packages": len(stats.duplicates),
            "duplicate_versions": stats.duplicate_versions,
            "depth_histogram": {str(k): v for k, v in sorted(stats.depth_histogram.items())},
            "by_ecosystem": dict(sorted(stats.by_ecosystem.items())),
        },
        "licenses": dict(sorted(analysis.licence_summary.items())),
        "advisories_checked": analysis.advisories_checked,
        "findings": [finding.as_dict() for finding in analysis.findings],
        "severity_counts": _severity_counts(analysis),
        "warnings": list(project.warnings),
        "source_scan": {
            "files": analysis.import_scan.files_scanned,
            "python_files": analysis.import_scan.python_files,
            "js_files": analysis.import_scan.js_files,
            "modules": len(analysis.import_scan.modules),
        },
    }


def _severity_counts(analysis: Analysis) -> dict[str, int]:
    counts = {severity.value: 0 for severity in Severity}
    for finding in analysis.findings:
        counts[finding.severity.value] += 1
    return counts


def render_json(analysis: Analysis, indent: int = 2) -> str:
    return json.dumps(analysis_to_dict(analysis), indent=indent, ensure_ascii=False, sort_keys=False)


HTML_TEMPLATE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>dep-radar report - __TITLE__</title>
<style>
  :root { color-scheme: dark; }
  body { margin:0; background:#0b0f17; color:#d7dee8;
         font:14px/1.55 ui-sans-serif,system-ui,-apple-system,Segoe UI,sans-serif; }
  header { padding:28px 32px 20px; border-bottom:1px solid #1f2937; background:#0f1624; }
  h1 { margin:0 0 4px; font-size:20px; letter-spacing:.2px; }
  .sub { color:#8b9bb4; font-size:12.5px; font-family:ui-monospace,Consolas,monospace; }
  .score { display:flex; align-items:center; gap:18px; margin-top:18px; }
  .num { font:700 44px/1 ui-monospace,Consolas,monospace; }
  .bar { flex:1; height:14px; border-radius:7px; background:#1b2637; overflow:hidden; }
  .fill { height:100%; }
  main { padding:22px 32px 40px; }
  .cards { display:grid; grid-template-columns:repeat(auto-fit,minmax(150px,1fr)); gap:12px; }
  .card { background:#111a29; border:1px solid #1f2937; border-radius:10px; padding:12px 14px; }
  .card b { display:block; font:700 22px/1.2 ui-monospace,Consolas,monospace; }
  .card span { color:#8b9bb4; font-size:12px; text-transform:uppercase; letter-spacing:.08em; }
  h2 { font-size:13px; text-transform:uppercase; letter-spacing:.1em; color:#8b9bb4;
       margin:30px 0 12px; }
  table { width:100%; border-collapse:collapse; }
  td, th { padding:9px 10px; border-bottom:1px solid #1a2334; text-align:left; vertical-align:top; }
  th { color:#8b9bb4; font-weight:600; font-size:12px; text-transform:uppercase; letter-spacing:.06em; }
  .sev { font:700 11px/1 ui-monospace,Consolas,monospace; padding:4px 7px; border-radius:5px; }
  .critical { background:#4c0d16; color:#ff8b8b; }
  .high { background:#4a1010; color:#ff9d9d; }
  .medium { background:#3d2a06; color:#ffd166; }
  .low { background:#0c2f3a; color:#67e8f9; }
  .info { background:#1b2331; color:#9aa8bd; }
  code { font-family:ui-monospace,Consolas,monospace; color:#c3cfe2; }
  .detail { color:#96a3b8; font-size:12.5px; }
  .fix { color:#6ee7a8; font-size:12.5px; margin-top:3px; }
  footer { padding:0 32px 34px; color:#5f6c82; font-size:12px; }
</style></head><body>
<header>
  <h1>__TITLE__</h1>
  <div class="sub">__SUBTITLE__</div>
  <div class="score">
    <div class="num" style="color:__COLOR__">__SCORE__<span style="font-size:16px;color:#5f6c82">/100</span></div>
    <div class="bar"><div class="fill" style="width:__SCORE__%;background:__COLOR__"></div></div>
    <div style="color:__COLOR__;font-weight:700">grade __GRADE__</div>
  </div>
</header>
<main>
  <div class="cards">__CARDS__</div>
  <h2>Findings (__COUNT__)</h2>
  <table><thead><tr><th>Severity</th><th>Package</th><th>Finding</th></tr></thead>
  <tbody>__ROWS__</tbody></table>
</main>
<footer>Generated offline by dep-radar __VERSION__ - no network access, deterministic output.</footer>
</body></html>
"""


def render_html(analysis: Analysis) -> str:
    """A self-contained HTML report (inline CSS, no external assets)."""
    import html as html_module

    project = analysis.project
    stats = analysis.stats
    colour = {"A": "#4ade80", "B": "#4ade80", "C": "#fbbf24", "D": "#ff5f5f", "F": "#ff5f5f"}[
        analysis.grade
    ]
    cards = [
        ("packages", stats.total),
        ("direct", stats.direct),
        ("transitive", stats.transitive),
        ("max depth", stats.max_depth),
        ("duplicate versions", stats.duplicate_versions),
        ("findings", len(analysis.findings)),
    ]
    card_html = "".join(
        '<div class="card"><b>' + str(value) + "</b><span>" + label + "</span></div>"
        for label, value in cards
    )
    rows: list[str] = []
    for finding in analysis.findings:
        rows.append(
            "<tr>"
            '<td><span class="sev '
            + finding.severity.value
            + '">'
            + finding.severity.value.upper()
            + "</span></td>"
            + "<td><code>"
            + html_module.escape(finding.package)
            + "</code></td>"
            + "<td><strong>"
            + html_module.escape(finding.title)
            + "</strong>"
            + ('<div class="detail">' + html_module.escape(finding.detail) + "</div>"
               if finding.detail else "")
            + ('<div class="fix">fix: ' + html_module.escape(finding.suggestion) + "</div>"
               if finding.suggestion else "")
            + "</td></tr>"
        )
    title = "dep-radar - " + project.root.name
    subtitle = " / ".join(project.manifests) + ("  lockfile: " + project.lockfile if project.lockfile else "")
    page = HTML_TEMPLATE
    for key, value in (
        ("__TITLE__", html_module.escape(title)),
        ("__SUBTITLE__", html_module.escape(subtitle)),
        ("__COLOR__", colour),
        ("__SCORE__", str(analysis.score)),
        ("__GRADE__", analysis.grade),
        ("__CARDS__", card_html),
        ("__COUNT__", str(len(analysis.findings))),
        ("__ROWS__", "".join(rows) or '<tr><td colspan="3">no findings</td></tr>'),
        ("__VERSION__", __version__),
    ):
        page = page.replace(key, value)
    return page
