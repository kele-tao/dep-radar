"""Command line interface for dep-radar.

Exit codes (documented in README):
  0  scan completed and the score met the gate
  1  findings/gate failed (score below --fail-under)
  2  usage error: bad arguments, missing path, unreadable manifest
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .analyzer import analyze
from .graph import compute_stats
from .graph import explain as explain_graph
from .model import Project
from .parsers import parse_ecosystem
from .parsers.npm import NpmParseError
from .parsers.python import RequirementError
from .report import (
    Theme,
    render_html,
    render_json,
    render_terminal,
    supports_color,
)
from .sbom import render as render_sbom
from .sbom import validate as validate_sbom

EPILOG = """examples:
  dep-radar scan .                          audit the current project
  dep-radar scan examples/node-app --json   machine-readable output
  dep-radar explain lodash                  why is lodash in my tree
  dep-radar sbom --format cyclonedx         emit a CycloneDX SBOM
  dep-radar scan . --fail-under 70          fail CI when the score is too low

exit codes: 0 ok, 1 quality gate failed, 2 usage error
"""


class UsageError(Exception):
    """A friendly error that maps to exit code 2."""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="dep-radar",
        description="Offline supply-chain audit for Python and Node projects.",
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version="dep-radar " + __version__)
    sub = parser.add_subparsers(dest="command", metavar="<command>")

    scan = sub.add_parser(
        "scan",
        help="audit a project and print a prioritised report",
        description="Parse manifests and lockfiles, build the dependency graph, score it.",
    )
    _add_common(scan)
    scan.add_argument("--json", action="store_true", help="emit the JSON report instead of text")
    scan.add_argument("--html", metavar="FILE", help="also write a self-contained HTML report")
    scan.add_argument(
        "--fail-under",
        type=int,
        metavar="N",
        default=None,
        help="exit 1 when the score is below N (0-100)",
    )
    scan.add_argument("--top", type=int, default=25, metavar="N", help="findings to print (default 25)")
    scan.add_argument(
        "--no-source-scan",
        action="store_true",
        help="skip import scanning (faster on huge trees; disables the unused-dependency check)",
    )

    explain = sub.add_parser(
        "explain",
        help="show why a package is in the tree and which direct dependency pulled it in",
        description="Print the shortest dependency paths from the project root to a package.",
    )
    explain.add_argument("package", help="package name or name@version")
    _add_common(explain)
    explain.add_argument("--json", action="store_true", help="emit JSON")
    explain.add_argument("--max-paths", type=int, default=3, metavar="N", help="paths to show")

    sbom = sub.add_parser(
        "sbom",
        help="emit an SBOM for the project",
        description="Emit a CycloneDX-like or SPDX-like JSON SBOM with purls and hashes.",
    )
    _add_common(sbom)
    sbom.add_argument(
        "--format",
        choices=["cyclonedx", "spdx", "cyclonedx-like", "spdx-like"],
        default="cyclonedx",
        help="SBOM dialect (default cyclonedx)",
    )
    sbom.add_argument("--out", metavar="FILE", help="write to FILE instead of stdout")
    sbom.add_argument("--validate", action="store_true", help="validate the documented schema subset")

    return parser


def _add_common(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("path", nargs="?", default=".", help="project directory (default: .)")
    parser.add_argument(
        "--ecosystem",
        choices=["auto", "npm", "pypi"],
        default="auto",
        help="force an ecosystem instead of auto-detection",
    )
    parser.add_argument("--no-color", action="store_true", help="disable ANSI colours")
    parser.add_argument("--quiet", action="store_true", help="suppress the terminal report")


def _load(path: Path, ecosystem: str) -> Project:
    if not path.exists():
        raise UsageError("path does not exist: " + str(path))
    if not path.is_dir():
        raise UsageError("expected a project directory, got a file: " + str(path))
    try:
        project = parse_ecosystem(path, ecosystem)
    except NpmParseError as exc:
        raise UsageError(str(exc)) from exc
    except RequirementError as exc:
        raise UsageError(str(exc)) from exc
    except OSError as exc:
        raise UsageError("cannot read project: " + str(exc)) from exc
    if project is None:
        raise UsageError(
            "no supported manifest found in "
            + str(path)
            + "\nexpected one of: package.json, package-lock.json, pyproject.toml, requirements.txt"
        )
    return project


def _can_encode(text: str, stream=None) -> bool:
    stream = stream or sys.stdout
    encoding = getattr(stream, "encoding", None) or "utf-8"
    try:
        text.encode(encoding)
    except (UnicodeEncodeError, LookupError):
        return False
    return True


def _theme(args: argparse.Namespace) -> Theme:
    return Theme(
        color=(not args.no_color) and supports_color(),
        unicode=_can_encode("\u2588\u2591\u2026"),
    )


def cmd_scan(args: argparse.Namespace) -> int:
    root = Path(args.path).resolve()
    project = _load(root, args.ecosystem)
    analysis = analyze(project, root=root, scan_sources_flag=not args.no_source_scan)
    theme = _theme(args)
    if args.html:
        out = Path(args.html)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(render_html(analysis), encoding="utf-8")
    if args.json:
        print(render_json(analysis))
    elif not args.quiet:
        print(render_terminal(analysis, theme=theme, top=max(1, args.top)))
    if args.fail_under is not None:
        if not 0 <= args.fail_under <= 100:
            raise UsageError("--fail-under must be between 0 and 100")
        if analysis.score < args.fail_under:
            if not args.json and not args.quiet:
                print(
                    theme.paint(
                        "score " + str(analysis.score) + " is below --fail-under " + str(args.fail_under),
                        "\x1b[1;91m",
                    ),
                    file=sys.stderr,
                )
            return 1
    return 0


def cmd_explain(args: argparse.Namespace) -> int:
    root = Path(args.path).resolve()
    project = _load(root, args.ecosystem)
    result = explain_graph(project, args.package)
    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return 0 if result["found"] else 1
    if not result["found"]:
        print(
            "no package matching '" + args.package + "' in " + str(root),
            file=sys.stderr,
        )
        return 1
    stats = compute_stats(project)
    print("dep-radar explain " + args.package)
    print("  tree: " + str(stats.total) + " packages, " + str(stats.direct) + " direct")
    for match in result["matches"]:
        kind = "direct dependency" if match["direct"] else "transitive dependency"
        print("")
        print("  " + match["key"] + "  (" + kind + ", ecosystem " + match["ecosystem"] + ")")
        if match["license"]:
            print("    licence: " + match["license"])
        if match["source_kind"] not in {"registry", ""}:
            print("    source:  " + match["source_kind"])
        if match["depth"] is not None:
            print("    depth:   " + str(match["depth"]) + " from the project root")
        if match["paths"]:
            print("    pulled in by:")
            for path in match["paths"][: args.max_paths]:
                print("      " + " -> ".join(path))
        if match["direct"]:
            print("    declared directly in the project manifest")
        elif not match["parents"]:
            print("    no parent edge found (unreachable package)")
    return 0


def cmd_sbom(args: argparse.Namespace) -> int:
    root = Path(args.path).resolve()
    project = _load(root, args.ecosystem)
    analysis = analyze(project, root=root, scan_sources_flag=False)
    fmt = {"cyclonedx-like": "cyclonedx", "spdx-like": "spdx"}.get(args.format, args.format)
    text = render_sbom(analysis, fmt=fmt)
    if args.validate:
        document = json.loads(text)
        problems = validate_sbom(document)
        if problems:
            for problem in problems:
                print("invalid: " + problem, file=sys.stderr)
            return 1
    if args.out:
        out = Path(args.out)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(text + "\n", encoding="utf-8")
        print("wrote " + str(out) + " (" + str(len(text)) + " bytes)")
    else:
        print(text)
    return 0


def _force_utf8_stdout() -> None:
    """Windows consoles default to a legacy code page; prefer UTF-8 when we can."""
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:
            continue
        try:
            reconfigure(encoding="utf-8")
        except (OSError, ValueError):
            continue


def main(argv: list[str] | None = None) -> int:
    _force_utf8_stdout()
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command is None:
        parser.print_help()
        return 2
    handlers = {"scan": cmd_scan, "explain": cmd_explain, "sbom": cmd_sbom}
    handler = handlers[args.command]
    try:
        return handler(args)
    except UsageError as exc:
        print("dep-radar: error: " + str(exc), file=sys.stderr)
        print("run 'dep-radar --help' for usage", file=sys.stderr)
        return 2
    except BrokenPipeError:  # pragma: no cover - piping into head
        return 0
    except KeyboardInterrupt:  # pragma: no cover
        return 130


if __name__ == "__main__":
    sys.exit(main())
