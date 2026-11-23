"""Risk analysis: turn a parsed graph into prioritised findings and a score.

Every finding has an id, a severity, the package it applies to, a one-line
title and an actionable suggestion. The score starts at 100 and loses points
per finding using the weights in :class:`dep_radar.model.Severity`, capped per
category so one systemic problem cannot zero the score by itself.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from pathlib import Path

from . import advisories, graph, licenses, typosquat
from .model import Project, Severity
from .semver import classify
from .source_scan import ImportScan, scan_sources, unused_direct_dependencies

# Each category has a maximum number of points it can remove, and the removal
# follows a diminishing-returns curve: the first finding in a category costs a
# lot, the tenth almost nothing. That keeps one systemic problem (60 unpinned
# ranges in a requirements.txt) from zeroing the score while still letting a
# single critical typosquat dominate. See docs/SCORING.md for the derivation.
CATEGORY_CAPS = {
    "version-pin": 18,
    "typosquat": 32,
    "licence": 16,
    "advisory": 40,
    "install-script": 14,
    "source-ref": 12,
    "duplicate": 8,
    "unused": 6,
    "abandoned": 8,
}

VAGUE_SPECS = {"", "*", "latest", "x", "X"}


@dataclass
class Finding:
    """One prioritised risk finding."""

    id: str
    category: str
    severity: Severity
    package: str
    title: str
    detail: str = ""
    suggestion: str = ""
    evidence: dict = field(default_factory=dict)

    def as_dict(self) -> dict:
        return {
            "id": self.id,
            "category": self.category,
            "severity": self.severity.value,
            "package": self.package,
            "title": self.title,
            "detail": self.detail,
            "suggestion": self.suggestion,
            "evidence": self.evidence,
        }


@dataclass
class Analysis:
    """Everything a scan produces, in report order."""

    project: Project
    stats: graph.GraphStats
    findings: list[Finding]
    score: int
    grade: str
    licence_summary: dict[str, int]
    advisories_checked: int
    import_scan: ImportScan


def _add(
    findings: list[Finding],
    category: str,
    severity: Severity,
    package: str,
    title: str,
    detail: str = "",
    suggestion: str = "",
    evidence: dict | None = None,
) -> None:
    number = sum(1 for f in findings if f.category == category) + 1
    findings.append(
        Finding(
            id=category + "-" + str(number),
            category=category,
            severity=severity,
            package=package,
            title=title,
            detail=detail,
            suggestion=suggestion,
            evidence=evidence or {},
        )
    )


def _pin_findings(project: Project, findings: list[Finding]) -> None:
    for dep in project._root_declared:
        spec = classify(dep.spec)
        name = dep.name.split("[", 1)[0]
        if dep.spec.strip() in VAGUE_SPECS or spec.kind == "any":
            _add(
                findings,
                "version-pin",
                Severity.HIGH,
                name,
                "unpinned dependency: any version will be installed",
                "the manifest declares '" + (dep.spec or "*") + "' for " + name,
                "pin an exact version (or commit a lockfile) so the version you "
                "tested is the version CI installs",
                {"spec": dep.spec or "*", "kind": dep.kind},
            )
        elif spec.is_unbounded and spec.kind in {"range", "wildcard"}:
            _add(
                findings,
                "version-pin",
                Severity.MEDIUM,
                name,
                "range without an upper bound",
                name + " declares '" + dep.spec + "': a future major release can break the build",
                "add an upper bound ('>=" + spec.lower + ",<" + _next_major(spec.lower) + "') or "
                "lock the resolved version",
                {"spec": dep.spec, "kind": dep.kind},
            )
        elif spec.kind == "caret" and _major_of(spec.lower) == 0:
            _add(
                findings,
                "version-pin",
                Severity.LOW,
                name,
                "caret range on a 0.x package",
                "npm treats '^0.a.b' as '>=0.a.b <0.(a+1).0', so minor bumps are breaking",
                "use '~" + spec.lower + "' for 0.x packages or pin the exact version",
                {"spec": dep.spec, "kind": dep.kind},
            )


def _next_major(version: str) -> str:
    parts = version.split(".")
    try:
        major = int(parts[0])
    except (ValueError, IndexError):
        return "next-major"
    return str(major + 1) + ".0.0"


def _major_of(version: str) -> int:
    try:
        return int(version.split(".")[0])
    except (ValueError, IndexError):
        return -1


def _duplicate_findings(project: Project, stats: graph.GraphStats, findings: list[Finding]) -> None:
    for name, versions in sorted(stats.duplicates.items()):
        severity = Severity.MEDIUM if len(versions) > 2 else Severity.LOW
        _add(
            findings,
            "duplicate",
            severity,
            name,
            "duplicate versions in the tree: " + ", ".join(versions),
            name + " is installed " + str(len(versions)) + " times at different depths",
            "dedupe with 'npm dedupe' (npm) or align the constraints of every parent",
            {"versions": versions},
        )


def _licence_findings(project: Project, findings: list[Finding]) -> dict[str, int]:
    summary: dict[str, int] = {}
    for package in sorted(project.packages.values(), key=lambda p: p.key):
        verdict = licenses.classify(package.license)
        summary[verdict.category] = summary.get(verdict.category, 0) + 1
        if verdict.category == "copyleft":
            _add(
                findings,
                "licence",
                Severity.HIGH,
                package.display,
                "copyleft licence: " + verdict.declared,
                "distributing binaries that include " + package.name + " triggers source "
                "release obligations",
                "replace it with a permissive alternative or isolate it behind a process boundary",
                {"license": verdict.declared, "category": verdict.category},
            )
        elif verdict.category == "proprietary":
            _add(
                findings,
                "licence",
                Severity.HIGH,
                package.display,
                "restricted licence: " + verdict.declared,
                verdict.detail,
                "review the vendor terms with legal before shipping",
                {"license": verdict.declared, "category": verdict.category},
            )
        elif verdict.category == "weak-copyleft":
            _add(
                findings,
                "licence",
                Severity.LOW,
                package.display,
                "weak copyleft: " + verdict.declared,
                "file-level obligations only, but modifications to " + package.name + " must "
                "be published",
                "keep the package unmodified and link dynamically",
                {"license": verdict.declared, "category": verdict.category},
            )
        elif verdict.category == "unknown" and package.version is not None:
            _add(
                findings,
                "licence",
                Severity.LOW,
                package.display,
                "no licence metadata",
                package.name + " declares no usable licence; using it is legally ambiguous",
                "ask upstream to add a licence field, or vendor a patched fork",
                {"license": package.license or ""},
            )
    return summary


def _advisory_findings(project: Project, findings: list[Finding]) -> int:
    hits = advisories.scan(project)
    for hit in hits:
        advisory = hit.advisory
        title = advisory.kind + ": " + advisory.summary
        if advisory.cve:
            title = advisory.cve + ": " + advisory.summary
        _add(
            findings,
            "advisory",
            advisory.severity,
            hit.package.display,
            title,
            advisory.id + " affects " + advisory.affected,
            "upgrade past the affected range or drop the dependency",
            {"advisory": advisory.id, "kind": advisory.kind, "cve": advisory.cve},
        )
    return len(advisories.load_advisories())


def _typosquat_findings(project: Project, findings: list[Finding]) -> None:
    names = {p.name: p.ecosystem.value for p in project.packages.values()}
    for hit in typosquat.find_typosquats(names, ecosystem=project.ecosystem.value):
        _add(
            findings,
            "typosquat",
            Severity.CRITICAL,
            hit.package,
            "possible typosquat: " + hit.package + " looks like " + hit.target,
            "edit distance " + str(hit.distance) + " (" + hit.edit_kind + ") from the popular "
            "package '" + hit.target + "'; a malicious lookalike can steal credentials at install time",
            "verify the publisher, then replace " + hit.package + " with " + hit.target
            + " or pin and audit the tarball",
            {
                "target": hit.target,
                "distance": hit.distance,
                "edit_kind": hit.edit_kind,
            },
        )


def _install_script_findings(project: Project, findings: list[Finding]) -> None:
    for package in sorted(project.packages.values(), key=lambda p: p.key):
        if not package.has_install_script:
            continue
        _add(
            findings,
            "install-script",
            Severity.MEDIUM,
            package.display,
            "runs code at install time",
            package.name + " declares a preinstall/install/postinstall hook that executes with "
            "your user's privileges before you ever import it",
            "install with 'npm ci --ignore-scripts' and whitelist the few packages that need hooks",
            {"scripts": sorted(package.scripts) or ["install"]},
        )


def _source_ref_findings(project: Project, findings: list[Finding]) -> None:
    for package in sorted(project.packages.values(), key=lambda p: p.key):
        kind = package.source_kind
        if kind in {"registry", "bundled", "workspace", ""}:
            continue
        severity = Severity.MEDIUM if kind in {"git", "url"} else Severity.LOW
        _add(
            findings,
            "source-ref",
            severity,
            package.display,
            "installed from " + kind + ", not a registry tarball",
            (package.source_ref or package.name) + " can change under the same version string",
            "vendor the artefact, pin a commit SHA and record its hash in the lockfile",
            {"source_kind": kind, "source_ref": package.source_ref},
        )



def _abandoned_findings(project: Project, findings: list[Finding]) -> None:
    seen: set[str] = set()
    for hit in advisories.scan(project):
        advisory = hit.advisory
        if advisory.kind != "deprecated":
            continue
        if advisory.package in seen:
            continue
        seen.add(advisory.package)
        _add(
            findings,
            "abandoned",
            Severity.MEDIUM,
            hit.package.display,
            "deprecated or unmaintained package",
            advisory.summary,
            "plan a migration; deprecated packages no longer receive security fixes",
            {"advisory": advisory.id},
        )
    for package in project.packages.values():
        if package.deprecated and package.name not in seen:
            seen.add(package.name)
            _add(
                findings,
                "abandoned",
                Severity.MEDIUM,
                package.display,
                "upstream marks this version deprecated",
                package.deprecated,
                "upgrade to the replacement named in the deprecation notice",
                {"deprecated": package.deprecated},
            )


def _unused_findings(project: Project, findings: list[Finding], scan: ImportScan) -> None:
    for name in unused_direct_dependencies(project, scan):
        _add(
            findings,
            "unused",
            Severity.INFO,
            name,
            "direct dependency is never imported",
            name + " is declared but no scanned source file imports it",
            "remove it from the manifest to shrink the tree and the attack surface",
            {"rule": "unused-direct"},
        )


def category_penalty(category: str, raw: int) -> float:
    """Diminishing-returns penalty: cap * (1 - e^(-raw/cap))."""
    cap = CATEGORY_CAPS.get(category, 20)
    if raw <= 0:
        return 0.0
    return cap * (1.0 - math.exp(-raw / cap))


def compute_score(findings: list[Finding]) -> tuple[int, str]:
    """100 minus the weighted, per-category-capped penalty of every finding."""
    penalty_by_category: dict[str, int] = {}
    for finding in findings:
        penalty_by_category[finding.category] = (
            penalty_by_category.get(finding.category, 0) + finding.severity.weight
        )
    total = sum(
        category_penalty(category, raw) for category, raw in penalty_by_category.items()
    )
    score = max(0, min(100, int(round(100 - total))))
    return score, grade_for(score)


def grade_for(score: int) -> str:
    if score >= 90:
        return "A"
    if score >= 80:
        return "B"
    if score >= 70:
        return "C"
    if score >= 60:
        return "D"
    return "F"


def analyze(project: Project, root: Path | None = None, scan_sources_flag: bool = True) -> Analysis:
    """Run every check against *project* and produce a ranked analysis."""
    findings: list[Finding] = []
    stats = graph.compute_stats(project)
    _pin_findings(project, findings)
    _duplicate_findings(project, stats, findings)
    summary = _licence_findings(project, findings)
    advisory_count = _advisory_findings(project, findings)
    _typosquat_findings(project, findings)
    _install_script_findings(project, findings)
    _source_ref_findings(project, findings)
    _abandoned_findings(project, findings)
    import_scan = ImportScan()
    if scan_sources_flag and root is not None:
        import_scan = scan_sources(root)
        _unused_findings(project, findings, import_scan)
    findings.sort(key=lambda f: (f.severity.rank, f.category, f.package))
    score, grade = compute_score(findings)
    return Analysis(
        project=project,
        stats=stats,
        findings=findings,
        score=score,
        grade=grade,
        licence_summary=summary,
        advisories_checked=advisory_count,
        import_scan=import_scan,
    )
