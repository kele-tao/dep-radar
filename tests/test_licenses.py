"""Offline licence classification."""

from __future__ import annotations

import pytest

from dep_radar.licenses import (
    classify,
    classify_project_license,
    known_licenses,
    parse_expression,
)


@pytest.mark.parametrize(
    ("declared", "category"),
    [
        ("MIT", "permissive"),
        ("Apache-2.0", "permissive"),
        ("BSD-3-Clause", "permissive"),
        ("ISC", "permissive"),
        ("GPL-3.0", "copyleft"),
        ("GPL-3.0-only", "copyleft"),
        ("AGPL-3.0", "copyleft"),
        ("LGPL-2.1", "weak-copyleft"),
        ("MPL-2.0", "weak-copyleft"),
        ("Unlicense", "public-domain"),
        ("CC0-1.0", "public-domain"),
        ("UNLICENSED", "proprietary"),
        ("SSPL-1.0", "proprietary"),
    ],
)
def test_category_of_common_licences(declared, category):
    assert classify(declared).category == category


def test_missing_licence_is_unknown_and_flagged():
    verdict = classify(None)
    assert verdict.category == "unknown"
    assert verdict.is_missing


def test_unrecognised_text_is_unknown():
    verdict = classify("Acme Proprietary Evaluation Agreement v3")
    assert verdict.category == "unknown"
    assert "not in the offline table" in verdict.detail


def test_or_expression_keeps_the_friendlier_branch():
    verdict = classify("MIT OR GPL-3.0")
    assert verdict.category == "permissive"
    assert set(verdict.terms) == {"MIT", "GPL-3.0"}


def test_and_expression_takes_the_stricter_branch():
    assert classify("MIT AND GPL-3.0").category == "copyleft"


def test_alias_resolution():
    assert classify("The MIT License").category == "permissive"
    assert classify("Apache License 2.0").category == "permissive"


def test_parse_expression_splits_operators():
    terms, operators = parse_expression("(MIT OR Apache-2.0) AND BSD-3-Clause")
    assert terms == ["MIT", "Apache-2.0", "BSD-3-Clause"]
    assert "AND" in operators


def test_risk_ordering():
    assert classify("MIT").risk < classify("GPL-3.0").risk < classify("").risk


def test_known_licenses_sorted_and_nonempty():
    table = known_licenses()
    assert len(table) > 30
    assert table == sorted(table)


def test_classify_project_license_reads_mit(tmp_path):
    (tmp_path / "LICENSE").write_text("MIT License\n\nCopyright (c) 2026\n", encoding="utf-8")
    assert classify_project_license(tmp_path).category == "permissive"


def test_classify_project_license_missing(tmp_path):
    verdict = classify_project_license(tmp_path)
    assert verdict.category == "unknown"
    assert "no LICENSE" in verdict.detail
