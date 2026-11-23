"""Typosquat detection and the Damerau-Levenshtein implementation."""

from __future__ import annotations

import pytest

from dep_radar.typosquat import (
    BENIGN_LOOKALIKES,
    damerau_levenshtein,
    find_typosquats,
    normalise,
    popular_packages,
)


@pytest.mark.parametrize(
    ("left", "right", "expected"),
    [
        ("lodash", "lodash", 0),
        ("lodahs", "lodash", 1),
        ("expresss", "express", 1),
        ("axois", "axios", 1),
        ("reqeusts", "requests", 1),
        ("requesst", "requests", 1),
        ("completely-different", "lodash", 3),
        ("", "abc", 3),
        ("abc", "", 3),
    ],
)
def test_damerau_levenshtein(left, right, expected):
    assert damerau_levenshtein(left, right, max_distance=2) in (
        expected,
        3 if expected > 2 else expected,
    )


def test_transposition_costs_one_edit():
    assert damerau_levenshtein("axois", "axios") == 1


def test_normalise_strips_scope_and_separators():
    assert normalise("@babel/core") == "core"
    assert normalise("Python_DateUtil") == "python-dateutil"


def test_popular_list_is_large_and_bilingual():
    table = popular_packages()
    assert len(table) >= 200
    assert table["lodash"] == "npm"
    assert table["requests"] == "pypi"


def test_finds_planted_npm_typosquat():
    hits = find_typosquats(["lodash", "axois", "react"], ecosystem="npm")
    assert len(hits) == 1
    assert hits[0].package == "axois"
    assert hits[0].target == "axios"
    assert "1 edit(s) from the popular package axios" in hits[0].message


def test_never_flags_a_popular_package():
    assert find_typosquats(["lodash", "express", "react", "axios"]) == []


def test_short_names_are_ignored():
    assert find_typosquats(["ws", "qs", "ms"], ecosystem="npm") == []


def test_pypi_typosquat_uses_pypi_list():
    hits = find_typosquats(["numpyy"], ecosystem="pypi")
    assert hits and hits[0].target == "numpy"
    assert find_typosquats(["numpyy"], ecosystem="npm") == []


def test_benign_lookalikes_are_suppressed():
    for name in sorted(BENIGN_LOOKALIKES)[:5]:
        assert find_typosquats([name], ecosystem="npm") == []


def test_hits_are_sorted_by_distance():
    hits = find_typosquats(["requesst", "axois"], ecosystem="npm")
    assert [hit.distance for hit in hits] == sorted(hit.distance for hit in hits)
    assert [hit.package for hit in hits] == sorted(hit.package for hit in hits)
