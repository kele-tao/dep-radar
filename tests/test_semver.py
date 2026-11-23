"""Version spec classification and range matching."""

from __future__ import annotations

import pytest

from dep_radar.model import compare_versions, version_tuple
from dep_radar.semver import (
    classify,
    is_pinned,
    satisfies,
    satisfies_node_range,
)


@pytest.mark.parametrize(
    ("spec", "kind"),
    [
        ("1.2.3", "exact"),
        ("==1.2.3", "exact"),
        ("", "any"),
        ("*", "any"),
        ("latest", "any"),
        ("^1.2.3", "caret"),
        ("~1.2.3", "tilde"),
        (">=1.0.0,<2.0.0", "range"),
        (">=1.0.0", "range"),
        ("~=1.4.2", "compatible"),
        ("1.x", "wildcard"),
        ("git+ssh://git@github.com/acme/repo.git", "url"),
        ("https://example.test/pkg.tgz", "url"),
    ],
)
def test_classify_kind(spec, kind):
    assert classify(spec).kind == kind


def test_unbounded_range_is_flagged():
    assert classify(">=1.0.0").is_unbounded
    assert classify(">=1.0.0,<2.0.0").is_unbounded is False


def test_wildcard_is_floating_and_unbounded():
    spec = classify("1.x")
    assert spec.is_floating and spec.is_unbounded


def test_exact_spec_is_pinned():
    assert is_pinned("1.2.3")
    assert not is_pinned("^1.2.3")
    assert not is_pinned("")


@pytest.mark.parametrize(
    ("version", "spec", "expected"),
    [
        ("1.2.3", ">=1.0.0,<2.0.0", True),
        ("2.0.0", ">=1.0.0,<2.0.0", False),
        ("1.2.3", "*", True),
        ("1.2.3", "<4.17.21", True),
        ("4.17.21", "<4.17.21", False),
        ("4.17.21", "4.17.21", True),
        ("1.5.0", "1.0.0 - 2.0.0", True),
        ("2.5.0", "1.0.0 - 2.0.0", False),
        ("1.2.3", "garbage-spec", False),
    ],
)
def test_satisfies(version, spec, expected):
    assert satisfies(version, spec) is expected


@pytest.mark.parametrize(
    ("version", "spec", "expected"),
    [
        ("18.3.1", "^18.2.0", True),
        ("19.0.0", "^18.2.0", False),
        ("0.2.5", "^0.2.1", True),
        ("0.3.0", "^0.2.1", False),
        ("1.2.9", "~1.2.3", True),
        ("1.3.0", "~1.2.3", False),
        ("4.19.2", ">=4.18.2 <5", True),
        ("5.0.0", ">=4.18.2 <5", False),
        ("1.0.0", "1.0.0 || 2.0.0", True),
        ("2.0.0", "1.0.0 || 2.0.0", True),
        ("3.0.0", "1.0.0 || 2.0.0", False),
        ("2.1.3", "2.x", True),
        ("3.0.0", "2.x", False),
    ],
)
def test_satisfies_node_range(version, spec, expected):
    assert satisfies_node_range(version, spec) is expected


def test_version_ordering_ignores_prerelease_suffix():
    assert version_tuple("1.20.3-beta.1") == version_tuple("1.20.3")
    assert version_tuple("") == (0,)
    assert compare_versions("1.10.0", "1.9.9") == 1
    assert compare_versions("1.0", "1.0.0") == 0
    assert compare_versions("0.9", "1.0") == -1
