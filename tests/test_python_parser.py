"""Python manifest and requirements parsing."""

from __future__ import annotations

import pytest

from dep_radar.parsers.python import (
    RequirementError,
    normalize_name,
    parse_python_project,
    parse_requirement_line,
    parse_requirements_file,
)


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("Django", "django"),
        ("PyYAML", "pyyaml"),
        ("python_dateutil", "python-dateutil"),
        ("zope.interface", "zope-interface"),
        ("A--B__C", "a-b-c"),
    ],
)
def test_normalize_name(raw, expected):
    assert normalize_name(raw) == expected


def test_parse_pinned_requirement():
    dep = parse_requirement_line("requests==2.31.0")
    assert dep is not None
    assert dep.name == "requests"
    assert dep.spec == "==2.31.0"


def test_parse_extras_and_marker():
    dep = parse_requirement_line('celery[redis,beat]>=5.3.0 ; python_version >= "3.10"')
    assert dep is not None
    assert dep.name == "celery[beat,redis]"
    assert dep.spec == ">=5.3.0"
    assert "python_version" in dep.marker


def test_parse_direct_url_requirement():
    dep = parse_requirement_line("pkg @ https://example.test/pkg-1.0.tar.gz")
    assert dep is not None
    assert dep.spec == "https://example.test/pkg-1.0.tar.gz"


def test_parse_line_ignores_blanks_comments_and_options():
    assert parse_requirement_line("") is None
    assert parse_requirement_line("   # a comment") is None
    assert parse_requirement_line("--index-url https://pypi.test/simple") is None
    assert parse_requirement_line("--hash=sha256:abc") is None


def test_parse_line_with_inline_comment_and_hash():
    dep = parse_requirement_line("flask  # web framework")
    assert dep is not None and dep.name == "flask" and dep.spec == ""
    dep = parse_requirement_line("flask==3.0.0 --hash=sha256:deadbeef")
    assert dep is not None and dep.spec == "==3.0.0"


def test_malformed_requirement_raises():
    with pytest.raises(RequirementError):
        parse_requirement_line("!!!not a requirement!!!")


def test_requirements_includes_are_followed(tmp_path):
    (tmp_path / "base.txt").write_text("requests==2.31.0\n", encoding="utf-8")
    (tmp_path / "requirements.txt").write_text(
        "-r base.txt\nflask==3.0.0\n", encoding="utf-8"
    )
    deps = parse_requirements_file(tmp_path / "requirements.txt")
    assert [d.name for d in deps] == ["requests", "flask"]


def test_circular_include_does_not_loop(tmp_path):
    (tmp_path / "a.txt").write_text("-r b.txt\nalpha==1.0\n", encoding="utf-8")
    (tmp_path / "b.txt").write_text("-r a.txt\nbeta==2.0\n", encoding="utf-8")
    deps = parse_requirements_file(tmp_path / "a.txt")
    assert sorted(d.name for d in deps) == ["alpha", "beta"]


def test_missing_include_reports_file(tmp_path):
    (tmp_path / "requirements.txt").write_text("-r nope.txt\n", encoding="utf-8")
    with pytest.raises(RequirementError, match="include not found"):
        parse_requirements_file(tmp_path / "requirements.txt")


def test_pyproject_pep621_and_optional_dependencies(tmp_path):
    (tmp_path / "pyproject.toml").write_text(
        """
[project]
name = "demo"
dependencies = ["requests==2.31.0", "PyYAML>=6.0"]

[project.optional-dependencies]
dev = ["pytest==8.0.2"]
""",
        encoding="utf-8",
    )
    project = parse_python_project(tmp_path)
    assert project is not None
    assert project.ecosystem.value == "pypi"
    kinds = {(d.name, d.kind) for d in project._root_declared}
    assert ("requests", "prod") in kinds
    assert ("pytest", "dev") in kinds or ("pytest", "optional") in kinds


def test_pyproject_poetry_dependencies(tmp_path):
    (tmp_path / "pyproject.toml").write_text(
        """
[tool.poetry]
name = "demo"

[tool.poetry.dependencies]
python = "^3.11"
django = "^4.2"
requests = { version = "^2.31", optional = true, markers = "python_version > '3.8'" }

[tool.poetry.group.dev.dependencies]
pytest = "^8.0"
""",
        encoding="utf-8",
    )
    project = parse_python_project(tmp_path)
    names = {d.name for d in project._root_declared}
    assert "django" in names and "pytest" in names and "python" not in names


def test_invalid_toml_raises_friendly_error(tmp_path):
    (tmp_path / "pyproject.toml").write_text("[project\nname = 1", encoding="utf-8")
    with pytest.raises(RequirementError, match="not valid TOML"):
        parse_python_project(tmp_path)


def test_requirements_only_project(tmp_path):
    (tmp_path / "requirements.txt").write_text("flask==3.0.0\n", encoding="utf-8")
    project = parse_python_project(tmp_path)
    assert project is not None
    assert project.manifests == ["requirements.txt"]
    assert "flask@==3.0.0" in project.packages


def test_pyproject_plus_requirements_are_deduped(tmp_path):
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "x"\ndependencies = ["requests>=2.0"]\n', encoding="utf-8"
    )
    (tmp_path / "requirements.txt").write_text("requests==2.31.0\n", encoding="utf-8")
    project = parse_python_project(tmp_path)
    names = [d.name for d in project._root_declared]
    assert names.count("requests") == 1


def test_poetry_lock_resolves_versions(tmp_path):
    (tmp_path / "pyproject.toml").write_text(
        '[tool.poetry]\nname = "x"\n[tool.poetry.dependencies]\nrequests = "^2.31"\n',
        encoding="utf-8",
    )
    (tmp_path / "poetry.lock").write_text(
        '[[package]]\nname = "requests"\nversion = "2.31.0"\n',
        encoding="utf-8",
    )
    project = parse_python_project(tmp_path)
    assert project.lockfile == "poetry.lock"
    assert "requests@2.31.0" in project.packages


def test_no_python_manifest_returns_none(tmp_path):
    assert parse_python_project(tmp_path) is None
