"""The bundled TOML reader and the Python 3.10 fallback path.

`tomllib` is stdlib from 3.11 only. These tests exercise `dep_radar.toml_lite`
directly and then force the parser module down the fallback path by setting its
`tomllib` reference to None - the same state a real Python 3.10 interpreter is
in - and assert the resulting graph is identical to the stdlib path.
"""

from __future__ import annotations

import pytest

import dep_radar.parsers.python as python_parser
from dep_radar.parsers.python import RequirementError, parse_python_project
from dep_radar.toml_lite import TomlError, loads

PEP621 = '''
# A PEP 621 manifest with the constructs dep-radar actually reads.
[build-system]
requires = ["setuptools>=68", "wheel"]
build-backend = "setuptools.build_meta"

[project]
name = "demo"
version = "0.9.3"
description = """
multi-line
description"""
requires-python = ">=3.10"
dependencies = [
  "Django>=4.2,<5.0",
  "requests==2.31.0",   # pinned on purpose
  "celery[redis]>=5.3.0 ; python_version >= '3.10'",
]

[project.optional-dependencies]
dev = ["pytest==8.0.2", "ruff>=0.3.0"]
'''

POETRY = '''
[tool.poetry]
name = "demo"

[tool.poetry.dependencies]
python = "^3.11"
django = "^4.2"
requests = { version = "^2.31", optional = true, extras = ["socks"], markers = "python_version > '3.8'" }

[tool.poetry.group.dev.dependencies]
pytest = "^8.0"

[[package]]
name = "requests"
version = "2.31.0"
'''

LOCK = '''
[[package]]
name = "requests"
version = "2.31.0"
description = 'HTTP for Humans'
files = [{file = "requests-2.31.0-py3-none-any.whl", hash = "sha256:abc"}]

[[package]]
name = "urllib3"
version = "2.2.1"
'''


def test_pep621_document():
    data = loads(PEP621)
    project = data["project"]
    assert project["name"] == "demo"
    assert project["requires-python"] == ">=3.10"
    assert project["dependencies"] == [
        "Django>=4.2,<5.0",
        "requests==2.31.0",
        "celery[redis]>=5.3.0 ; python_version >= '3.10'",
    ]
    assert project["optional-dependencies"]["dev"] == ["pytest==8.0.2", "ruff>=0.3.0"]
    assert data["build-system"]["build-backend"] == "setuptools.build_meta"
    assert project["description"] == "multi-line\ndescription"


def test_poetry_tables_and_inline_tables():
    data = loads(POETRY)
    poetry = data["tool"]["poetry"]
    assert poetry["dependencies"]["python"] == "^3.11"
    assert poetry["dependencies"]["requests"] == {
        "version": "^2.31",
        "optional": True,
        "extras": ["socks"],
        "markers": "python_version > '3.8'",
    }
    assert poetry["group"]["dev"]["dependencies"]["pytest"] == "^8.0"
    assert data["package"][0]["name"] == "requests"


def test_array_of_tables_like_a_lockfile():
    data = loads(LOCK)
    assert [entry["name"] for entry in data["package"]] == ["requests", "urllib3"]
    assert data["package"][0]["files"][0]["hash"] == "sha256:abc"
    assert data["package"][0]["description"] == "HTTP for Humans"


def test_scalars_and_dotted_keys():
    data = loads(
        "int = 1_000\n"
        "hex = 0xff\n"
        "float = 1.5e3\n"
        "yes = true\n"
        "no = false\n"
        "dotted.key = 'v'\n"
        "quoted.\"weird key\" = 1\n"
    )
    assert data["int"] == 1000
    assert data["hex"] == 255
    assert data["float"] == 1500.0
    assert data["yes"] is True and data["no"] is False
    assert data["dotted"]["key"] == "v"
    assert data["quoted"]["weird key"] == 1


def test_escapes_and_literal_strings():
    # In a literal string backslashes are data, not escapes.
    data = loads(r'a = "tab\there"' + "\n" + r"b = 'C:\temp\new'" + "\n" + r'c = "\u00e9"')
    assert data["a"] == "tab\there"
    assert data["b"] == "C:\\temp\\new"
    assert data["c"] == "\u00e9"


@pytest.mark.parametrize(
    ("document", "fragment", "line"),
    [
        ("[a\nname = 'x'", "expected ']'", 1),
        ("a = ", "expected a value", 1),
        ('a = "unterminated', "unterminated string", 1),
        ("a = 1\na = 2", "duplicate key", 2),
        ("a = 1 trailing", "unexpected characters", 1),
        ("a = unknown-token", "unsupported value", 1),
        ("a = [1, 2", "expected ',' or ']'", 1),
        ("a = {b = 1", "expected ',' or '}'", 1),
    ],
)
def test_syntax_errors_carry_a_line_number(document, fragment, line):
    with pytest.raises(TomlError) as excinfo:
        loads(document)
    assert fragment in str(excinfo.value)
    assert "line " + str(line) in str(excinfo.value)


def test_empty_document():
    assert loads("") == {}
    assert loads("# only a comment\n") == {}


def test_loads_rejects_non_string():
    with pytest.raises(TypeError):
        loads(b"[project]")


@pytest.fixture
def fallback(monkeypatch):
    """Force the parser module to behave like Python 3.10 (no tomllib)."""
    monkeypatch.setattr(python_parser, "tomllib", None)
    return python_parser


def test_fallback_parses_the_python_example(py_app, fallback):
    project = parse_python_project(py_app)
    assert project is not None
    declared = {dep.name: dep.spec for dep in project._root_declared}
    assert declared["requests"] == "==2.31.0"
    assert declared["django"] == ">=4.2,<5.0"
    assert "pytest" in declared


def test_fallback_matches_the_stdlib_parser(py_app, monkeypatch):
    stdlib_project = parse_python_project(py_app)
    stdlib_declared = sorted((d.name, d.spec, d.kind) for d in stdlib_project._root_declared)
    monkeypatch.setattr(python_parser, "tomllib", None)
    fallback_project = parse_python_project(py_app)
    fallback_declared = sorted((d.name, d.spec, d.kind) for d in fallback_project._root_declared)
    assert fallback_declared == stdlib_declared


def test_fallback_parses_poetry(tmp_path, fallback):
    (tmp_path / "pyproject.toml").write_text(POETRY, encoding="utf-8")
    (tmp_path / "poetry.lock").write_text(LOCK, encoding="utf-8")
    project = parse_python_project(tmp_path)
    assert project.lockfile == "poetry.lock"
    assert "requests@2.31.0" in project.packages
    assert "urllib3@2.2.1" in project.packages
    names = {dep.name for dep in project._root_declared}
    assert {"django", "pytest"} <= names and "python" not in names


def test_fallback_reports_unparseable_toml(tmp_path, fallback):
    (tmp_path / "pyproject.toml").write_text("[project\nname = 'x'\n", encoding="utf-8")
    with pytest.raises(RequirementError) as excinfo:
        parse_python_project(tmp_path)
    message = str(excinfo.value)
    assert "pyproject.toml is not valid TOML" in message
    assert "line 1" in message


def test_fallback_survives_a_broken_poetry_lock(tmp_path, fallback):
    (tmp_path / "pyproject.toml").write_text(POETRY, encoding="utf-8")
    (tmp_path / "poetry.lock").write_text("[[package]\nname = ", encoding="utf-8")
    project = parse_python_project(tmp_path)
    assert project is not None
    assert project.lockfile == ""


def test_requirements_parsing_is_unchanged_on_310(tmp_path, fallback):
    (tmp_path / "requirements.txt").write_text(
        "requests==2.31.0\ncelery[redis]>=5.3.0 ; python_version >= '3.10'\n",
        encoding="utf-8",
    )
    project = parse_python_project(tmp_path)
    assert project.manifests == ["requirements.txt"]
    assert [dep.name for dep in project._root_declared] == ["requests", "celery[redis]"]
