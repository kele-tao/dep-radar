"""npm manifest and lockfile parsing."""

from __future__ import annotations

import json

import pytest
from conftest import write_npm_project

from dep_radar.model import Ecosystem
from dep_radar.parsers.npm import (
    NpmParseError,
    _name_from_path,
    _source_of,
    _split_spec,
    parse_npm_project,
    parse_package_json,
)


def test_split_spec_handles_scoped_names():
    assert _split_spec("@babel/core@7.24.0") == ("@babel/core", "7.24.0")
    assert _split_spec("@babel/core") == ("@babel/core", "")
    assert _split_spec("lodash@4.17.21") == ("lodash", "4.17.21")
    assert _split_spec("lodash") == ("lodash", "")


def test_name_from_install_path():
    assert _name_from_path("node_modules/lodash") == "lodash"
    assert _name_from_path("node_modules/@babel/core") == "@babel/core"
    assert _name_from_path("node_modules/a/node_modules/@scope/pkg") == "@scope/pkg"


@pytest.mark.parametrize(
    ("spec", "kind"),
    [
        ("^1.2.3", "registry"),
        ("git+https://github.com/a/b.git", "git"),
        ("github:acme/repo", "git"),
        ("https://example.test/pkg-1.0.0.tgz", "tarball"),
        ("https://example.test/pkg.js", "url"),
        ("file:../local", "file"),
        ("workspace:*", "workspace"),
    ],
)
def test_source_of(spec, kind):
    assert _source_of(spec)[0] == kind


def test_parse_package_json_reads_all_dependency_kinds(tmp_path):
    (tmp_path / "package.json").write_text(
        json.dumps(
            {
                "name": "x",
                "dependencies": {"a": "^1.0.0"},
                "devDependencies": {"b": "^2.0.0"},
                "optionalDependencies": {"c": "^3.0.0"},
                "peerDependencies": {"d": "^4.0.0"},
            }
        ),
        encoding="utf-8",
    )
    data, deps = parse_package_json(tmp_path / "package.json")
    assert data["name"] == "x"
    assert {(d.name, d.kind) for d in deps} == {
        ("a", "prod"),
        ("b", "dev"),
        ("c", "optional"),
        ("d", "peer"),
    }


def test_malformed_package_json_raises_friendly_error(tmp_path):
    (tmp_path / "package.json").write_text('{"name": "x",,}', encoding="utf-8")
    with pytest.raises(NpmParseError) as excinfo:
        parse_package_json(tmp_path / "package.json")
    message = str(excinfo.value)
    assert "not valid JSON" in message
    assert "line 1" in message


def test_package_json_must_be_an_object(tmp_path):
    (tmp_path / "package.json").write_text("[1, 2, 3]", encoding="utf-8")
    with pytest.raises(NpmParseError, match="JSON object"):
        parse_package_json(tmp_path / "package.json")


def test_lockfile_builds_graph_and_duplicates(tmp_path):
    write_npm_project(
        tmp_path,
        {
            "a": ("1.0.0", {"c": "^1.0.0"}, "MIT"),
            "b": ("1.0.0", {"c": "^2.0.0"}, "MIT"),
            "c": ("1.0.0", {}, "MIT"),
        },
    )
    # b pins c@2 which npm would nest under b
    lock = json.loads((tmp_path / "package-lock.json").read_text(encoding="utf-8"))
    lock["packages"]["node_modules/b"]["dependencies"] = {"c": "^2.0.0"}
    lock["packages"]["node_modules/b/node_modules/c"] = {
        "version": "2.0.0",
        "license": "MIT",
        "name": "c",
    }
    lock["packages"][""]["dependencies"] = {"a": "^1.0.0", "b": "^1.0.0"}
    (tmp_path / "package-lock.json").write_text(json.dumps(lock), encoding="utf-8")
    project = parse_npm_project(tmp_path)
    assert project is not None
    assert project.ecosystem is Ecosystem.NPM
    assert len(project.packages) == 4
    assert {p.key for p in project.packages.values()} >= {"c@1.0.0", "c@2.0.0"}
    children = {e.child for e in project.edges if e.parent == "b@1.0.0"}
    assert "c@2.0.0" in children


def test_lockfile_records_install_scripts_and_deprecations(tmp_path):
    write_npm_project(
        tmp_path,
        {"a": ("1.0.0", {}, "MIT")},
    )
    lock = json.loads((tmp_path / "package-lock.json").read_text(encoding="utf-8"))
    lock["packages"]["node_modules/a"]["hasInstallScript"] = True
    lock["packages"]["node_modules/a"]["deprecated"] = "use b instead"
    (tmp_path / "package-lock.json").write_text(json.dumps(lock), encoding="utf-8")
    project = parse_npm_project(tmp_path)
    package = project.packages["a@1.0.0"]
    assert package.has_install_script is True
    assert package.deprecated == "use b instead"


def test_manifest_without_lockfile_still_yields_edges(tmp_path):
    (tmp_path / "package.json").write_text(
        json.dumps({"name": "x", "dependencies": {"left-pad": "^1.3.0"}}), encoding="utf-8"
    )
    project = parse_npm_project(tmp_path)
    assert project is not None
    assert project.lockfile == ""
    assert any("no package-lock.json" in warning for warning in project.warnings)
    assert [edge.child for edge in project.edges] == ["left-pad@unresolved"]


def test_v1_lockfile_is_flattened(tmp_path):
    (tmp_path / "package.json").write_text(
        json.dumps({"name": "x", "dependencies": {"a": "^1.0.0"}}), encoding="utf-8"
    )
    lock = {
        "name": "x",
        "lockfileVersion": 1,
        "dependencies": {"a": {"version": "1.0.0", "dependencies": {"b": {"version": "2.0.0"}}}},
    }
    (tmp_path / "package-lock.json").write_text(json.dumps(lock), encoding="utf-8")
    project = parse_npm_project(tmp_path)
    assert "a@1.0.0" in project.packages
    assert "b@2.0.0" in project.packages


def test_yarn_lock_v1_is_parsed(tmp_path):
    (tmp_path / "package.json").write_text(
        json.dumps({"name": "x", "dependencies": {"a": "^1.0.0"}}), encoding="utf-8"
    )
    (tmp_path / "yarn.lock").write_text(
        '# yarn lockfile v1\n'
        '\n'
        'a@^1.0.0:\n'
        '  version "1.0.0"\n'
        '  resolved "https://registry.yarnpkg.com/a/-/a-1.0.0.tgz"\n'
        '  integrity sha512-AAA\n'
        '  dependencies:\n'
        '    b "^2.0.0"\n'
        '\n'
        'b@^2.0.0:\n'
        '  version "2.0.0"\n'
        '  resolved "https://registry.yarnpkg.com/b/-/b-2.0.0.tgz"\n',
        encoding="utf-8",
    )
    project = parse_npm_project(tmp_path)
    assert project is not None
    assert project.lockfile == "yarn.lock"
    assert {p.key for p in project.packages.values()} == {"a@1.0.0", "b@2.0.0"}
    assert any(edge.parent == "a@1.0.0" and edge.child == "b@2.0.0" for edge in project.edges)


def test_non_registry_resolved_urls_are_flagged(tmp_path):
    write_npm_project(tmp_path, {"a": ("1.0.0", {}, "MIT")})
    lock = json.loads((tmp_path / "package-lock.json").read_text(encoding="utf-8"))
    lock["packages"]["node_modules/a"]["resolved"] = "git+ssh://git@github.com/acme/a.git#v1"
    (tmp_path / "package-lock.json").write_text(json.dumps(lock), encoding="utf-8")
    project = parse_npm_project(tmp_path)
    assert project.packages["a@1.0.0"].source_kind == "git"
