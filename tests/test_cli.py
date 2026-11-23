"""End-to-end CLI behaviour: exit codes, output formats and error messages."""

from __future__ import annotations

import json

import pytest

from dep_radar.cli import main


def test_help_exits_zero(capsys):
    with pytest.raises(SystemExit) as excinfo:
        main(["--help"])
    assert excinfo.value.code == 0
    assert "supply-chain audit for Python and Node" in capsys.readouterr().out


def test_version_flag(capsys):
    with pytest.raises(SystemExit) as excinfo:
        main(["--version"])
    assert excinfo.value.code == 0
    assert "dep-radar 1.0.0" in capsys.readouterr().out


def test_no_command_prints_help_and_exits_2(capsys):
    assert main([]) == 2
    assert "usage:" in capsys.readouterr().out


def test_scan_node_example_text_output(node_app, capsys):
    assert main(["scan", str(node_app), "--no-color"]) == 0
    out = capsys.readouterr().out
    assert "supply-chain score" in out
    assert "axois" in out
    assert "typosquat" in out


def test_scan_json_schema(node_app, capsys):
    assert main(["scan", str(node_app), "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["schema"] == "dep-radar/scan@1"
    assert payload["ecosystem"] == "npm"
    assert payload["stats"]["packages"] > 100
    assert payload["score"] == payload["score"]
    assert isinstance(payload["findings"], list)
    assert {"critical", "high", "medium", "low", "info"} == set(payload["severity_counts"])


def test_scan_fail_under_exits_1(node_app, capsys):
    assert main(["scan", str(node_app), "--json", "--fail-under", "90"]) == 1
    capsys.readouterr()


def test_scan_fail_under_passes_for_python_example(py_app, capsys):
    assert main(["scan", str(py_app), "--json", "--fail-under", "60"]) == 0
    capsys.readouterr()


def test_scan_fail_under_out_of_range_is_usage_error(node_app, capsys):
    assert main(["scan", str(node_app), "--fail-under", "101"]) == 2
    assert "--fail-under" in capsys.readouterr().err


def test_scan_html_report(node_app, tmp_path, capsys):
    out = tmp_path / "nested" / "report.html"
    assert main(["scan", str(node_app), "--html", str(out), "--quiet"]) == 0
    html = out.read_text(encoding="utf-8")
    assert "<!doctype html>" in html
    assert "axois" in html
    assert "http-equiv" not in html


def test_scan_quiet_prints_nothing(node_app, capsys):
    assert main(["scan", str(node_app), "--quiet"]) == 0
    assert capsys.readouterr().out.strip() == ""


def test_scan_missing_path_is_usage_error(tmp_path, capsys):
    assert main(["scan", str(tmp_path / "nope")]) == 2
    assert "path does not exist" in capsys.readouterr().err


def test_scan_file_path_is_usage_error(tmp_path, capsys):
    target = tmp_path / "package.json"
    target.write_text("{}", encoding="utf-8")
    assert main(["scan", str(target)]) == 2
    assert "expected a project directory" in capsys.readouterr().err


def test_scan_directory_without_manifest(tmp_path, capsys):
    assert main(["scan", str(tmp_path)]) == 2
    err = capsys.readouterr().err
    assert "no supported manifest" in err
    assert "package.json" in err


def test_scan_malformed_manifest_is_usage_error(tmp_path, capsys):
    (tmp_path / "package.json").write_text("{oops", encoding="utf-8")
    assert main(["scan", str(tmp_path)]) == 2
    assert "not valid JSON" in capsys.readouterr().err


def test_explain_text_output(node_app, capsys):
    assert main(["explain", "accepts", str(node_app)]) == 0
    out = capsys.readouterr().out
    assert "pulled in by" in out
    assert "express@4.19.2 -> accepts@1.3.8" in out


def test_explain_json_output(node_app, capsys):
    assert main(["explain", "lodash", str(node_app), "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["found"] is True
    assert payload["matches"][0]["direct"] is True


def test_explain_unknown_package_exits_1(node_app, capsys):
    assert main(["explain", "not-a-real-package", str(node_app)]) == 1
    assert "no package matching" in capsys.readouterr().err


def test_explain_ecosystem_override(node_app, capsys):
    assert main(["explain", "lodash", str(node_app), "--ecosystem", "npm", "--json"]) == 0
    capsys.readouterr()


def test_sbom_cyclonedx_to_stdout(node_app, capsys):
    assert main(["sbom", str(node_app), "--format", "cyclonedx"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["bomFormat"] == "CycloneDX"


def test_sbom_aliases_and_out_file(node_app, tmp_path, capsys):
    out = tmp_path / "sbom.json"
    assert main(["sbom", str(node_app), "--format", "spdx-like", "--out", str(out)]) == 0
    payload = json.loads(out.read_text(encoding="utf-8"))
    assert payload["spdxVersion"] == "SPDX-2.3"
    assert "wrote" in capsys.readouterr().out


def test_sbom_validate_passes(node_app, capsys):
    assert main(["sbom", str(node_app), "--validate"]) == 0
    capsys.readouterr()


def test_forced_ecosystem_mismatch_is_usage_error(node_app, capsys):
    assert main(["scan", str(node_app), "--ecosystem", "pypi"]) == 2
    assert "no supported manifest" in capsys.readouterr().err


def test_scan_no_source_scan_flag(node_app, capsys):
    assert main(["scan", str(node_app), "--json", "--no-source-scan"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["source_scan"]["files"] == 0


def test_scan_unicode_project(tmp_path, capsys):
    project = tmp_path / "项目-项目"
    project.mkdir()
    (project / "package.json").write_text(
        json.dumps(
            {
                "name": "unicode-app",
                "description": "emoji \U0001f680 and CJK \u4f9d\u8d56",
                "dependencies": {"lodash": "4.17.21"},
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )
    (project / ".gitignore").write_text("node_modules/\n", encoding="utf-8")
    assert main(["scan", str(project), "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["stats"]["packages"] == 1


def test_scan_large_tree_performance(tmp_path, capsys):
    """A 1000-package lockfile must scan quickly and without recursion errors."""
    packages: dict = {"": {"name": "big", "version": "1.0.0", "dependencies": {}}}
    for index in range(1000):
        name = "pkg" + str(index)
        packages["node_modules/" + name] = {
            "version": "1.0.0",
            "license": "MIT",
            "name": name,
            "resolved": "https://registry.npmjs.org/" + name + "/-/" + name + "-1.0.0.tgz",
        }
        packages[""]["dependencies"][name] = "^1.0.0"
    (tmp_path / "package.json").write_text(
        json.dumps({"name": "big", "dependencies": packages[""]["dependencies"]}), encoding="utf-8"
    )
    (tmp_path / "package-lock.json").write_text(
        json.dumps({"name": "big", "version": "1.0.0", "lockfileVersion": 3, "packages": packages}),
        encoding="utf-8",
    )
    assert main(["scan", str(tmp_path), "--json", "--no-source-scan"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["stats"]["packages"] == 1000
    assert payload["stats"]["direct"] == 1000


def test_scan_is_deterministic(node_app, capsys):
    main(["scan", str(node_app), "--json"])
    first = capsys.readouterr().out
    main(["scan", str(node_app), "--json"])
    second = capsys.readouterr().out
    assert first == second
