"""Source import scanning and unused-dependency detection."""

from __future__ import annotations

from dep_radar.parsers import parse_ecosystem
from dep_radar.source_scan import (
    ImportScan,
    _js_module,
    scan_sources,
    unused_direct_dependencies,
)


def test_python_imports_are_extracted(tmp_path):
    (tmp_path / "app.py").write_text(
        "import os\nimport requests\nfrom yaml import safe_load\nfrom . import local\n",
        encoding="utf-8",
    )
    scan = scan_sources(tmp_path)
    assert scan.python_files == 1
    assert {"os", "requests", "yaml"} <= scan.modules
    assert "local" not in scan.modules


def test_relative_python_imports_are_ignored(tmp_path):
    (tmp_path / "pkg").mkdir()
    (tmp_path / "pkg" / "mod.py").write_text("from . import sibling\n", encoding="utf-8")
    scan = scan_sources(tmp_path)
    assert scan.modules == set()


def test_broken_python_file_falls_back_to_regex(tmp_path):
    (tmp_path / "broken.py").write_text("import numpy\ndef (:\n", encoding="utf-8")
    scan = scan_sources(tmp_path)
    assert "numpy" in scan.modules


def test_js_import_forms_are_extracted(tmp_path):
    (tmp_path / "app.js").write_text(
        "import React from 'react';\n"
        "const lodash = require('lodash');\n"
        "const scoped = require('@babel/core');\n"
        "const local = require('./local');\n"
        "const builtin = require('node:fs');\n"
        "import('./lazy.js');\n",
        encoding="utf-8",
    )
    scan = scan_sources(tmp_path)
    assert {"react", "lodash", "@babel/core", "fs"} <= scan.modules
    assert "./local" not in scan.modules
    assert scan.js_files == 1


def test_skip_directories_are_not_scanned(tmp_path):
    (tmp_path / "node_modules" / "x").mkdir(parents=True)
    (tmp_path / "node_modules" / "x" / "index.js").write_text(
        "require('left-pad');\n", encoding="utf-8"
    )
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "index.js").write_text("require('react');\n", encoding="utf-8")
    scan = scan_sources(tmp_path)
    assert "react" in scan.modules
    assert "left-pad" not in scan.modules
    assert scan.files_scanned == 1


def test_js_module_normalisation():
    assert _js_module("./relative") is None
    assert _js_module("/absolute") is None
    assert _js_module("react/jsx-runtime") == "react"
    assert _js_module("@scope/pkg/sub") == "@scope/pkg"
    assert _js_module("node:fs/promises") == "fs"
    assert _js_module("@broken") is None


def test_import_aliases_match_distribution_names(tmp_path):
    (tmp_path / "app.py").write_text("from PIL import Image\nimport yaml\n", encoding="utf-8")
    scan = scan_sources(tmp_path)
    assert scan.imported("Pillow", "pypi")
    assert scan.imported("PyYAML", "pypi")
    assert not scan.imported("pandas", "pypi")


def test_unused_direct_dependencies(tmp_path):
    (tmp_path / "package.json").write_text(
        '{"name": "x", "dependencies": {"react": "18.2.0", "left-pad": "1.3.0"}}',
        encoding="utf-8",
    )
    (tmp_path / "index.js").write_text("import React from 'react';\n", encoding="utf-8")
    project = parse_ecosystem(tmp_path, "npm")
    scan = scan_sources(tmp_path)
    assert unused_direct_dependencies(project, scan) == ["left-pad"]


def test_no_sources_means_no_unused_findings(tmp_path):
    (tmp_path / "package.json").write_text(
        '{"name": "x", "dependencies": {"left-pad": "1.3.0"}}', encoding="utf-8"
    )
    project = parse_ecosystem(tmp_path, "npm")
    scan = scan_sources(tmp_path)
    assert scan.files_scanned == 0
    assert unused_direct_dependencies(project, scan) == []


def test_dev_dependencies_are_never_reported_unused(tmp_path):
    (tmp_path / "package.json").write_text(
        '{"name": "x", "devDependencies": {"jest": "29.0.0"}}', encoding="utf-8"
    )
    (tmp_path / "index.js").write_text("console.log(1);\n", encoding="utf-8")
    project = parse_ecosystem(tmp_path, "npm")
    assert unused_direct_dependencies(project, scan_sources(tmp_path)) == []


def test_empty_scan_object():
    scan = ImportScan()
    assert scan.files_scanned == 0
    assert scan.imported("anything", "npm") is False
