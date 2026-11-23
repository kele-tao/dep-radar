"""Generate the bundled example projects.

The examples are synthetic fixtures: a realistic npm app (hoisted lockfile,
duplicate versions, a planted typosquat) and a Python app with markers and
requirements includes. Data is deterministic so the committed fixtures never
churn. Run:  python scripts/gen_examples.py
"""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
NODE_APP = ROOT / "examples" / "node-app"
PY_APP = ROOT / "examples" / "py-app"

# name -> (license, {version: {dependency: range}})
NPM_PACKAGES: dict[str, tuple[str, dict[str, dict[str, str]]]] = {
    "accepts": ("MIT", {"1.3.8": {"mime-types": "~2.1.34", "negotiator": "0.6.3"}}),
    "acorn": ("MIT", {"8.11.3": {}}),
    "acorn-jsx": ("MIT", {"5.3.2": {"acorn": "^6.0.0 || ^7.0.0 || ^8.0.0"}}),
    "ajv": ("MIT", {"6.12.6": {"fast-deep-equal": "^3.1.1", "fast-json-stable-stringify": "^2.0.0", "json-schema-traverse": "^0.4.1", "uri-js": "^4.2.2"}}),
    "ansi-regex": ("MIT", {"5.0.1": {}}),
    "ansi-styles": ("MIT", {"4.3.0": {"color-convert": "^2.0.1"}}),
    "argparse": ("Python-2.0", {"2.0.1": {}}),
    "array-flatten": ("MIT", {"1.1.1": {}}),
    "asynckit": ("MIT", {"0.4.0": {}}),
    "axios": ("MIT", {"1.6.8": {"follow-redirects": "^1.15.6", "form-data": "^4.0.0", "proxy-from-env": "^1.1.0"}}),
    "balanced-match": ("MIT", {"1.0.2": {}}),
    "body-parser": ("MIT", {"1.20.2": {"bytes": "3.1.2", "content-type": "~1.0.5", "debug": "2.6.9", "depd": "2.0.0", "destroy": "1.2.0", "http-errors": "2.0.0", "iconv-lite": "0.4.24", "on-finished": "2.4.1", "qs": "6.11.0", "raw-body": "2.5.2", "type-is": "~1.6.18", "unpipe": "1.0.0"}}),
    "brace-expansion": ("MIT", {"1.1.11": {"balanced-match": "^1.0.0", "concat-map": "0.0.1"}}),
    "braces": ("MIT", {"3.0.2": {"fill-range": "^7.0.1"}}),
    "bytes": ("MIT", {"3.1.2": {}}),
    "call-bind": ("MIT", {"1.0.7": {"es-define-property": "^1.0.0", "es-errors": "^1.3.0", "function-bind": "^1.1.2", "get-intrinsic": "^1.2.4", "set-function-length": "^1.2.1"}}),
    "chalk": ("MIT", {"5.3.0": {}, "4.1.2": {"ansi-styles": "^4.1.0", "supports-color": "^7.1.0"}}),
    "color-convert": ("MIT", {"2.0.1": {"color-name": "~1.1.4"}}),
    "color-name": ("MIT", {"1.1.4": {}}),
    "combined-stream": ("MIT", {"1.0.8": {"delayed-stream": "~1.0.0"}}),
    "concat-map": ("MIT", {"0.0.1": {}}),
    "content-disposition": ("MIT", {"0.5.4": {"safe-buffer": "5.2.1"}}),
    "content-type": ("MIT", {"1.0.5": {}}),
    "cookie": ("MIT", {"0.6.0": {}}),
    "core-js": ("MIT", {"3.36.1": {}}),
    "cross-spawn": ("MIT", {"7.0.3": {"path-key": "^3.1.0", "shebang-command": "^2.0.0", "which": "^2.0.1"}}),
    "debug": ("MIT", {"4.3.4": {"ms": "2.1.3"}, "2.6.9": {"ms": "2.0.0"}}),
    "deep-is": ("MIT", {"0.1.4": {}}),
    "delayed-stream": ("MIT", {"1.0.0": {}}),
    "depd": ("MIT", {"2.0.0": {}}),
    "destroy": ("MIT", {"1.2.0": {}}),
    "doctrine": ("Apache-2.0", {"3.0.0": {"esutils": "^2.0.2"}}),
    "dotenv": ("BSD-2-Clause", {"16.4.5": {}}),
    "ee-first": ("MIT", {"1.1.1": {}}),
    "encodeurl": ("MIT", {"1.0.2": {}}),
    "es-define-property": ("MIT", {"1.0.0": {}}),
    "es-errors": ("MIT", {"1.3.0": {}}),
    "escape-html": ("MIT", {"1.0.3": {}}),
    "eslint": ("MIT", {"8.57.0": {"ajv": "^6.12.4", "chalk": "^4.0.0", "cross-spawn": "^7.0.2", "debug": "^4.3.2", "doctrine": "^3.0.0", "espree": "^9.6.0", "esquery": "^1.4.2", "glob-parent": "^6.0.2", "ignore": "^5.2.0", "js-yaml": "^4.1.0", "levn": "^0.4.1", "lodash.merge": "^4.6.2", "minimatch": "^3.1.2", "optionator": "^0.9.3", "strip-ansi": "^6.0.1", "text-table": "^0.2.0"}}),
    "eslint-visitor-keys": ("Apache-2.0", {"3.4.3": {}}),
    "espree": ("BSD-2-Clause", {"9.6.1": {"acorn": "^8.9.0", "acorn-jsx": "^5.3.2", "eslint-visitor-keys": "^3.4.1"}}),
    "esquery": ("BSD-3-Clause", {"1.5.0": {"estraverse": "^5.1.0"}}),
    "estraverse": ("BSD-2-Clause", {"5.3.0": {}}),
    "esutils": ("BSD-2-Clause", {"2.0.3": {}}),
    "etag": ("MIT", {"1.8.1": {}}),
    "express": ("MIT", {"4.19.2": {"accepts": "~1.3.8", "array-flatten": "1.1.1", "body-parser": "1.20.2", "content-disposition": "0.5.4", "cookie": "0.6.0", "debug": "2.6.9", "depd": "2.0.0", "encodeurl": "~1.0.2", "escape-html": "~1.0.3", "etag": "~1.8.1", "finalhandler": "1.2.0", "fresh": "0.5.2", "http-errors": "2.0.0", "merge-descriptors": "1.0.3", "methods": "~1.1.2", "on-finished": "2.4.1", "parseurl": "~1.3.3", "path-to-regexp": "0.1.7", "proxy-addr": "~2.0.7", "qs": "6.11.0", "range-parser": "~1.2.1", "safe-buffer": "5.2.1", "send": "0.18.0", "serve-static": "1.15.0", "setprototypeof": "1.2.0", "statuses": "2.0.1", "type-is": "~1.6.18", "utils-merge": "1.0.1", "vary": "~1.1.2"}}),
    "fast-deep-equal": ("MIT", {"3.1.3": {}}),
    "fast-json-stable-stringify": ("MIT", {"2.1.0": {}}),
    "fill-range": ("MIT", {"7.1.1": {"to-regex-range": "^5.0.1"}}),
    "finalhandler": ("MIT", {"1.2.0": {"debug": "2.6.9", "encodeurl": "~1.0.2", "escape-html": "~1.0.3", "on-finished": "2.4.1", "parseurl": "~1.3.3", "statuses": "2.0.1", "unpipe": "~1.0.0"}}),
    "follow-redirects": ("MIT", {"1.15.6": {}}),
    "form-data": ("MIT", {"4.0.0": {"asynckit": "^0.4.0", "combined-stream": "^1.0.8", "mime-types": "^2.1.12"}}),
    "forwarded": ("MIT", {"0.2.0": {}}),
    "fresh": ("MIT", {"0.5.2": {}}),
    "fs.realpath": ("ISC", {"1.0.0": {}}),
    "function-bind": ("MIT", {"1.1.2": {}}),
    "get-intrinsic": ("MIT", {"1.2.4": {"es-errors": "^1.3.0", "function-bind": "^1.1.2", "has-symbols": "^1.0.3", "hasown": "^2.0.0"}}),
    "glob": ("ISC", {"7.2.3": {"fs.realpath": "^1.0.0", "inflight": "^1.0.4", "inherits": "2", "minimatch": "^3.1.1", "once": "^1.3.0", "path-is-absolute": "^1.0.0"}}),
    "glob-parent": ("ISC", {"6.0.2": {"is-glob": "^4.0.3"}}),
    "has-flag": ("MIT", {"4.0.0": {}}),
    "has-symbols": ("MIT", {"1.0.3": {}}),
    "hasown": ("MIT", {"2.0.2": {"function-bind": "^1.1.2"}}),
    "http-errors": ("MIT", {"2.0.0": {"depd": "2.0.0", "inherits": "2.0.4", "setprototypeof": "1.2.0", "statuses": "2.0.1", "toidentifier": "1.0.1"}}),
    "iconv-lite": ("MIT", {"0.4.24": {"safer-buffer": ">= 2.1.2 < 3"}}),
    "ignore": ("MIT", {"5.3.1": {}}),
    "inflight": ("ISC", {"1.0.6": {"once": "^1.3.0", "wrappy": "1"}}),
    "inherits": ("ISC", {"2.0.4": {}}),
    "ipaddr.js": ("MIT", {"1.9.1": {}}),
    "is-extglob": ("MIT", {"2.1.1": {}}),
    "is-glob": ("MIT", {"4.0.3": {"is-extglob": "^2.1.1"}}),
    "is-number": ("MIT", {"7.0.0": {}}),
    "isexe": ("ISC", {"2.0.0": {}}),
    "js-tokens": ("MIT", {"4.0.0": {}}),
    "js-yaml": ("MIT", {"4.1.0": {"argparse": "^2.0.1"}}),
    "json-schema-traverse": ("MIT", {"0.4.1": {}}),
    "levn": ("MIT", {"0.4.1": {"prelude-ls": "^1.2.1", "type-check": "~0.4.0"}}),
    "lodash": ("MIT", {"4.17.21": {}}),
    "lodash.merge": ("MIT", {"4.6.2": {}}),
    "loose-envify": ("MIT", {"1.4.0": {"js-tokens": "^3.0.0 || ^4.0.0"}}),
    "media-typer": ("MIT", {"0.3.0": {}}),
    "merge-descriptors": ("MIT", {"1.0.3": {}}),
    "methods": ("MIT", {"1.1.2": {}}),
    "mime": ("MIT", {"1.6.0": {}}),
    "mime-db": ("MIT", {"1.52.0": {}}),
    "mime-types": ("MIT", {"2.1.35": {"mime-db": "1.52.0"}}),
    "minimatch": ("ISC", {"3.1.2": {"brace-expansion": "^1.1.7"}}),
    "ms": ("MIT", {"2.1.3": {}, "2.0.0": {}}),
    "mupdf": ("AGPL-3.0", {"1.24.0": {}}),
    "negotiator": ("MIT", {"0.6.3": {}}),
    "object-inspect": ("MIT", {"1.13.1": {}}),
    "on-finished": ("MIT", {"2.4.1": {"ee-first": "1.1.1"}}),
    "once": ("ISC", {"1.4.0": {"wrappy": "1"}}),
    "optionator": ("MIT", {"0.9.4": {"deep-is": "^0.1.3", "levn": "^0.4.1", "prelude-ls": "^1.2.1", "type-check": "^0.4.0", "word-wrap": "^1.2.5"}}),
    "parseurl": ("MIT", {"1.3.3": {}}),
    "path-is-absolute": ("MIT", {"1.0.1": {}}),
    "path-key": ("MIT", {"3.1.1": {}}),
    "path-to-regexp": ("MIT", {"0.1.7": {}}),
    "prelude-ls": ("MIT", {"1.2.1": {}}),
    "proxy-addr": ("MIT", {"2.0.7": {"forwarded": "0.2.0", "ipaddr.js": "1.9.1"}}),
    "proxy-from-env": ("MIT", {"1.1.0": {}}),
    "punycode": ("MIT", {"2.3.1": {}}),
    "qs": ("BSD-3-Clause", {"6.11.0": {"side-channel": "^1.0.6"}}),
    "range-parser": ("MIT", {"1.2.1": {}}),
    "raw-body": ("MIT", {"2.5.2": {"bytes": "3.1.2", "http-errors": "2.0.0", "iconv-lite": "0.4.24", "unpipe": "1.0.0"}}),
    "react": ("MIT", {"18.3.1": {"loose-envify": "^1.1.0"}}),
    "react-dom": ("MIT", {"18.3.1": {"loose-envify": "^1.1.0", "scheduler": "^0.23.2"}}),
    "request": ("Apache-2.0", {"2.88.2": {}}),
    "rimraf": ("ISC", {"3.0.2": {"glob": "^7.1.3"}}),
    "safe-buffer": ("MIT", {"5.2.1": {}}),
    "safer-buffer": ("MIT", {"2.1.2": {}}),
    "scheduler": ("MIT", {"0.23.2": {"loose-envify": "^1.1.0"}}),
    "send": ("MIT", {"0.18.0": {"debug": "2.6.9", "depd": "2.0.0", "destroy": "1.2.0", "encodeurl": "~1.0.2", "escape-html": "~1.0.3", "etag": "~1.8.1", "fresh": "0.5.2", "http-errors": "2.0.0", "mime": "1.6.0", "ms": "2.1.3", "on-finished": "2.4.1", "range-parser": "~1.2.1", "statuses": "2.0.1"}}),
    "serve-static": ("MIT", {"1.15.0": {"encodeurl": "~1.0.2", "escape-html": "~1.0.3", "parseurl": "~1.3.3", "send": "0.18.0"}}),
    "set-function-length": ("MIT", {"1.2.2": {"define-data-property": "^1.1.4", "es-errors": "^1.3.0", "function-bind": "^1.1.2", "get-intrinsic": "^1.2.4", "gopd": "^1.0.1", "has-property-descriptors": "^1.0.2"}}),
    "setprototypeof": ("ISC", {"1.2.0": {}}),
    "shebang-command": ("MIT", {"2.0.0": {"shebang-regex": "^3.0.0"}}),
    "shebang-regex": ("MIT", {"3.0.0": {}}),
    "side-channel": ("MIT", {"1.0.6": {"call-bind": "^1.0.7", "es-errors": "^1.3.0", "get-intrinsic": "^1.2.4", "object-inspect": "^1.13.1"}}),
    "statuses": ("MIT", {"2.0.1": {}}),
    "strip-ansi": ("MIT", {"6.0.1": {"ansi-regex": "^5.0.1"}}),
    "supports-color": ("MIT", {"7.2.0": {"has-flag": "^4.0.0"}}),
    "text-table": ("MIT", {"0.2.0": {}}),
    "to-regex-range": ("MIT", {"5.0.1": {"is-number": "^7.0.0"}}),
    "toidentifier": ("MIT", {"1.0.1": {}}),
    "tslint": ("Apache-2.0", {"6.1.3": {}}),
    "type-check": ("MIT", {"0.4.0": {"prelude-ls": "^1.2.1"}}),
    "type-is": ("MIT", {"1.6.18": {"media-typer": "0.3.0", "mime-types": "~2.1.24"}}),
    "typescript": ("Apache-2.0", {"5.4.5": {}}),
    "unpipe": ("MIT", {"1.0.0": {}}),
    "uri-js": ("BSD-2-Clause", {"4.4.1": {"punycode": "^2.1.0"}}),
    "utils-merge": ("MIT", {"1.0.1": {}}),
    "vary": ("MIT", {"1.1.2": {}}),
    "which": ("ISC", {"2.0.2": {"isexe": "^2.0.0"}}),
    "word-wrap": ("MIT", {"1.2.5": {}}),
    "wrappy": ("ISC", {"1.0.2": {}}),
    # --- planted supply-chain hazards -------------------------------------
    "axois": ("MIT", {"1.6.8": {"follow-redirects": "^1.15.6", "form-data": "^4.0.0", "proxy-from-env": "^1.1.0"}}),
    "expres": ("MIT", {"4.18.1": {"body-parser": "1.20.2", "debug": "2.6.9"}}),
    "define-data-property": ("MIT", {"1.1.4": {"es-define-property": "^1.0.0", "es-errors": "^1.3.0"}}),
    "gopd": ("MIT", {"1.0.1": {}}),
    "has-property-descriptors": ("MIT", {"1.0.2": {"es-define-property": "^1.0.0"}}),
}

# Extra packages that are metadata-only hazards (no deps, flagged in the lockfile).
DEPRECATED = {
    "request": "request has been deprecated, see https://github.com/request/request/issues/3142",
    "tslint": "tslint has been deprecated, use typescript-eslint instead",
}
INSTALL_SCRIPTS = {"core-js": "node -e \"try{require('./postinstall')}catch(e){}\""}
GIT_PACKAGES = {
    "acme-github-fetch": (
        "1.2.0",
        "MIT",
        {"follow-redirects": "^1.15.6"},
        "git+ssh://git@github.com/acme/github-fetch.git#v1.2.0",
    )
}
TARBALL_PACKAGES = {
    "legacy-sdk": (
        "1.0.0",
        "UNLICENSED",
        {},
        "https://artifacts.acme.example/legacy-sdk-1.0.0.tgz",
    )
}

ROOT_MANIFEST = {
    "name": "acme-dashboard",
    "version": "2.4.0",
    "private": True,
    "description": "Synthetic demo application used by the dep-radar examples.",
    "scripts": {
        "build": "node scripts/build.js",
        "start": "node src/server.js",
        "test": "node scripts/test.js",
    },
    "dependencies": {
        "acme-github-fetch": "github:acme/github-fetch#v1.2.0",
        "axios": "^1.6.3",
        "axois": "^1.6.3",
        "chalk": "^5.3.0",
        "core-js": "^3.36.0",
        "dotenv": "*",
        "expres": "^4.18.0",
        "express": "^4.18.2",
        "legacy-sdk": "https://artifacts.acme.example/legacy-sdk-1.0.0.tgz",
        "lodash": "^4.17.20",
        "mupdf": "^1.24.0",
        "react": "^18.2.0",
        "react-dom": "^18.2.0",
    },
    "devDependencies": {
        "eslint": "^8.56.0",
        "request": "^2.88.2",
        "tslint": "^6.1.3",
        "typescript": "^5.3.2",
    },
}


def integrity(name: str, version: str) -> str:
    digest = hashlib.sha512((name + "@" + version).encode("utf-8")).digest()
    return "sha512-" + base64.b64encode(digest).decode("ascii")


def resolve(installed: dict[str, dict[str, str]], parent_path: str, dep: str) -> str | None:
    """Find node_modules/<dep> visible from *parent_path*, nearest first."""
    segments = parent_path.split("/") if parent_path else []
    depth = 0
    while True:
        prefix = "/".join(segments[: len(segments) - depth]) if depth else parent_path
        candidate = (prefix + "/" if prefix else "") + "node_modules/" + dep
        if candidate in installed:
            return candidate
        if depth >= len(segments):
            break
        depth += 1
    return None


def build_lock() -> dict:
    installed: dict[str, dict[str, str]] = {}
    queue: list[tuple[str, str, str]] = []  # (path, name, range)
    for dep, spec in sorted(ROOT_MANIFEST["dependencies"].items()):
        queue.append(("", dep, spec))
    for dep, spec in sorted(ROOT_MANIFEST["devDependencies"].items()):
        queue.append(("", dep, spec))

    lock_packages: dict[str, dict] = {"": {"name": ROOT_MANIFEST["name"], "version": "2.4.0",
                                           "dependencies": dict(ROOT_MANIFEST["dependencies"]),
                                           "devDependencies": dict(ROOT_MANIFEST["devDependencies"])}}
    index = 0
    while index < len(queue):
        parent_path, dep, spec = queue[index]
        index += 1
        existing = resolve(installed, parent_path, dep)
        if existing is not None and _satisfies(installed[existing]["version"], spec, dep):
            continue
        if dep in GIT_PACKAGES:
            version, license_id, deps, resolved = GIT_PACKAGES[dep]
        elif dep in TARBALL_PACKAGES:
            version, license_id, deps, resolved = TARBALL_PACKAGES[dep]
        else:
            entry = NPM_PACKAGES.get(dep)
            if entry is None:
                raise SystemExit("unknown package in fixture: " + dep)
            license_id = entry[0]
            versions = entry[1]
            version = _best_version(versions, spec)
            deps = versions[version]
            resolved = "https://registry.npmjs.org/" + dep + "/-/" + dep + "-" + version + ".tgz"
        path = (parent_path + "/" if parent_path else "") + "node_modules/" + dep
        record: dict = {"version": version, "resolved": resolved, "integrity": integrity(dep, version)}
        if dep in GIT_PACKAGES or dep in TARBALL_PACKAGES:
            record.pop("integrity", None)
        if license_id:
            record["license"] = license_id
        if dep in DEPRECATED:
            record["deprecated"] = DEPRECATED[dep]
        if dep in INSTALL_SCRIPTS:
            record["hasInstallScript"] = True
            record["scripts"] = {"postinstall": INSTALL_SCRIPTS[dep]}
        if deps:
            record["dependencies"] = dict(sorted(deps.items()))
        if parent_path:
            record["name"] = dep
            record["dev"] = _is_dev(parent_path)
        installed[path] = {"version": version, "name": dep}
        lock_packages[path] = record
        for child, child_spec in sorted(deps.items()):
            queue.append((path, child, child_spec))
    # dev/optional flags derived from reachability would be more precise; the
    # fixture marks dev only where a dev dependency pulled the package in.
    for path, record in lock_packages.items():
        if path and "dev" not in record:
            record["dev"] = _is_dev(path)
        if path and "dev" in record and not record["dev"]:
            del record["dev"]
    return {
        "name": ROOT_MANIFEST["name"],
        "version": ROOT_MANIFEST["version"],
        "lockfileVersion": 3,
        "requires": True,
        "packages": dict(sorted(lock_packages.items())),
    }


def _is_dev(path: str) -> bool:
    return "node_modules/eslint" in path or "node_modules/tslint" in path or "node_modules/request" in path


def _keys(version: str) -> tuple[int, ...]:
    return tuple(int(part) for part in version.split("."))


def _best_version(versions: dict[str, dict[str, str]], spec: str) -> str:
    """Highest published version that satisfies the range (highest overall as fallback)."""
    candidates = sorted(versions, key=_keys)
    if spec.strip() in versions:
        return spec.strip()
    for version in reversed(candidates):
        if _satisfies(version, spec, ""):
            return version
    return candidates[-1]


def _satisfies(version: str, spec: str, name: str) -> bool:
    from dep_radar.semver import satisfies_node_range

    _ = name
    return satisfies_node_range(version, spec)


SOURCE_FILES = {
    "src/server.js": (
        "// Synthetic demo server for the dep-radar example.\n"
        "const express = require('express');\n"
        "const bodyParser = require('body-parser');\n"
        "const axios = require('axios');\n"
        "const lodash = require('lodash');\n"
        "\n"
        "const app = express();\n"
        "app.use(bodyParser.json());\n"
        "\n"
        "app.get('/health', (req, res) => {\n"
        "  res.json({ ok: true, version: '2.4.0' });\n"
        "});\n"
        "\n"
        "app.get('/metrics', async (req, res) => {\n"
        "  const upstream = await axios.get(process.env.METRICS_URL);\n"
        "  res.json(lodash.pick(upstream.data, ['cpu', 'memory', 'requests']));\n"
        "});\n"
        "\n"
        "app.listen(process.env.PORT || 8080);\n"
    ),
    "src/components/Dashboard.jsx": (
        "// Synthetic demo component tree.\n"
        "import React from 'react';\n"
        "import { createRoot } from 'react-dom/client';\n"
        "import chalk from 'chalk';\n"
        "\n"
        "export function Dashboard({ metrics }) {\n"
        "  console.log(chalk.green('render'), metrics.length);\n"
        "  return <table>{metrics.map((row) => <tr key={row.id}>{row.label}</tr>)}</table>;\n"
        "}\n"
        "\n"
        "export function mount(node) {\n"
        "  createRoot(node).render(<Dashboard metrics={[]} />);\n"
        "}\n"
    ),
    "scripts/build.js": (
        "// Synthetic bundler stub: the fixture exists to be audited, not executed.\n"
        "require('dotenv').config();\n"
        "const fs = require('node:fs');\n"
        "\n"
        "for (const file of fs.readdirSync('src')) {\n"
        "  console.log('build', file);\n"
        "}\n"
    ),
}


def write_node_app() -> None:
    NODE_APP.mkdir(parents=True, exist_ok=True)
    (NODE_APP / "package.json").write_text(
        json.dumps(ROOT_MANIFEST, indent=2) + "\n", encoding="utf-8"
    )
    (NODE_APP / "package-lock.json").write_text(
        json.dumps(build_lock(), indent=2) + "\n", encoding="utf-8"
    )
    for relative, content in SOURCE_FILES.items():
        path = NODE_APP / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    (NODE_APP / ".gitignore").write_text("node_modules/\n", encoding="utf-8")
    (NODE_APP / "README.md").write_text(
        "# node-app (synthetic fixture)\n\n"
        "A hand-crafted npm app used by dep-radar's examples and tests. The lockfile is\n"
        "synthetic: it contains a planted typosquat (axois), duplicate versions, a copyleft\n"
        "licence, an install script, git and tarball dependencies. Do not run it.\n",
        encoding="utf-8",
    )


PY_REQUIREMENTS = """# Runtime dependencies for the synthetic Python example.
-r requirements-dev.txt

Django>=4.2,<5.0
requests==2.31.0
PyYAML>=6.0
numpy>=1.26
celery[redis]>=5.3.0 ; python_version >= "3.10"
pandas>=2.0,<3.0
flask
PyJWT>=2.8.0 ; python_version >= "3.9"
"""

PY_REQUIREMENTS_DEV = """# Development tooling, pulled in by the -r include above.
pytest==8.0.2
ruff>=0.3.0
mypy>=1.8.0
coverage[toml]>=7.4.0
"""

PYPROJECT = """[build-system]
requires = ["setuptools>=68", "wheel"]
build-backend = "setuptools.build_meta"

[project]
name = "acme-pipeline"
version = "0.9.3"
description = "Synthetic Python example for dep-radar."
requires-python = ">=3.10"
dependencies = [
    "Django>=4.2,<5.0",
    "requests==2.31.0",
    "PyYAML>=6.0",
    "numpy>=1.26",
    "celery[redis]>=5.3.0 ; python_version >= '3.10'",
    "pandas>=2.0,<3.0",
    "PyJWT>=2.8.0 ; python_version >= '3.9'",
]

[project.optional-dependencies]
dev = ["pytest==8.0.2", "ruff>=0.3.0", "mypy>=1.8.0"]

[tool.ruff]
line-length = 100
"""

PY_SOURCES = {
    "app/__init__.py": "",
    "app/pipeline.py": (
        '"""Synthetic pipeline module for the dep-radar example."""\n'
        "import json\n"
        "\n"
        "import numpy as np\n"
        "import requests\n"
        "import yaml\n"
        "\n"
        "\n"
        "def fetch(url: str) -> dict:\n"
        "    response = requests.get(url, timeout=5)\n"
        "    return response.json()\n"
        "\n"
        "\n"
        "def load_config(path: str) -> dict:\n"
        "    with open(path, encoding='utf-8') as handle:\n"
        "        return yaml.safe_load(handle)\n"
        "\n"
        "\n"
        "def summarise(values: list[float]) -> float:\n"
        "    return float(np.mean(values))\n"
        "\n"
        "\n"
        "def dumps(payload: dict) -> str:\n"
        "    return json.dumps(payload)\n"
    ),
    "app/settings.py": (
        '"""Synthetic Django settings module."""\n'
        "import django\n"
        "\n"
        "DEBUG = False\n"
        "INSTALLED_APPS: list[str] = []\n"
        "django_version = django.__version__\n"
    ),
}


def write_py_app() -> None:
    PY_APP.mkdir(parents=True, exist_ok=True)
    (PY_APP / "requirements.txt").write_text(PY_REQUIREMENTS, encoding="utf-8")
    (PY_APP / "requirements-dev.txt").write_text(PY_REQUIREMENTS_DEV, encoding="utf-8")
    (PY_APP / "pyproject.toml").write_text(PYPROJECT, encoding="utf-8")
    for relative, content in PY_SOURCES.items():
        path = PY_APP / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    (PY_APP / "README.md").write_text(
        "# py-app (synthetic fixture)\n\n"
        "A hand-crafted Python project with requirements includes, environment markers,\n"
        "extras and a PEP 621 pyproject, used by dep-radar's examples and tests.\n",
        encoding="utf-8",
    )


def main() -> int:
    write_node_app()
    write_py_app()
    packages = json.loads((NODE_APP / "package-lock.json").read_text(encoding="utf-8"))["packages"]
    print("node-app packages:", len(packages) - 1)
    print("py-app requirements:", len((PY_APP / "requirements.txt").read_text().splitlines()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
