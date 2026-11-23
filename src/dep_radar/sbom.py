"""SBOM export: CycloneDX-like and SPDX-like documents.

The output is a real, parseable document that follows the documented subset of
each schema (see docs/SBOM.md for exactly which fields dep-radar emits and why).
Identifiers are Package URLs; hashes come from the lockfile integrity field,
which dep-radar never invents.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone

from .analyzer import Analysis
from .licenses import classify
from .version import __version__

CYCLONEDX_VERSION = "1.5"
SPDX_VERSION = "SPDX-2.3"

# Fixed namespace so the same project always produces the same serial number.
_SERIAL_NAMESPACE = uuid.UUID("6f1b0a3e-2c4d-4e1a-9d8a-1b2c3d4e5f60")


def _hash_entries(integrity: str) -> list[dict]:
    """Convert an SRI string ('sha512-base64') into CycloneDX hash objects."""
    entries: list[dict] = []
    for token in (integrity or "").split():
        algorithm, _, value = token.partition("-")
        if algorithm not in {"sha512", "sha384", "sha256", "sha1"} or not value:
            continue
        entries.append({"alg": algorithm.upper().replace("SHA", "SHA-"), "content": value})
    return entries


def _spdx_checksum(integrity: str) -> list[dict]:
    checksums: list[dict] = []
    for token in (integrity or "").split():
        algorithm, _, value = token.partition("-")
        if algorithm not in {"sha512", "sha384", "sha256", "sha1"} or not value:
            continue
        checksums.append(
            {
                "algorithm": "SHA" + algorithm[3:],
                "checksumValue": value,
            }
        )
    return checksums


def _license_id(declared: str | None) -> str:
    verdict = classify(declared)
    if not verdict.declared:
        return "NOASSERTION"
    return verdict.declared


def _serial(analysis: Analysis) -> str:
    seed = str(analysis.project.root).lower().encode("utf-8")
    digest = hashlib.sha256(seed).hexdigest()[:24]
    return "urn:uuid:" + str(uuid.uuid5(_SERIAL_NAMESPACE, digest))


def _timestamp() -> str:
    epoch = __import__("os").environ.get("SOURCE_DATE_EPOCH")
    if epoch and epoch.isdigit():
        moment = datetime.fromtimestamp(int(epoch), tz=timezone.utc)
    else:
        moment = datetime(2026, 1, 1, tzinfo=timezone.utc)
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


def cyclonedx(analysis: Analysis) -> dict:
    """Build a CycloneDX 1.5-like BOM for the scanned project."""
    project = analysis.project
    root_name = project.root.name or "project"
    components: list[dict] = []
    dependency_graph: dict[str, list[str]] = {}
    seen_refs: dict[str, str] = {}
    for package in sorted(project.packages.values(), key=lambda p: (p.name, p.version or "")):
        ref = "pkg:" + ("npm" if package.ecosystem.value == "npm" else "pypi") + "/"
        ref += package.name + ("@" + package.version if package.version else "")
        suffix = 2
        unique = ref
        while unique in seen_refs:
            unique = ref + "#" + str(suffix)
            suffix += 1
        seen_refs[package.key] = unique
        component = {
            "type": "library",
            "bom-ref": unique,
            "name": package.name,
            "purl": package.purl,
            "scope": "optional" if package.optional else ("excluded" if package.dev else "required"),
        }
        if package.version:
            component["version"] = package.version
        component["licenses"] = (
            [{"license": {"id": _license_id(package.license)}}]
            if package.license
            else [{"license": {"name": "NOASSERTION"}}]
        )
        hashes = _hash_entries(package.integrity)
        if hashes:
            component["hashes"] = hashes
        if package.source_kind not in {"registry", ""} and package.source_ref:
            component["externalReferences"] = [
                {"type": "distribution", "url": package.source_ref}
            ]
        components.append(component)
    root_ref = "pkg:" + project.ecosystem.value + "/" + root_name + "@root"
    dependency_graph[root_ref] = [
        seen_refs[edge.child]
        for edge in project.edges
        if edge.parent == "" and edge.child in seen_refs
    ]
    for edge in project.edges:
        if not edge.parent or edge.parent not in seen_refs or edge.child not in seen_refs:
            continue
        dependency_graph.setdefault(seen_refs[edge.parent], [])
        if seen_refs[edge.child] not in dependency_graph[seen_refs[edge.parent]]:
            dependency_graph[seen_refs[edge.parent]].append(seen_refs[edge.child])
    return {
        "bomFormat": "CycloneDX",
        "specVersion": CYCLONEDX_VERSION,
        "serialNumber": _serial(analysis),
        "version": 1,
        "metadata": {
            "timestamp": _timestamp(),
            "tools": [{"vendor": "dep-radar", "name": "dep-radar", "version": __version__}],
            "component": {
                "type": "application",
                "bom-ref": root_ref,
                "name": root_name,
            },
        },
        "components": components,
        "dependencies": [
            {"ref": ref, "dependsOn": sorted(deps)}
            for ref, deps in sorted(dependency_graph.items())
        ],
    }


def spdx(analysis: Analysis) -> dict:
    """Build an SPDX 2.3-like document for the scanned project."""
    project = analysis.project
    root_name = project.root.name or "project"
    packages: list[dict] = []
    relationships: list[dict] = []
    document_namespace = "https://dep-radar.dev/spdx/" + hashlib.sha256(
        str(project.root).lower().encode("utf-8")
    ).hexdigest()[:16]
    root_spdx_id = "SPDXRef-RootPackage"
    packages.append(
        {
            "SPDXID": root_spdx_id,
            "name": root_name,
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": False,
            "licenseConcluded": "NOASSERTION",
            "licenseDeclared": "NOASSERTION",
            "copyrightText": "NOASSERTION",
        }
    )
    for index, package in enumerate(
        sorted(project.packages.values(), key=lambda p: (p.name, p.version or "")), start=1
    ):
        spdx_id = "SPDXRef-Package-" + str(index)
        entry = {
            "SPDXID": spdx_id,
            "name": package.name,
            "versionInfo": package.version or "NOASSERTION",
            "downloadLocation": package.source_ref or "NOASSERTION",
            "filesAnalyzed": False,
            "licenseConcluded": "NOASSERTION",
            "licenseDeclared": _license_id(package.license),
            "copyrightText": "NOASSERTION",
            "externalRefs": [
                {
                    "referenceCategory": "PACKAGE-MANAGER",
                    "referenceType": "purl",
                    "referenceLocator": package.purl,
                }
            ],
        }
        checksums = _spdx_checksum(package.integrity)
        if checksums:
            entry["checksums"] = checksums
        packages.append(entry)
        relationships.append(
            {
                "spdxElementId": root_spdx_id,
                "relationshipType": "DEPENDS_ON",
                "relatedSpdxElement": spdx_id,
            }
        )
    return {
        "spdxVersion": SPDX_VERSION,
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": root_name + "-sbom",
        "documentNamespace": document_namespace,
        "creationInfo": {
            "created": _timestamp(),
            "creators": ["Tool: dep-radar-" + __version__],
        },
        "packages": packages,
        "relationships": relationships,
    }


def render(analysis: Analysis, fmt: str = "cyclonedx", indent: int = 2) -> str:
    """Render an SBOM as JSON in the requested format."""
    if fmt == "cyclonedx":
        document = cyclonedx(analysis)
    elif fmt == "spdx":
        document = spdx(analysis)
    else:
        raise ValueError("unknown SBOM format: " + fmt + " (use cyclonedx or spdx)")
    return json.dumps(document, indent=indent, ensure_ascii=False)


def validate(document: dict) -> list[str]:
    """Check the documented schema subset. Returns a list of problems (empty is ok)."""
    problems: list[str] = []
    if document.get("bomFormat") == "CycloneDX":
        for key in ("bomFormat", "specVersion", "serialNumber", "version", "components"):
            if key not in document:
                problems.append("missing key: " + key)
        for component in document.get("components", []):
            if not str(component.get("purl", "")).startswith("pkg:"):
                problems.append("component without purl: " + str(component.get("name")))
            if "bom-ref" not in component:
                problems.append("component without bom-ref: " + str(component.get("name")))
            if "licenses" not in component:
                problems.append("component without licenses: " + str(component.get("name")))
        refs = {c.get("bom-ref") for c in document.get("components", [])}
        for relation in document.get("dependencies", []):
            for child in relation.get("dependsOn", []):
                if child not in refs and not child.endswith("@root"):
                    problems.append("dangling dependency ref: " + child)
        return problems
    if document.get("spdxVersion"):
        for key in ("spdxVersion", "dataLicense", "SPDXID", "name", "packages", "relationships"):
            if key not in document:
                problems.append("missing key: " + key)
        ids = {p.get("SPDXID") for p in document.get("packages", [])}
        for relationship in document.get("relationships", []):
            if relationship.get("relatedSpdxElement") not in ids:
                problems.append(
                    "dangling relationship: " + str(relationship.get("relatedSpdxElement"))
                )
        return problems
    return ["document is neither CycloneDX nor SPDX"]
