"""SBOM generation and schema-subset validation."""

from __future__ import annotations

import json

import pytest

from dep_radar.analyzer import analyze
from dep_radar.parsers import parse_ecosystem
from dep_radar.sbom import cyclonedx, render, spdx, validate


@pytest.fixture(scope="module")
def node_analysis(node_app):
    project = parse_ecosystem(node_app, "npm")
    return analyze(project, root=node_app, scan_sources_flag=False)


def test_cyclonedx_document_shape(node_analysis):
    document = cyclonedx(node_analysis)
    assert document["bomFormat"] == "CycloneDX"
    assert document["specVersion"] == "1.5"
    assert document["serialNumber"].startswith("urn:uuid:")
    assert document["metadata"]["tools"][0]["name"] == "dep-radar"
    assert document["components"]


def test_cyclonedx_components_have_purls_and_licences(node_analysis):
    document = cyclonedx(node_analysis)
    for component in document["components"]:
        assert component["purl"].startswith("pkg:npm/")
        assert component["bom-ref"]
        assert component["licenses"]
        assert component["type"] == "library"


def test_cyclonedx_hashes_come_from_lockfile_integrity(node_analysis):
    document = cyclonedx(node_analysis)
    hashed = [c for c in document["components"] if c.get("hashes")]
    assert hashed
    assert hashed[0]["hashes"][0]["alg"] == "SHA-512"


def test_cyclonedx_dependencies_are_not_dangling(node_analysis):
    document = cyclonedx(node_analysis)
    refs = {c["bom-ref"] for c in document["components"]}
    root_refs = {relation["ref"] for relation in document["dependencies"]} - refs
    assert len(root_refs) == 1
    for relation in document["dependencies"]:
        assert relation["ref"] in refs | root_refs
        for child in relation["dependsOn"]:
            assert child in refs


def test_cyclonedx_is_deterministic(node_analysis):
    assert render(node_analysis, "cyclonedx") == render(node_analysis, "cyclonedx")


def test_spdx_document_shape(node_analysis):
    document = spdx(node_analysis)
    assert document["spdxVersion"] == "SPDX-2.3"
    assert document["dataLicense"] == "CC0-1.0"
    assert document["creationInfo"]["creators"][0].startswith("Tool: dep-radar-")
    assert len(document["packages"]) == len(node_analysis.project.packages) + 1


def test_spdx_relationships_point_at_known_ids(node_analysis):
    document = spdx(node_analysis)
    ids = {package["SPDXID"] for package in document["packages"]}
    for relationship in document["relationships"]:
        assert relationship["relatedSpdxElement"] in ids
        assert relationship["spdxElementId"] in ids


def test_spdx_external_refs_are_purls(node_analysis):
    document = spdx(node_analysis)
    for package in document["packages"][1:]:
        ref = package["externalRefs"][0]
        assert ref["referenceType"] == "purl"
        assert ref["referenceLocator"].startswith("pkg:npm/")


def test_validate_accepts_generated_documents(node_analysis):
    assert validate(cyclonedx(node_analysis)) == []
    assert validate(spdx(node_analysis)) == []


def test_validate_rejects_missing_fields():
    problems = validate({"bomFormat": "CycloneDX"})
    assert "missing key: components" in problems


def test_validate_rejects_unknown_format():
    assert validate({"foo": "bar"}) == ["document is neither CycloneDX nor SPDX"]


def test_unknown_format_raises(node_analysis):
    with pytest.raises(ValueError, match="unknown SBOM format"):
        render(node_analysis, "swid")


def test_sbom_json_is_parseable(node_analysis):
    assert json.loads(render(node_analysis, "spdx"))["spdxVersion"] == "SPDX-2.3"
